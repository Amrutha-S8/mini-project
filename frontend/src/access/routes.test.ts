import { test } from "node:test";
import assert from "node:assert/strict";

import { parse } from "../api/validate.ts";
import { UserPublic } from "../api/schemas.ts";
import {
  ACTIONS,
  can,
  effectiveRole,
  LOGIN_PATH,
  PAGES,
  resolveRoute,
  safeNextPath,
  visiblePages,
} from "./routes.ts";
import { userFixture } from "../test-support/fakeServer.ts";

const user = (role: string, is_active = true) =>
  parse(UserPublic, userFixture({ role, is_active }));
const admin = user("admin");
const viewer = user("viewer");
const member = user("member");

test("seven pages in the reference sidebar order", () => {
  assert.deepEqual(
    PAGES.map((p) => p.title),
    [
      "Dashboard",
      "Live Monitoring",
      "Access Management",
      "Security Events",
      "AI Assistant",
      "Analytics",
      "Settings",
    ],
  );
  assert.equal(new Set(PAGES.map((p) => p.path)).size, 7);
});

test("page visibility per role", () => {
  const ids = (u: typeof admin | null) => visiblePages(u).map((p) => p.id);
  assert.equal(ids(admin).length, 7);
  assert.deepEqual(ids(viewer), [
    "dashboard",
    "access_management",
    "security_events",
    "ai_assistant",
    "analytics",
    "settings",
  ]);
  assert.deepEqual(ids(member), ["dashboard", "access_management", "ai_assistant", "settings"]);
});

test("Live Monitoring is admin-only (it shows faces at the door)", () => {
  for (const u of [viewer, member]) {
    assert.equal(resolveRoute("/live-monitoring", u).kind, "forbidden");
  }
  assert.equal(resolveRoute("/live-monitoring", admin).kind, "render");
});

test("access rules fail closed", () => {
  const emptyRole = { ...admin, role: "" }; // cannot come from the API; checked anyway
  for (const u of [null, user("admin", false), user("superuser"), user("Admin"), emptyRole]) {
    assert.equal(effectiveRole(u as typeof admin | null), null);
    assert.deepEqual(visiblePages(u as typeof admin | null), []);
    for (const action of Object.keys(ACTIONS) as (keyof typeof ACTIONS)[]) {
      assert.equal(can(u as typeof admin | null, action), false);
    }
  }
});

test("only admins get mutation controls", () => {
  for (const action of [
    "members.create",
    "members.update",
    "members.deactivate",
    "members.revoke",
    "users.register",
  ] as const) {
    assert.equal(can(admin, action), true, action);
    assert.equal(can(viewer, action), false, action);
    assert.equal(can(member, action), false, action);
  }
  assert.equal(can(member, "members.list"), true);
});

test("signed-out users are sent to login with a safe next path", () => {
  assert.deepEqual(resolveRoute("/analytics", null), {
    kind: "redirect",
    to: "/login?next=%2Fanalytics",
  });
  assert.deepEqual(resolveRoute("/", null), { kind: "redirect", to: LOGIN_PATH });
  assert.deepEqual(resolveRoute("/no-such-page", null), { kind: "redirect", to: LOGIN_PATH });
  assert.deepEqual(resolveRoute(LOGIN_PATH, null), { kind: "render_login" });
});

test("signed-in users leave the login page for a validated destination", () => {
  assert.deepEqual(resolveRoute(LOGIN_PATH, admin, "?next=%2Fsettings"), {
    kind: "redirect",
    to: "/settings",
  });
  assert.deepEqual(resolveRoute(LOGIN_PATH, admin, "?next=https://evil.example"), {
    kind: "redirect",
    to: "/",
  });
  assert.equal(resolveRoute("/nope", admin).kind, "not_found");
  assert.equal(resolveRoute("/settings/", admin).kind, "render");
});

test("next-path handling blocks open redirects", () => {
  for (const bad of [
    "https://evil.example",
    "//evil.example",
    "/\\evil.example",
    // eslint-disable-next-line no-script-url -- deliberate malicious input under test
    "javascript:alert(1)",
    "/settings\n",
    "/%2F%2Fevil.example",
    "/unknown",
    "x".repeat(300),
    null,
    undefined,
  ]) {
    assert.equal(safeNextPath(bad), "/", String(bad));
  }
  assert.equal(safeNextPath("/security-events"), "/security-events");
});
