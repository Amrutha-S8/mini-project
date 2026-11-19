/**
 * The feature registry against the backend source: every "available" feature
 * points at a real route with a matching guard, every route is accounted for,
 * and every unfinished feature says why.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { FEATURES, SESSION_ENDPOINTS, featureRoles, type Feature } from "./features.ts";
import { PAGES } from "./routes.ts";
import { backendRoutes } from "../test-support/backendSource.ts";

const all: [string, string, Feature][] = Object.entries(FEATURES).flatMap(([page, features]) =>
  Object.entries(features as Record<string, Feature>).map(
    ([name, f]) => [page, name, f] as [string, string, Feature],
  ),
);
const routes = backendRoutes();
const key = (m: string, p: string) => `${m} ${p}`;

test("every page has a feature list", () => {
  assert.deepEqual(Object.keys(FEATURES).sort(), PAGES.map((p) => p.id).sort());
});

test("every available feature uses an endpoint that exists in the backend", () => {
  const existing = new Set(routes.map((r) => key(r.method, r.path)));
  for (const [page, name, f] of all) {
    if (f.status === "available") {
      assert.ok(existing.has(key(f.endpoint.method, f.endpoint.path)), `${page}.${name}`);
    }
  }
});

test("UI roles match the backend guard of each endpoint", () => {
  const routeOf = new Map(routes.map((r) => [key(r.method, r.path), r]));
  for (const [page, name, f] of all) {
    if (f.status !== "available") continue;
    const route = routeOf.get(key(f.endpoint.method, f.endpoint.path));
    const roles = featureRoles(f);
    if (route?.guard === "admin") {
      assert.deepEqual(roles, ["admin"], `${page}.${name} is admin-only in the backend`);
    } else if (route && roles !== null) {
      assert.deepEqual(
        [...roles].sort(),
        route.roles,
        `${page}.${name}: UI roles must equal the backend's (${route.roles.join(", ")})`,
      );
    }
  }
});

test("role-filtered routes are parsed from ensure_role", () => {
  const rolesOf = (m: string, p: string) =>
    routes.find((r) => key(r.method, r.path) === key(m, p))?.roles;
  assert.deepEqual(rolesOf("GET", "/members"), ["admin", "member"]);
  assert.deepEqual(rolesOf("GET", "/incidents"), ["admin", "viewer"]);
  assert.deepEqual(rolesOf("GET", "/events/access"), ["admin", "member", "viewer"]);
  assert.deepEqual(rolesOf("PATCH", "/incidents/{id}"), ["admin"]);
});

test("every backend route is used by a feature or by the session", () => {
  const used = new Set([
    ...all.flatMap(([, , f]) =>
      f.status === "available" ? [key(f.endpoint.method, f.endpoint.path)] : [],
    ),
    ...SESSION_ENDPOINTS.map((e) => key(e.method, e.path)),
  ]);
  for (const r of routes)
    assert.ok(used.has(key(r.method, r.path)), `${r.method} ${r.path} unused`);
});

test("unfinished features explain themselves and expose no endpoint", () => {
  for (const [page, name, f] of all) {
    if (f.status === "unavailable") {
      assert.ok(f.reason.length >= 20, `${page}.${name}`);
      assert.ok(!("endpoint" in f), `${page}.${name}`);
    }
  }
});

test("recognition, decisions, AI and backup are not claimed", () => {
  const status = (page: keyof typeof FEATURES, name: string) =>
    (FEATURES[page] as Record<string, Feature>)[name]?.status;
  assert.equal(status("live_monitoring", "recognition"), "unavailable");
  assert.equal(status("live_monitoring", "access_decision"), "unavailable");
  assert.equal(status("live_monitoring", "face_detection"), "unavailable");
  assert.equal(status("live_monitoring", "webcam_preview"), "browser_only");
  assert.equal(status("settings", "backup"), "unavailable");
  assert.equal(status("settings", "ai_settings"), "unavailable");
  for (const f of Object.values(FEATURES.ai_assistant) as Feature[]) {
    assert.equal(f.status, "unavailable");
  }
});

test("no feature talks about unlocking or deciding access", () => {
  for (const [page, name, f] of all) {
    if (f.status === "available") {
      assert.doesNotMatch(f.endpoint.path, /unlock|door|decision|lockdown/, `${page}.${name}`);
    }
  }
});
