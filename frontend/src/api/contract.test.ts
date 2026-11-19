/**
 * Contract drift checks against the backend *source* (the backend cannot be
 * run here). If a Pydantic model, a route, a guard or the CORS method list
 * changes, these fail and point at the frontend file to update.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { ALLOWED_METHODS } from "./http.ts";
import { FORBIDDEN_RESPONSE_KEYS, PASSWORD_MAX_LENGTH, PASSWORD_MIN_LENGTH } from "./schemas.ts";
import { memberFixture, tokensFixture, userFixture } from "../test-support/fakeServer.ts";
import { backendRoutes, pydanticFields, readBackend } from "../test-support/backendSource.ts";

const sorted = (xs: Iterable<string>) => [...xs].sort();

test("UserPublic fields match backend/app/schemas/auth.py", () => {
  assert.deepEqual(
    sorted(Object.keys(userFixture())),
    sorted(pydanticFields("schemas/auth.py", "UserPublic")),
  );
});

test("TokenPair fields match", () => {
  assert.deepEqual(
    sorted(Object.keys(tokensFixture())),
    sorted(pydanticFields("schemas/auth.py", "TokenPair")),
  );
});

test("LoginResponse fields match", () => {
  assert.deepEqual(pydanticFields("schemas/auth.py", "LoginResponse"), ["user", "tokens"]);
});

test("request bodies match LoginRequest, RefreshRequest and RegisterRequest", () => {
  assert.deepEqual(pydanticFields("schemas/auth.py", "LoginRequest"), ["email", "password"]);
  assert.deepEqual(pydanticFields("schemas/auth.py", "RefreshRequest"), ["refresh_token"]);
  assert.deepEqual(pydanticFields("schemas/auth.py", "RegisterRequest"), [
    "email",
    "password",
    "full_name",
    "role",
  ]);
});

test("FamilyMemberPublic fields match backend/app/schemas/family_member.py", () => {
  assert.deepEqual(
    sorted(Object.keys(memberFixture())),
    sorted(pydanticFields("schemas/family_member.py", "FamilyMemberPublic")),
  );
});

test("member create and update fields match", () => {
  assert.deepEqual(pydanticFields("schemas/family_member.py", "FamilyMemberCreate"), [
    "full_name",
    "member_type",
    "relationship_label",
    "notes",
    "user_id",
  ]);
  assert.deepEqual(pydanticFields("schemas/family_member.py", "FamilyMemberUpdate"), [
    "full_name",
    "member_type",
    "relationship_label",
    "notes",
  ]);
});

test("member enum values match the backend Literal types", () => {
  const source = readBackend("schemas/family_member.py");
  assert.match(
    source,
    /MemberType = Literal\["family", "resident", "staff", "recurring_visitor"\]/,
  );
  assert.match(source, /MemberStatus = Literal\["active", "inactive", "revoked"\]/);
  assert.match(
    source,
    /EnrollmentStatus = Literal\["not_enrolled", "enrolled", "needs_reenrollment"\]/,
  );
});

test("HealthResponse fields and values match", () => {
  const source = readBackend("api/v1/health.py");
  assert.deepEqual(pydanticFields("api/v1/health.py", "HealthResponse"), ["status", "database"]);
  for (const value of ['"ok"', '"degraded"', '"unreachable"', '"not_checked"']) {
    assert.ok(source.includes(value), value);
  }
});

test("client methods equal the backend CORS allow_methods", () => {
  const main = readBackend("main.py");
  const m = /allow_methods=\[([^\]]*)\]/.exec(main);
  assert.ok(m?.[1], "allow_methods not found");
  const backend = [...m[1].matchAll(/"([A-Z]+)"/g)].map((x) => x[1] ?? "");
  assert.deepEqual(sorted(backend), sorted(ALLOWED_METHODS));
  assert.match(main, /allow_headers=\["Authorization", "Content-Type"\]/);
  assert.match(main, /allow_credentials=False/);
});

test("password hint lengths match backend/app/utils/validators.py", () => {
  const source = readBackend("utils/validators.py");
  assert.match(source, new RegExp(`MIN_PASSWORD_LENGTH = ${PASSWORD_MIN_LENGTH}\\b`));
  assert.match(source, new RegExp(`MAX_PASSWORD_LENGTH = ${PASSWORD_MAX_LENGTH}\\b`));
});

test("the error envelope shape matches core/errors.py and main.py", () => {
  assert.match(
    readBackend("core/errors.py"),
    /"error": \{"code": self\.code, "message": self\.message\}/,
  );
  assert.match(readBackend("main.py"), /"code": codes\.get\(exc\.status_code, "http_error"\)/);
});

test("no backend response model declares a forbidden key", () => {
  for (const [file, cls] of [
    ["schemas/auth.py", "UserPublic"],
    ["schemas/auth.py", "TokenPair"],
    ["schemas/family_member.py", "FamilyMemberPublic"],
  ] as const) {
    const fields = pydanticFields(file, cls);
    for (const key of FORBIDDEN_RESPONSE_KEYS) assert.ok(!fields.includes(key), `${cls}.${key}`);
  }
});

test("the backend route parser sees all 31 routes", () => {
  const routes = backendRoutes().map((r) => `${r.method} ${r.path} ${r.guard}`);
  assert.deepEqual(
    sorted(routes),
    sorted([
      "GET /health public",
      "GET /health/ready public",
      "POST /auth/register admin",
      "POST /auth/login public",
      "POST /auth/refresh public",
      "POST /auth/logout authenticated",
      "GET /auth/me authenticated",
      "GET /members authenticated",
      "GET /members/{id} authenticated",
      "POST /members admin",
      "PATCH /members/{id} admin",
      "POST /members/{id}/deactivate admin",
      "POST /members/{id}/revoke admin",
      "GET /events/access authenticated",
      "GET /events/security authenticated",
      "GET /incidents authenticated",
      "GET /incidents/{id} authenticated",
      "PATCH /incidents/{id} admin",
      "GET /dashboard/summary authenticated",
      "POST /incidents/{id}/acknowledge admin",
      "POST /incidents/{id}/investigate admin",
      "POST /incidents/{id}/resolve admin",
      "GET /incidents/{id}/notifications admin",
      "POST /incidents/{id}/notify admin",
      "POST /monitoring/events admin",
      "GET /notifications admin",
      "GET /notifications/channels admin",
      "POST /notifications/{id}/refresh admin",
      "GET /notifications/webhooks/whatsapp public",
      "POST /notifications/webhooks/whatsapp public",
      "POST /notifications/webhooks/twilio public",
    ]),
  );
});
