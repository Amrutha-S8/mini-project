import { test } from "node:test";
import assert from "node:assert/strict";

import {
  array,
  bool,
  email,
  int,
  isoDateTime,
  literal,
  nullable,
  object,
  parse,
  str,
  ValidationFailure,
} from "./validate.ts";
import {
  FamilyMemberList,
  FamilyMemberPublic,
  HealthResponse,
  LoginResponse,
  TokenPair,
  UserPublic,
} from "./schemas.ts";
import { memberFixture, tokensFixture, userFixture } from "../test-support/fakeServer.ts";

const fails = (fn: () => unknown, path?: string) =>
  assert.throws(fn, (err: unknown) => {
    assert.ok(err instanceof ValidationFailure);
    if (path !== undefined) assert.equal(err.path, path);
    return true;
  });

test("primitive validators", () => {
  assert.equal(parse(str({ max: 3 }), "abc"), "abc");
  fails(() => parse(str({ max: 3 }), "abcd"));
  fails(() => parse(str(), 5));
  assert.equal(parse(int({ min: 1 }), 3), 3);
  for (const bad of [0, 1.5, "3", Number.NaN, Infinity, 2 ** 60, true]) {
    fails(() => parse(int({ min: 1 }), bad));
  }
  assert.equal(parse(bool, false), false);
  fails(() => parse(bool, "false"));
  assert.equal(parse(literal("a", "b"), "b"), "b");
  fails(() => parse(literal("a", "b"), "c"));
  assert.equal(parse(nullable(int()), null), null);
  assert.equal(parse(nullable(int()), undefined), null);
});

test("email shape", () => {
  assert.equal(parse(email, "a@example.com"), "a@example.com");
  for (const bad of ["", "a", "a@", "@b.c", "a b@c.d", 3]) fails(() => parse(email, bad));
});

test("ISO date-times as Pydantic writes them", () => {
  for (const ok of [
    "2026-11-15T10:00:00Z",
    "2026-11-15T10:00:00.123456Z",
    "2026-11-15T10:00:00+05:30",
    "2026-11-15T10:00:00",
  ]) {
    assert.equal(parse(isoDateTime, ok), ok);
  }
  for (const bad of ["2026-11-15", "yesterday", "2026-13-45T99:00:00Z", "", 1794823200]) {
    fails(() => parse(isoDateTime, bad));
  }
});

test("arrays are bounded and report the failing index", () => {
  assert.deepEqual(parse(array(int()), [1, 2]), [1, 2]);
  fails(() => parse(array(int()), [1, "x"]), "$[1]");
  fails(() => parse(array(int(), { max: 2 }), [1, 2, 3]));
  fails(() => parse(array(int()), { length: 1 }));
});

test("objects are projected: unknown keys never reach the UI", () => {
  const v = object({ a: int() });
  assert.deepEqual(parse(v, { a: 1, injected: "<script>" }), { a: 1 });
  fails(() => parse(v, null));
  fails(() => parse(v, [1]));
  fails(() => parse(v, {}), "$.a");
});

test("objects with non-plain prototypes are rejected", () => {
  class Fake {
    a = 1;
  }
  fails(() => parse(object({ a: int() }), new Fake()));
});

test("a forbidden key invalidates the whole object", () => {
  fails(
    () => parse(UserPublic, userFixture({ password_hash: "$argon2id$..." })),
    "$.password_hash",
  );
  fails(() => parse(UserPublic, userFixture({ embedding: [0.1] })));
  fails(() => parse(FamilyMemberPublic, memberFixture({ face_embedding: "AAAA" })));
});

test("backend-shaped fixtures validate", () => {
  const user = parse(UserPublic, userFixture());
  assert.equal(user.role, "admin");
  parse(TokenPair, tokensFixture());
  parse(LoginResponse, { user: userFixture(), tokens: tokensFixture() });
  assert.equal(parse(FamilyMemberList, [memberFixture(), memberFixture({ id: 8 })]).length, 2);
  parse(HealthResponse, { status: "ok", database: "not_checked" });
});

test("an unknown role is kept as text so access rules can fail closed", () => {
  assert.equal(parse(UserPublic, userFixture({ role: "superuser" })).role, "superuser");
});

test("contract violations are rejected", () => {
  fails(() => parse(TokenPair, { ...tokensFixture(), token_type: "mac" }));
  fails(() => parse(TokenPair, { ...tokensFixture(), expires_in: 0 }));
  fails(() => parse(FamilyMemberPublic, memberFixture({ status: "deleted" })));
  fails(() => parse(FamilyMemberPublic, memberFixture({ member_type: "visitor" })));
  fails(() => parse(FamilyMemberPublic, memberFixture({ id: 0 })));
  fails(() => parse(HealthResponse, { status: "fine", database: "ok" }));
  fails(() => parse(UserPublic, userFixture({ is_active: 1 })));
});
