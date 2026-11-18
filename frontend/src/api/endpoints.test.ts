import { test } from "node:test";
import assert from "node:assert/strict";

import { createApiConfig } from "../config/apiConfig.ts";
import { ApiError } from "./errors.ts";
import { HttpClient } from "./http.ts";
import { healthApi, membersApi, usersApi } from "./endpoints.ts";
import { AuthSession } from "../auth/session.ts";
import {
  BASE,
  FakeServer,
  json,
  memberFixture,
  tokensFixture,
  userFixture,
} from "../test-support/fakeServer.ts";

async function signedIn() {
  const server = new FakeServer();
  server.on("POST", "/auth/login", () =>
    json(200, { user: userFixture(), tokens: tokensFixture() }),
  );
  const http = new HttpClient(createApiConfig({ baseUrl: BASE }), server.fetch);
  const session = new AuthSession(http);
  await session.login("owner@example.com", "pw");
  return { server, http, session };
}

test("health endpoints are public", async () => {
  const server = new FakeServer()
    .on("GET", "/health", () => json(200, { status: "ok", database: "not_checked" }))
    .on("GET", "/health/ready", () => json(200, { status: "degraded", database: "unreachable" }));
  const api = healthApi(new HttpClient(createApiConfig({ baseUrl: BASE }), server.fetch));
  assert.deepEqual(await api.live(), { status: "ok", database: "not_checked" });
  assert.deepEqual(await api.ready(), { status: "degraded", database: "unreachable" });
  assert.ok(server.calls.every((c) => c.headers["Authorization"] === undefined));
});

test("member endpoints use the exact backend methods and paths", async () => {
  const { server, session } = await signedIn();
  const member = () => json(200, memberFixture());
  server
    .on("GET", "/members", () => json(200, [memberFixture()]))
    .on("GET", "/members/7", member)
    .on("POST", "/members", () => json(201, memberFixture()))
    .on("PATCH", "/members/7", member)
    .on("POST", "/members/7/deactivate", () => json(200, memberFixture({ status: "inactive" })))
    .on("POST", "/members/7/revoke", () => json(200, memberFixture({ status: "revoked" })));
  const api = membersApi(session);

  assert.equal((await api.list()).length, 1);
  await api.list({ includeRevoked: true });
  await api.get(7);
  await api.create({ full_name: "New Person", member_type: "family" });
  await api.update(7, { notes: "updated" });
  assert.equal((await api.deactivate(7)).status, "inactive");
  assert.equal((await api.revoke(7)).status, "revoked");

  const calls = server.calls.slice(1).map((c) => `${c.method} ${c.url.replace(BASE, "")}`);
  assert.deepEqual(calls, [
    "GET /members",
    "GET /members?include_revoked=true",
    "GET /members/7",
    "POST /members",
    "PATCH /members/7",
    "POST /members/7/deactivate",
    "POST /members/7/revoke",
  ]);
  assert.deepEqual(server.calls[4]?.body, { full_name: "New Person", member_type: "family" });
  assert.deepEqual(server.calls[5]?.body, { notes: "updated" });
  assert.equal(server.calls[6]?.body, undefined, "deactivate sends no body");
});

test("invalid member ids never reach the network", async () => {
  const { server, session } = await signedIn();
  const api = membersApi(session);
  for (const bad of [0, -1, 1.5, Number.NaN, 2 ** 60]) {
    await assert.rejects(api.get(bad), ApiError);
  }
  assert.equal(server.calls.length, 1); // the login only
});

test("register is sent with the admin's token", async () => {
  const { server, session } = await signedIn();
  server.on("POST", "/auth/register", () => json(201, userFixture({ id: 5, role: "viewer" })));
  const created = await usersApi(session).register({
    email: "viewer@example.com",
    password: "a long passphrase",
    full_name: "Viewer",
    role: "viewer",
  });
  assert.equal(created.role, "viewer");
  assert.match(server.calls.at(-1)?.headers["Authorization"] ?? "", /^Bearer access-/);
});
