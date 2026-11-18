/**
 * Session behaviour against a scripted fake backend. These prove the client
 * logic (single-flight refresh, one retry, sign-out reasons), not the real
 * backend.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { createApiConfig } from "../config/apiConfig.ts";
import { ApiError } from "../api/errors.ts";
import { HttpClient } from "../api/http.ts";
import { UserPublic } from "../api/schemas.ts";
import { AuthSession, type SessionState } from "./session.ts";
import {
  BASE,
  deferred,
  errorEnvelope,
  FakeServer,
  json,
  tokensFixture,
  userFixture,
} from "../test-support/fakeServer.ts";

function setup(opts: { expiresIn?: number } = {}) {
  const server = new FakeServer();
  let now = 1_000_000;
  const clock = {
    get: () => now,
    advance: (ms: number) => {
      now += ms;
    },
  };
  const http = new HttpClient(createApiConfig({ baseUrl: BASE }), server.fetch);
  const session = new AuthSession(http, clock.get);
  const states: SessionState[] = [];
  session.subscribe((s) => states.push(s));
  const firstTokens = tokensFixture(opts.expiresIn ?? 900);
  server.on("POST", "/auth/login", () => json(200, { user: userFixture(), tokens: firstTokens }));
  return { server, session, clock, states, firstTokens };
}

const me = () => json(200, userFixture());

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

async function signedOutError(promise: Promise<unknown>): Promise<ApiError> {
  try {
    await promise;
  } catch (err) {
    assert.ok(err instanceof ApiError);
    return err;
  }
  assert.fail("expected an error");
}

test("login stores the session in memory and notifies", async () => {
  const { session, server, states } = setup();
  const user = await session.login("owner@example.com", "correct horse battery");
  assert.equal(user.email, "owner@example.com");
  assert.equal(session.state.status, "signed_in");
  assert.deepEqual(
    states.map((s) => s.status),
    ["signed_in"],
  );
  assert.deepEqual(server.calls[0]?.body, {
    email: "owner@example.com",
    password: "correct horse battery",
  });
  assert.equal(server.calls[0]?.headers["Authorization"], undefined);
});

test("tokens are never written to web storage", async () => {
  const touched: string[] = [];
  const spy = new Proxy(
    {},
    {
      get: (_t, key) => {
        touched.push(String(key));
        return () => null;
      },
    },
  );
  const g = globalThis as Record<string, unknown>;
  g["localStorage"] = spy;
  g["sessionStorage"] = spy;
  try {
    const { session, server } = setup();
    server.on("GET", "/auth/me", me);
    await session.login("owner@example.com", "pw");
    await session.reloadUser();
    await session.logout();
    assert.deepEqual(touched, []);
  } finally {
    delete g["localStorage"];
    delete g["sessionStorage"];
  }
});

test("bad credentials and rate limits leave the user signed out", async () => {
  const { session, server } = setup();
  server.on(
    "POST",
    "/auth/login",
    () => errorEnvelope(401, "invalid_credentials", "Incorrect email or password"),
    () =>
      errorEnvelope(429, "rate_limited", "Too many attempts. Try again later.", {
        "Retry-After": "60",
      }),
  );
  const first = await signedOutError(session.login("a@b.co", "x"));
  assert.equal(first.code, "invalid_credentials");
  const second = await signedOutError(session.login("a@b.co", "x"));
  assert.equal(second.retryAfterSeconds, 60);
  assert.equal(session.state.status, "signed_out");
});

test("an inactive account is not signed in", async () => {
  const { session, server } = setup();
  server.on("POST", "/auth/login", () =>
    json(200, { user: userFixture({ is_active: false }), tokens: tokensFixture() }),
  );
  const err = await signedOutError(session.login("a@b.co", "x"));
  assert.equal(err.code, "account_inactive");
  assert.equal(session.state.status, "signed_out");
});

test("authorised calls send the access token", async () => {
  const { session, server, firstTokens } = setup();
  server.on("GET", "/auth/me", me);
  await session.login("a@b.co", "x");
  await session.reloadUser();
  assert.equal(server.calls[1]?.headers["Authorization"], `Bearer ${firstTokens.access_token}`);
});

test("refreshes shortly before expiry, then uses the rotated tokens", async () => {
  const { session, server, clock, firstTokens } = setup({ expiresIn: 900 });
  const second = tokensFixture();
  server.on("POST", "/auth/refresh", () => json(200, second));
  server.on("GET", "/auth/me", me);
  await session.login("a@b.co", "x");
  clock.advance(900_000 - 29_000); // inside the 30 s skew
  await session.reloadUser();
  assert.equal(server.count("POST", "/auth/refresh"), 1);
  assert.deepEqual(server.calls[1]?.body, { refresh_token: firstTokens.refresh_token });
  assert.equal(server.calls[2]?.headers["Authorization"], `Bearer ${second.access_token}`);
});

test("concurrent callers share ONE refresh (rotated-token replay would revoke the session)", async () => {
  const { session, server, clock } = setup();
  const gate = deferred<Response>();
  server.on("POST", "/auth/refresh", () => gate.promise);
  server.on("GET", "/auth/me", me);
  await session.login("a@b.co", "x");
  clock.advance(10 * 60 * 60 * 1000);
  const calls = Array.from({ length: 8 }, () => session.reloadUser());
  await sleep(10);
  gate.resolve(json(200, tokensFixture()));
  await Promise.all(calls);
  assert.equal(server.count("POST", "/auth/refresh"), 1);
  assert.equal(server.count("GET", "/auth/me"), 8);
});

test("a 401 triggers one refresh and one retry", async () => {
  const { session, server } = setup();
  const second = tokensFixture();
  server.on("POST", "/auth/refresh", () => json(200, second));
  server.on(
    "GET",
    "/auth/me",
    () => errorEnvelope(401, "unauthenticated", "Authentication required"),
    me,
  );
  await session.login("a@b.co", "x");
  const user = await session.reloadUser();
  assert.equal(user.id, 1);
  assert.equal(server.count("POST", "/auth/refresh"), 1);
  assert.equal(server.count("GET", "/auth/me"), 2);
  assert.equal(server.calls.at(-1)?.headers["Authorization"], `Bearer ${second.access_token}`);
});

test("a second 401 after the retry ends the session instead of looping", async () => {
  const { session, server, states } = setup();
  server.on("POST", "/auth/refresh", () => json(200, tokensFixture()));
  server.on("GET", "/auth/me", () =>
    errorEnvelope(401, "unauthenticated", "Authentication required"),
  );
  await session.login("a@b.co", "x");
  const err = await signedOutError(session.reloadUser());
  assert.equal(err.kind, "signed_out");
  assert.equal(server.count("GET", "/auth/me"), 2);
  assert.equal(server.count("POST", "/auth/refresh"), 1);
  assert.deepEqual(states.at(-1), { status: "signed_out", reason: "expired" });
});

for (const [code, reason] of [
  ["token_reuse_detected", "reuse_detected"],
  ["session_revoked", "revoked"],
  ["unauthenticated", "expired"],
] as const) {
  test(`refresh refused with ${code} signs out with reason ${reason}`, async () => {
    const { session, server, clock, states } = setup();
    server.on("POST", "/auth/refresh", () =>
      errorEnvelope(401, code, "Session is no longer valid"),
    );
    server.on("GET", "/auth/me", me);
    await session.login("a@b.co", "x");
    clock.advance(2 * 900_000);
    const err = await signedOutError(session.reloadUser());
    assert.equal(err.kind, "signed_out");
    assert.equal(session.state.status, "signed_out");
    assert.deepEqual(states.at(-1), { status: "signed_out", reason });
    assert.equal(server.count("GET", "/auth/me"), 0);
  });
}

test("a revoked session reported by a protected call ends immediately", async () => {
  const { session, server } = setup();
  server.on("GET", "/auth/me", () =>
    errorEnvelope(401, "session_revoked", "Session is no longer valid"),
  );
  await session.login("a@b.co", "x");
  await signedOutError(session.reloadUser());
  assert.equal(server.count("POST", "/auth/refresh"), 0);
  assert.equal(session.state.status, "signed_out");
});

test("rate-limited or failed refresh keeps the session", async () => {
  const { session, server, clock } = setup();
  server.on(
    "POST",
    "/auth/refresh",
    () =>
      errorEnvelope(429, "rate_limited", "Too many attempts. Try again later.", {
        "Retry-After": "5",
      }),
    () => Promise.reject(new TypeError("Failed to fetch")),
    () => json(200, tokensFixture()),
  );
  server.on("GET", "/auth/me", me);
  await session.login("a@b.co", "x");
  clock.advance(2 * 900_000);
  assert.equal((await signedOutError(session.reloadUser())).status, 429);
  assert.equal(session.state.status, "signed_in");
  assert.equal((await signedOutError(session.reloadUser())).kind, "network");
  assert.equal(session.state.status, "signed_in");
  await session.reloadUser();
  assert.equal(server.count("POST", "/auth/refresh"), 3);
});

test("403 is passed through and does not end the session", async () => {
  const { session, server } = setup();
  server.on("POST", "/members", () =>
    errorEnvelope(403, "forbidden", "You do not have permission"),
  );
  await session.login("a@b.co", "x");
  const err = await signedOutError(
    session.authorized({ method: "POST", path: "/members", body: {}, expect: UserPublic }),
  );
  assert.equal(err.status, 403);
  assert.equal(session.state.status, "signed_in");
});

test("logout revokes on the server and clears locally", async () => {
  const { session, server, firstTokens, states } = setup();
  server.on("POST", "/auth/logout", () => new Response(null, { status: 204 }));
  await session.login("a@b.co", "x");
  assert.deepEqual(await session.logout(), { serverRevoked: true });
  const call = server.calls.at(-1);
  assert.deepEqual(call?.body, { refresh_token: firstTokens.refresh_token });
  assert.equal(call?.headers["Authorization"], `Bearer ${firstTokens.access_token}`);
  assert.deepEqual(states.at(-1), { status: "signed_out", reason: "logout" });
  await signedOutError(session.reloadUser());
});

test("logout still clears locally when the server cannot be reached, and says so", async () => {
  const { session, server } = setup();
  server.on("POST", "/auth/logout", () => Promise.reject(new TypeError("Failed to fetch")));
  await session.login("a@b.co", "x");
  assert.deepEqual(await session.logout(), { serverRevoked: false });
  assert.equal(session.state.status, "signed_out");
});

test("logout after expiry refreshes first and revokes the ROTATED token", async () => {
  const { session, server, clock } = setup();
  const second = tokensFixture();
  server.on("POST", "/auth/refresh", () => json(200, second));
  server.on("POST", "/auth/logout", () => new Response(null, { status: 204 }));
  await session.login("a@b.co", "x");
  clock.advance(2 * 900_000);
  await session.logout();
  assert.deepEqual(server.calls.at(-1)?.body, { refresh_token: second.refresh_token });
});

test("a refresh that finishes after a new login cannot overwrite the new session", async () => {
  const { session, server, clock } = setup();
  const gate = deferred<Response>();
  server.on("POST", "/auth/refresh", () => gate.promise);
  server.on("GET", "/auth/me", me);
  await session.login("a@b.co", "x");
  clock.advance(2 * 900_000);
  const pending = session.reloadUser(); // starts a refresh for the OLD session
  await sleep(5);
  const newTokens = tokensFixture();
  server.on("POST", "/auth/login", () =>
    json(200, { user: userFixture({ id: 2, role: "viewer" }), tokens: newTokens }),
  );
  await session.login("viewer@example.com", "y");
  gate.resolve(json(200, tokensFixture())); // stale result for the old session
  await signedOutError(pending);
  assert.equal(session.user?.id, 2);
  assert.equal(server.count("POST", "/auth/refresh"), 1, "the new session did not refresh");
  await session.reloadUser();
  assert.equal(server.calls.at(-1)?.headers["Authorization"], `Bearer ${newTokens.access_token}`);
});

test("a failing subscriber does not break the session", async () => {
  const { session } = setup();
  session.subscribe(() => {
    throw new Error("listener bug");
  });
  await session.login("a@b.co", "x");
  assert.equal(session.state.status, "signed_in");
});

test("calls while signed out fail without contacting the server", async () => {
  const { session, server } = setup();
  const err = await signedOutError(session.reloadUser());
  assert.equal(err.kind, "signed_out");
  assert.equal(server.calls.length, 0);
});

test("error messages never contain tokens", async () => {
  const { session, server, firstTokens } = setup();
  server.on("GET", "/auth/me", () => new Response("boom", { status: 500 }));
  await session.login("a@b.co", "x");
  const err = await signedOutError(session.reloadUser());
  assert.ok(!err.message.includes(firstTokens.access_token));
  assert.ok(!err.message.includes(firstTokens.refresh_token));
});
