import { test } from "node:test";
import assert from "node:assert/strict";

import { ConfigError, createApiConfig } from "../config/apiConfig.ts";
import { ApiError, parseRetryAfter } from "./errors.ts";
import { HttpClient, buildUrl, MAX_RESPONSE_CHARS, type FetchLike } from "./http.ts";
import { HealthResponse } from "./schemas.ts";
import { BASE, errorEnvelope, FakeServer, json } from "../test-support/fakeServer.ts";

const config = createApiConfig({ baseUrl: BASE, timeoutMs: 200 });

async function apiError(promise: Promise<unknown>): Promise<ApiError> {
  try {
    await promise;
  } catch (err) {
    assert.ok(err instanceof ApiError, String(err));
    return err;
  }
  assert.fail("expected an ApiError");
}

// --- configuration --------------------------------------------------------------

test("base URL is normalised and validated", () => {
  assert.equal(createApiConfig({ baseUrl: "http://localhost:8000/api/v1/" }).baseUrl, BASE);
  assert.equal(
    createApiConfig({ baseUrl: "https://home.example/api/v1" }).baseUrl,
    "https://home.example/api/v1",
  );
  for (const bad of [
    "localhost:8000",
    "ftp://localhost/api",
    "http://home.example/api/v1", // plain http off-host
    "https://user:pw@home.example/api",
    "https://home.example/api?x=1",
    "https://home.example/api#x",
    // eslint-disable-next-line no-script-url -- deliberate malicious input under test
    "javascript:alert(1)",
  ]) {
    assert.throws(() => createApiConfig({ baseUrl: bad }), ConfigError, bad);
  }
  assert.throws(() => createApiConfig({ timeoutMs: 0 }), ConfigError);
  assert.throws(() => createApiConfig({ timeoutMs: 1.5 }), ConfigError);
});

test("paths cannot escape the API prefix", () => {
  assert.equal(buildUrl(config, "/members/3"), `${BASE}/members/3`);
  assert.equal(
    buildUrl(config, "/members", { include_revoked: "true", skip: undefined }),
    `${BASE}/members?include_revoked=true`,
  );
  for (const bad of [
    "members",
    "//evil.example/x",
    "/../admin",
    "/a/../b",
    "/x?y=1",
    "/a b",
    "http://x",
  ]) {
    assert.throws(() => buildUrl(config, bad), ApiError, bad);
  }
});

// --- requests -------------------------------------------------------------------

test("sends only CORS-allowed headers, no cookies, JSON body", async () => {
  const server = new FakeServer().on("POST", "/auth/login", () =>
    json(200, { status: "ok", database: "ok" }),
  );
  const http = new HttpClient(config, server.fetch);
  await http.request({
    method: "POST",
    path: "/auth/login",
    body: { email: "a@b.co", password: "x" },
    accessToken: "tok",
    expect: HealthResponse,
  });
  const call = server.calls[0];
  assert.ok(call);
  assert.deepEqual(Object.keys(call.headers).sort(), ["Accept", "Authorization", "Content-Type"]);
  assert.equal(call.headers["Authorization"], "Bearer tok");
  assert.equal(call.init.credentials, "omit");
  assert.equal(call.init.redirect, "error");
  assert.deepEqual(call.body, { email: "a@b.co", password: "x" });
});

test("GET without a body sends no Content-Type", async () => {
  const server = new FakeServer().on("GET", "/health", () =>
    json(200, { status: "ok", database: "not_checked" }),
  );
  await new HttpClient(config, server.fetch).request({
    method: "GET",
    path: "/health",
    expect: HealthResponse,
  });
  assert.equal(server.calls[0]?.headers["Content-Type"], undefined);
  assert.equal(server.calls[0]?.headers["Authorization"], undefined);
});

test("methods outside the CORS policy are refused before sending", async () => {
  const server = new FakeServer();
  const http = new HttpClient(config, server.fetch);
  const err = await apiError(
    http.request({ method: "DELETE" as "GET", path: "/members/1", expect: null }),
  );
  assert.equal(err.code, "invalid_method");
  assert.equal(server.calls.length, 0);
});

// --- failures -------------------------------------------------------------------

test("backend error envelope becomes a typed error", async () => {
  const server = new FakeServer().on("GET", "/members/9", () =>
    errorEnvelope(404, "not_found", "Resource not found"),
  );
  const err = await apiError(
    new HttpClient(config, server.fetch).request({
      method: "GET",
      path: "/members/9",
      expect: null,
    }),
  );
  assert.equal(err.kind, "http");
  assert.equal(err.status, 404);
  assert.equal(err.code, "not_found");
  assert.equal(err.message, "Resource not found");
});

test("429 carries Retry-After", async () => {
  const server = new FakeServer().on("POST", "/auth/login", () =>
    errorEnvelope(429, "rate_limited", "Too many attempts. Try again later.", {
      "Retry-After": "42",
    }),
  );
  const err = await apiError(
    new HttpClient(config, server.fetch).request({
      method: "POST",
      path: "/auth/login",
      body: {},
      expect: null,
    }),
  );
  assert.ok(err.isRateLimited);
  assert.equal(err.retryAfterSeconds, 42);
});

test("non-envelope error bodies are never echoed", async () => {
  const secretPage = "<html>Traceback: password=hunter2 at /srv/app.py</html>";
  const server = new FakeServer().on(
    "GET",
    "/health",
    () => new Response(secretPage, { status: 502 }),
  );
  const err = await apiError(
    new HttpClient(config, server.fetch).request({
      method: "GET",
      path: "/health",
      expect: HealthResponse,
    }),
  );
  assert.equal(err.code, "http_error");
  assert.doesNotMatch(err.message, /hunter2|Traceback|app\.py/);
});

test("network failure, timeout and caller abort are distinguished", async () => {
  const down: FetchLike = () => Promise.reject(new TypeError("Failed to fetch"));
  assert.equal(
    (
      await apiError(
        new HttpClient(config, down).request({ method: "GET", path: "/health", expect: null }),
      )
    ).kind,
    "network",
  );

  const hang: FetchLike = (_url, init) =>
    new Promise((_resolve, reject) => {
      init.signal?.addEventListener("abort", () =>
        reject(new DOMException("aborted", "AbortError")),
      );
    });
  const slow = new HttpClient(createApiConfig({ baseUrl: BASE, timeoutMs: 20 }), hang);
  assert.equal(
    (await apiError(slow.request({ method: "GET", path: "/health", expect: null }))).kind,
    "timeout",
  );

  const controller = new AbortController();
  const pending = new HttpClient(config, hang).request({
    method: "GET",
    path: "/health",
    expect: null,
    signal: controller.signal,
  });
  controller.abort();
  assert.equal((await apiError(pending)).kind, "aborted");
});

test("an already-aborted signal never sends", async () => {
  const server = new FakeServer();
  const controller = new AbortController();
  controller.abort();
  const err = await apiError(
    new HttpClient(config, server.fetch).request({
      method: "GET",
      path: "/health",
      expect: null,
      signal: controller.signal,
    }),
  );
  assert.equal(err.kind, "aborted");
  assert.equal(server.calls.length, 0);
});

test("2xx responses that break the contract are rejected", async () => {
  const cases: [Response, string][] = [
    [new Response("{}", { status: 200, headers: { "Content-Type": "text/html" } }), "not_json"],
    [
      new Response("{bad", { status: 200, headers: { "Content-Type": "application/json" } }),
      "malformed_json",
    ],
    [json(200, { status: "ok" }), "schema:$.database"],
    [json(200, { status: "ok", database: "ok", password_hash: "x" }), "schema:forbidden_key"],
    [
      json(200, { status: "ok", database: "ok", x: [{ Embedding: [0.1] }] }),
      "schema:forbidden_key",
    ],
  ];
  for (const [response, code] of cases) {
    const fetch: FetchLike = async () => response;
    const err = await apiError(
      new HttpClient(config, fetch).request({
        method: "GET",
        path: "/health",
        expect: HealthResponse,
      }),
    );
    assert.equal(err.kind, "invalid_response");
    assert.ok(err.code.startsWith(code), `${err.code} vs ${code}`);
  }
});

test("projected responses drop unexpected fields", async () => {
  const fetch: FetchLike = async () =>
    json(200, { status: "ok", database: "ok", debug: "internal" });
  const result = await new HttpClient(config, fetch).request({
    method: "GET",
    path: "/health",
    expect: HealthResponse,
  });
  assert.deepEqual(result, { status: "ok", database: "ok" });
});

test("204 must be empty when no body is expected", async () => {
  const empty: FetchLike = async () => new Response(null, { status: 204 });
  assert.equal(
    await new HttpClient(config, empty).request({
      method: "POST",
      path: "/auth/logout",
      body: {},
      expect: null,
    }),
    undefined,
  );
  const chatty: FetchLike = async () => json(200, { unexpected: true });
  const err = await apiError(
    new HttpClient(config, chatty).request({
      method: "POST",
      path: "/auth/logout",
      body: {},
      expect: null,
    }),
  );
  assert.equal(err.code, "unexpected_body");
});

test("oversized responses are refused", async () => {
  const big: FetchLike = async () =>
    new Response("x".repeat(MAX_RESPONSE_CHARS + 1), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  const err = await apiError(
    new HttpClient(config, big).request({ method: "GET", path: "/health", expect: HealthResponse }),
  );
  assert.equal(err.code, "response_too_large");
});

test("Retry-After parsing", () => {
  assert.equal(parseRetryAfter("30"), 30);
  assert.equal(parseRetryAfter(" 5 "), 5);
  assert.equal(parseRetryAfter("999999"), 86400);
  for (const bad of [null, "", "-1", "1.5", "Wed, 21 Oct 2026 07:28:00 GMT", "1e3"]) {
    assert.equal(parseRetryAfter(bad), null);
  }
});
