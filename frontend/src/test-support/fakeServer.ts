/**
 * A scripted stand-in for the backend, for unit tests only.
 *
 * It returns whatever each test scripts, so it proves how the client behaves
 * for a given response. It proves nothing about the real backend, which has
 * never been run. Response bodies follow backend/app/schemas exactly.
 */

import type { FetchLike } from "../api/http.ts";

export interface RecordedCall {
  method: string;
  url: string;
  path: string;
  headers: Record<string, string>;
  body: unknown;
  init: RequestInit;
}

export type Handler = (call: RecordedCall) => Response | Promise<Response>;

export function json(status: number, body: unknown, headers: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

export function errorEnvelope(status: number, code: string, message: string, headers = {}) {
  return json(status, { error: { code, message } }, headers);
}

export const BASE = "http://localhost:8000/api/v1";

export class FakeServer {
  readonly calls: RecordedCall[] = [];
  readonly #routes = new Map<string, Handler[]>();

  /** Queue handlers for `METHOD /path`; the last one repeats. */
  on(method: string, path: string, ...handlers: Handler[]): this {
    this.#routes.set(`${method} ${path}`, handlers);
    return this;
  }

  count(method: string, path: string): number {
    return this.calls.filter((c) => c.method === method && c.path === path).length;
  }

  readonly fetch: FetchLike = async (input, init) => {
    const url = new URL(input);
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries((init.headers ?? {}) as Record<string, string>)) {
      headers[k] = v;
    }
    const call: RecordedCall = {
      method: init.method ?? "GET",
      url: input,
      path: url.pathname.replace("/api/v1", ""),
      headers,
      body: typeof init.body === "string" ? JSON.parse(init.body) : undefined,
      init,
    };
    this.calls.push(call);
    const queue = this.#routes.get(`${call.method} ${call.path}`);
    if (!queue || queue.length === 0) {
      return errorEnvelope(404, "not_found", "Not Found");
    }
    const handler = queue.length > 1 ? queue.shift() : queue[0];
    if (!handler) throw new Error("no handler");
    return handler(call);
  };
}

// --- fixtures shaped like the Pydantic response models ------------------------

export function userFixture(overrides: Record<string, unknown> = {}) {
  return {
    id: 1,
    email: "owner@example.com",
    full_name: "Test Owner",
    role: "admin",
    is_active: true,
    last_login_at: null,
    created_at: "2026-11-15T10:00:00Z",
    ...overrides,
  };
}

let tokenCounter = 0;

export function tokensFixture(expiresIn = 900) {
  tokenCounter += 1;
  return {
    access_token: `access-${tokenCounter}`,
    refresh_token: `refresh-${tokenCounter}`,
    token_type: "bearer",
    expires_in: expiresIn,
  };
}

export function memberFixture(overrides: Record<string, unknown> = {}) {
  return {
    id: 7,
    full_name: "Test Member",
    member_type: "family",
    status: "active",
    enrollment_status: "not_enrolled",
    relationship_label: null,
    notes: null,
    user_id: null,
    created_at: "2026-11-15T10:00:00Z",
    updated_at: "2026-11-15T10:00:00Z",
    ...overrides,
  };
}

/** A promise you resolve from the test, to hold a response open. */
export function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}
