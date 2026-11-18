/**
 * Typed functions for every backend endpoint that exists today — and only
 * those (backend/app/api/v1/{health,auth,members}.py). Pages for features
 * without an endpoint use `access/features.ts` to show an unavailable state;
 * nothing here invents a route.
 */

import type { AuthSession } from "../auth/session.ts";
import type { HttpClient, RequestOptions } from "./http.ts";
import {
  FamilyMemberList,
  FamilyMemberPublic,
  HealthResponse,
  UserPublic,
  type FamilyMemberCreate,
  type FamilyMemberUpdate,
  type RegisterRequest,
} from "./schemas.ts";
import { ApiError } from "./errors.ts";

function memberPath(id: number, suffix = ""): string {
  if (!Number.isSafeInteger(id) || id < 1) {
    throw new ApiError("invalid_response", "Invalid member id", { code: "invalid_id" });
  }
  return `/members/${id}${suffix}`;
}

function withSignal<T>(opts: RequestOptions<T>, signal?: AbortSignal): RequestOptions<T> {
  return signal ? { ...opts, signal } : opts;
}

/** Public, unauthenticated (SR-AUTHZ-01 exempts health). */
export function healthApi(http: HttpClient) {
  return {
    live: (signal?: AbortSignal) =>
      http.request(withSignal({ method: "GET", path: "/health", expect: HealthResponse }, signal)),
    /** Includes database reachability. */
    ready: (signal?: AbortSignal) =>
      http.request(
        withSignal({ method: "GET", path: "/health/ready", expect: HealthResponse }, signal),
      ),
  };
}

export function usersApi(session: AuthSession) {
  return {
    /** Admin only (backend: `admin: AdminUser`). */
    register: (payload: RegisterRequest, signal?: AbortSignal) =>
      session.authorized(
        withSignal(
          { method: "POST", path: "/auth/register", body: payload, expect: UserPublic },
          signal,
        ),
      ),
  };
}

/** Every function is async, so a bad id rejects like any other API error. */
export function membersApi(session: AuthSession) {
  return {
    /** Any signed-in operator. */
    list: async (opts: { includeRevoked?: boolean; signal?: AbortSignal } = {}) =>
      session.authorized(
        withSignal(
          {
            method: "GET",
            path: "/members",
            query: { include_revoked: opts.includeRevoked ? "true" : undefined },
            expect: FamilyMemberList,
          },
          opts.signal,
        ),
      ),
    get: async (id: number, signal?: AbortSignal) =>
      session.authorized(
        withSignal({ method: "GET", path: memberPath(id), expect: FamilyMemberPublic }, signal),
      ),
    /** Admin only. */
    create: async (payload: FamilyMemberCreate, signal?: AbortSignal) =>
      session.authorized(
        withSignal(
          { method: "POST", path: "/members", body: payload, expect: FamilyMemberPublic },
          signal,
        ),
      ),
    /** Admin only. Status changes are not accepted here. */
    update: async (id: number, changes: FamilyMemberUpdate, signal?: AbortSignal) =>
      session.authorized(
        withSignal(
          { method: "PATCH", path: memberPath(id), body: changes, expect: FamilyMemberPublic },
          signal,
        ),
      ),
    /** Admin only. Soft deactivation; the row is never deleted. */
    deactivate: async (id: number, signal?: AbortSignal) =>
      session.authorized(
        withSignal(
          { method: "POST", path: memberPath(id, "/deactivate"), expect: FamilyMemberPublic },
          signal,
        ),
      ),
    /** Admin only. Revokes access rights, keeps history. */
    revoke: async (id: number, signal?: AbortSignal) =>
      session.authorized(
        withSignal(
          { method: "POST", path: memberPath(id, "/revoke"), expect: FamilyMemberPublic },
          signal,
        ),
      ),
  };
}
