/**
 * Authentication session: login, logout, token refresh and authorised calls.
 *
 * Matches backend/app/api/v1/auth.py and services/auth_service.py:
 *
 * * Tokens travel in the JSON body and the `Authorization` header, never in
 *   cookies. They are held **in memory only** (private fields), never in
 *   browser web storage, so injected script cannot read them from storage
 *   and they disappear when the tab closes. A page reload therefore
 *   needs a new login; persisting the refresh token is a separate decision.
 * * Refresh tokens rotate, and replaying a rotated token revokes the whole
 *   session family (SR-AUTH-08). Refresh is therefore **single-flight**: any
 *   number of concurrent callers share one `/auth/refresh` request.
 * * A 401 on an authorised call triggers at most one refresh and one retry.
 *   If refresh is refused, the session ends locally with a reason.
 * * Rate limiting (429) and network failures never end the session.
 *
 * Role checks in the UI are convenience only; the backend enforces every
 * permission again.
 */

import { ApiError, FIXED_MESSAGES } from "../api/errors.ts";
import type { HttpClient, RequestOptions } from "../api/http.ts";
import { LoginResponse, TokenPair, UserPublic } from "../api/schemas.ts";

export type SignOutReason = "logout" | "expired" | "revoked" | "reuse_detected" | "inactive";

export type SessionState =
  | { readonly status: "signed_out"; readonly reason: SignOutReason | null }
  | { readonly status: "signed_in"; readonly user: UserPublic };

export type SessionListener = (state: SessionState) => void;

export interface LogoutResult {
  /** True only if the backend confirmed the session was revoked. */
  serverRevoked: boolean;
}

/** Refresh this long before expiry, or half the lifetime if that is shorter. */
export const REFRESH_SKEW_MS = 30_000;

const REASON_BY_CODE: Record<string, SignOutReason> = {
  token_reuse_detected: "reuse_detected",
  session_revoked: "revoked",
  account_inactive: "inactive",
};

type AuthorizedOptions<T> = Omit<RequestOptions<T>, "accessToken">;

export class AuthSession {
  readonly #http: HttpClient;
  readonly #now: () => number;
  #state: SessionState = { status: "signed_out", reason: null };
  #access: string | null = null;
  #refresh: string | null = null;
  #expiresAt = 0;
  #lifetimeMs = 0;
  #refreshing: Promise<void> | null = null;
  /** Bumped on every login and sign-out, so stale refreshes are discarded. */
  #generation = 0;
  readonly #listeners = new Set<SessionListener>();

  constructor(http: HttpClient, now: () => number = Date.now) {
    this.#http = http;
    this.#now = now;
  }

  get state(): SessionState {
    return this.#state;
  }

  get user(): UserPublic | null {
    return this.#state.status === "signed_in" ? this.#state.user : null;
  }

  subscribe(listener: SessionListener): () => void {
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  }

  async login(email: string, password: string, signal?: AbortSignal): Promise<UserPublic> {
    this.#clear(null);
    const opts: RequestOptions<LoginResponse> = {
      method: "POST",
      path: "/auth/login",
      body: { email, password },
      expect: LoginResponse,
    };
    if (signal) opts.signal = signal;
    const result = await this.#http.request(opts);
    if (!result.user.is_active) {
      this.#clear("inactive");
      throw new ApiError("signed_out", FIXED_MESSAGES.signed_out, { code: "account_inactive" });
    }
    this.#generation += 1;
    this.#setTokens(result.tokens);
    this.#setState({ status: "signed_in", user: result.user });
    return result.user;
  }

  /**
   * Revoke the session on the server, then always clear it locally. The result
   * says whether the server confirmed; the UI must not claim more than that.
   */
  async logout(): Promise<LogoutResult> {
    if (this.#state.status !== "signed_in") return { serverRevoked: false };
    let serverRevoked = false;
    try {
      const access = await this.#validAccessToken();
      const refresh = this.#refresh;
      if (refresh) {
        await this.#http.request({
          method: "POST",
          path: "/auth/logout",
          body: { refresh_token: refresh },
          accessToken: access,
          expect: null,
        });
        serverRevoked = true;
      }
    } catch {
      serverRevoked = false;
    } finally {
      this.#clear("logout");
    }
    return { serverRevoked };
  }

  /** Re-read the current user from the backend (`GET /auth/me`). */
  async reloadUser(signal?: AbortSignal): Promise<UserPublic> {
    const opts: AuthorizedOptions<UserPublic> = {
      method: "GET",
      path: "/auth/me",
      expect: UserPublic,
    };
    if (signal) opts.signal = signal;
    const user = await this.authorized(opts);
    if (!user.is_active) {
      this.#clear("inactive");
      throw new ApiError("signed_out", FIXED_MESSAGES.signed_out, { code: "account_inactive" });
    }
    if (this.#state.status === "signed_in") this.#setState({ status: "signed_in", user });
    return user;
  }

  /** Call a protected endpoint with a valid access token. */
  async authorized<T>(opts: AuthorizedOptions<T>): Promise<T> {
    const token = await this.#validAccessToken();
    try {
      return await this.#http.request({ ...opts, accessToken: token });
    } catch (err) {
      if (!(err instanceof ApiError) || err.status !== 401) throw err;
      if (err.endsSession) {
        this.#clear(REASON_BY_CODE[err.code] ?? "expired");
        throw new ApiError("signed_out", FIXED_MESSAGES.signed_out, { code: err.code });
      }
      // The token was rejected: refresh once, unless another call already did.
      if (this.#access === token) await this.#refreshOnce();
      const retryToken = await this.#validAccessToken();
      try {
        return await this.#http.request({ ...opts, accessToken: retryToken });
      } catch (retryErr) {
        if (retryErr instanceof ApiError && retryErr.status === 401) {
          this.#clear(REASON_BY_CODE[retryErr.code] ?? "expired");
          throw new ApiError("signed_out", FIXED_MESSAGES.signed_out, {
            code: retryErr.code,
          });
        }
        throw retryErr;
      }
    }
  }

  // --- internals -------------------------------------------------------------

  async #validAccessToken(): Promise<string> {
    if (this.#state.status !== "signed_in" || !this.#access) {
      throw new ApiError("signed_out", FIXED_MESSAGES.signed_out);
    }
    const skew = Math.min(REFRESH_SKEW_MS, this.#lifetimeMs / 2);
    if (this.#now() >= this.#expiresAt - skew) await this.#refreshOnce();
    if (!this.#access) throw new ApiError("signed_out", FIXED_MESSAGES.signed_out);
    return this.#access;
  }

  #refreshOnce(): Promise<void> {
    if (!this.#refreshing) {
      const current: Promise<void> = this.#doRefresh().finally(() => {
        if (this.#refreshing === current) this.#refreshing = null;
      });
      this.#refreshing = current;
    }
    return this.#refreshing;
  }

  async #doRefresh(): Promise<void> {
    const generation = this.#generation;
    const refresh = this.#refresh;
    if (!refresh) throw new ApiError("signed_out", FIXED_MESSAGES.signed_out);
    let tokens: TokenPair;
    try {
      tokens = await this.#http.request({
        method: "POST",
        path: "/auth/refresh",
        body: { refresh_token: refresh },
        expect: TokenPair,
      });
    } catch (err) {
      if (err instanceof ApiError && err.status === 401 && generation === this.#generation) {
        this.#clear(REASON_BY_CODE[err.code] ?? "expired");
        throw new ApiError("signed_out", FIXED_MESSAGES.signed_out, { code: err.code });
      }
      throw err; // network, timeout, 429: keep the session
    }
    // Logged out or re-logged in meanwhile: this result belongs to nobody.
    if (generation !== this.#generation || this.#state.status !== "signed_in") {
      throw new ApiError("signed_out", FIXED_MESSAGES.signed_out);
    }
    this.#setTokens(tokens);
  }

  #setTokens(tokens: TokenPair): void {
    this.#access = tokens.access_token;
    this.#refresh = tokens.refresh_token;
    this.#lifetimeMs = tokens.expires_in * 1000;
    this.#expiresAt = this.#now() + this.#lifetimeMs;
  }

  #clear(reason: SignOutReason | null): void {
    const wasSignedIn = this.#state.status === "signed_in";
    this.#generation += 1;
    // An in-flight refresh belongs to the old session; new calls must not join it.
    this.#refreshing = null;
    this.#access = null;
    this.#refresh = null;
    this.#expiresAt = 0;
    this.#lifetimeMs = 0;
    if (wasSignedIn || reason !== null) {
      this.#setState({ status: "signed_out", reason });
    }
  }

  #setState(state: SessionState): void {
    this.#state = state;
    for (const listener of [...this.#listeners]) {
      try {
        listener(state);
      } catch {
        // A broken subscriber must not break authentication.
      }
    }
  }
}
