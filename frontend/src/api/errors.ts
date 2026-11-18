/**
 * One error type for every API failure, so pages can show a precise state.
 *
 * Messages shown to the user come only from the backend's error envelope
 * (already client-safe, SR-STORE-17) or from fixed text here. Response bodies,
 * tokens and URLs with query strings are never put into an error.
 */

export type ApiErrorKind =
  | "network" // fetch failed: server down, CORS refusal, offline
  | "timeout"
  | "aborted" // the caller cancelled (e.g. page left)
  | "http" // the server answered with an error status
  | "invalid_response" // 2xx but not the contract we expect
  | "signed_out"; // no valid session; the user must log in again

export class ApiError extends Error {
  readonly kind: ApiErrorKind;
  readonly status: number | null;
  readonly code: string;
  readonly retryAfterSeconds: number | null;

  constructor(
    kind: ApiErrorKind,
    message: string,
    opts: { status?: number | null; code?: string; retryAfterSeconds?: number | null } = {},
  ) {
    super(message);
    this.name = "ApiError";
    this.kind = kind;
    this.status = opts.status ?? null;
    this.code = opts.code ?? kind;
    this.retryAfterSeconds = opts.retryAfterSeconds ?? null;
  }

  get isRateLimited(): boolean {
    return this.status === 429;
  }

  /** The session is gone and cannot be recovered by refreshing. */
  get endsSession(): boolean {
    return (
      this.kind === "signed_out" ||
      (this.status === 401 &&
        ["session_revoked", "token_reuse_detected", "account_inactive"].includes(this.code))
    );
  }
}

export const FIXED_MESSAGES: Record<Exclude<ApiErrorKind, "http">, string> = {
  network: "Cannot reach the security server. Check that the backend is running.",
  timeout: "The security server took too long to respond.",
  aborted: "The request was cancelled.",
  invalid_response: "The security server sent an unexpected response.",
  signed_out: "Your session has ended. Please sign in again.",
};

const MAX_RETRY_AFTER = 24 * 60 * 60;

/** The backend sends whole seconds (core/errors.py RateLimitedError). */
export function parseRetryAfter(header: string | null): number | null {
  if (header === null) return null;
  const text = header.trim();
  if (!/^\d{1,6}$/.test(text)) return null;
  return Math.min(Number(text), MAX_RETRY_AFTER);
}
