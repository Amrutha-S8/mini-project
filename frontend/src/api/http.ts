/**
 * Low-level JSON client: one place for URLs, headers, timeouts, error mapping
 * and response validation. Knows nothing about tokens; `auth/session.ts`
 * supplies the Authorization header.
 *
 * Matches the backend's CORS policy (backend/app/main.py): only GET, POST and
 * PATCH, only `Authorization` and `Content-Type` request headers, no cookies
 * (`credentials: "omit"`). `contract.test.ts` checks the method list against
 * the backend source.
 */

import type { ApiConfig } from "../config/apiConfig.ts";
import { ApiError, FIXED_MESSAGES, parseRetryAfter } from "./errors.ts";
import { ErrorEnvelope, FORBIDDEN_RESPONSE_KEYS } from "./schemas.ts";
import { parse, ValidationFailure, type Validator } from "./validate.ts";

export const ALLOWED_METHODS = ["GET", "POST", "PATCH"] as const;
export type Method = (typeof ALLOWED_METHODS)[number];

export const MAX_RESPONSE_CHARS = 2_000_000;

export type FetchLike = (input: string, init: RequestInit) => Promise<Response>;

export interface RequestOptions<T> {
  method: Method;
  /** Path below the base URL, e.g. `/members/3`. Query via `query`. */
  path: string;
  query?: Record<string, string | number | boolean | undefined>;
  body?: unknown;
  accessToken?: string | null;
  signal?: AbortSignal;
  /** Validator for a 2xx JSON body; `null` means the response must be empty. */
  expect: Validator<T> | null;
}

const SAFE_PATH = /^\/(?:[A-Za-z0-9._~-]+\/?)*$/;

export function buildUrl(
  config: ApiConfig,
  path: string,
  query?: RequestOptions<unknown>["query"],
): string {
  if (!SAFE_PATH.test(path) || path.includes("//") || path.split("/").includes("..")) {
    throw new ApiError("invalid_response", "Invalid request path", { code: "invalid_path" });
  }
  const url = new URL(config.baseUrl + path);
  for (const [key, value] of Object.entries(query ?? {})) {
    if (value !== undefined) url.searchParams.set(key, String(value));
  }
  return url.toString();
}

export class HttpClient {
  readonly config: ApiConfig;
  readonly #fetch: FetchLike;

  constructor(config: ApiConfig, fetchImpl: FetchLike) {
    this.config = config;
    this.#fetch = fetchImpl;
  }

  async request<T>(opts: RequestOptions<T>): Promise<T> {
    if (!(ALLOWED_METHODS as readonly string[]).includes(opts.method)) {
      throw new ApiError("invalid_response", "Method not allowed by the API", {
        code: "invalid_method",
      });
    }
    const url = buildUrl(this.config, opts.path, opts.query);
    if (opts.signal?.aborted) throw new ApiError("aborted", FIXED_MESSAGES.aborted);
    const headers: Record<string, string> = { Accept: "application/json" };
    if (opts.body !== undefined) headers["Content-Type"] = "application/json";
    if (opts.accessToken) headers["Authorization"] = `Bearer ${opts.accessToken}`;

    const timeout = new AbortController();
    const timer = setTimeout(() => timeout.abort(), this.config.timeoutMs);
    const onCallerAbort = (): void => timeout.abort();
    opts.signal?.addEventListener("abort", onCallerAbort, { once: true });

    let response: Response;
    try {
      const init: RequestInit = {
        method: opts.method,
        headers,
        credentials: "omit",
        cache: "no-store",
        redirect: "error",
        signal: timeout.signal,
      };
      if (opts.body !== undefined) init.body = JSON.stringify(opts.body);
      response = await this.#fetch(url, init);
    } catch {
      if (opts.signal?.aborted) throw new ApiError("aborted", FIXED_MESSAGES.aborted);
      if (timeout.signal.aborted) throw new ApiError("timeout", FIXED_MESSAGES.timeout);
      throw new ApiError("network", FIXED_MESSAGES.network);
    } finally {
      clearTimeout(timer);
      opts.signal?.removeEventListener("abort", onCallerAbort);
    }

    const text = await readBody(response);
    if (!response.ok) throw errorFromResponse(response, text);
    return decodeSuccess(response, text, opts.expect);
  }
}

async function readBody(response: Response): Promise<string> {
  try {
    const text = await response.text();
    if (text.length > MAX_RESPONSE_CHARS) {
      throw new ApiError("invalid_response", FIXED_MESSAGES.invalid_response, {
        status: response.status,
        code: "response_too_large",
      });
    }
    return text;
  } catch (err) {
    if (err instanceof ApiError) throw err;
    throw new ApiError("network", FIXED_MESSAGES.network);
  }
}

function errorFromResponse(response: Response, text: string): ApiError {
  const retryAfterSeconds = parseRetryAfter(response.headers.get("Retry-After"));
  try {
    const envelope = parse(ErrorEnvelope, JSON.parse(text));
    return new ApiError("http", envelope.error.message, {
      status: response.status,
      code: envelope.error.code,
      retryAfterSeconds,
    });
  } catch {
    // Not our envelope (proxy page, crash): never echo the body.
    return new ApiError("http", `The security server returned an error (${response.status}).`, {
      status: response.status,
      code: "http_error",
      retryAfterSeconds,
    });
  }
}

/**
 * Search the whole response for keys that must never reach a browser
 * (hashes, embeddings, secrets), at any depth. Defence in depth: the backend
 * response models already exclude them.
 */
export function findForbiddenKey(data: unknown, depth = 0): string | null {
  if (depth > 32 || data === null || typeof data !== "object") return null;
  if (Array.isArray(data)) {
    for (const item of data) {
      const hit = findForbiddenKey(item, depth + 1);
      if (hit !== null) return hit;
    }
    return null;
  }
  for (const [key, value] of Object.entries(data)) {
    if ((FORBIDDEN_RESPONSE_KEYS as readonly string[]).includes(key.toLowerCase())) return key;
    const hit = findForbiddenKey(value, depth + 1);
    if (hit !== null) return hit;
  }
  return null;
}

function decodeSuccess<T>(response: Response, text: string, expect: Validator<T> | null): T {
  const invalid = (code: string): ApiError =>
    new ApiError("invalid_response", FIXED_MESSAGES.invalid_response, {
      status: response.status,
      code,
    });
  if (expect === null) {
    if (text.trim() !== "") throw invalid("unexpected_body");
    return undefined as T;
  }
  const type = response.headers.get("Content-Type") ?? "";
  if (!/^application\/json\b/i.test(type)) throw invalid("not_json");
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    throw invalid("malformed_json");
  }
  const leaked = findForbiddenKey(data);
  if (leaked !== null) throw invalid(`schema:forbidden_key:${leaked}`);
  try {
    return parse(expect, data);
  } catch (err) {
    if (err instanceof ValidationFailure) throw invalid(`schema:${err.path}`);
    throw err;
  }
}
