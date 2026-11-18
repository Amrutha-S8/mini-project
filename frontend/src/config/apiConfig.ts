/**
 * Centralised API configuration.
 *
 * In Option A the base URL will come from `import.meta.env.VITE_API_BASE_URL`
 * (a public build-time value, never a secret). The frontend holds no API keys:
 * the Gemini key, the JWT secret and every other secret stay on the server.
 */

export const DEFAULT_API_BASE_URL = "http://localhost:8000/api/v1";
export const DEFAULT_TIMEOUT_MS = 15_000;
export const MAX_TIMEOUT_MS = 120_000;

export interface ApiConfig {
  /** Absolute, normalised, without a trailing slash. */
  readonly baseUrl: string;
  readonly timeoutMs: number;
}

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

/**
 * Validate the base URL. Plain HTTP is allowed only for a local backend, so a
 * production build cannot silently send tokens unencrypted (SR-STORE-20).
 */
export function createApiConfig(input: { baseUrl?: string; timeoutMs?: number } = {}): ApiConfig {
  const raw = (input.baseUrl ?? DEFAULT_API_BASE_URL).trim();
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new ConfigError("API base URL is not a valid absolute URL");
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new ConfigError("API base URL must use http or https");
  }
  if (url.protocol === "http:" && !LOCAL_HOSTS.has(url.hostname)) {
    throw new ConfigError("plain http is allowed only for localhost");
  }
  if (url.username || url.password) {
    throw new ConfigError("API base URL must not contain credentials");
  }
  if (url.search || url.hash || raw.includes("?") || raw.includes("#")) {
    throw new ConfigError("API base URL must not contain a query or fragment");
  }
  const timeoutMs = input.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > MAX_TIMEOUT_MS) {
    throw new ConfigError(`timeout must be 1..${MAX_TIMEOUT_MS} ms`);
  }
  const path = url.pathname.replace(/\/+$/, "");
  return { baseUrl: `${url.origin}${path}`, timeoutMs };
}
