/**
 * Small runtime validators for API responses (no dependencies).
 *
 * The backend is trusted to enforce security, but the frontend still never
 * renders a response it has not checked: a proxy, a misconfigured server or a
 * backend bug must produce a clear "invalid response" state, not a page built
 * from wrong data.
 *
 * Objects are *projected*: only declared keys are copied, so an unexpected
 * extra field (for example a hash that should never leave the server) never
 * reaches the UI. Declared forbidden keys make the whole response invalid.
 */

export type Validator<T> = (value: unknown, path: string) => T;

export class ValidationFailure extends Error {
  readonly path: string;

  constructor(path: string, reason: string) {
    super(`${path}: ${reason}`);
    this.name = "ValidationFailure";
    this.path = path;
  }
}

export const MAX_STRING = 10_000;

export function str(opts: { min?: number; max?: number } = {}): Validator<string> {
  const min = opts.min ?? 0;
  const max = opts.max ?? MAX_STRING;
  return (value, path) => {
    if (typeof value !== "string") throw new ValidationFailure(path, "expected string");
    if (value.length < min || value.length > max) {
      throw new ValidationFailure(path, `length must be ${min}..${max}`);
    }
    return value;
  };
}

export function int(opts: { min?: number; max?: number } = {}): Validator<number> {
  const min = opts.min ?? Number.MIN_SAFE_INTEGER;
  const max = opts.max ?? Number.MAX_SAFE_INTEGER;
  return (value, path) => {
    if (typeof value !== "number" || !Number.isSafeInteger(value)) {
      throw new ValidationFailure(path, "expected integer");
    }
    if (value < min || value > max) {
      throw new ValidationFailure(path, `must be ${min}..${max}`);
    }
    return value;
  };
}

export const bool: Validator<boolean> = (value, path) => {
  if (typeof value !== "boolean") throw new ValidationFailure(path, "expected boolean");
  return value;
};

export function literal<const T extends readonly string[]>(...allowed: T): Validator<T[number]> {
  return (value, path) => {
    if (typeof value !== "string" || !allowed.includes(value)) {
      throw new ValidationFailure(path, `expected one of ${allowed.join(", ")}`);
    }
    return value as T[number];
  };
}

/** Pydantic EmailStr has already validated it; this is a shape check only. */
export const email: Validator<string> = (value, path) => {
  const text = str({ min: 3, max: 320 })(value, path);
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(text)) {
    throw new ValidationFailure(path, "expected an email address");
  }
  return text;
};

const ISO_DATETIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})?$/;

/**
 * ISO-8601 date-time as Pydantic serialises it. Kept as the original string;
 * a value without a timezone is read as UTC (the backend stores UTC only).
 */
export const isoDateTime: Validator<string> = (value, path) => {
  const text = str({ max: 40 })(value, path);
  if (!ISO_DATETIME.test(text)) {
    throw new ValidationFailure(path, "expected ISO-8601 date-time");
  }
  const hasZone = /(?:Z|[+-]\d{2}:\d{2})$/.test(text);
  if (Number.isNaN(Date.parse(hasZone ? text : `${text}Z`))) {
    throw new ValidationFailure(path, "invalid date-time");
  }
  return text;
};

export function nullable<T>(inner: Validator<T>): Validator<T | null> {
  return (value, path) => (value === null || value === undefined ? null : inner(value, path));
}

export function array<T>(item: Validator<T>, opts: { max?: number } = {}): Validator<T[]> {
  const max = opts.max ?? 10_000;
  return (value, path) => {
    if (!Array.isArray(value)) throw new ValidationFailure(path, "expected array");
    if (value.length > max) throw new ValidationFailure(path, `more than ${max} items`);
    return value.map((v, i) => item(v, `${path}[${i}]`));
  };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value) as unknown;
  return proto === Object.prototype || proto === null;
}

export type Shape = Record<string, Validator<unknown>>;
export type Infer<S extends Shape> = { [K in keyof S]: ReturnType<S[K]> };

/**
 * Object validator. ``forbidden`` keys make the value invalid even if empty:
 * they name data that must never be sent to a browser.
 */
export function object<S extends Shape>(
  shape: S,
  opts: { forbidden?: readonly string[] } = {},
): Validator<Infer<S>> {
  const forbidden = opts.forbidden ?? [];
  return (value, path) => {
    if (!isPlainObject(value)) throw new ValidationFailure(path, "expected object");
    for (const key of forbidden) {
      if (Object.prototype.hasOwnProperty.call(value, key)) {
        throw new ValidationFailure(`${path}.${key}`, "field must never be sent to the client");
      }
    }
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(shape)) {
      const validator = shape[key];
      if (validator === undefined) continue;
      out[key] = validator(value[key], `${path}.${key}`);
    }
    return out as Infer<S>;
  };
}

/** Run a validator; returns the typed value or throws ValidationFailure. */
export function parse<T>(validator: Validator<T>, value: unknown, root = "$"): T {
  return validator(value, root);
}
