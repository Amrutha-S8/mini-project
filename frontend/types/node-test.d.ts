/**
 * Minimal hand-written declarations for the Node built-ins the tests use.
 *
 * Interim only: `@types/node` cannot be installed while the npm registry is
 * blocked. Option A replaces this file with `@types/node`. It declares only
 * what the tests call, so a test using anything else fails the type check
 * instead of silently passing as `any`.
 */

declare module "node:test" {
  type TestFn = (t: TestContext) => void | Promise<void>;
  interface TestContext {
    readonly name: string;
  }
  export function test(name: string, fn: TestFn): Promise<void>;
  export function describe(name: string, fn: () => void): Promise<void>;
  export function it(name: string, fn: TestFn): Promise<void>;
}

declare module "node:assert/strict" {
  interface Assert {
    (value: unknown, message?: string): asserts value;
    ok(value: unknown, message?: string): asserts value;
    equal<T>(actual: unknown, expected: T, message?: string): asserts actual is T;
    notEqual(actual: unknown, expected: unknown, message?: string): void;
    deepEqual<T>(actual: unknown, expected: T, message?: string): asserts actual is T;
    match(value: string, pattern: RegExp, message?: string): void;
    doesNotMatch(value: string, pattern: RegExp, message?: string): void;
    throws(fn: () => unknown, expected?: unknown, message?: string): void;
    doesNotThrow(fn: () => unknown, message?: string): void;
    rejects(
      promise: Promise<unknown> | (() => Promise<unknown>),
      expected?: unknown,
      message?: string,
    ): Promise<void>;
    fail(message?: string): never;
  }
  const assert: Assert;
  export default assert;
}

declare module "node:fs" {
  export function readFileSync(path: string | URL, encoding: "utf8"): string;
  export function readdirSync(path: string | URL, options: { recursive: true }): string[];
}
