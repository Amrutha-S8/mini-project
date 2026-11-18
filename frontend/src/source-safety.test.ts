/**
 * Static checks over the frontend source (not the tests):
 *
 * * no dynamic code execution, raw HTML injection, cookies or web storage;
 * * no console output (tokens could end up in logs);
 * * no secrets or API keys;
 * * no sample data copied from the reference image, and no invented
 *   confidence or count values;
 * * no code path that could decide access or call a door, lockdown or
 *   AccessEngine route.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";

const SRC = new URL("./", import.meta.url);
const files = readdirSync(SRC, { recursive: true })
  .filter((f) => f.endsWith(".ts") && !f.endsWith(".test.ts") && !f.startsWith("test-support"))
  .map((f) => ({ name: f, text: readFileSync(new URL(f, SRC), "utf8") }));

function offenders(pattern: RegExp): string[] {
  return files.filter((f) => pattern.test(f.text)).map((f) => f.name);
}

test("the scan sees the source files", () => {
  assert.ok(files.length >= 12, String(files.length));
  assert.ok(files.some((f) => f.name.endsWith("session.ts")));
});

test("no dynamic code, HTML injection, cookies or web storage", () => {
  assert.deepEqual(
    offenders(
      /\beval\s*\(|new\s+Function\s*\(|innerHTML|outerHTML|insertAdjacentHTML|document\.write/,
    ),
    [],
  );
  assert.deepEqual(offenders(/document\.cookie|\blocalStorage\b|\bsessionStorage\b|indexedDB/), []);
});

test("no console output", () => {
  assert.deepEqual(offenders(/\bconsole\./), []);
});

test("no secrets or keys in the frontend", () => {
  assert.deepEqual(
    offenders(
      /AIza[0-9A-Za-z_-]{35}|sk-[A-Za-z0-9]{20,}|eyJ[A-Za-z0-9_-]{10,}\.|GEMINI_API_KEY|SECRET_KEY\s*=/,
    ),
    [],
  );
});

test("no sample data from the reference image", () => {
  assert.deepEqual(offenders(/Amrutha|John Smith|Sarah Wilson|98\.7|\b98%/i), []);
});

test("no access decision is computed in the frontend", () => {
  // The only place that names the engine's outcomes is the display mapping.
  const naming = offenders(/["'](?:allow|deny|hold)["']/).filter((n) => !n.endsWith("status.ts"));
  assert.deepEqual(naming, []);
  assert.deepEqual(offenders(/\/(?:unlock|door|lockdown|decide|decision)\b/i), []);
});
