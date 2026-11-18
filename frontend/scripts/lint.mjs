// Interim lint (Option B only).
//
// `typescript-eslint` cannot be installed while the npm registry is blocked,
// and ESLint's own parser cannot read TypeScript. So this script:
//   1. compiles src/ (tests included) to plain JavaScript in a temp folder
//      with the globally installed TypeScript compiler, then
//   2. runs the globally installed ESLint, with ESLint's built-in rules only,
//      on that JavaScript.
// Type annotations are gone by step 2, so typing problems are left to
// `tsc --noEmit` (npm run typecheck). Option A replaces this file with a
// normal typescript-eslint setup.

import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const root = new URL("..", import.meta.url).pathname;
const out = mkdtempSync(join(tmpdir(), "frontend-lint-"));

try {
  execFileSync(
    "tsc",
    [
      "-p",
      "tsconfig.test.json",
      "--noEmit",
      "false",
      "--allowImportingTsExtensions",
      "false",
      "--rewriteRelativeImportExtensions",
      "true",
      "--outDir",
      out,
    ],
    { cwd: root, stdio: "inherit" },
  );

  const globalRoot = execFileSync("npm", ["root", "-g"], { encoding: "utf8" }).trim();
  const { ESLint } = await import(pathToFileURL(join(globalRoot, "eslint", "lib", "api.js")).href);

  const eslint = new ESLint({
    cwd: out,
    overrideConfigFile: true,
    overrideConfig: [
      {
        files: ["**/*.js"],
        languageOptions: {
          ecmaVersion: 2022,
          sourceType: "module",
          globals: {
            URL: "readonly",
            URLSearchParams: "readonly",
            Response: "readonly",
            AbortController: "readonly",
            DOMException: "readonly",
            Intl: "readonly",
            setTimeout: "readonly",
            clearTimeout: "readonly",
            globalThis: "readonly",
          },
        },
        rules: {
          "no-eval": "error",
          "no-implied-eval": "error",
          "no-new-func": "error",
          "no-script-url": "error",
          "no-console": "error",
          "no-debugger": "error",
          "no-alert": "error",
          eqeqeq: ["error", "always"],
          "no-var": "error",
          "prefer-const": "error",
          "no-undef": "error",
          "no-unused-vars": ["error", { args: "after-used", argsIgnorePattern: "^_" }],
          "no-unreachable": "error",
          "no-constant-condition": "error",
          "no-dupe-keys": "error",
          "no-duplicate-case": "error",
          "no-self-compare": "error",
          "no-throw-literal": "error",
          "no-prototype-builtins": "error",
          "no-unsafe-finally": "error",
          "no-unsafe-negation": "error",
          "no-unsafe-optional-chaining": "error",
          "no-async-promise-executor": "error",
          "no-promise-executor-return": "error",
          "no-return-assign": "error",
          "no-sequences": "error",
          "no-shadow-restricted-names": "error",
          "require-atomic-updates": "off",
          "use-isnan": "error",
          "valid-typeof": "error",
        },
      },
    ],
  });

  const results = await eslint.lintFiles(["**/*.js"]);
  const formatter = await eslint.loadFormatter("stylish");
  const text = formatter.format(results);
  const errors = results.reduce((n, r) => n + r.errorCount, 0);
  const files = results.length;
  process.stdout.write(text || `eslint: ${files} compiled files, 0 problems\n`);
  if (errors > 0 || files === 0) process.exitCode = 1;
} finally {
  rmSync(out, { recursive: true, force: true });
}
