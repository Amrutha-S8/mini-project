/**
 * Reads the backend's Python source so frontend tests can detect contract
 * drift without running the backend (which cannot run here). Deliberately
 * simple parsers for the constructs the backend actually uses; they throw if
 * the source stops matching, rather than silently finding nothing.
 */

import { readFileSync } from "node:fs";

export const BACKEND = new URL("../../../backend/app/", import.meta.url);

export function readBackend(rel: string): string {
  return readFileSync(new URL(rel, BACKEND), "utf8");
}

/** Field names declared in a Pydantic class body. */
export function pydanticFields(rel: string, className: string): string[] {
  const source = readBackend(rel);
  const start = source.indexOf(`class ${className}(`);
  if (start < 0) throw new Error(`class ${className} not found in ${rel}`);
  const body = source.slice(start).split("\n").slice(1);
  const fields: string[] = [];
  for (const line of body) {
    if (/^\S/.test(line)) break; // next top-level statement
    const m = /^ {4}([a-z_][a-z0-9_]*)\s*:/.exec(line);
    if (m?.[1] && m[1] !== "model_config") fields.push(m[1]);
  }
  if (fields.length === 0) throw new Error(`no fields parsed for ${className}`);
  return fields;
}

export interface BackendRoute {
  method: string;
  /** Below /api/v1, path parameters normalised to `{id}`. */
  path: string;
  handler: string;
  guard: "public" | "authenticated" | "admin";
}

const ROUTE_FILES = ["api/v1/health.py", "api/v1/auth.py", "api/v1/members.py"];

export function backendRoutes(): BackendRoute[] {
  const routerFile = readBackend("api/v1/router.py");
  const included = [...routerFile.matchAll(/include_router\((\w+)\.router\)/g)].map((m) => m[1]);
  if (included.join(",") !== "health,auth,members") {
    throw new Error(`router.py includes ${included.join(",")}; update ROUTE_FILES`);
  }
  const routes: BackendRoute[] = [];
  for (const rel of ROUTE_FILES) {
    const source = readBackend(rel);
    const prefix = /APIRouter\(\s*prefix="([^"]*)"/.exec(source)?.[1] ?? "";
    const decorator =
      /@router\.(get|post|put|patch|delete)\(\s*"([^"]*)"[\s\S]*?\ndef (\w+)\(([\s\S]*?)\)\s*->/g;
    for (const m of source.matchAll(decorator)) {
      const [, method = "", path = "", handler = "", params = ""] = m;
      const guard = /:\s*AdminUser\b/.test(params)
        ? "admin"
        : /:\s*CurrentUser\b/.test(params)
          ? "authenticated"
          : "public";
      routes.push({
        method: method.toUpperCase(),
        path: (prefix + path).replace(/\{[a-z_]+\}/g, "{id}") || "/",
        handler,
        guard,
      });
    }
  }
  if (routes.length < 10) throw new Error(`only ${routes.length} routes parsed`);
  return routes;
}
