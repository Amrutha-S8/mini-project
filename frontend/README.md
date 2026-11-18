# Frontend — Option B foundations

**Status:** foundations only. There is **no UI yet**: no React, no pages, no
3D scene. React, Vite, Tailwind, Three.js, React Three Fiber, Drei, Recharts,
Framer Motion and Lucide cannot be installed while the sandbox's npm access
is blocked. Option A builds the seven pages on top of this code once npm
access returns.

Everything here is plain TypeScript with no dependencies. It is checked with
the globally installed TypeScript, ESLint and Prettier and tested with Node's
built-in test runner. Tests use a scripted fake backend: **they prove the
client logic, not the real backend, which has never been run.**

## Contents

```
src/
  config/apiConfig.ts     base URL + timeout; http only for localhost; no secrets
  api/
    validate.ts           runtime validators; objects are projected (extra keys dropped)
    schemas.ts            mirrors backend/app/schemas (UserPublic, TokenPair, members, health, errors)
    errors.ts             ApiError: network | timeout | aborted | http | invalid_response | signed_out
    http.ts               JSON client matching the backend CORS policy; forbidden-key scan
    endpoints.ts          functions for the 13 backend routes that exist, and no others
  auth/session.ts         login, logout, single-flight token refresh, one retry on 401
  access/
    routes.ts             7 pages, role rules, route decisions, safe ?next= handling
    features.ts           per-page feature status: available / browser_only / unavailable + reason
  design/
    tokens.ts             colours, glass, glow, radii, type, motion + reduced motion, CSS variables
    status.ts             labels for AccessEngine outcomes (display only, never decided here)
  lib/initials.ts         initials avatars (no face photos)
  test-support/           fake backend and backend-source readers (tests only)
types/node-test.d.ts      interim types for node:test / node:assert (until @types/node)
scripts/lint.mjs          interim lint: compile to JS, then ESLint built-in rules
```

## Commands

Run from `frontend/`. No `npm install` is needed or possible yet.

```
npm run typecheck      # tsc --noEmit on src, then on tests
npm run lint           # interim: tsc -> JS, ESLint core rules
npm run format:check   # prettier
npm test               # node --test (type stripping, Node >= 22.18)
npm run check          # all of the above
```

## Rules the later UI must keep

- Access decisions (ALLOW, DENY, HOLD) come only from the backend AccessEngine.
  `design/status.ts` labels a value the backend returned and shows UNKNOWN for
  anything else.
- No sample data. `source-safety.test.ts` fails if names or numbers from the
  reference image appear in the source.
- Features marked `unavailable` show their reason and no active control.
- Tokens live in memory only. A page reload needs a new login.
- The UI's role checks are for display. The backend enforces every permission.

## Interim pieces to replace in Option A

| Interim                         | Replace with                        |
| ------------------------------- | ----------------------------------- |
| `types/node-test.d.ts`          | `@types/node`                       |
| `scripts/lint.mjs`              | `typescript-eslint` flat config     |
| `createApiConfig()` default URL | `import.meta.env.VITE_API_BASE_URL` |
