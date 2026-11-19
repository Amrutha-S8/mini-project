/**
 * Routes and role-based access for the seven pages (UI convenience only).
 *
 * The backend enforces every permission itself (`CurrentUser`, `AdminUser` in
 * backend/app/api/deps.py). These rules only decide what to show, and they
 * fail closed: no user, an inactive user or an unknown role sees nothing.
 *
 * Page roles follow DD-08 decision 5 (admin: all household records; viewer:
 * summaries and incident reports, no private visitor history; member:
 * documentation and their own access records). Live Monitoring shows faces at
 * the door, so it is admin-only.
 */

import { ROLES, type Role, type UserPublic } from "../api/schemas.ts";

export type PageId =
  | "dashboard"
  | "live_monitoring"
  | "access_management"
  | "security_events"
  | "ai_assistant"
  | "analytics"
  | "settings";

export interface PageRoute {
  readonly id: PageId;
  readonly path: string;
  readonly title: string;
  /** Lucide icon name, used by the sidebar in Option A. */
  readonly icon: string;
  readonly roles: readonly Role[];
}

const ALL: readonly Role[] = ROLES;

/** Sidebar order matches the reference design. */
export const PAGES: readonly PageRoute[] = [
  { id: "dashboard", path: "/", title: "Dashboard", icon: "LayoutDashboard", roles: ALL },
  {
    id: "live_monitoring",
    path: "/live-monitoring",
    title: "Live Monitoring",
    icon: "Video",
    roles: ["admin"],
  },
  {
    id: "access_management",
    path: "/access-management",
    title: "Access Management",
    icon: "Users",
    roles: ALL,
  },
  {
    id: "security_events",
    path: "/security-events",
    title: "Security Events",
    icon: "ShieldAlert",
    roles: ["admin", "viewer"],
  },
  { id: "ai_assistant", path: "/ai-assistant", title: "AI Assistant", icon: "Bot", roles: ALL },
  {
    id: "analytics",
    path: "/analytics",
    title: "Analytics",
    icon: "BarChart3",
    roles: ["admin", "viewer"],
  },
  { id: "settings", path: "/settings", title: "Settings", icon: "Settings", roles: ALL },
];

export const LOGIN_PATH = "/login";

/** Actions the UI may offer. Each mirrors a backend endpoint's guard. */
export const ACTIONS = {
  // Viewers never see member records (finding S5, decision D-3); a member
  // sees only their own, filtered by the backend.
  "members.list": ["admin", "member"],
  "members.view": ["admin", "member"],
  "members.create": ["admin"],
  "members.update": ["admin"],
  "members.deactivate": ["admin"],
  "members.revoke": ["admin"],
  "users.register": ["admin"],
  "profile.view": ALL,
  // Every role may call these; the backend filters what each role receives
  // (viewers get no member identities, members only their own records).
  "events.access": ALL,
  "events.security": ALL,
  "dashboard.summary": ALL,
  "incidents.list": ["admin", "viewer"],
  "incidents.view": ["admin", "viewer"],
  "incidents.update": ["admin"],
} as const satisfies Record<string, readonly Role[]>;

export type Action = keyof typeof ACTIONS;

/** The caller's role, or null if they must be treated as having none. */
export function effectiveRole(user: UserPublic | null): Role | null {
  if (!user || !user.is_active) return null;
  return (ROLES as readonly string[]).includes(user.role) ? (user.role as Role) : null;
}

export function canViewPage(user: UserPublic | null, page: PageRoute): boolean {
  const role = effectiveRole(user);
  return role !== null && page.roles.includes(role);
}

export function can(user: UserPublic | null, action: Action): boolean {
  const role = effectiveRole(user);
  return role !== null && (ACTIONS[action] as readonly Role[]).includes(role);
}

export function visiblePages(user: UserPublic | null): PageRoute[] {
  return PAGES.filter((p) => canViewPage(user, p));
}

export function findPage(path: string): PageRoute | undefined {
  const normalised = path.length > 1 ? path.replace(/\/+$/, "") : path;
  return PAGES.find((p) => p.path === normalised);
}

/**
 * Where to go after login. Only known page paths are accepted, so a crafted
 * `?next=` cannot send the user to another site (open redirect).
 */
export function safeNextPath(raw: string | null | undefined): string {
  if (typeof raw !== "string" || raw.length > 200) return "/";
  if (!raw.startsWith("/") || raw.startsWith("//") || raw.includes("\\")) return "/";
  if (/[\s\x00-\x1f]/.test(raw)) return "/";
  const page = findPage(raw);
  return page ? page.path : "/";
}

export type RouteDecision =
  | { readonly kind: "render"; readonly page: PageRoute }
  | { readonly kind: "render_login" }
  | { readonly kind: "redirect"; readonly to: string }
  | { readonly kind: "forbidden"; readonly page: PageRoute }
  | { readonly kind: "not_found" };

/** The single routing decision the React router will apply in Option A. */
export function resolveRoute(
  pathname: string,
  user: UserPublic | null,
  search = "",
): RouteDecision {
  const signedIn = effectiveRole(user) !== null;
  if (pathname === LOGIN_PATH) {
    if (!signedIn) return { kind: "render_login" };
    const next = new URLSearchParams(search).get("next");
    return { kind: "redirect", to: safeNextPath(next) };
  }
  const page = findPage(pathname);
  if (!page) return signedIn ? { kind: "not_found" } : { kind: "redirect", to: LOGIN_PATH };
  if (!signedIn) {
    const next = page.path === "/" ? "" : `?next=${encodeURIComponent(page.path)}`;
    return { kind: "redirect", to: `${LOGIN_PATH}${next}` };
  }
  return canViewPage(user, page) ? { kind: "render", page } : { kind: "forbidden", page };
}
