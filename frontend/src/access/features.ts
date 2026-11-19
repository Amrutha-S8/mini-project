/**
 * What each page can really do today, and why not when it cannot.
 *
 * This registry is the single source for "unavailable" states, so no page
 * pretends a feature works. Rules for Option A:
 *
 * * `available`: the endpoint exists in the backend source (checked by
 *   `features.test.ts`). The backend has still never been run, so pages must
 *   handle every error state.
 * * `browser_only`: works in the browser without the backend (the webcam
 *   preview). It produces no recognition, confidence or decision.
 * * `unavailable`: show the reason; render no active control, no sample data
 *   and no placeholder numbers.
 *
 * Access decisions (ALLOW, DENY, HOLD) come only from the backend
 * AccessEngine. No feature here computes one.
 */

import type { Role } from "../api/schemas.ts";
import type { Method } from "../api/http.ts";
import { ACTIONS, type Action, type PageId } from "./routes.ts";

export interface Endpoint {
  readonly method: Method;
  /** Path below /api/v1, with `{id}` for path parameters. */
  readonly path: string;
}

export type Feature =
  | {
      readonly status: "available";
      readonly endpoint: Endpoint;
      /** Who may use it; defaults to everyone who can see the page. */
      readonly action?: Action;
    }
  | { readonly status: "browser_only"; readonly note: string }
  | { readonly status: "unavailable"; readonly reason: string };

const NO_VISITOR_API =
  "No API reads visitor events yet. The table exists (migration 0002) but is not exposed.";
const NO_ANALYTICS_API =
  "Trend analytics endpoints are not built yet. The dashboard summary shows the current counts.";
const NO_RECOGNITION =
  "Face recognition is not connected: the YuNet + SFace recognition service and the AccessEngine endpoint are not built yet.";
const SUMMARY: Endpoint = { method: "GET", path: "/dashboard/summary" };
const AI_OFF =
  "The AI assistant is disabled (AI_ENABLED=false). No AI endpoint exists yet, and it stays off until the security gate checks are recorded.";
const NO_NOTIFY = "Notification delivery (email, WhatsApp, SMS) is not built yet.";

export const FEATURES = {
  dashboard: {
    system_status: { status: "available", endpoint: { method: "GET", path: "/health/ready" } },
    security_status: { status: "available", endpoint: SUMMARY, action: "dashboard.summary" },
    total_events: { status: "available", endpoint: SUMMARY, action: "dashboard.summary" },
    recent_activity: {
      status: "available",
      endpoint: { method: "GET", path: "/events/access" },
      action: "events.access",
    },
    access_overview: { status: "available", endpoint: SUMMARY, action: "dashboard.summary" },
    notifications: { status: "unavailable", reason: NO_NOTIFY },
  },
  live_monitoring: {
    webcam_preview: {
      status: "browser_only",
      note: "The camera preview runs in your browser. Nothing is recognised or decided until the backend recognition endpoint exists.",
    },
    face_detection: { status: "unavailable", reason: NO_RECOGNITION },
    recognition: { status: "unavailable", reason: NO_RECOGNITION },
    access_decision: { status: "unavailable", reason: NO_RECOGNITION },
  },
  access_management: {
    members_list: {
      status: "available",
      endpoint: { method: "GET", path: "/members" },
      action: "members.list",
    },
    member_detail: {
      status: "available",
      endpoint: { method: "GET", path: "/members/{id}" },
      action: "members.view",
    },
    member_create: {
      status: "available",
      endpoint: { method: "POST", path: "/members" },
      action: "members.create",
    },
    member_update: {
      status: "available",
      endpoint: { method: "PATCH", path: "/members/{id}" },
      action: "members.update",
    },
    member_deactivate: {
      status: "available",
      endpoint: { method: "POST", path: "/members/{id}/deactivate" },
      action: "members.deactivate",
    },
    member_revoke: {
      status: "available",
      endpoint: { method: "POST", path: "/members/{id}/revoke" },
      action: "members.revoke",
    },
    face_enrollment: {
      status: "unavailable",
      reason: "Face enrolment needs the embedding service (Day 3), which is not built.",
    },
    visitors: { status: "unavailable", reason: NO_VISITOR_API },
    permissions: {
      status: "unavailable",
      reason: "The permissions table and API arrive with Day 4 persistence.",
    },
  },
  security_events: {
    event_list: {
      status: "available",
      endpoint: { method: "GET", path: "/events/security" },
      action: "events.security",
    },
    access_history: {
      status: "available",
      endpoint: { method: "GET", path: "/events/access" },
      action: "events.access",
    },
    incident_timeline: {
      status: "available",
      endpoint: { method: "GET", path: "/incidents" },
      action: "incidents.list",
    },
    incident_detail: {
      status: "available",
      endpoint: { method: "GET", path: "/incidents/{id}" },
      action: "incidents.view",
    },
    incident_update: {
      status: "available",
      endpoint: { method: "PATCH", path: "/incidents/{id}" },
      action: "incidents.update",
    },
    evidence_refs: {
      status: "unavailable",
      reason: "Evidence retrieval is not built (it must be authenticated and audited).",
    },
  },
  ai_assistant: {
    chat: { status: "unavailable", reason: AI_OFF },
    suggested_questions: { status: "unavailable", reason: AI_OFF },
  },
  analytics: {
    trends: { status: "unavailable", reason: NO_ANALYTICS_API },
    access_distribution: { status: "unavailable", reason: NO_ANALYTICS_API },
    visitor_activity: { status: "unavailable", reason: NO_VISITOR_API },
  },
  settings: {
    profile_view: {
      status: "available",
      endpoint: { method: "GET", path: "/auth/me" },
      action: "profile.view",
    },
    profile_edit: { status: "unavailable", reason: "No profile update endpoint exists." },
    password_change: { status: "unavailable", reason: "No password change endpoint exists." },
    user_registration: {
      status: "available",
      endpoint: { method: "POST", path: "/auth/register" },
      action: "users.register",
    },
    roles_permissions: {
      status: "unavailable",
      reason: "Listing users and changing roles has no endpoint.",
    },
    notification_preferences: { status: "unavailable", reason: NO_NOTIFY },
    whatsapp: { status: "unavailable", reason: NO_NOTIFY },
    sms: { status: "unavailable", reason: NO_NOTIFY },
    ai_settings: { status: "unavailable", reason: AI_OFF },
    retention_policy: {
      status: "unavailable",
      reason: "Retention rules exist in the backend core, but no API exposes them.",
    },
    database_status: {
      status: "available",
      endpoint: { method: "GET", path: "/health/ready" },
    },
    backup: { status: "unavailable", reason: "No backup endpoint exists." },
  },
} as const satisfies Record<PageId, Record<string, Feature>>;

/** Endpoints called by the session itself rather than by a page feature. */
export const SESSION_ENDPOINTS: readonly Endpoint[] = [
  { method: "POST", path: "/auth/login" },
  { method: "POST", path: "/auth/refresh" },
  { method: "POST", path: "/auth/logout" },
  { method: "GET", path: "/health" },
];

export function featureRoles(feature: Feature): readonly Role[] | null {
  if (feature.status !== "available" || feature.action === undefined) return null;
  return ACTIONS[feature.action];
}
