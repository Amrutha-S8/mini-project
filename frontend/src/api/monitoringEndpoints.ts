/**
 * Typed calls for incidents, security events, notifications and the
 * dashboard (backend/app/api/v1/{incidents,events,notifications,dashboard}.py).
 *
 * The backend enforces every role rule; these functions only call it. None of
 * them can unlock the door or change an access decision: no such endpoint is
 * exposed to the UI.
 */

import type { AuthSession } from "../auth/session.ts";
import { ApiError } from "./errors.ts";
import {
  ChannelStatusList,
  DashboardSummary,
  IncidentDetail,
  IncidentList,
  NotificationList,
  NotificationPublic,
  NotifyResponse,
  SecurityEventList,
  type IncidentResolve,
  type IncidentStatus,
  type Severity,
} from "./monitoringSchemas.ts";

function idPath(prefix: string, id: number, suffix = ""): string {
  if (!Number.isSafeInteger(id) || id < 1) {
    throw new ApiError("invalid_response", "Invalid id", { code: "invalid_id" });
  }
  return `${prefix}/${id}${suffix}`;
}

function signal(s?: AbortSignal): { signal?: AbortSignal } {
  return s ? { signal: s } : {};
}

export interface IncidentFilter {
  status?: IncidentStatus;
  severity?: Severity;
  limit?: number;
  beforeId?: number;
}

export function incidentsApi(session: AuthSession) {
  return {
    /** Admin and viewer. */
    list: async (filter: IncidentFilter = {}, s?: AbortSignal) =>
      session.authorized({
        method: "GET",
        path: "/incidents",
        query: {
          status: filter.status,
          severity: filter.severity,
          limit: filter.limit,
          before_id: filter.beforeId,
        },
        expect: IncidentList,
        ...signal(s),
      }),
    /** Admin and viewer. Includes every detection with its reason. */
    get: async (id: number, s?: AbortSignal) =>
      session.authorized({
        method: "GET",
        path: idPath("/incidents", id),
        expect: IncidentDetail,
        ...signal(s),
      }),
    /** Admin only. */
    acknowledge: async (id: number, s?: AbortSignal) =>
      session.authorized({
        method: "POST",
        path: idPath("/incidents", id, "/acknowledge"),
        expect: IncidentDetail,
        ...signal(s),
      }),
    /** Admin only. */
    investigate: async (id: number, s?: AbortSignal) =>
      session.authorized({
        method: "POST",
        path: idPath("/incidents", id, "/investigate"),
        expect: IncidentDetail,
        ...signal(s),
      }),
    /** Admin only. Notes are required. */
    resolve: async (id: number, payload: IncidentResolve, s?: AbortSignal) =>
      session.authorized({
        method: "POST",
        path: idPath("/incidents", id, "/resolve"),
        body: payload,
        expect: IncidentDetail,
        ...signal(s),
      }),
    /** Admin only. Attempts with the provider-reported status. */
    notifications: async (id: number, s?: AbortSignal) =>
      session.authorized({
        method: "GET",
        path: idPath("/incidents", id, "/notifications"),
        expect: NotificationList,
        ...signal(s),
      }),
    /** Admin only. Starts a new attempt; the answer never claims delivery. */
    notify: async (id: number, s?: AbortSignal) =>
      session.authorized({
        method: "POST",
        path: idPath("/incidents", id, "/notify"),
        expect: NotifyResponse,
        ...signal(s),
      }),
  };
}

export function securityEventsApi(session: AuthSession) {
  return {
    /** Every role; the backend removes identities a role may not see. */
    list: async (
      filter: { severity?: Severity; suspiciousOnly?: boolean; limit?: number } = {},
      s?: AbortSignal,
    ) =>
      session.authorized({
        method: "GET",
        path: "/events/security",
        query: {
          severity: filter.severity,
          suspicious_only: filter.suspiciousOnly ? "true" : undefined,
          limit: filter.limit,
        },
        expect: SecurityEventList,
        ...signal(s),
      }),
  };
}

export function notificationsApi(session: AuthSession) {
  return {
    /** Admin only. */
    recent: async (limit = 50, s?: AbortSignal) =>
      session.authorized({
        method: "GET",
        path: "/notifications",
        query: { limit },
        expect: NotificationList,
        ...signal(s),
      }),
    /** Admin only. Setting names that are missing; never secret values. */
    channels: async (s?: AbortSignal) =>
      session.authorized({
        method: "GET",
        path: "/notifications/channels",
        expect: ChannelStatusList,
        ...signal(s),
      }),
    /** Admin only. Asks Twilio for an SMS's current status. */
    refresh: async (id: number, s?: AbortSignal) =>
      session.authorized({
        method: "POST",
        path: idPath("/notifications", id, "/refresh"),
        expect: NotificationPublic,
        ...signal(s),
      }),
  };
}

export function dashboardApi(session: AuthSession) {
  return {
    /** Every role; members get their own counts only. */
    summary: async (s?: AbortSignal) =>
      session.authorized({
        method: "GET",
        path: "/dashboard/summary",
        expect: DashboardSummary,
        ...signal(s),
      }),
  };
}
