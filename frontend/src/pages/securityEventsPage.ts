/**
 * Security Events page model: incidents from suspicious-activity detection,
 * the security event feed, and (for admins) notification status.
 *
 * Framework-free so it is testable without React; the page component only
 * renders the `PageState` this returns. Every value comes from the backend.
 * There is no sample data: an empty database gives the `empty` state.
 *
 * Role handling mirrors the backend (which enforces it):
 *  admin  - incidents, events, notifications, and the case actions.
 *  viewer - incidents and events, read-only, no member identities.
 *  member - no incidents; only their own security events.
 */

import { ApiError } from "../api/errors.ts";
import type {
  IncidentSummary,
  NotificationPublic,
  SecurityEventPublic,
  Severity,
} from "../api/monitoringSchemas.ts";
import type { Role } from "../api/schemas.ts";
import { color } from "../design/tokens.ts";
import { notificationSummary, type NotificationLabel } from "./notificationLabels.ts";

export type PageState<T> =
  | { readonly kind: "loading" }
  | { readonly kind: "error"; readonly message: string }
  | { readonly kind: "empty"; readonly message: string }
  | { readonly kind: "ready"; readonly data: T };

export interface IncidentRow {
  readonly id: number;
  readonly uid: string;
  readonly title: string;
  readonly reason: string;
  readonly severity: Severity;
  readonly severityTone: string;
  readonly statusLabel: string;
  readonly acknowledged: boolean;
  readonly openedAt: string;
  readonly eventCount: number;
  /** Admin only; null when the role cannot see notifications. */
  readonly notification: NotificationLabel | null;
  readonly actions: readonly IncidentAction[];
}

export type IncidentAction = "acknowledge" | "investigate" | "resolve" | "notify";

export interface EventRow {
  readonly id: number;
  readonly type: string;
  readonly severity: Severity;
  readonly severityTone: string;
  readonly suspicious: boolean;
  readonly outcome: string;
  readonly occurredAt: string;
  readonly source: string;
  readonly incidentId: number | null;
}

export interface SecurityEventsView {
  readonly incidents: readonly IncidentRow[] | null;
  readonly events: readonly EventRow[];
}

export interface SecurityEventsSource {
  incidents: () => Promise<IncidentSummary[]>;
  events: () => Promise<SecurityEventPublic[]>;
  notifications: (incidentId: number) => Promise<NotificationPublic[]>;
}

const STATUS_LABEL = {
  open: "Open",
  investigating: "Investigating",
  resolved: "Resolved",
  false_positive: "False positive",
} as const;

export function severityTone(severity: Severity): string {
  return color.severity[severity];
}

export function allowedActions(role: Role, incident: IncidentSummary): IncidentAction[] {
  if (role !== "admin") return [];
  const closed = incident.status === "resolved" || incident.status === "false_positive";
  if (closed) return ["notify"];
  const actions: IncidentAction[] = [];
  if (!incident.acknowledged_at) actions.push("acknowledge");
  if (incident.status === "open") actions.push("investigate");
  actions.push("resolve", "notify");
  return actions;
}

function incidentRow(
  role: Role,
  incident: IncidentSummary,
  notifications: NotificationPublic[] | null,
): IncidentRow {
  return {
    id: incident.id,
    uid: incident.incident_uid,
    title: incident.title,
    reason: incident.latest_reason ?? "No detection reason recorded.",
    severity: incident.severity,
    severityTone: severityTone(incident.severity),
    statusLabel: STATUS_LABEL[incident.status],
    acknowledged: incident.acknowledged_at !== null,
    openedAt: incident.opened_at,
    eventCount: incident.event_count,
    notification: notifications === null ? null : notificationSummary(notifications),
    actions: allowedActions(role, incident),
  };
}

function eventRow(event: SecurityEventPublic): EventRow {
  return {
    id: event.id,
    type: event.event_type,
    severity: event.severity,
    severityTone: severityTone(event.severity),
    suspicious: event.suspicious,
    outcome: event.outcome,
    occurredAt: event.occurred_at,
    source: event.source_module,
    incidentId: event.incident_id,
  };
}

function errorMessage(err: unknown): string {
  if (err instanceof ApiError) return err.message;
  return "The security events could not be loaded.";
}

export async function loadSecurityEvents(
  role: Role,
  source: SecurityEventsSource,
): Promise<PageState<SecurityEventsView>> {
  try {
    const [incidents, events] = await Promise.all([
      role === "member" ? Promise.resolve(null) : source.incidents(),
      source.events(),
    ]);
    let rows: IncidentRow[] | null = null;
    if (incidents !== null) {
      const notifications = await Promise.all(
        incidents.map((i) => (role === "admin" ? source.notifications(i.id) : null)),
      );
      rows = incidents.map((i, n) => incidentRow(role, i, notifications[n] ?? null));
    }
    if ((rows === null || rows.length === 0) && events.length === 0) {
      return {
        kind: "empty",
        message:
          role === "member"
            ? "No security events about you have been recorded."
            : "No incidents or security events have been recorded yet.",
      };
    }
    return { kind: "ready", data: { incidents: rows, events: events.map(eventRow) } };
  } catch (err) {
    return { kind: "error", message: errorMessage(err) };
  }
}
