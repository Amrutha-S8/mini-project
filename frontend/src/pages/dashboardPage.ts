/**
 * Dashboard page model built only from `GET /dashboard/summary` and, for
 * admins and viewers, the most recent incidents. No hard-coded numbers: a
 * card whose value the role may not see is `null` and is rendered as
 * unavailable, never as zero.
 */

import { ApiError } from "../api/errors.ts";
import type { DashboardSummary, IncidentSummary, Severity } from "../api/monitoringSchemas.ts";
import type { Role } from "../api/schemas.ts";
import { color } from "../design/tokens.ts";
import type { PageState } from "./securityEventsPage.ts";

export interface StatCard {
  readonly id: string;
  readonly label: string;
  /** null = not available to this role (render "Not available"). */
  readonly value: number | null;
  readonly tone: string;
}

export interface RecentIncident {
  readonly id: number;
  readonly title: string;
  readonly reason: string;
  readonly severity: Severity;
  readonly tone: string;
  readonly acknowledged: boolean;
}

export interface DashboardView {
  readonly scope: "household" | "own";
  readonly generatedAt: string;
  readonly cards: readonly StatCard[];
  readonly recentIncidents: readonly RecentIncident[] | null;
  readonly hasAnyActivity: boolean;
}

export interface DashboardSource {
  summary: () => Promise<DashboardSummary>;
  recentIncidents: () => Promise<IncidentSummary[]>;
}

const SEVERE: readonly Severity[] = ["medium", "high", "critical"];

export function buildDashboard(
  summary: DashboardSummary,
  incidents: IncidentSummary[] | null,
): DashboardView {
  const bySeverity = summary.active_incidents_by_severity;
  const activeIncidents =
    bySeverity === null ? null : Object.values(bySeverity).reduce((a, b) => a + b, 0);
  const severeIncidents =
    bySeverity === null ? null : SEVERE.reduce((a, s) => a + bySeverity[s], 0);
  const cards: StatCard[] = [
    {
      id: "access_24h",
      label: "Access attempts (24 h)",
      value: summary.access_last_24h.total,
      tone: color.neon.cyan,
    },
    {
      id: "denied_24h",
      label: "Denied (24 h)",
      value: summary.access_last_24h.deny,
      tone: color.status.deny,
    },
    {
      id: "hold_24h",
      label: "On hold (24 h)",
      value: summary.access_last_24h.hold,
      tone: color.status.hold,
    },
    {
      id: "active_incidents",
      label: "Active incidents",
      value: activeIncidents,
      tone: color.neon.purple,
    },
    {
      id: "severe_incidents",
      label: "Medium or higher",
      value: severeIncidents,
      tone: color.severity.high,
    },
    {
      id: "unacknowledged",
      label: "Not yet acknowledged",
      value: summary.unacknowledged_active_incidents,
      tone: color.severity.critical,
    },
    {
      id: "suspicious_24h",
      label: "Suspicious events (24 h)",
      value: summary.suspicious_events_last_24h,
      tone: color.severity.medium,
    },
  ];
  const recent =
    incidents === null
      ? null
      : incidents.slice(0, 5).map((i) => ({
          id: i.id,
          title: i.title,
          reason: i.latest_reason ?? "No detection reason recorded.",
          severity: i.severity,
          tone: color.severity[i.severity],
          acknowledged: i.acknowledged_at !== null,
        }));
  const hasAnyActivity =
    summary.access_all_time.total > 0 ||
    (activeIncidents ?? 0) > 0 ||
    (summary.suspicious_events_last_24h ?? 0) > 0 ||
    (recent?.length ?? 0) > 0;
  return {
    scope: summary.scope,
    generatedAt: summary.generated_at,
    cards,
    recentIncidents: recent,
    hasAnyActivity,
  };
}

export async function loadDashboard(
  role: Role,
  source: DashboardSource,
): Promise<PageState<DashboardView>> {
  try {
    const [summary, incidents] = await Promise.all([
      source.summary(),
      role === "member" ? Promise.resolve(null) : source.recentIncidents(),
    ]);
    const view = buildDashboard(summary, incidents);
    if (!view.hasAnyActivity) {
      return {
        kind: "empty",
        message: "No access attempts, incidents or suspicious events have been recorded yet.",
      };
    }
    return { kind: "ready", data: view };
  } catch (err) {
    return {
      kind: "error",
      message: err instanceof ApiError ? err.message : "The dashboard could not be loaded.",
    };
  }
}
