/**
 * Validators for incidents, detections, notifications, security events and
 * the dashboard summary.
 *
 * Source of truth: backend/app/schemas/events.py (IncidentSummary,
 * IncidentDetail, DetectionPublic, NotificationPublic, ChannelStatus,
 * SecurityEventPublic, DashboardSummary). `contract.test.ts` re-reads that
 * file and fails if a field name drifts.
 */

import { FORBIDDEN_RESPONSE_KEYS } from "./schemas.ts";
import {
  array,
  bool,
  int,
  isoDateTime,
  literal,
  nullable,
  object,
  str,
  type Infer,
  type Validator,
} from "./validate.ts";

export const SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;
export type Severity = (typeof SEVERITIES)[number];
export const INCIDENT_STATUSES = ["open", "investigating", "resolved", "false_positive"] as const;
export type IncidentStatus = (typeof INCIDENT_STATUSES)[number];
export const NOTIFICATION_STATUSES = [
  "pending",
  "not_configured",
  "send_failed",
  "accepted",
  "sent",
  "delivered",
  "read",
  "failed",
] as const;
export type NotificationStatus = (typeof NOTIFICATION_STATUSES)[number];

const opts = { forbidden: FORBIDDEN_RESPONSE_KEYS };
const maybeTime = nullable(isoDateTime);
const maybeId = nullable(int({ min: 1 }));

const incidentSummaryShape = {
  id: int({ min: 1 }),
  incident_uid: str({ min: 1, max: 64 }),
  title: str({ min: 1, max: 200 }),
  category: str({ min: 1, max: 50 }),
  severity: literal(...SEVERITIES),
  status: literal(...INCIDENT_STATUSES),
  opened_at: isoDateTime,
  closed_at: maybeTime,
  event_count: int({ min: 0 }),
  first_event_at: maybeTime,
  last_event_at: maybeTime,
  notify_recommended: bool,
  assigned_to_user_id: maybeId,
  acknowledged_at: maybeTime,
  acknowledged_by_user_id: maybeId,
  latest_reason: nullable(str({ max: 1000 })),
};
export const IncidentSummary = object(incidentSummaryShape, opts);
export type IncidentSummary = Infer<typeof incidentSummaryShape>;
export const IncidentList: Validator<IncidentSummary[]> = array(IncidentSummary, { max: 200 });

const detectionShape = {
  id: int({ min: 1 }),
  detector_rule: str({ min: 1, max: 100 }),
  severity: literal(...SEVERITIES),
  reason: str({ min: 1, max: 1000 }),
  detected_at: isoDateTime,
  security_event_id: int({ min: 1 }),
  event_uids: array(str({ min: 1, max: 128 }), { max: 1000 }),
};
export const DetectionPublic = object(detectionShape, opts);
export type DetectionPublic = Infer<typeof detectionShape>;

/**
 * Detail adds resolution fields and the detections. The attack chain and AI
 * advisory are admin-only free-form data and are deliberately not rendered,
 * so they are not projected here.
 */
const incidentDetailShape = {
  ...incidentSummaryShape,
  resolution_notes: nullable(str({ max: 2000 })),
  resolved_by_user_id: maybeId,
  detections: array(DetectionPublic, { max: 1000 }),
};
export const IncidentDetail = object(incidentDetailShape, opts);
export type IncidentDetail = Infer<typeof incidentDetailShape>;

const notificationShape = {
  id: int({ min: 1 }),
  incident_id: int({ min: 1 }),
  channel: literal("whatsapp", "sms"),
  provider: str({ min: 1, max: 40 }),
  recipient_masked: nullable(str({ max: 32 })),
  trigger_reason: str({ min: 1, max: 20 }),
  status: literal(...NOTIFICATION_STATUSES),
  delivery_confirmed: bool,
  provider_message_id: nullable(str({ max: 128 })),
  provider_status: nullable(str({ max: 32 })),
  error_code: nullable(str({ max: 64 })),
  error_message: nullable(str({ max: 300 })),
  created_at: isoDateTime,
  sent_at: maybeTime,
  delivered_at: maybeTime,
  failed_at: maybeTime,
  status_checked_at: maybeTime,
};
export const NotificationPublic = object(notificationShape, opts);
export type NotificationPublic = Infer<typeof notificationShape>;
export const NotificationList: Validator<NotificationPublic[]> = array(NotificationPublic, {
  max: 500,
});

export const NotifyResponse = object({ queued: bool, message: str({ min: 1, max: 500 }) });

const channelShape = {
  channel: literal("whatsapp", "sms"),
  provider: str({ min: 1, max: 40 }),
  configured: bool,
  recipient_masked: nullable(str({ max: 32 })),
  problems: array(str({ max: 300 }), { max: 20 }),
  delivery_confirmation: str({ max: 300 }),
};
export const ChannelStatus = object(channelShape, opts);
export type ChannelStatus = Infer<typeof channelShape>;
export const ChannelStatusList: Validator<ChannelStatus[]> = array(ChannelStatus, { max: 5 });

const securityEventShape = {
  id: int({ min: 1 }),
  event_uid: str({ min: 1, max: 128 }),
  event_type: str({ min: 1, max: 64 }),
  modality: str({ min: 1, max: 20 }),
  severity: literal(...SEVERITIES),
  outcome: literal("succeeded", "blocked", "failed", "observed"),
  suspicious: bool,
  occurred_at: isoDateTime,
  source_module: str({ min: 1, max: 64 }),
  detector_rule: nullable(str({ max: 100 })),
  door_id: nullable(str({ max: 128 })),
  camera_id: nullable(str({ max: 128 })),
  incident_id: maybeId,
};
export const SecurityEventPublic = object(securityEventShape, opts);
export type SecurityEventPublic = Infer<typeof securityEventShape>;
export const SecurityEventList: Validator<SecurityEventPublic[]> = array(SecurityEventPublic, {
  max: 200,
});

const countsShape = {
  allow: int({ min: 0 }),
  deny: int({ min: 0 }),
  hold: int({ min: 0 }),
  total: int({ min: 0 }),
};
const Counts = object(countsShape);

/** Severity -> count, with every key validated. */
const severityCounts: Validator<Record<Severity, number>> = (value, path) =>
  object({
    info: int({ min: 0 }),
    low: int({ min: 0 }),
    medium: int({ min: 0 }),
    high: int({ min: 0 }),
    critical: int({ min: 0 }),
  })(value, path);

const dashboardShape = {
  generated_at: isoDateTime,
  scope: literal("household", "own"),
  access_last_24h: Counts,
  access_last_7d: Counts,
  access_all_time: Counts,
  last_access_event_at: maybeTime,
  active_incidents_by_severity: nullable(severityCounts),
  unacknowledged_active_incidents: nullable(int({ min: 0 })),
  suspicious_events_last_24h: nullable(int({ min: 0 })),
};
export const DashboardSummary = object(dashboardShape, opts);
export type DashboardSummary = Infer<typeof dashboardShape>;

/** Projected keys per backend class, for the contract test. */
export const SHAPE_KEYS = {
  IncidentSummary: Object.keys(incidentSummaryShape),
  IncidentDetail: Object.keys(incidentDetailShape),
  DetectionPublic: Object.keys(detectionShape),
  NotificationPublic: Object.keys(notificationShape),
  ChannelStatus: Object.keys(channelShape),
  SecurityEventPublic: Object.keys(securityEventShape),
  DashboardSummary: Object.keys(dashboardShape),
  DecisionCounts: Object.keys(countsShape),
} as const;

export interface IncidentResolve {
  resolution: "resolved" | "false_positive";
  resolution_notes: string;
}
