/**
 * Plain-language labels for notification attempts.
 *
 * Only `delivered` and `read`, which the backend sets solely from a provider
 * report, are ever described as delivered. `accepted` and `sent` say the
 * provider took the message; everything else says nothing was delivered.
 */

import type { NotificationPublic, NotificationStatus } from "../api/monitoringSchemas.ts";
import { color } from "../design/tokens.ts";

export interface NotificationLabel {
  readonly text: string;
  readonly tone: string;
  readonly delivered: boolean;
}

const CHANNEL = { whatsapp: "WhatsApp", sms: "SMS" } as const;

const TEXT: Record<NotificationStatus, (channel: string) => string> = {
  pending: (c) => `${c}: sending…`,
  not_configured: (c) => `${c}: not configured, nothing sent`,
  send_failed: (c) => `${c}: send failed, nothing delivered`,
  accepted: (c) => `${c}: accepted by provider, delivery not confirmed`,
  sent: (c) => `${c}: sent by provider, delivery not confirmed`,
  delivered: (c) => `${c}: delivered (confirmed by provider)`,
  read: (c) => `${c}: read (confirmed by provider)`,
  failed: (c) => `${c}: provider reported delivery failure`,
};

export function notificationLabel(row: NotificationPublic): NotificationLabel {
  const channel = CHANNEL[row.channel];
  // Trust the backend's flag only together with a confirming status.
  const delivered = row.delivery_confirmed && (row.status === "delivered" || row.status === "read");
  const tone = delivered
    ? color.status.allow
    : row.status === "accepted" || row.status === "sent" || row.status === "pending"
      ? color.status.hold
      : color.status.deny;
  return { text: TEXT[row.status](channel), tone, delivered };
}

/** One line for an incident: the best confirmed outcome, else the latest. */
export function notificationSummary(rows: readonly NotificationPublic[]): NotificationLabel {
  const confirmed = rows.find((r) => notificationLabel(r).delivered);
  const chosen = confirmed ?? rows[rows.length - 1];
  if (!chosen) {
    return { text: "No notification attempted", tone: color.status.unavailable, delivered: false };
  }
  return notificationLabel(chosen);
}
