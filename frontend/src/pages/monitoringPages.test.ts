/**
 * Security Events and Dashboard page models, and the monitoring API calls.
 * The fake server returns bodies shaped like backend/app/schemas/events.py;
 * this proves how the frontend treats them, not how the backend behaves.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { AuthSession } from "../auth/session.ts";
import { createApiConfig } from "../config/apiConfig.ts";
import { ApiError } from "../api/errors.ts";
import { HttpClient } from "../api/http.ts";
import {
  dashboardApi,
  incidentsApi,
  notificationsApi,
  securityEventsApi,
} from "../api/monitoringEndpoints.ts";
import type { NotificationPublic } from "../api/monitoringSchemas.ts";
import { BASE, FakeServer, json, tokensFixture, userFixture } from "../test-support/fakeServer.ts";
import { buildDashboard, loadDashboard } from "./dashboardPage.ts";
import { notificationLabel, notificationSummary } from "./notificationLabels.ts";
import { allowedActions, loadSecurityEvents } from "./securityEventsPage.ts";

function incident(overrides: Record<string, unknown> = {}) {
  return {
    id: 1,
    incident_uid: "inc-0123456789abcdef",
    title: "Repeated denied access at front",
    category: "repeated_denied_access",
    severity: "medium",
    status: "open",
    opened_at: "2026-11-19T14:00:00Z",
    closed_at: null,
    event_count: 3,
    first_event_at: "2026-11-19T13:58:00Z",
    last_event_at: "2026-11-19T14:00:00Z",
    notify_recommended: true,
    assigned_to_user_id: null,
    acknowledged_at: null,
    acknowledged_by_user_id: null,
    latest_reason: "3 denied access decisions at front within 10 minutes (threshold 3).",
    ...overrides,
  };
}

function notification(overrides: Record<string, unknown> = {}): NotificationPublic {
  return {
    id: 1,
    incident_id: 1,
    channel: "whatsapp",
    provider: "meta_whatsapp_cloud",
    recipient_masked: "+91******3210",
    trigger_reason: "created",
    status: "accepted",
    delivery_confirmed: false,
    provider_message_id: "wamid.1",
    provider_status: "accepted",
    error_code: null,
    error_message: null,
    created_at: "2026-11-19T14:00:01Z",
    sent_at: "2026-11-19T14:00:02Z",
    delivered_at: null,
    failed_at: null,
    status_checked_at: null,
    ...overrides,
  } as NotificationPublic;
}

function securityEvent(overrides: Record<string, unknown> = {}) {
  return {
    id: 10,
    event_uid: "e-10",
    event_type: "access.denied",
    modality: "access",
    severity: "low",
    outcome: "blocked",
    suspicious: true,
    occurred_at: "2026-11-19T14:00:00Z",
    source_module: "ingest.camera_client",
    detector_rule: null,
    confidence: null,
    door_id: "front",
    camera_id: null,
    incident_id: 1,
    family_member_id: null,
    user_id: null,
    ip_address: null,
    details: null,
    ...overrides,
  };
}

function summary(overrides: Record<string, unknown> = {}) {
  const zero = { allow: 0, deny: 0, hold: 0, total: 0 };
  return {
    generated_at: "2026-11-19T14:05:00Z",
    scope: "household",
    access_last_24h: zero,
    access_last_7d: zero,
    access_all_time: zero,
    last_access_event_at: null,
    active_incidents_by_severity: { info: 0, low: 0, medium: 0, high: 0, critical: 0 },
    unacknowledged_active_incidents: 0,
    suspicious_events_last_24h: 0,
    ...overrides,
  };
}

async function signedIn(role = "admin") {
  const server = new FakeServer();
  server.on("POST", "/auth/login", () =>
    json(200, { user: userFixture({ role }), tokens: tokensFixture() }),
  );
  const session = new AuthSession(new HttpClient(createApiConfig({ baseUrl: BASE }), server.fetch));
  await session.login("owner@example.com", "pw");
  return { server, session };
}

// --- API calls -------------------------------------------------------------------------

test("monitoring endpoints call the exact backend methods and paths", async () => {
  const { server, session } = await signedIn();
  const detail = () =>
    json(200, { ...incident(), resolution_notes: null, resolved_by_user_id: null, detections: [] });
  server
    .on("GET", "/incidents", () => json(200, [incident()]))
    .on("GET", "/incidents/1", detail)
    .on("POST", "/incidents/1/acknowledge", detail)
    .on("POST", "/incidents/1/investigate", detail)
    .on("POST", "/incidents/1/resolve", detail)
    .on("GET", "/incidents/1/notifications", () => json(200, [notification()]))
    .on("POST", "/incidents/1/notify", () => json(202, { queued: true, message: "started" }))
    .on("GET", "/events/security", () => json(200, [securityEvent()]))
    .on("GET", "/notifications/channels", () => json(200, []))
    .on("POST", "/notifications/1/refresh", () => json(200, notification({ channel: "sms" })))
    .on("GET", "/dashboard/summary", () => json(200, summary()));

  const incidents = incidentsApi(session);
  await incidents.list({ status: "open", limit: 20 });
  await incidents.get(1);
  await incidents.acknowledge(1);
  await incidents.investigate(1);
  await incidents.resolve(1, { resolution: "false_positive", resolution_notes: "Test." });
  await incidents.notifications(1);
  await incidents.notify(1);
  await securityEventsApi(session).list({ suspiciousOnly: true });
  await notificationsApi(session).channels();
  await notificationsApi(session).refresh(1);
  await dashboardApi(session).summary();

  const calls = server.calls.slice(1).map((c) => `${c.method} ${c.url.replace(BASE, "")}`);
  assert.deepEqual(calls, [
    "GET /incidents?status=open&limit=20",
    "GET /incidents/1",
    "POST /incidents/1/acknowledge",
    "POST /incidents/1/investigate",
    "POST /incidents/1/resolve",
    "GET /incidents/1/notifications",
    "POST /incidents/1/notify",
    "GET /events/security?suspicious_only=true",
    "GET /notifications/channels",
    "POST /notifications/1/refresh",
    "GET /dashboard/summary",
  ]);
  assert.deepEqual(server.calls[5]?.body, {
    resolution: "false_positive",
    resolution_notes: "Test.",
  });
});

test("security events drop identity fields the UI never renders", async () => {
  const { server, session } = await signedIn();
  server.on("GET", "/events/security", () =>
    json(200, [securityEvent({ family_member_id: 4, ip_address: "10.0.0.5" })]),
  );
  const [event] = await securityEventsApi(session).list();
  assert.ok(event);
  assert.ok(!("family_member_id" in event) && !("ip_address" in event));
});

test("a malformed incident list is rejected, not rendered", async () => {
  const { server, session } = await signedIn();
  server.on("GET", "/incidents", () => json(200, [incident({ severity: "apocalyptic" })]));
  await assert.rejects(incidentsApi(session).list(), ApiError);
});

test("invalid ids never reach the network", async () => {
  const { server, session } = await signedIn();
  await assert.rejects(incidentsApi(session).acknowledge(0), ApiError);
  assert.equal(server.calls.length, 1);
});

// --- notification labels -----------------------------------------------------------------

test("accepted is never shown as delivered", () => {
  const label = notificationLabel(notification());
  assert.equal(label.delivered, false);
  assert.match(label.text, /delivery not confirmed/);
});

test("delivered is shown only with a confirming status", () => {
  assert.equal(
    notificationLabel(notification({ status: "delivered", delivery_confirmed: true })).delivered,
    true,
  );
  // A contradictory flag is not trusted on its own.
  assert.equal(notificationLabel(notification({ delivery_confirmed: true })).delivered, false);
});

test("failure and missing configuration say nothing was delivered", () => {
  assert.match(
    notificationLabel(notification({ status: "send_failed" })).text,
    /nothing delivered/,
  );
  assert.match(
    notificationLabel(notification({ status: "not_configured", channel: "sms" })).text,
    /^SMS: not configured, nothing sent$/,
  );
  assert.match(notificationLabel(notification({ status: "failed" })).text, /delivery failure/);
});

test("summary prefers a confirmed delivery, else the latest attempt", () => {
  const rows = [
    notification({ id: 1, status: "send_failed" }),
    notification({ id: 2, channel: "sms", status: "accepted" }),
  ];
  assert.match(notificationSummary(rows).text, /^SMS: accepted/);
  const delivered = [
    notification({ id: 1, status: "delivered", delivery_confirmed: true }),
    notification({ id: 2, status: "send_failed" }),
  ];
  assert.equal(notificationSummary(delivered).delivered, true);
  assert.equal(notificationSummary([]).text, "No notification attempted");
});

// --- Security Events page ---------------------------------------------------------------------

const noCalls = {
  incidents: async () => assert.fail("not allowed"),
  events: async () => [],
  notifications: async () => assert.fail("not allowed"),
};

test("empty database gives the empty state, not sample rows", async () => {
  const state = await loadSecurityEvents("admin", {
    incidents: async () => [],
    events: async () => [],
    notifications: async () => [],
  });
  assert.equal(state.kind, "empty");
});

test("admin sees incidents with reasons, notifications and actions", async () => {
  const { server, session } = await signedIn();
  server
    .on("GET", "/incidents", () => json(200, [incident()]))
    .on("GET", "/events/security", () => json(200, [securityEvent()]))
    .on("GET", "/incidents/1/notifications", () => json(200, [notification()]));
  const incidents = incidentsApi(session);
  const state = await loadSecurityEvents("admin", {
    incidents: () => incidents.list(),
    events: () => securityEventsApi(session).list(),
    notifications: (id) => incidents.notifications(id),
  });
  assert.equal(state.kind, "ready");
  if (state.kind !== "ready") return;
  const [row] = state.data.incidents ?? [];
  assert.ok(row);
  assert.match(row.reason, /3 denied access decisions/);
  assert.deepEqual(row.actions, ["acknowledge", "investigate", "resolve", "notify"]);
  assert.match(row.notification?.text ?? "", /delivery not confirmed/);
  assert.equal(state.data.events.length, 1);
});

test("viewer gets incidents without actions or notification calls", async () => {
  const state = await loadSecurityEvents("viewer", {
    incidents: async () => [incident()] as never,
    events: async () => [],
    notifications: async () => assert.fail("viewer must not load notifications"),
  });
  assert.equal(state.kind, "ready");
  if (state.kind !== "ready") return;
  assert.deepEqual(state.data.incidents?.[0]?.actions, []);
  assert.equal(state.data.incidents?.[0]?.notification, null);
});

test("member never requests incidents", async () => {
  const state = await loadSecurityEvents("member", noCalls);
  assert.equal(state.kind, "empty");
  if (state.kind === "empty") assert.match(state.message, /about you/);
});

test("API errors become an error state", async () => {
  const state = await loadSecurityEvents("admin", {
    incidents: async () => {
      throw new ApiError("http", "You do not have permission.", { status: 403, code: "forbidden" });
    },
    events: async () => [],
    notifications: async () => [],
  });
  assert.deepEqual(state, { kind: "error", message: "You do not have permission." });
});

test("actions follow the incident state", () => {
  const ack = { acknowledged_at: "2026-11-19T14:01:00Z" };
  assert.deepEqual(allowedActions("admin", incident(ack) as never), [
    "investigate",
    "resolve",
    "notify",
  ]);
  assert.deepEqual(
    allowedActions("admin", incident({ ...ack, status: "investigating" }) as never),
    ["resolve", "notify"],
  );
  assert.deepEqual(allowedActions("admin", incident({ status: "resolved" }) as never), ["notify"]);
  assert.deepEqual(allowedActions("viewer", incident() as never), []);
});

// --- Dashboard page ----------------------------------------------------------------------------

test("dashboard cards come from the summary only", () => {
  const view = buildDashboard(
    summary({
      access_last_24h: { allow: 2, deny: 3, hold: 1, total: 6 },
      access_all_time: { allow: 2, deny: 3, hold: 1, total: 6 },
      active_incidents_by_severity: { info: 0, low: 1, medium: 2, high: 1, critical: 0 },
      unacknowledged_active_incidents: 2,
      suspicious_events_last_24h: 5,
    }) as never,
    [incident()] as never,
  );
  const value = (id: string) => view.cards.find((c) => c.id === id)?.value;
  assert.equal(value("access_24h"), 6);
  assert.equal(value("denied_24h"), 3);
  assert.equal(value("hold_24h"), 1);
  assert.equal(value("active_incidents"), 4);
  assert.equal(value("severe_incidents"), 3);
  assert.equal(value("unacknowledged"), 2);
  assert.equal(value("suspicious_24h"), 5);
  assert.match(view.recentIncidents?.[0]?.reason ?? "", /denied access/);
});

test("member dashboard shows unavailable cards as null, not zero", async () => {
  const state = await loadDashboard("member", {
    summary: async () =>
      summary({
        scope: "own",
        access_last_24h: { allow: 1, deny: 0, hold: 0, total: 1 },
        access_all_time: { allow: 1, deny: 0, hold: 0, total: 1 },
        active_incidents_by_severity: null,
        unacknowledged_active_incidents: null,
        suspicious_events_last_24h: null,
      }) as never,
    recentIncidents: async () => assert.fail("members get no incidents"),
  });
  assert.equal(state.kind, "ready");
  if (state.kind !== "ready") return;
  assert.equal(state.data.cards.find((c) => c.id === "active_incidents")?.value, null);
  assert.equal(state.data.recentIncidents, null);
});

test("empty database gives an empty dashboard state", async () => {
  const { server, session } = await signedIn();
  server
    .on("GET", "/dashboard/summary", () => json(200, summary()))
    .on("GET", "/incidents", () => json(200, []));
  const state = await loadDashboard("admin", {
    summary: () => dashboardApi(session).summary(),
    recentIncidents: () => incidentsApi(session).list({ limit: 5 }),
  });
  assert.equal(state.kind, "empty");
});
