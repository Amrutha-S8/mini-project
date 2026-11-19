/**
 * The monitoring validators against backend/app/schemas/events.py.
 * Fails when a Pydantic field is renamed, added or removed.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { pydanticFields } from "../test-support/backendSource.ts";
import { SHAPE_KEYS } from "./monitoringSchemas.ts";

const FILE = "schemas/events.py";
const sorted = (xs: readonly string[]) => [...xs].sort();

test("validators project exactly the backend fields", () => {
  for (const cls of [
    "IncidentSummary",
    "DetectionPublic",
    "NotificationPublic",
    "ChannelStatus",
    "DashboardSummary",
    "DecisionCounts",
  ] as const) {
    assert.deepEqual(sorted(SHAPE_KEYS[cls]), sorted(pydanticFields(FILE, cls)), cls);
  }
});

test("detail adds the declared fields and leaves admin-only free-form data out", () => {
  const detailOnly = pydanticFields(FILE, "IncidentDetail");
  const expected = [
    ...pydanticFields(FILE, "IncidentSummary"),
    ...detailOnly.filter(
      (f) => !["attack_chain", "attack_chain_generated_at", "ai_advisory"].includes(f),
    ),
  ];
  assert.deepEqual(sorted(SHAPE_KEYS.IncidentDetail), sorted(expected));
});

test("security events project a subset without identities, IPs or details", () => {
  const backend = new Set(pydanticFields(FILE, "SecurityEventPublic"));
  for (const key of SHAPE_KEYS.SecurityEventPublic) assert.ok(backend.has(key), key);
  for (const hidden of ["family_member_id", "user_id", "ip_address", "details"]) {
    assert.ok(!(SHAPE_KEYS.SecurityEventPublic as readonly string[]).includes(hidden), hidden);
  }
});
