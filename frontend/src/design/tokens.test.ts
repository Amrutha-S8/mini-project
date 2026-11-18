import { test } from "node:test";
import assert from "node:assert/strict";

import {
  color,
  composite,
  contrastRatio,
  motion,
  motionFor,
  MONITORING_PARTICLE_BUDGET,
  parseColor,
  reducedMotion,
  toCssVariables,
} from "./tokens.ts";
import { outcomeBadge } from "./status.ts";
import { readBackend } from "../test-support/backendSource.ts";

const bg = parseColor(color.bg.base);
const glass = composite(parseColor(color.glass.fill), bg);
const glassStrong = composite(parseColor(color.glass.fillStrong), bg);
const ratio = (fg: string, on = bg) => contrastRatio(parseColor(fg), on);

test("contrast maths matches known WCAG values", () => {
  assert.equal(Math.round(ratio("#ffffff", parseColor("#000000")) * 100) / 100, 21);
  assert.equal(ratio("#777777", parseColor("#777777")), 1);
});

test("body text meets WCAG AA (4.5:1) on the page and on glass cards", () => {
  for (const surface of [bg, glass, glassStrong]) {
    for (const text of [color.text.primary, color.text.secondary, color.text.muted]) {
      assert.ok(ratio(text, surface) >= 4.5, `${text}: ${ratio(text, surface).toFixed(2)}`);
    }
  }
});

test("status and severity colours meet 3:1 for badges and large text", () => {
  const tones = [...Object.values(color.status), ...Object.values(color.severity)];
  for (const tone of tones) {
    for (const surface of [bg, glass]) {
      assert.ok(ratio(tone, surface) >= 3, `${tone}: ${ratio(tone, surface).toFixed(2)}`);
    }
  }
});

test("text on accent buttons is readable", () => {
  for (const accent of [color.neon.cyan, color.neon.green, color.status.allow]) {
    assert.ok(ratio(color.text.onAccent, parseColor(accent)) >= 4.5, accent);
  }
});

test("reduced motion removes all movement", () => {
  assert.deepEqual(motionFor({ reduced: true }), reducedMotion);
  assert.equal(reducedMotion.pageTransitionMs, 0);
  assert.equal(reducedMotion.maxParticles, 0);
  assert.equal(reducedMotion.scannerRotates, false);
  assert.equal(reducedMotion.scannerBeam, false);
  assert.deepEqual(motionFor({ reduced: true, page: "live_monitoring" }), reducedMotion);
});

test("the webcam page gets a smaller 3D budget", () => {
  assert.equal(
    motionFor({ reduced: false, page: "live_monitoring" }).maxParticles,
    MONITORING_PARTICLE_BUDGET,
  );
  assert.equal(motionFor({ reduced: false, page: "dashboard" }), motion);
});

test("CSS variables are deterministic and complete", () => {
  const css = toCssVariables();
  assert.equal(css, toCssVariables());
  assert.match(css, /--color-bg-base: #050816;/);
  assert.match(css, /--color-status-hold: #f59e0b;/);
  assert.match(css, /--color-avatar-0: #2563eb;/);
  assert.match(css, /--radius-lg: 16px;/);
  assert.doesNotMatch(css, /undefined|\[object/);
});

test("outcome badges only label the engine's values", () => {
  const engine = readBackend("domain/access_engine.py");
  for (const v of ["allow", "deny", "hold"]) assert.match(engine, new RegExp(`= "${v}"`));
  assert.equal(outcomeBadge("allow").label, "ALLOW");
  assert.equal(outcomeBadge("deny").label, "DENY");
  assert.equal(outcomeBadge("hold").label, "HOLD");
  for (const bad of ["ALLOW", "granted", "", null, undefined, 1, true, { outcome: "allow" }]) {
    assert.equal(outcomeBadge(bad).label, "UNKNOWN", String(bad));
  }
  assert.match(outcomeBadge("hold").description, /locked/);
});
