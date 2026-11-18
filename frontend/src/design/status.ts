/**
 * How backend outcomes are *displayed*. The UI never computes an outcome: it
 * only labels a value the backend AccessEngine returned. Anything that is not
 * exactly one of the engine's values is shown as "UNKNOWN", never guessed.
 */

import { color } from "./tokens.ts";

/** The AccessEngine's values (backend/app/domain/access_engine.py Outcome). */
export const ENGINE_OUTCOMES = ["allow", "deny", "hold"] as const;
export type EngineOutcome = (typeof ENGINE_OUTCOMES)[number];

export interface OutcomeBadge {
  readonly label: "ALLOW" | "DENY" | "HOLD" | "UNKNOWN";
  readonly tone: string;
  readonly description: string;
}

const BADGES: Record<EngineOutcome, OutcomeBadge> = {
  allow: {
    label: "ALLOW",
    tone: color.status.allow,
    description: "Granted by the AccessEngine.",
  },
  deny: {
    label: "DENY",
    tone: color.status.deny,
    description: "Denied by the AccessEngine. The door stays locked.",
  },
  hold: {
    label: "HOLD",
    tone: color.status.hold,
    description: "The door stays locked until an admin reviews it.",
  },
};

export function outcomeBadge(value: unknown): OutcomeBadge {
  if (typeof value === "string" && (ENGINE_OUTCOMES as readonly string[]).includes(value)) {
    return BADGES[value as EngineOutcome];
  }
  return {
    label: "UNKNOWN",
    tone: color.status.unavailable,
    description: "No valid decision was received from the AccessEngine.",
  };
}
