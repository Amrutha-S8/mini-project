/**
 * Response validators and request types mirroring the backend contracts.
 *
 * Source of truth (read, not guessed):
 *   backend/app/schemas/auth.py          UserPublic, TokenPair, LoginResponse,
 *                                        LoginRequest, RefreshRequest, RegisterRequest
 *   backend/app/schemas/family_member.py FamilyMemberPublic/Create/Update
 *   backend/app/api/v1/health.py         HealthResponse
 *   backend/app/main.py, core/errors.py  error envelope
 *
 * `src/api/contract.test.ts` re-reads those Python files and fails if a field
 * name drifts. The backend has never been run, so these mirror the code, not
 * observed responses.
 */

import {
  array,
  bool,
  email,
  int,
  isoDateTime,
  literal,
  nullable,
  object,
  str,
  type Infer,
  type Validator,
} from "./validate.ts";

/** Keys that must never appear in any response (SR-STORE-03, SR-AUTH). */
export const FORBIDDEN_RESPONSE_KEYS = [
  "password",
  "password_hash",
  "refresh_token_hash",
  "embedding",
  "embeddings",
  "face_embedding",
  "secret_key",
] as const;

export const ROLES = ["admin", "member", "viewer"] as const;
export type Role = (typeof ROLES)[number];

export const MEMBER_TYPES = ["family", "resident", "staff", "recurring_visitor"] as const;
export const MEMBER_STATUSES = ["active", "inactive", "revoked"] as const;
export const ENROLLMENT_STATUSES = ["not_enrolled", "enrolled", "needs_reenrollment"] as const;

export type MemberType = (typeof MEMBER_TYPES)[number];

const userPublicShape = {
  id: int({ min: 1 }),
  email,
  full_name: str({ min: 1, max: 200 }),
  // The backend types role as `str`; the CHECK constraint limits it to three
  // values. Anything else is kept as text so access rules can fail closed.
  role: str({ min: 1, max: 20 }),
  is_active: bool,
  last_login_at: nullable(isoDateTime),
  created_at: isoDateTime,
};

export const UserPublic = object(userPublicShape, { forbidden: FORBIDDEN_RESPONSE_KEYS });
export type UserPublic = Infer<typeof userPublicShape>;

const tokenPairShape = {
  access_token: str({ min: 1, max: 4096 }),
  refresh_token: str({ min: 1, max: 512 }),
  token_type: literal("bearer"),
  expires_in: int({ min: 1, max: 24 * 60 * 60 }),
};
export const TokenPair = object(tokenPairShape);
export type TokenPair = Infer<typeof tokenPairShape>;

export const LoginResponse = object({ user: UserPublic, tokens: TokenPair });
export type LoginResponse = { user: UserPublic; tokens: TokenPair };

const memberShape = {
  id: int({ min: 1 }),
  full_name: str({ min: 1, max: 200 }),
  member_type: literal(...MEMBER_TYPES),
  status: literal(...MEMBER_STATUSES),
  enrollment_status: literal(...ENROLLMENT_STATUSES),
  relationship_label: nullable(str({ max: 100 })),
  notes: nullable(str({ max: 2000 })),
  user_id: nullable(int({ min: 1 })),
  created_at: isoDateTime,
  updated_at: isoDateTime,
};
export const FamilyMemberPublic = object(memberShape, { forbidden: FORBIDDEN_RESPONSE_KEYS });
export type FamilyMemberPublic = Infer<typeof memberShape>;
export const FamilyMemberList: Validator<FamilyMemberPublic[]> = array(FamilyMemberPublic, {
  max: 5_000,
});

const healthShape = {
  status: literal("ok", "degraded"),
  database: literal("ok", "unreachable", "not_checked"),
};
export const HealthResponse = object(healthShape);
export type HealthResponse = Infer<typeof healthShape>;

/** `{"error": {"code", "message", "details"?}}` from every error handler. */
export const ErrorEnvelope = object({
  error: object({
    code: str({ min: 1, max: 100 }),
    message: str({ min: 1, max: 500 }),
  }),
});

// --- requests (typed only; the backend validates) -----------------------------

export interface LoginRequest {
  email: string;
  password: string;
}

export interface RegisterRequest {
  email: string;
  password: string;
  full_name: string;
  role?: Role;
}

export interface FamilyMemberCreate {
  full_name: string;
  member_type?: MemberType;
  relationship_label?: string | null;
  notes?: string | null;
  user_id?: number | null;
}

/** Partial update. Status changes use the deactivate/revoke endpoints. */
export interface FamilyMemberUpdate {
  full_name?: string;
  member_type?: MemberType;
  relationship_label?: string | null;
  notes?: string | null;
}

/** Same numbers as backend/app/utils/validators.py; used for form hints only. */
export const PASSWORD_MIN_LENGTH = 12;
export const PASSWORD_MAX_LENGTH = 256;
