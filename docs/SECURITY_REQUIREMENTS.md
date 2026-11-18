# SECURITY REQUIREMENTS

**Project:** AI-Powered Smart Home Security and Automated Access Management System
**Version:** 1.0 (Day 1 design)
**Status:** Requirements only — nothing implemented, nothing tested

Requirements use **MUST** (mandatory), **MUST NOT** (prohibited) and **SHOULD** (strong default, deviation needs recording).

---

## 1. Threat Model

### 1.1 Assets, ranked by harm if compromised

| Rank | Asset | Harm |
|---|---|---|
| 1 | **Door control** | Physical intrusion into a home |
| 2 | **Face embeddings** | Irrevocable biometric exposure — you cannot reissue a face |
| 3 | **Permission rules** | Silent persistent unauthorised access |
| 4 | **Access + audit history** | Loss of forensic truth; attacker covers tracks |
| 5 | Operator credentials | Full system control |
| 6 | Visitor snapshots | Privacy harm to non-consenting third parties |
| 7 | Gemini API key | Financial abuse |

### 1.2 Adversaries

| ID | Adversary | Capability | Primary goal |
|---|---|---|---|
| T1 | Opportunistic intruder | Stands at the camera | Get the door open |
| T2 | Presentation attacker | Holds a photo, phone screen or mask of a resident | Impersonate a known face |
| T3 | Network attacker | Reaches the API | Forge a grant, exfiltrate biometrics |
| T4 | Credential attacker | Guesses or steals operator logins | Add a permission for themselves |
| T5 | **Prompt-injection attacker** | Controls text or imagery the AI tier will read | **Make the AI open the door** |
| T6 | Malicious insider | Legitimate admin account | Grant covert access, erase traces |
| T7 | Device thief | Steals the host machine | Read the database offline |

### 1.3 T5 is the defining threat for this architecture

T5 is why §4 exists and why it is written as a structural control rather than a prompt-hardening exercise. **Prompt-hardening is not a security boundary.** Any defence that depends on a model behaving well under adversarial input is a defence that fails eventually. The only durable answer is to ensure the AI tier has no mechanism to act, so that a fully successful injection yields nothing but misleading text.

### 1.4 Explicitly out of scope for v1

Physical destruction of the camera or host; network-layer attacks below TLS; supply-chain compromise of pip packages; a compromised host OS. These are acknowledged, not addressed.

---

## 2. Authentication

### 2.1 Two distinct authentication domains — do not conflate

| Domain | Subject | Credential | Authority |
|---|---|---|---|
| **System authentication** | Operators | Email + password → JWT | M01 |
| **Physical access identification** | People at the door | Face biometric | M06 identifies, **M08 decides** |

**SR-AUTH-01.** These domains MUST remain separate. A valid operator JWT MUST NOT by itself open the door, and a recognised face MUST NOT grant any API privilege. A single compromise must not cross the boundary.

### 2.2 Password handling

- **SR-AUTH-02.** Passwords MUST be hashed with **Argon2id** using per-password salts and tuned memory/time/parallelism parameters. MD5, SHA-1, SHA-256 and unsalted schemes are prohibited.
- **SR-AUTH-03.** Plaintext passwords MUST NOT be logged, stored, cached, echoed in errors, or included in audit records.
- **SR-AUTH-04.** Minimum length 12 characters, checked against a common-password denylist. Composition rules are not required; length and uniqueness matter more.
- **SR-AUTH-05.** Password change MUST revoke all sessions except the one performing the change.

### 2.3 Tokens and sessions

- **SR-AUTH-06.** Access tokens MUST be short-lived (15 minutes) and signed with HS256 or better, using a secret of at least 32 bytes loaded from the environment. The secret MUST NOT appear in source or version control.
- **SR-AUTH-07.** Refresh tokens MUST be long-lived but **rotated on every use**, with only a hash stored server-side (`sessions.refresh_token_hash`).
- **SR-AUTH-08.** Refresh-token **reuse MUST be treated as theft**: detecting reuse via `parent_session_id` lineage MUST revoke the entire session family, write a `security_events` row and notify the user.
- **SR-AUTH-09.** Every token MUST carry `sub`, `role`, `exp`, `iat` and `jti`, and MUST be validated for signature, expiry and algorithm on every request. Algorithm confusion (`alg: none`, RS→HS substitution) MUST be rejected explicitly.
- **SR-AUTH-10.** Logout MUST revoke server-side. Client-side token discard alone is insufficient.

### 2.4 Brute force

- **SR-AUTH-11.** Failed logins MUST increment `users.failed_login_count` and trigger progressive lockout via `locked_until`.
- **SR-AUTH-12.** Login responses MUST NOT reveal whether an email exists. Identical message and comparable timing for both cases.
- **SR-AUTH-13.** Authentication endpoints MUST be rate-limited per IP and per account.
- **SR-AUTH-14.** Every attempt, success or failure, MUST be written to `audit_log`.

### 2.5 Face authentication integrity

- **SR-AUTH-15.** A face match MUST be treated as an **identity claim**, never as an authorisation. M08 re-verifies the threshold independently (rule 3) rather than trusting M06's verdict.
- **SR-AUTH-16.** The match threshold MUST be configurable, MUST have a secure default, and every change MUST be audited. The threshold in force MUST be recorded on each decision (`access_events.threshold_used`), so historical decisions stay explainable after a change.
- **SR-AUTH-17.** Where the best and second-best candidates fall within a configured margin, the result MUST be UNKNOWN. **Ambiguity MUST NOT resolve to the top candidate.**
- **SR-AUTH-18 (T2).** Presentation-attack signals available from detector metadata SHOULD be evaluated, and v1 MUST document that full liveness detection is **not implemented**. Until it is, a photo-based impersonation is a known residual risk and MUST NOT be described as mitigated.

---

## 3. Authorisation and Permission Checks

### 3.1 API authorisation

- **SR-AUTHZ-01.** Every endpoint except login, refresh and health MUST require a valid token. Default-deny: a route without an explicit auth dependency MUST fail closed, and a test MUST enumerate routes to prove none is unprotected.
- **SR-AUTHZ-02.** RBAC roles: `admin` (full control including permissions and enrollment), `member` (own history, door state), `viewer` (read-only monitoring).
- **SR-AUTHZ-03.** Permission mutation, face enrollment, member revocation, threshold changes and manual override MUST be `admin`-only.
- **SR-AUTHZ-04.** Object-level checks MUST accompany role checks. A `member` MUST NOT read another member's events by changing an id — this is the IDOR class and MUST be tested per endpoint.
- **SR-AUTHZ-05.** Role MUST be read from the server-side user record at request time, never trusted from client input or from a stale token claim alone.

### 3.2 Door permission checks (M08)

- **SR-AUTHZ-06.** Every access attempt MUST pass through `AccessEngine.decide()`. There MUST be no alternative code path to the door.
- **SR-AUTHZ-07.** Rules MUST evaluate in the fixed documented order, first match deciding (`SYSTEM_ARCHITECTURE.md` §5.1).
- **SR-AUTHZ-08.** The engine MUST verify, in order: lockdown state, identity known, confidence ≥ threshold, member active, permission exists, permission unexpired, time window satisfied, rate limit not exceeded.
- **SR-AUTHZ-09.** **Deny MUST be the default.** GRANT is returned only by rule 9, after every prior rule has been evaluated and passed.
- **SR-AUTHZ-10.** Permission revocation MUST take effect on the next decision, with no caching that could extend access.
- **SR-AUTHZ-11.** Time windows MUST evaluate against the household timezone stored on the permission, correctly handling DST. An ambiguous local time MUST resolve to the **more restrictive** interpretation.
- **SR-AUTHZ-12.** Manual admin override MUST be routed through M08 with `source = manual_override`, so it is rule-checked, recorded in `access_events` and written to `audit_log`. A bypass path that skips the engine is prohibited.

### 3.3 Fail-secure

- **SR-AUTHZ-13.** Every failure mode MUST resolve to DENY: missing model, failed embedding, unreadable database, corrupt permission row, engine exception, clock failure.
- **SR-AUTHZ-14.** `AccessEngine.decide()` MUST wrap its body such that **any** unhandled exception returns `DENY / engine_error`. It MUST NOT propagate an exception that a caller might interpret permissively.
- **SR-AUTHZ-15.** Door resting state MUST be LOCKED. On startup, restart, crash recovery or unknown state, the door MUST initialise LOCKED.
- **SR-AUTHZ-16.** Unlock MUST be time-bounded with automatic relock. An indefinite unlock MUST NOT be possible.

---

## 4. AI Boundaries — AI MUST NOT Unlock the Door

This section is the project's central security control. It is stated as structure, not as policy.

### 4.1 Absolute prohibitions

- **SR-AI-01.** **No AI component MAY make, alter, override, veto or influence an access decision.** M15, M16, M17 and M18 are advisory and read-only, without exception.
- **SR-AI-02.** **No AI component MAY cause the virtual door to unlock,** directly or transitively through any intermediary.
- **SR-AI-03.** M08 MUST NOT import, reference or depend on any AI library — not `google-generativeai`, `langchain`, `chromadb` or `langgraph`.
- **SR-AI-04.** M08 MUST perform no network I/O of any kind.
- **SR-AI-05.** The AI tier MUST NOT hold a write-capable database session. It receives the read-only facade from M12 only.
- **SR-AI-06.** The AI tier MUST NOT write to `permissions`, `face_embeddings`, `access_events`, `family_members`, `users` or `sessions`. Its only permitted writes are the advisory columns of `incidents` and rows in `workflow_executions`.
- **SR-AI-07.** Gemini MUST be configured **without tools and without function calling**. The model MUST have no mechanism to invoke application code.
- **SR-AI-08.** Model output MUST NOT be interpreted as a command, parsed for actions, or dispatched. It is text destined for storage and display.

### 4.2 How each prohibition is enforced

Policy that is only written down is not enforcement. Each control below is mechanical:

| Control | Mechanism | Verified by |
|---|---|---|
| No AI in the engine | `access_engine.py` imports only stdlib, SQLAlchemy models, project types | **Automated import-graph test asserting no AI package is reachable** — Day 7 |
| No door reference from AI | M15–M18 contain no import of M08 or M09 | Same import-graph test |
| No write capability | Separate read-only session factory is the only handle passed to the AI tier | Unit test asserting writes raise |
| No tool invocation | Gemini client constructed with no tool declarations | Configuration test |
| Output is inert | Responses parsed into a strict Pydantic schema; unparseable output discarded and logged | Schema test with adversarial fixtures |
| Grant authenticity | `AccessDecision` constructible only by M08; M09 asserts `granted is True` plus a valid engine signature | Test attempting a forged decision |
| No unlock route | No HTTP route, scheduler job, or AI path reaches `unlock()` without an engine grant | Route enumeration test |

**SR-AI-09.** These tests MUST exist and MUST pass before any AI module is enabled. They are the Day 7 gate. **None of them has been written or run — no test result is claimed anywhere in this document.**

### 4.3 Prompt-injection containment (T5)

- **SR-AI-10.** All untrusted content entering a prompt — visitor-derived text, filenames, operator notes, OCR output — MUST be clearly delimited and labelled as data, never concatenated into instruction position.
- **SR-AI-11.** Prompt templates MUST be versioned in code, never constructed from database content.
- **SR-AI-12.** The system MUST assume prompt injection will eventually succeed. **A successful injection MUST be survivable**, and it is: because of SR-AI-01 through SR-AI-08, the maximum achievable impact is a misleading incident narrative. The attacker gains no door state change, no permission change and no data write.
- **SR-AI-13.** The attack chain used in narratives MUST be produced deterministically by M15, so the factual record remains correct even when the prose is manipulated.

### 4.4 Advisory labelling

- **SR-AI-14.** Every AI artefact MUST be stored with `is_ai_enriched = 1` and the generating model version.
- **SR-AI-15.** The UI MUST visually mark AI content as advisory and MUST NOT present it as a system decision.
- **SR-AI-16.** AI recommendations MUST require explicit operator action to take effect. Auto-application is prohibited.

### 4.5 The one AI-influenced action that is permitted

- **SR-AI-17.** High-severity detection MAY trigger **lockdown**. This is permitted because lockdown is **deny-side**: it makes the system strictly more restrictive, and under fail-secure principles a spurious lockdown is a safe failure. The inverse — an AI-influenced unlock, or an AI-influenced lockdown *release* — MUST NOT exist.
- **SR-AI-18.** Lockdown release MUST require an authenticated `admin` action and MUST be audited.

---

## 5. Unknown Visitor Privacy

Unknown visitors are people who never consented to biometric processing. Delivery drivers, neighbours, passers-by. Their data demands more restraint than residents', not less.

- **SR-PRIV-01.** An unknown visitor's face vector MUST NOT be written to `face_embeddings`. Enrolment is for consenting members only.
- **SR-PRIV-02.** Visitor grouping MUST use a **transient** cluster key held in memory and discarded on retention expiry. It MUST NOT become a durable biometric identifier.
- **SR-PRIV-03.** Every `visitor_events` row MUST carry `retention_expires_at` at creation. Indefinite retention is prohibited.
- **SR-PRIV-04.** An automated purge job MUST delete expired snapshots and cluster data and MUST stamp `purged_at` as evidence the purge ran. **A privacy promise without a verifiable purge record is not a control.**
- **SR-PRIV-05.** Snapshot capture MUST be minimal: the smallest useful crop, only when a security purpose exists. Continuous recording of all passers-by is prohibited.
- **SR-PRIV-06.** Visitor snapshots MUST be stored outside the web root with restricted filesystem permissions and MUST be served only through an authenticated, authorised, audited route.
- **SR-PRIV-07.** Visitor images and embeddings MUST NOT be sent to Gemini or indexed into ChromaDB. Only de-identified textual summaries may be indexed.
- **SR-PRIV-08.** Notification bodies MUST NOT embed visitor images. They reference an incident id and link into the authenticated UI.
- **SR-PRIV-09.** Promotion of a visitor to a named member MUST be an explicit operator action, MUST be audited, and MUST re-run consented enrollment through M05 rather than silently reusing transient data.
- **SR-PRIV-10.** Retention periods MUST be documented and configurable, with the default favouring the shortest useful window.
- **SR-PRIV-11.** The system MUST support purging all data for a specific visitor cluster on request.

---

## 6. Secure Storage

### 6.1 Biometric data

- **SR-STORE-01.** Only embeddings are persisted for recognition. **Raw enrollment images MUST NOT be retained** after embeddings are extracted. An embedding is not reversible to a photograph, which materially limits leak severity.
- **SR-STORE-02.** Embeddings MUST record `dim`, `dtype`, `model_name` and `model_version`, validated on read, so a model change is detected rather than silently corrupting comparisons.
- **SR-STORE-03.** Embeddings MUST NOT be returned by any API response, logged, included in notifications, exported, or sent to any external service including Gemini.
- **SR-STORE-04.** The database file MUST have owner-only filesystem permissions.
- **SR-STORE-05.** Encryption at rest for the database and evidence directory SHOULD be provided by full-disk or filesystem-level encryption. **v1 does not implement application-level encryption of embeddings; this is a documented residual risk under T7 and MUST NOT be described as mitigated.**

### 6.2 Secrets

- **SR-STORE-06.** JWT signing secret, Gemini API key and SMTP credentials MUST come from environment variables or a secret store. Hardcoded secrets are prohibited.
- **SR-STORE-07.** `.env` MUST be git-ignored. A secret-scanning check SHOULD run before any commit.
- **SR-STORE-08.** Secrets MUST NOT appear in logs, error responses, audit records or AI prompts.
- **SR-STORE-09.** The application MUST refuse to start in production mode with a default or missing signing secret. Failing to boot is better than booting insecurely.

### 6.3 Evidence files

- **SR-STORE-10.** Evidence MUST be stored outside the web root with restricted permissions.
- **SR-STORE-11.** Every evidence file MUST have **SHA-256 computed at capture** and stored in `incident_evidence.sha256`. Integrity MUST be verifiable on retrieval; a mismatch MUST raise a security event.
- **SR-STORE-12.** Evidence filenames MUST be server-generated. Client-supplied paths and filenames are prohibited, closing the path-traversal class.
- **SR-STORE-13.** Evidence retrieval MUST be authenticated, authorised and recorded in `audit_log`.

### 6.4 Input and output handling

- **SR-STORE-14.** All database access MUST use parameterised statements through M12 repositories. String-concatenated SQL is prohibited.
- **SR-STORE-15.** All request bodies, query parameters and path parameters MUST be validated by Pydantic models at the trust boundary.
- **SR-STORE-16.** Uploaded images MUST be validated for type, dimensions and size, and MUST be decoded defensively with explicit limits.
- **SR-STORE-17.** API errors MUST return a generic envelope. Stack traces, SQL text, file paths and library versions MUST NOT reach clients.
- **SR-STORE-18.** Responses MUST set `Content-Type` explicitly and MUST NOT reflect unescaped user input.
- **SR-STORE-19.** CORS MUST use an explicit origin allowlist. Wildcard origins with credentials are prohibited.
- **SR-STORE-20.** TLS MUST terminate in front of the application for any non-loopback deployment.

---

## 7. Audit Logging

### 7.1 What MUST be logged

- **SR-AUDIT-01.** **Every access decision** MUST be recorded in `access_events`, granted or denied, with no exception and no sampling.
- **SR-AUDIT-02.** Each record MUST include the rule number, rule name, reason code, engine version, confidence, threshold in force, resolved identity (or null), source and correlation id. **A decision that cannot be explained from its stored record is a defect.**
- **SR-AUDIT-03.** The following MUST be written to `audit_log` with before/after values: permission create/update/revoke, member create/revoke, enrollment add/remove, threshold or policy change, lockdown enable/release, manual override, role change, login success and failure, evidence view, retention purge.
- **SR-AUDIT-04.** Each audit entry MUST record actor, actor IP, timestamp, action, entity, outcome and correlation id. System actions MUST be attributed to `system` with a null actor rather than left ambiguous.
- **SR-AUDIT-05.** Pipeline stage execution MUST be recorded in `pipeline_logs` for operational traceability.

### 7.2 Integrity of the record

- **SR-AUDIT-06.** `access_events`, `security_events`, `visitor_events`, `pipeline_logs` and `audit_log` MUST be **append-only**. The application MUST expose no update or delete path for them.
- **SR-AUDIT-07.** No API endpoint MUST allow an operator — **including an admin** — to edit or delete an access event or audit entry. This is the primary control against T6, the malicious insider.
- **SR-AUDIT-08.** Retention purges MUST be limited to privacy-scoped data (visitor snapshots, expired evidence, old pipeline logs) and MUST themselves be audited. Security history MUST NOT be auto-purged.
- **SR-AUDIT-09.** Database backups MUST be scheduled so the audit trail survives host loss.

### 7.3 Log hygiene

- **SR-AUDIT-10.** Logs MUST NOT contain passwords, tokens, refresh-token values, API keys, embedding vectors or image data.
- **SR-AUDIT-11.** Logs MUST be structured JSON with a correlation id threading every record of a single event.
- **SR-AUDIT-12.** Timestamps MUST be UTC ISO-8601.
- **SR-AUDIT-13.** Log volume MUST be bounded by rotation so disk exhaustion cannot become a denial of service.

---

## 8. Requirement-to-Threat Coverage

| Threat | Controls | Residual risk |
|---|---|---|
| T1 Opportunistic intruder | SR-AUTHZ-06/08/09, SR-AUTH-15 | Low |
| T2 **Presentation attack** | SR-AUTH-16/17/18 | **HIGH — no liveness detection in v1** |
| T3 Network attacker | SR-AUTH-06/09, SR-AUTHZ-01/04, SR-STORE-14/15/20 | Medium until tested |
| T4 Credential attacker | SR-AUTH-02/11/12/13, SR-AUTHZ-03 | Low-medium; MFA not in v1 |
| T5 **Prompt injection** | SR-AI-01…18 | **LOW by construction** — AI has no mechanism to act |
| T6 Malicious insider | SR-AUDIT-03/06/07, SR-AUTHZ-12 | Medium — admin can still grant a real permission, but cannot do so invisibly |
| T7 Device theft | SR-STORE-01/04/05 | **Medium-high — no application-level encryption at rest in v1** |

### 8.1 Honest statement of residual risk

Three risks are **not** mitigated in v1 and are recorded here rather than glossed over:

1. **No liveness detection (T2).** A printed photo or phone screen may defeat face matching. This is the most serious open gap in the access path.
2. **No application-level encryption at rest (T7).** Physical possession of the host may yield the embedding database.
3. **No MFA for operators (T4).** Password plus lockout is the only barrier to an admin account.

None of these is caused by the AI tier, and none is made worse by it — which is the point of §4.

---

## 9. Verification Plan (Day 7)

These are the checks that must pass. **None has been written or executed. No test result is reported in this document, and none may be claimed until recorded command output exists.**

| # | Check | Requirement |
|---|---|---|
| V1 | AccessEngine rule matrix — every rule, every boundary, exhaustive | SR-AUTHZ-07/08/09 |
| V2 | **Import-graph test: no AI package reachable from M08** | SR-AI-03 |
| V3 | **Import-graph test: M15–M18 cannot reach M08 or M09** | SR-AI-02 |
| V4 | Forged `AccessDecision` rejected by M09 | §4.2 grant authenticity |
| V5 | Route enumeration: no unauthenticated or unlock-capable route | SR-AUTHZ-01, SR-AI-02 |
| V6 | AI tier write attempt raises on the read-only session | SR-AI-05/06 |
| V7 | Adversarial Gemini fixtures produce no action | SR-AI-08/12 |
| V8 | Fail-secure matrix: every failure yields DENY | SR-AUTHZ-13/14 |
| V9 | IDOR probes across every object endpoint | SR-AUTHZ-04 |
| V10 | Refresh-token reuse revokes the session family | SR-AUTH-08 |
| V11 | Audit completeness: every decision produces a row | SR-AUDIT-01 |
| V12 | Append-only enforcement: no update/delete path exists | SR-AUDIT-06/07 |
| V13 | Visitor purge runs and stamps `purged_at` | SR-PRIV-04 |
| V14 | No embedding or secret appears in any log or response | SR-STORE-03, SR-AUDIT-10 |
| V15 | Path traversal rejected on evidence retrieval | SR-STORE-12 |

**V2, V3, V4 and V5 are the gate.** If any of them fails, the AI tier MUST remain disabled, because without them the claim "AI cannot unlock the door" is unproven.

---

## 10. Summary

The system's security rests on a single structural decision: **the deterministic Python AccessEngine is the only access decision authority, and the AI tier has no mechanism — no import, no session, no tool, no route — to reach the door.**

Everything else in this document hardens the surfaces around that core. The core itself is pure, offline, exhaustively testable Python, which is why it is built first and why it is the one security-critical component that can be fully verified in the current constrained environment.
