# AI Privacy Policy — what may be sent to Gemini

**Status:** owner-approved 2026-11-15 (DD-10). Implemented and tested in
`backend/app/ai/core/privacy.py` and `backend/tests/test_ai_privacy.py`.
Gemini itself is **not connected** and stays disabled (`GEMINI_ENABLED=false`,
no gate checks recorded).

## 1. Default

Household data stays in the house. Gemini may receive only:

- general project documentation,
- public technical information,
- non-sensitive security policies,

and only when the item is marked `public` and contains no credentials,
biometric payloads or evidence references.

## 2. Never sent, under any exception

| Category | How it is stopped |
|---|---|
| Face images, biometric data, embeddings | Not an indexable record kind; image data URIs, base64 blobs and number vectors are refused by content scan |
| Visitor identities and private visitor history | `visitor_history` kind never shareable |
| Raw access logs | `access_record` kind never shareable |
| Raw security events | `security_event` kind never shareable |
| Attack-chain records, member records | `attack_chain`, `member_record` kinds never shareable |
| Incident evidence | Not an indexable kind; evidence paths refused by content scan |
| Credentials and tokens | Refused by content scan (JWTs, bearer tokens, API keys, password assignments, password hashes, private keys) |
| Personal household information | Household-term list (member names, door and camera ids) matched locally; emails, phone numbers, IP and MAC addresses in a question are refused |

## 3. Rules

1. **Source class decides first, content second.** A record's kind and
   sensitivity decide whether it can leave at all. A clean content scan is a
   necessary condition, never a sufficient one.
2. **Redaction is not anonymity.** A sanitised household record is still
   household data and is still refused.
3. **Reject before the adapter.** `GeminiPrivacyPolicy.approve` raises
   `PrivacyViolation` listing every problem. Only it can create an
   `ApprovedGeminiPayload`, which carries an HMAC seal over its exact content
   (per-process key). Hand-built or edited payloads fail `verify_approved`.
   Prompts for Gemini are built only from approved payloads
   (`prompt_safety.prompt_for_payload`).
4. **Only one route may use Gemini:** `general_knowledge`
   (`routing.GEMINI_ELIGIBLE_ROUTES`). Visitor history, incident analysis,
   security reports, monitoring and escalation are answered by local,
   deterministic rules.
5. **Limits:** at most 20 items, 30,000 characters of context and a
   2,000-character question per request.

## 4. Exceptions (documented allowlist)

Any future exception needs explicit owner approval and an entry in the table
below before it may be configured. Requirements enforced in code
(`EgressException.problems`):

- only `security_summary` or `incident_report` kinds;
- an explicit list of allowed fields, none of which may identify a person,
  place, device or evidence (names, members, users, visitors, emails, phones,
  IPs, addresses, cameras, doors, evidence, images, faces, embeddings,
  sessions, tokens, keys, ids);
- an approving user id, a justification of at least 20 characters, an
  approval time and an expiry;
- excepted items carry only those fields, no free text, and **any** finding
  in a value (even an email-shaped string) refuses the item.

| Exception id | Kind | Allowed fields | Approved by | Approved | Expires | Justification |
|---|---|---|---|---|---|---|
| *(none)* | | | | | | |

No exception exists in code or configuration today; a test asserts this.

## 5. Known limits

- Pattern detection cannot recognise every name or household detail. The
  household-term list must be maintained from the member and device tables
  when the Gemini adapter is built.
- The seal key is per process. It protects against accidental bypass inside
  the application, not against code that deliberately imports private
  helpers.
- Nothing here has been run against the real Gemini API.
