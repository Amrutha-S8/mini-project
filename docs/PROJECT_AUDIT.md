# PROJECT AUDIT — Day 1

**Project:** AI-Powered Smart Home Security and Automated Access Management System
**Audit date:** 2026-11-14
**Audit scope:** Workspace baseline, environment capability, GitHub access, open-source reuse assessment
**Auditor:** Kiro (Day 1 architecture and audit phase)

---

## 1. Executive Summary

| Question | Finding |
|---|---|
| Does project code exist in the workspace? | **No.** The workspace is an empty baseline. |
| Is a project GitHub repository available? | **No.** No repository was provided to this session, and GitHub authentication is failing. |
| Can reference repositories be cloned or read? | **No.** Sandbox has no outbound internet. |
| Was any third-party code downloaded? | **No. Nothing was downloaded.** |
| Is Day 1 (design + audit) achievable in this environment? | **Yes.** Day 1 is documentation-only and requires no network. |
| Is Day 2 (backend + DB) achievable in this environment? | **Blocked pending dependency access.** See §6. |

---

## 2. Workspace Baseline Audit

### 2.1 Observed state

Full recursive inspection of `/projects/sandbox/` at session start returned:

```
/projects/sandbox
/projects/sandbox/.kiro
/projects/sandbox/.kiro/settings/permissions.yaml
/projects/sandbox/.kiro/settings/permissions.json
```

### 2.2 Baseline classification

**The workspace is an EMPTY BASELINE.** This is formally recorded, not inferred.

- Zero application source files.
- Zero Python packages, modules, or entry points.
- Zero frontend scaffolding (`package.json` absent).
- Zero dependency manifests (`requirements.txt`, `pyproject.toml`, `poetry.lock` absent).
- Zero database files or migrations.
- Zero tests.
- Zero CI configuration.
- Zero git repository (`.git` absent — the workspace is not under version control).
- The only pre-existing files are Kiro sandbox permission settings, which are **environment configuration, not project work**.

### 2.3 Preservation statement

No pre-existing file was read-modified, moved, renamed, or deleted. The two `.kiro/settings/` files are untouched. All files produced in Day 1 are **new files at previously unoccupied paths**. No overwrite occurred because no target path was occupied.

---

## 3. Feature Status Classification

Classification is applied against the 20 modules defined in `MODULE_DESIGN.md`. Because the workspace is empty, every feature classifies as **MISSING**. The categories *completed*, *partial*, *broken* and *untested* are retained in the table to show they were evaluated and found to have zero members — this is an audit result, not an omission.

| # | Module | Status | Evidence |
|---|---|---|---|
| M01 | Auth & Session | MISSING | No source file exists |
| M02 | Identity Registry (users / family members) | MISSING | No source file exists |
| M03 | Camera Capture & Frame Ingest | MISSING | No source file exists |
| M04 | Face Detection & Alignment | MISSING | No source file exists |
| M05 | Face Embedding & Enrollment | MISSING | No source file exists |
| M06 | Face Matching & Identification | MISSING | No source file exists |
| M07 | Permission & Policy Store | MISSING | No source file exists |
| M08 | **AccessEngine** (decision authority) | MISSING | No source file exists |
| M09 | Virtual Door Controller | MISSING | No source file exists |
| M10 | Visitor Monitoring | MISSING | No source file exists |
| M11 | Event Pipeline | MISSING | No source file exists |
| M12 | Persistence & Repository Layer | MISSING | No source file exists |
| M13 | Security Event Detection | MISSING | No source file exists |
| M14 | Incident Manager & Evidence Store | MISSING | No source file exists |
| M15 | Attack Chain Reconstruction | MISSING | No source file exists |
| M16 | Gemini Gateway | MISSING | No source file exists |
| M17 | RAG Knowledge Service | MISSING | No source file exists |
| M18 | LangGraph Orchestrator | MISSING | No source file exists |
| M19 | Automation Scheduler | MISSING | No source file exists |
| M20 | Notification Service | MISSING | No source file exists |
| — | React Frontend (client surface, Day 14) | MISSING | No source file exists |

**Totals:** Completed 0 · Partial 0 · Missing 21 · Broken 0 · Untested 0

### 3.1 Test status

**No tests were executed and no test results are reported.** There is no code to test and no test runner configured. Any future claim of passing tests must be backed by recorded command output.

---

## 4. GitHub Access Audit

### 4.1 Authentication check

`gh auth status` reports an active account against the Kiro connection gateway but **rejects the supplied token**:

- The token in `GH_ENTERPRISE_TOKEN` is reported invalid.
- `gh api user` fails with **HTTP 404 — "No user principal found for this instance"**.
- `gh api user/repos` fails with the same error.

**Conclusion: GitHub API access is unauthenticated and non-functional in this session.**

### 4.2 Project repository availability

- No `<repositories>` entry was supplied to this session, so no repository was pre-fetched.
- No repository exists on disk.
- Repository listing cannot be performed because the API rejects authentication.

**Conclusion: the project repository is NOT available.** Whether one exists elsewhere cannot be determined from this environment.

**No repository URL has been invented or assumed.** To connect a repository, the owner must supply the exact `owner/repo` and a working credential.

### 4.3 Push status

**Nothing has been committed and nothing has been pushed.** The workspace is not even a git repository. Initialising git, committing, branching and pushing are all deferred until the owner approves and supplies a repository target.

---

## 5. Open-Source Code Reuse Assessment (Task 2)

### 5.1 Inspection method and its limits — read this first

**Direct inspection was impossible.** Three independent access paths were tested and all failed:

| Access path | Result |
|---|---|
| `git clone` / `curl https://github.com/...` from sandbox | **Failed** — HTTP 000, connection refused by sandbox egress policy |
| `gh api repos/{owner}/{repo}` | **Failed** — HTTP 404, invalid token |
| Host-side page fetch of repo URLs | **Failed** — HTTP 403 Forbidden |
| Host-side **web search** (metadata only) | **Partially succeeded** |

Therefore the assessment below rests on **search-result metadata only**. For every repository:

- **No source file was read.**
- **No `LICENSE` file was read.**
- **No dependency manifest (`requirements.txt` / `pyproject.toml` / `package.json`) was read.**
- **No code was downloaded, copied, vendored, or adapted.**
- No file list, line count, or commit history was obtained.

Statements marked *unverified* are search-derived claims that **must be re-checked against the actual repository before any code is reused.** Licence conclusions in particular are not legally reliable until the `LICENSE` file is read directly.

### 5.2 Per-repository findings

#### R1 — `deepinsight/insightface`

| Field | Finding |
|---|---|
| Intended role | Face detection + 512-D face embeddings (modules M04–M06) |
| Source tree inspected | **NO** |
| Licence verified by reading `LICENSE` | **NO** |
| Licence (search-derived, unverified) | **Split licence.** Repository documentation states the InsightFace *code* and the Python library are released under MIT with no restriction on academic or commercial use. Separate licensing notes state the pre-trained *model packages* and model-zoo weights are for non-commercial academic research only, with commercial licensing directed to insightface.ai. Sources: [insightface README](https://github.com/deepinsight/insightface/blob/master/README.md), [python-package README](https://github.com/deepinsight/insightface/blob/master/python-package/README.md), [server/LICENSING.md](https://github.com/deepinsight/insightface/blob/master/server/LICENSING.md), [model_zoo README](https://github.com/deepinsight/insightface/blob/master/model_zoo/README.md). *Content was rephrased for compliance with licensing restrictions.* |
| Dependencies (unverified) | Expected `insightface`, `onnxruntime`, `numpy`, `opencv-python`. Not confirmed from a manifest. |
| Useful source files | **Not determined** — tree not inspected. |
| **Adaptation requirement** | **Consume as an installed pip package via a thin adapter. Do not vendor source.** All InsightFace calls are confined behind the M05/M06 interface so the model provider can be swapped. |
| **Blocking action before use** | Read the repository `LICENSE` plus the model-zoo licence terms directly, and confirm the licence of the specific model pack used (e.g. `buffalo_l`). The code/model licence split is the critical risk: a permissive code licence does **not** imply the weights are permissive. If this project is ever non-academic, the model weights may require a commercial licence. |
| Risk | **HIGH (licence)** — unresolved model-weight terms. **MEDIUM (technical)** — large model download and ONNX runtime needed, both currently blocked. |

#### R2 — `gaganpreet/fastapi-starter`

| Field | Finding |
|---|---|
| Intended role | FastAPI project layout, settings, auth scaffolding, test harness patterns |
| Repository existence | **Confirmed to exist** via search |
| Source tree inspected | **NO** |
| Licence | **NOT DETERMINED.** No licence information was obtained from any source. |
| Description (search-derived, unverified) | A low-code FastAPI starter/boilerplate using async SQLAlchemy 2.0, Postgres, React-Admin, pytest and cypress. Source: [gaganpreet/fastapi-starter](https://github.com/gaganpreet/fastapi-starter). *Content was rephrased for compliance with licensing restrictions.* |
| Dependencies | **Not determined** — no manifest read. |
| Useful source files | **Not determined** — tree not inspected. |
| **Adaptation requirement** | **Reference for patterns only; do not copy files.** Two concrete mismatches against our architecture: it targets **Postgres** whereas we are committed to **SQLite**, and it bundles **React-Admin** whereas we build a custom React UI. Async SQLAlchemy patterns would need SQLite-specific adjustment (single-writer behaviour, `aiosqlite` driver, WAL mode, no Postgres-only types). |
| **Blocking action before use** | Read `LICENSE` and `pyproject.toml` directly. Treat as unusable until the licence is confirmed permissive. |
| Risk | **MEDIUM (licence unknown)**, **MEDIUM (stack mismatch)** |

#### R3 — `arttuladhar/gemini-rag-example`

| Field | Finding |
|---|---|
| Intended role | Gemini + RAG wiring reference (modules M16–M17) |
| Repository existence | **NOT VERIFIED.** Search surfaced the user profile `arttuladhar` but did not return this repository. It may be private, renamed, or deleted. |
| Source tree inspected | **NO** |
| Licence | **NOT DETERMINED** |
| Dependencies | **Not determined** |
| Useful source files | **Not determined** |
| **Adaptation requirement** | Cannot be assessed. |
| **Status** | **NOT INSPECTED — existence unconfirmed.** Do not plan any dependency on this repository. Owner should confirm the correct URL. |
| Risk | **UNASSESSABLE** |

#### R4 — `imirghania/rag_langgraph`

| Field | Finding |
|---|---|
| Intended role | LangGraph-driven RAG workflow reference (modules M17–M18) |
| Repository existence | **NOT VERIFIED.** Search returned other LangGraph-RAG projects but not this one. |
| Source tree inspected | **NO** |
| Licence | **NOT DETERMINED** |
| Dependencies | **Not determined** |
| Useful source files | **Not determined** |
| **Adaptation requirement** | Cannot be assessed. |
| **Status** | **NOT INSPECTED — existence unconfirmed.** Owner should confirm the correct URL. |
| Risk | **UNASSESSABLE** |

#### R5 — `borhanst/fastapi-admin-kit`

| Field | Finding |
|---|---|
| Intended role | Admin CRUD, RBAC and audit-log patterns (modules M01, M07, M20 and the audit trail) |
| Repository existence | **Confirmed to exist** via search |
| Source tree inspected | **NO** |
| Licence | **NOT DETERMINED.** Search surfaced Apache-2.0 for the *unrelated* `fastapi-admin/fastapi-admin` project; that finding **does not transfer** to this repository and must not be assumed. |
| Description (search-derived, unverified) | A zero-config, drop-in admin panel for FastAPI with SQLAlchemy/SQLModel, offering auto-discovered CRUD, role-based access control, audit logging and a Tailwind/HTMX interface, in the spirit of Django Admin. Source: [borhanst/fastapi-admin-kit](https://github.com/borhanst/fastapi-admin-kit). *Content was rephrased for compliance with licensing restrictions.* |
| Dependencies | **Not determined** |
| Useful source files | **Not determined** |
| **Adaptation requirement** | **Conceptual reference only.** Its Tailwind/HTMX server-rendered UI conflicts with our React SPA, so the UI layer is not reusable. Its RBAC and audit-log *data shapes* are the interesting part and are worth comparing against our `permissions` and `audit_log` designs. Critically, **no auto-generated CRUD may ever expose write access to `permissions`, `face_embeddings`, or any access-decision table**, since that would create a second path to authorisation outside the AccessEngine (see `SECURITY_REQUIREMENTS.md` §4). |
| **Blocking action before use** | Read `LICENSE` directly; assess project maturity (described as early stage). |
| Risk | **MEDIUM (licence unknown)**, **HIGH (security)** if auto-CRUD were pointed at access-control tables |

### 5.3 Reuse decision summary

| Repo | Inspected | Licence verified | Code taken | Day-1 verdict |
|---|---|---|---|---|
| deepinsight/insightface | No | No | **None** | Planned as pip dependency behind an adapter; licence must be cleared first |
| gaganpreet/fastapi-starter | No | No | **None** | Pattern reference only; blocked on licence |
| arttuladhar/gemini-rag-example | **No — not inspected** | No | **None** | Cannot plan around it; URL unconfirmed |
| imirghania/rag_langgraph | **No — not inspected** | No | **None** | Cannot plan around it; URL unconfirmed |
| borhanst/fastapi-admin-kit | No | No | **None** | Concept reference only; blocked on licence |

**Net reuse achieved on Day 1: zero lines of third-party code.** The Day 2+ plan is therefore written to stand on its own, using only mainstream pip packages, with these repositories as optional accelerators once access and licences are cleared.

### 5.4 Licence policy for this project

1. No third-party source enters the repository until its `LICENSE` has been read directly and recorded in this document.
2. Copyleft licences (GPL/AGPL) are rejected for linked code.
3. Any vendored file retains its original copyright header and is logged in a `THIRD_PARTY_NOTICES.md` created when the first such file is added.
4. Model weights are licensed separately from code and are assessed separately. This is the specific trap in R1.

---

## 6. Environment Limitations (Recorded Blockers)

| ID | Limitation | Evidence | Impact | Blocks |
|---|---|---|---|---|
| **E1** | **No outbound internet.** Sandbox network mode is `INTEGRATIONS_ONLY`. | `curl` to github.com, api.github.com and pypi.org all returned HTTP 000; DNS resolves but connections are refused | `pip install` and `npm install` cannot run. No dependency can be installed. | Day 2 onward |
| **E2** | **GitHub authentication invalid.** | `GH_ENTERPRISE_TOKEN` rejected; `gh api user` → HTTP 404 | No repo read, clone, commit-push or PR | Version control for all days |
| **E3** | **No project repository supplied.** | No `<repositories>` entry; no `.git` on disk | Work is local-only and unbacked | All days |
| **E4** | **Host page-fetch blocked (HTTP 403).** | `web_fetch` of GitHub URLs returned 403 | Licences and manifests cannot be read even host-side | Task 2 verification |
| **E5** | **No webcam / video capture device.** | Headless container; no `/dev/video*` expected | Live OpenCV capture cannot be exercised | Day 3, Day 5 |
| **E6** | **No InsightFace model weights present, and they cannot be downloaded (see E1).** | Empty workspace + no network | Real face recognition cannot run | Day 3 |
| **E7** | **No Gemini API key and no reachable Gemini endpoint.** | No credential in environment; E1 blocks egress | Live LLM calls impossible | Days 9–11 |
| **E8** | **No GPU.** | Standard sandbox container | Face inference will be CPU-only and slower | Day 3 performance targets |

### 6.1 Mitigations designed into the architecture

E1, E5, E6 and E7 are environment facts, not design faults, so the architecture absorbs them:

- **M03 Camera Capture** is written against a frame-source interface with a file/synthetic-frame driver, so the pipeline runs without a webcam.
- **M05/M06** sit behind a recognizer interface with a deterministic stub recognizer, so access logic is fully testable without model weights.
- **M16 Gemini Gateway** has an offline/mock mode, so Days 9–11 can be built and unit-tested without a key.
- **M08 AccessEngine is pure Python with no network and no model dependency**, so the single most security-critical module is **fully implementable and testable in this environment today.**

### 6.2 What the owner must supply to unblock

1. Network egress to PyPI and npm, **or** a pre-populated dependency cache.
2. A valid GitHub credential plus the exact `owner/repo`.
3. A Gemini API key (needed from Day 9, not before).
4. Sample face images and video clips to substitute for a live webcam.

---

## 7. Audit Conclusions

1. The workspace is a **verified empty baseline**; Day 1 starts from zero with nothing to preserve beyond sandbox settings.
2. **No GitHub repository is available** and authentication is broken. No URL was invented. Nothing was pushed.
3. **No reference repository was inspected and no code was downloaded.** Two of the five could not even be confirmed to exist.
4. **No licence has been verified by reading a `LICENSE` file.** Every licence statement here is search-derived and provisional.
5. **No tests were run and no test results are claimed.**
6. Eight environment blockers are recorded. None of them block Day 1. Several block Day 2 onward and need owner action.
7. The architecture deliberately isolates the deterministic AccessEngine from every blocked dependency, so the system's security core can be built first and verified without network, camera, model or LLM.
