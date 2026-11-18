# GitHub Reuse Audit

**Project:** AI-Powered Smart Home Security and Automated Access Management System
**Date:** 2026-11-14
**Requested by:** project owner ("GitHub code reuse" instruction)

---

## 1. Result

**None of the four repositories could be cloned. No source file, LICENSE file or
dependency manifest was read directly. Zero lines of third-party code were
copied into the project.**

Everything in sections 3–5 comes from web-search metadata (titles and short
snippets). It is enough to plan reuse and flag risks. It is **not** enough to
copy code: the project's licence policy (`PROJECT_AUDIT.md` §5.4) and the
owner's instruction both require the licence to be read first.

---

## 2. Clone attempts (exact results)

Target directory: `external_references/`. It was created for the clones and
removed again because it stayed empty. The backend and documentation were not
touched.

| Repository | Command | Exit | Exact error |
|---|---|---|---|
| sergenp/fastapi-starter-template | `git clone --depth 1 https://github.com/sergenp/fastapi-starter-template.git` | 128 | `remote: No user principal found for this instance` / `fatal: repository 'https://us-east-1.gateway.connections.autonomous-agents.kiro.dev/github/sergenp/fastapi-starter-template.git/' not found` |
| fastapi/full-stack-fastapi-template | same form | 128 | same two lines, for this repository |
| langchain-ai/langgraph | same form | 128 | same two lines, for this repository |
| deepinsight/insightface | same form | 128 | same two lines, for this repository |

### Why it fails

1. The sandbox's global git config rewrites `https://github.com/` to the Kiro
   connections gateway (`url.<gateway>/github/.insteadof https://github.com/`).
   The gateway serves only repositories authorised to the Kiro GitHub app for a
   connected user. No GitHub account is connected, hence "No user principal
   found". Kiro's documentation describes access only to repositories granted
   to the Kiro app, not arbitrary public repositories.
2. With the rewrite disabled (`GIT_CONFIG_GLOBAL=/dev/null`), git goes straight
   to github.com and fails with `CONNECT tunnel failed, response 403`. The
   sandbox network mode is `INTEGRATIONS_ONLY` ("Connections access only").
3. Host-side fetches of `raw.githubusercontent.com/.../LICENSE` return
   `HTTP 403: Forbidden`.

### What would make cloning work

- A **new session** created after Internet Access is set to **Common
  dependencies**. Kiro documents that level's allow-list as including
  `github.com` and `githubusercontent.com`. This sandbox has run continuously
  since 12:24:47 UTC, before the setting was changed, so it never received it.
  It is not documented whether the gateway rewrite still applies at that level;
  this must be checked in the new sandbox.
- Possibly: fork the repositories into an account where the Kiro GitHub app is
  installed. This is an inference from the docs, not a documented workflow.

Source: [Kiro internet access](https://kiro.dev/docs/web/sandbox/internet-access.md),
[Kiro GitHub](https://kiro.dev/docs/web/github.md),
[Kiro sandbox](https://kiro.dev/docs/web/sandbox.md).
*Content was rephrased for compliance with licensing restrictions.*

---

## 3. Per-repository findings

Legend: **Verified** = read directly (nothing qualifies). **Reported** = stated
by a search result, not checked against the repository.

### R1 — sergenp/fastapi-starter-template

| Field | Finding |
|---|---|
| URL | https://github.com/sergenp/fastapi-starter-template |
| Exists | **Reported only**: listed on the owner's GitHub profile ([profile](https://github.com/sergenp)) |
| README / LICENSE / pyproject | **Not obtained** |
| Licence | **Unknown** |
| Useful modules | Unknown |
| Dependencies / compatibility | Unknown |
| Security concerns | Cannot be assessed |
| Useful tests | Unknown |
| Files proposed for reuse | **None** — licence unknown |
| Files not to reuse | All, until the licence is read |

### R2 — fastapi/full-stack-fastapi-template

| Field | Finding |
|---|---|
| URL | https://github.com/fastapi/full-stack-fastapi-template |
| Licence | **Not verified.** The LICENSE fetch returned 403 and no search result stated it |
| Stack (reported) | FastAPI, React, SQLModel, PostgreSQL, Vite, Tailwind, Docker Compose ([repo](https://github.com/fastapi/full-stack-fastapi-template)) |
| Dependencies (reported) | Backend `pyproject.toml` requires `fastapi[standard]` at a recent version ([pyproject](https://github.com/fastapi/full-stack-fastapi-template/blob/master/backend/pyproject.toml)); full list not obtained |
| Password hashing (reported) | Release notes say it moved to `pwdlib` with Argon2 by default and upgrades old bcrypt hashes on login ([releases](https://github.com/fastapi/full-stack-fastapi-template/releases)) |
| Useful ideas | (a) Upgrading hashes on login — **already implemented here** via `security.needs_rehash()`. (b) An env-configured first superuser created at startup — one option for this project's open "admin bootstrap" decision |
| Compatibility | **Low for code.** SQLModel and PostgreSQL vs this project's SQLAlchemy 2.0 and SQLite. `pwdlib` vs the approved `argon2-cffi`. Its React frontend is out of scope until Day 14 |
| Security concerns | A 2024 discussion raised concerns about `python-jose` being unmaintained ([discussion](https://github.com/fastapi/full-stack-fastapi-template/discussions/1188)). This project already uses PyJWT. Whether the template still uses python-jose is not known |
| Useful tests | Not inspected |
| Files proposed for reuse | **None now.** After the licence is verified, the candidates are its auth tests and first-superuser setup, as **patterns** rewritten for SQLAlchemy and argon2-cffi |
| Files not to reuse | `frontend/` (Day 14 rule), SQLModel models, PostgreSQL and Docker config, password hashing (would replace the approved argon2-cffi) |

### R3 — langchain-ai/langgraph

| Field | Finding |
|---|---|
| URL | https://github.com/langchain-ai/langgraph |
| Licence | **Reported MIT.** GitHub's licence summary describes a short permissive licence that only requires keeping copyright and licence notices ([LICENSE page](https://github.com/langchain-ai/langgraph/blob/main/LICENSE)). The text itself was not read |
| Model / dataset licensing | Not applicable: a framework, no bundled models |
| Dependencies | Not obtained. A LangChain project template targets Python ≥ 3.10 ([template](https://github.com/langchain-ai/new-langgraph-project/blob/main/pyproject.toml)), which is compatible with 3.11 here. LangGraph's own pins were not read |
| Useful modules | State-graph builder, conditional edges, checkpointing (M18 design) |
| Compatibility | Good, as a **pip dependency**. Vendoring its source is unnecessary and would make security patching harder |
| **Security concerns** | Three deserialization advisories affect the checkpointing M18 plans to use (see table below) |
| Useful tests | Not inspected |
| Files proposed for reuse | **None to copy.** Install the package on Day 11 with patched minimum versions |
| Files not to reuse | Prebuilt agent and tool-calling helpers: they contradict SR-AI-07 (no tools or function calling). Node caching (`CachePolicy` / `BaseCache`): affected by CVE-2026-27794 |

**LangGraph advisories relevant to Day 11:**

| Advisory | Component | Issue (paraphrased) | Fixed in |
|---|---|---|---|
| [CVE-2025-64439 / GHSA-wwqv-p2pp-99h5](https://github.com/langchain-ai/langgraph/security/advisories/GHSA-wwqv-p2pp-99h5) | `langgraph-checkpoint`, JsonPlusSerializer "json" mode | Remote code execution when deserializing saved payloads | `langgraph-checkpoint` 3.0 |
| [CVE-2026-27794 / GHSA-mhr3-j7m5-c7c9](https://github.com/advisories/GHSA-mhr3-j7m5-c7c9) | Caching layer (`BaseCache`, `CachePolicy`) | Remote code execution from cached data | `langgraph-checkpoint` 4.0 |
| [CVE-2026-48775 / GHSA-fjqc-hq36-qh5p](https://github.com/advisories/GHSA-fjqc-hq36-qh5p) | `langgraph-checkpoint-sqlite` | Code execution at load time if checkpoint bytes at rest are modified | Reported as fixed after 4.1.0 ([SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2026-48775/)); exact version to be confirmed |

The third advisory matters most here: M18 planned SQLite checkpointing. Day 11
requirements that follow from it:

1. Pin `langgraph-checkpoint` and `langgraph-checkpoint-sqlite` at or above
   the fixed versions, confirmed against PyPI on the day.
2. Keep checkpoints in a **separate database file** that only the orchestrator
   writes. Never put them in `smarthome.db`.
3. Do not enable node caching.
4. Treat checkpoint data as untrusted on load. A tampered checkpoint must not
   be able to reach the AccessEngine or the door, which the AI containment
   design already ensures (SR-AI-01…08).

*Content was rephrased for compliance with licensing restrictions.*

### R4 — deepinsight/insightface

| Field | Finding |
|---|---|
| URL | https://github.com/deepinsight/insightface |
| Code licence | **Reported MIT** for the Python library, academic and commercial use ([python-package](https://github.com/deepinsight/insightface/blob/master/python-package), [PyPI](https://pypi.org/project/insightface/)) |
| **Model licence (separate)** | **Reported non-commercial research only** for the pretrained models, whether downloaded automatically or manually ([python-package](https://github.com/deepinsight/insightface/blob/master/python-package), [model zoo](https://github.com/deepinsight/insightface/blob/master/model_zoo/README.md)). The README directs licensing questions about recognition packs such as `buffalo_l` to the InsightFace team ([README](https://github.com/deepinsight/insightface/blob/master/README.md)) |
| Newer releases (reported) | An "InsightFace 1.0" and new model packs are mentioned ([repo](https://github.com/deepinsight/insightface)). Their licences are unknown |
| Dependencies | Not obtained. Expected: `onnxruntime`, `numpy`, `opencv-python` |
| Useful modules | `FaceAnalysis` (detection + alignment + 512-D embedding) behind the M04–M06 recogniser interface |
| Compatibility | Code: yes, as a pip dependency. Models: **depends on whether this project is commercial** |
| Security concerns | Model files are downloaded at runtime by default. They must be pinned by checksum and stored locally, never fetched silently |
| Useful tests | Not inspected |
| Files proposed for reuse | **None to copy.** Use the pip package through an adapter, once the model licence question is answered |
| Files not to reuse | Training code, model zoo weights (until licensed), any GUI or demo apps |

*Content was rephrased for compliance with licensing restrictions.*

---

## 4. Licence-safe alternative for Day 3 (needs owner decision)

Search results report that OpenCV Zoo's **YuNet** face detector is MIT and its
**SFace** face recognizer is Apache-2.0, with no non-commercial restriction
([HF OpenCV Zoo SFace licence](https://huggingface.co/opencv/opencv_zoo/blob/main/models/face_recognition_sface/LICENSE),
[summary](https://huggingface.co/cstr/sface-GGUF)). Both run on OpenCV's
built-in DNN module, and OpenCV is already in the approved stack.

| | InsightFace `buffalo_l` | OpenCV YuNet + SFace |
|---|---|---|
| Model licence | Non-commercial research (reported) | MIT / Apache-2.0 (reported) |
| Extra runtime | `onnxruntime` | None beyond OpenCV |
| Embedding size | 512-D | **128-D** (reported) |
| Accuracy | Higher (expected, unmeasured here) | Lower (expected, unmeasured here) |
| Approved stack change | None | **Yes**: replaces InsightFace |

The schema already stores `dim` and `model_version` per embedding and the codec
takes `dim` as a parameter, so either choice fits the database design.
**Switching would change the approved stack, so it has not been done.**

*Content was rephrased for compliance with licensing restrictions.*

---

## 5. Reuse decision

| Repository | Cloned | LICENSE read | Code copied | Decision |
|---|---|---|---|---|
| sergenp/fastapi-starter-template | No | No | **0 lines** | Blocked: licence unknown |
| fastapi/full-stack-fastapi-template | No | No | **0 lines** | Patterns only; re-check after cloning |
| langchain-ai/langgraph | No | No | **0 lines** | Install as a dependency on Day 11, patched versions |
| deepinsight/insightface | No | No | **0 lines** | Install as a dependency on Day 3 if the model licence fits; otherwise see §4 |

No `THIRD_PARTY_NOTICES.md` was created because no third-party file entered the
project.

### Conditions before any code is copied

1. The repository is cloned and its LICENSE is read and recorded here.
2. The licence is permissive (MIT, BSD, Apache-2.0). GPL/AGPL code is not linked.
3. Copied files keep their copyright header, and `THIRD_PARTY_NOTICES.md` lists
   the source, commit and licence.
4. Copied code is adapted to the approved stack: synchronous SQLAlchemy 2.0,
   SQLite, argon2-cffi, PyJWT, and the existing auth/session design.
5. Nothing copied may bypass the AccessEngine, unlock the door, give the AI tier
   write access, or auto-enrol unknown visitors.
