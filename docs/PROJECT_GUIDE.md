# GuardX Project Guide

**Audience:** engineers, reviewers, operators, and interviewers
**Project:** GuardX — a multi-agent AI safety and guardrail gateway
**Guide revision:** 7 October 2026

This guide explains the implementation currently in this repository. It is intended to help a new team member understand the system and to provide a factual interview-preparation guide. It describes current behavior, including prototype limitations; it does not promise perfect detection or production readiness.

## 1. GuardX in one page

GuardX is a Python web service that sits between an application and an LLM or agent. The caller submits text before it is sent to a model (`input`), after a model returns it (`output`), or before a tool/action is executed (`action`). GuardX runs local detectors and policy agents, optionally asks a local Ollama model for a semantic opinion, combines the signals, and returns one of four decisions:

| Decision | Meaning to an integrator |
|---|---|
| `ALLOW` | No configured control raised a decision. Continue according to the caller's own policy. |
| `MODIFY` | A safe replacement is available. Continue only with `sanitized_content`; never forward the original. |
| `BLOCK` | Do not deliver the content or execute the action. |
| `HUMAN_REVIEW` | Hold the request for a person or an explicitly designed approval workflow. |

It is a **modular monolith**: one FastAPI application, several independent detector/agent modules, and one relational database. It is not a distributed multi-agent runtime. The agents are Python evaluators that produce structured signals; only the optional semantic judge is an LLM call.

### Current local configuration observed during preparation

- Database: SQLite file `guardx.db`.
- Semantic judge: enabled, provider `ollama`, configured model `qwen2.5:3b`; `/api/v1/health` reported the configured model available.
- PII mode: `REDACT`.
- Local NER setting: `en_core_web_sm`; actual use depends on the spaCy package and model being installed. The detector falls back to deterministic rules if it cannot load them.
- Automated suite after the recent security regression fixes: **81 passed**, with one Starlette/httpx deprecation warning.

These are machine-local observations, not universal defaults. `.env` is excluded from source control and may contain secrets. Never copy its secret values into this guide, an issue, or a repository.

## 2. Architecture and request lifecycle

```text
Browser / SDK / application
          |
          v
 FastAPI route + auth/scope checks
          |
          v
 PipelineService: load tenant policy, invoke GuardPipeline
          |
          +--> local PII/secret detector + local redaction
          +--> SecurityAgent (injection, disclosure, suspicious action)
          +--> PrivacyAgent (PII decision)
          +--> ContentAgent (configured phrase rules)
          +--> PolicyAgent (organization substring rules)
          +--> optional local Ollama semantic judge (eligible requests only)
          |
          v
 risk scoring --> deterministic Arbiter --> result + audit/usage/review records
```

Detailed flow:

1. **Authenticate.** Browser management routes use a signed bearer JWT. Programmatic checks can use a hashed API key in `X-API-Key`, or a bearer token. API keys may be scoped, expiring, revoked, and optionally bound to one application.
2. **Validate scope.** Check routes validate `guard:check` on API keys and ensure application/policy IDs belong to the caller's organization. An app-bound API key cannot name a different app.
3. **Build request context.** The route loads enabled policy rules and supplies bounded metadata and, for output checks, optional trusted `sensitive_context` markers.
4. **Run local privacy detection first.** PII/secret matches are held in memory and transformed locally according to `PII_MODE`. Original matched content is not sent to the semantic judge.
5. **Run four local agents.** Security, privacy, content, and policy each return an `AgentResult` with score, level, decision, categories, explanation, confidence, and optional metadata.
6. **Optionally consult semantic judge.** If enabled and no local agent has already blocked, GuardX sends locally redacted text plus a small allow-listed request summary to the local Ollama endpoint. If the local PII detector found PII and local security found no attack, semantic judging is skipped to avoid model false positives overriding deterministic privacy behavior. Provider setup, timeout, and response errors fail to review by default, or block if configured.
7. **Aggregate risk and decide.** The risk scorer uses configured weights and floors risk for block/review decisions. The Arbiter uses fixed precedence: `BLOCK`, then `HUMAN_REVIEW`, then `MODIFY`, then `ALLOW`.
8. **Return safe integration contract.** If decision is `MODIFY`, the returned sanitized text is the only version the caller should forward. A judge cannot rewrite content. For `BLOCK`, do not deliver or execute the original.
9. **Persist a minimal audit trail.** The service stores content hashes, decisions, categories, agent summaries, latency, usage, and review state. It does not store the submitted prompt text in `GuardRequest`.

`input` and `output` are the same pipeline with different request-type context; output adds checks for runtime fingerprints and exact trusted-context leaks. `action` converts the tool name and parameters to text for pipeline analysis and also supplies structured action context to SecurityAgent.

## 3. Agents, detectors, models, and decision logic

### Local agents

- **SecurityAgent** (`app/agents/security_agent.py`): invokes normalized injection rules; on output it also checks direct system-prompt/environment disclosure and optional exact `sensitive_context` matches. For action requests it flags selected sensitive data transfers for a small set of tools. These checks are deterministic, not a general-purpose language understanding system.
- **PrivacyAgent** (`app/agents/privacy_agent.py`): applies PII/secret findings from the local detector. `REDACT` and `PSEUDONYMIZE` produce `MODIFY`; `BLOCK` mode blocks; `ALLOW` does not transform; high-risk credentials/identifiers are blocked. Unknown modes fail closed during sanitization.
- **ContentAgent** (`app/agents/content_agent.py`): uses local phrase lists in `content_detector.py` for a few harmful/toxic phrases. This is a starter ruleset, not a broad content moderation model.
- **PolicyAgent** (`app/agents/policy_agent.py`): currently matches each configured rule's category as a case-insensitive substring in the content and applies the strongest matching action. Its stored `threshold` and `config` are not used by this implementation yet.
- **SemanticJudgeAgent** (`app/agents/semantic_judge.py`): validates the provider's JSON-like answer, bounds scores, allow-lists categories, removes contradictory low-risk category labels, and maps uncertain `MODIFY`/review outcomes to human review. It cannot edit text or downgrade a deterministic block.
- **ArbiterAgent** (`app/agents/arbiter_agent.py`): applies deterministic precedence. It intentionally does not let a weighted average overrule a hard block or review signal.

### PII and injection detection

The PII detector uses Python regular expressions, context labels, validation checks (Luhn for payment card candidates and Verhoeff for Aadhaar candidates), and optionally a locally installed spaCy PERSON NER pipeline. Supported categories include common contact, identity, finance, credential, network, and private-key data. It returns span offsets and matched values in memory so replacement can happen in place; stored audit rows do not contain those values.

The injection detector normalizes Unicode, removes selected zero-width characters, maps selected confusables, decodes HTML entities and URL escapes (bounded passes), then tests rules for common instruction overrides, role-boundary tokens, prompt extraction, tool/data exfiltration, jailbreak phrasing, and indirect hidden-instruction requests. Some Base64-labelled payloads are also decoded and checked within length limits. This catches known patterns but cannot decide every meaning or encoding.

### Language models and NER models

There are **no project-trained or fine-tuned models** in this repository.

| Model / class | Purpose | Current status and boundary |
|---|---|---|
| Ollama model `qwen2.5:3b` | Optional semantic safety classification | Active in the local `.env` observed for this guide; served by the local Ollama process. It is not the source of truth for PII, and its output can be wrong. It sees locally redacted text only when the pipeline elects to invoke it. |
| spaCy `en_core_web_sm` | Optional local PERSON NER to improve unlabelled-name detection | Configured by name locally; only runs if both spaCy and the model are installed. No runtime model download. Rules remain active if unavailable. |
| Mock provider | Test double / no-op evaluator | Exists as code, but the active provider factory does not select it as a semantic judge. |
| OpenAI-compatible / Anthropic classes | Provider-interface experiments | Present in source but not selected by `factory.py`. The factory currently allows only local Ollama. Treat these as inactive/incomplete adapters, not supported live backends. |

When a deployment requires a strict guarantee that no prompt text reaches any language model, disable `SEMANTIC_JUDGE_ENABLED`. That trades semantic discovery for data minimization and local-rule coverage.

### Risk scoring

`risk_scorer.py` applies weights: security 0.25, privacy 0.25, content 0.15, policy 0.15, semantic judge 0.20. It applies configurable low/medium/high level thresholds and floors the overall score to at least 0.75 if any agent blocks and at least 0.50 if any agent requests human review. The weights summarize signals; the Arbiter's precedence determines the final action.

## 4. Authentication, tenant isolation, and data model

- Passwords are hashed with Argon2 through `argon2-cffi`.
- JWTs are signed with PyJWT; the configured lifetime is 60 minutes by default. This project currently has a single configured signing secret and HS256 default.
- API keys are generated from cryptographic randomness, prefixed `gx_`, stored as SHA-256 digests, shown only once on creation, checked for expiry/revocation, and carry scopes. Since generated keys have high entropy, a fast cryptographic digest is suitable for lookup; keys still require careful storage and rotation.
- SQLAlchemy models separate organizations, users, applications, keys, policies/rules, guard requests, per-agent results, decisions, audit logs, reviews, feedback, and usage.
- Most list/read routes scope rows by organization. Tests cover cross-organization isolation and app/policy binding.
- For production, rotate development secrets, use HTTPS, use a real secrets manager, add rate limiting/abuse controls, review role checks, deploy PostgreSQL, back up data, and establish retention/deletion policy. This prototype has no general distributed rate limiter or full IAM system.

### Tables

| Table/model | Main purpose |
|---|---|
| `organizations` / `Organization` | Tenant boundary. |
| `users` / `User` | Login identity, password hash, role, organization. |
| `applications` / `Application` | Tenant-owned client/application identity. |
| `api_keys` / `APIKey` | Key digest, scopes, expiry, revocation, optional application binding. |
| `policies`, `policy_rules` | Tenant policy metadata and category/action rule records. |
| `guard_requests` / `GuardRequest` | Request type, content hash, risk, decision, categories, latency and tenant/application links. |
| `agent_results` / `AgentResult` | Each agent's score, decision, categories, explanation, confidence. |
| `decisions` / `Decision` | Final decision, reason, remediation, contributing agents. |
| `audit_logs` / `AuditLog` | Minimal decision events and structured metadata. |
| `reviews` / `Review` | Pending/resolved human-review item and reviewer outcome. |
| `feedback` / `Feedback` | Correct/incorrect/false-positive/false-negative/override labels. |
| `usage_records` / `UsageRecord` | Per-organization request type and latency. |

## 5. HTTP API and UI

Interactive OpenAPI documentation is at `/docs`; the app is served at `/`. All application API routes use `/api/v1` except `/api/v1/health` (also under that prefix when mounted). API endpoints include:

| Method/path | Function and auth |
|---|---|
| `POST /api/v1/auth/signup` | Create organization + OWNER user and return JWT. |
| `POST /api/v1/auth/login` | Verify password and return JWT. |
| `GET, POST /api/v1/applications` | List/create tenant applications. |
| `GET, POST /api/v1/api-keys` | Admin list/create API keys; raw key appears only in create response. |
| `POST /api/v1/api-keys/{key_id}/revoke` | Revoke a tenant-owned key. |
| `GET, POST /api/v1/policies` | Read/create policies and rules. |
| `POST /api/v1/check/input` | Screen a proposed user/model input. JWT or `X-API-Key` with check scope. |
| `POST /api/v1/check/output` | Screen generated output; supports trusted `sensitive_context` markers. |
| `POST /api/v1/check/action` | Screen a proposed tool/action name and parameter object. |
| `GET /api/v1/audit/requests?limit=50` | List up to 100 newest tenant audit requests. |
| `GET /api/v1/audit/requests/{request_id}` | Tenant-scoped request detail with agents/decision/review. |
| `GET /api/v1/reviews` | List tenant review items. |
| `POST /api/v1/reviews/{review_id}` | Resolve a review with `ALLOW`, `BLOCK`, or `MODIFY`. |
| `POST /api/v1/reviews/{request_id}/feedback` | Attach a feedback label/comment. |
| `GET /api/v1/analytics` | Tenant counts, average risk, high-risk count, categories. |
| `GET /api/v1/health` | App/database health and semantic-provider readiness. |

Check request bodies carry content or action fields, optional app/policy IDs, metadata, and (for text checks) optional trusted markers. Content is capped at 50,000 characters by schema. See `docs/api.md` and `/docs` for exact schemas and response examples.

### Browser UI pages

The UI is deliberately a small vanilla JavaScript dashboard:

- **Overview:** analytics summary and category/decision distributions.
- **Applications:** lists and creates applications.
- **API Keys:** lists key metadata and creates a key; the one-time raw key is shown in an alert.
- **Live Check:** selects input/output, sends text through the authenticated API, displays decision and structured response.
- **Requests:** recent audit rows.
- **Policies:** lists and creates policies with one simple category/action rule.
- **Review Queue:** lists review items. API supports resolution and feedback; the UI currently does not expose every review API operation.
- **Settings:** static integration guidance. Settings are configured through environment variables.

The header's “Connect” field is for a **JWT bearer token**; it is not an API-key field. The login form obtains and stores that token in browser local storage. The UI is a management/test client, not a complete customer-facing application.

## 6. Configuration, development, and deployment

Settings are loaded by `pydantic-settings` from environment variables and `.env` (case-insensitive). Common settings:

| Setting | Purpose / default |
|---|---|
| `DATABASE_URL` | SQLite local default; Compose supplies PostgreSQL URL. |
| `JWT_SECRET`, `JWT_ALGORITHM`, `ACCESS_TOKEN_EXPIRE_MINUTES` | JWT signing and lifetime. Use unique high-entropy secret outside development. |
| `LLM_PROVIDER`, `SEMANTIC_JUDGE_ENABLED`, `SEMANTIC_JUDGE_FAIL_MODE` | Optional semantic backend and fail-closed behavior. |
| `OLLAMA_URL`, `OLLAMA_MODEL`, `OLLAMA_TIMEOUT_SECONDS` | Local Ollama service, model, and request timeout. Provider rejects non-local hosts. |
| `PII_MODE`, `PII_NER_MODEL` | PII handling and optional local spaCy model. |
| `RISK_THRESHOLD_LOW/MEDIUM/HIGH` | Risk-level boundaries. |
| `MAX_REQUEST_CHARS`, `AUTO_CREATE_DB`, `GUARDX_SEED`, `LOG_LEVEL` | Request/config/seed/logging behavior. |

### Run locally (Windows PowerShell)

```powershell
cd C:\path\to\GuardX_complete_project_fixed\guardx
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
# Replace the development JWT secret; configure local Ollama only if desired.
uvicorn app.main:app --reload
```

If using the semantic judge: install/run Ollama separately, pull `qwen2.5:3b`, set the provider/model values in `.env`, and confirm `/api/v1/health`. Optional NER setup is described in `docs/privacy.md`; the model must be installed locally.

```powershell
python -m scripts.seed
python -m pytest -q
python -m evaluation.run --dataset evaluation/sample_dataset.json
```

Docker deployment files provide a PostgreSQL 16 Alpine service and GuardX container. Compose currently has development credentials/defaults and should not be used as-is for production. The Python image is Python 3.11 slim. Alembic artifacts exist, but `app.main` currently uses SQLAlchemy `create_all` when `AUTO_CREATE_DB=true`; production schema lifecycle should use a reviewed migration workflow rather than implicit table creation.

## 7. Dependencies and what they do

Versions are bounded in `requirements.txt`; the installed environment may have a concrete resolved version. The project does not vendor these packages.

| Library | Role |
|---|---|
| FastAPI | HTTP application, routers, dependency injection, OpenAPI generation. |
| Uvicorn (`standard`) | ASGI server and local reload workflow. |
| SQLAlchemy 2 | ORM, engine, sessions, database models. |
| psycopg binary | PostgreSQL driver for Compose/production-style database URLs. |
| Alembic | Schema migration framework and initial migration artifacts. |
| Pydantic + pydantic-settings | Request/response validation and environment configuration. |
| PyJWT | JWT encoding/verification. |
| argon2-cffi | Argon2 password hashing and verification. |
| httpx | Ollama HTTP transport, SDK HTTP calls, and mock transport in tests. |
| python-multipart | Multipart form support dependency; not central to current UI/check flow. |
| pytest + pytest-asyncio | Automated test infrastructure; test suite is mostly synchronous. |
| spaCy (optional, `requirements-ner.txt`) | Local named entity recognition to improve person-name recall. |
| Ollama + `qwen2.5:3b` (external runtime/model) | Optional local semantic judge; not a Python package and not bundled in project files. |
| Browser runtime | UI is plain HTML/CSS/JavaScript; no React/Vue/Node build chain. |

## 8. Repository file-by-file map

The map below covers all checked-in/project source, docs, config, tests, and references present when this guide was written. The local `.env` is described without revealing values. Generated `__pycache__`, `.pytest_cache`, `.venv`, and SQLite state files are not source files and are excluded from the map; their role is summarized at the end.

### Root files

| File | Usage |
|---|---|
| `.env` | Machine-local configuration and potentially secrets. Git-ignored; never publish or copy values into docs. Current local values enable Ollama and PII redaction. |
| `.env.example` | Safe configuration template with development defaults and comments. Replace development secrets before deployment. |
| `.gitignore` | Excludes virtual environments, caches, local env files, database files, coverage output, and logs from Git. |
| `README.md` | Project introduction, setup, demo seed, high-level API, and evaluation commands. |
| `PROJECT_STATUS.md` | Build/test notes and readiness caveats. It may describe an earlier validation snapshot; use this guide's timestamped verification and live health endpoint for current status. |
| `requirements.txt` | Runtime, database, auth, provider-transport, and test package constraints. |
| `requirements-ner.txt` | Optional spaCy dependency for local NER. Install separately; the language model is a separate local download. |
| `alembic.ini` | Alembic migration configuration and database URL placeholder/environment wiring. |
| `Dockerfile` | Builds Python 3.11 slim image, installs requirements, copies app, launches Uvicorn. |
| `docker-compose.yml` | Local PostgreSQL + GuardX services, environment forwarding, health check, port and persistent volume. Contains development-only DB/JWT defaults. |
| `LICENSE` | MIT license text. |
| `test.py` | Small API-key smoke test using the SDK. It now reads `GUARDX_API_KEY` from the environment and does not contain a hard-coded key. |

### Python package initializers

These files make directories importable Python packages; they contain no separate runtime behavior:

| Files | Usage |
|---|---|
| `app/__init__.py`, `app/agents/__init__.py`, `app/api/__init__.py`, `app/api/v1/__init__.py` | Package markers for the application, agent, and API namespaces. |
| `app/core/__init__.py`, `app/db/__init__.py`, `app/db/migrations/__init__.py`, `app/db/models/__init__.py` | Package markers for configuration/security, persistence, migrations, and ORM models. |
| `app/detectors/__init__.py`, `app/engine/__init__.py`, `app/providers/__init__.py`, `app/schemas/__init__.py`, `app/services/__init__.py` | Package markers for detection, decision engine, model adapters, schemas, and service layer. |
| `evaluation/__init__.py`, `scripts/__init__.py`, `sdk/__init__.py` | Package markers; `sdk/__init__.py` also exports the public SDK client. |
| `app/db/migrations/versions/.gitkeep` | Keeps the otherwise-empty migration versions directory present in Git. |

### `app/` application code

#### Startup and API routes

| File | Usage |
|---|---|
| `app/main.py` | Creates FastAPI app, configures logging, optionally creates DB tables, mounts versioned routers and static UI, serves `/`. |
| `app/api/v1/auth.py` | Signup/login endpoints, password verification, JWT issuance. |
| `app/api/v1/applications.py` | Tenant-scoped application list and create routes. |
| `app/api/v1/api_keys.py` | Admin list/create/revoke routes; only the creation response reveals the raw key; listing returns metadata, not hashes. |
| `app/api/v1/policies.py` | Tenant policy list/create and rule persistence. |
| `app/api/v1/checks.py` | Input/output/action endpoints; auth/scope checks, tenant-owned app/policy validation, response assembly. |
| `app/api/v1/audit.py` | Tenant-scoped request listing and request detail with related agent/decision/review rows. |
| `app/api/v1/reviews.py` | Review list/resolve and feedback endpoints; checks that review belongs to requester's tenant. |
| `app/api/v1/analytics.py` | Aggregates request totals, decisions, average risk, high-risk count, and category counts. |
| `app/api/v1/health.py` | Tests DB connectivity and reports semantic provider/model availability without requiring user auth. |

#### Core, schemas, and persistence

| File | Usage |
|---|---|
| `app/core/config.py` | Typed environment settings via Pydantic Settings; one shared `settings` object. |
| `app/core/security.py` | Argon2 password hash/verify, JWT creation/decode, API-key generation and SHA-256 digest. |
| `app/core/dependencies.py` | FastAPI dependencies for current JWT user, API key or JWT identity, expiry/revocation checks, and admin authorization. |
| `app/core/logging.py` | Basic process logging configuration. |
| `app/schemas/schemas.py` | Pydantic request/response inputs, literals, validation limits (including content and trusted markers). |
| `app/db/database.py` | SQLAlchemy engine/session setup and request-scoped session dependency; SQLite gets thread option. |
| `app/db/models/models.py` | ORM definitions for organization, user, application, key, policy/rule, request, agent result, decision, audit, review, feedback, usage. |
| `app/db/models/__init__.py` | Package marker. |
| `app/db/migrations/env.py` | Alembic runtime environment using project metadata/configuration. |
| `app/db/migrations/script.py.mako` | Template Alembic uses to generate new migration scripts. |
| `app/db/migrations/versions/03eef6688fe9_initial_guardx_schema.py` | Initial schema creation/reversal migration. |

#### Agents and detectors

| File | Usage |
|---|---|
| `app/agents/base.py` | `AgentResult` data contract and abstract `GuardrailAgent.evaluate` interface. |
| `app/agents/security_agent.py` | Wires injection and output-disclosure detectors to security decisions; basic suspicious-tool checks. |
| `app/agents/privacy_agent.py` | Converts local PII/secret matches and PII mode into allow/modify/block agent result. |
| `app/agents/content_agent.py` | Converts content-detector phrase hits to content decision. |
| `app/agents/policy_agent.py` | Matches simple configured category substrings and chooses the strongest matched action. |
| `app/agents/semantic_judge.py` | Validates/normalizes semantic provider output and prevents malformed model answers from becoming arbitrary app behavior. |
| `app/agents/arbiter_agent.py` | Applies final deterministic precedence and writes a reason/remediation summary. |
| `app/detectors/pii_detector.py` | Local regex, contextual patterns, checksum validation, optional local spaCy PERSON NER, overlapping span resolution, redaction/pseudonymization. |
| `app/detectors/injection_detector.py` | Unicode/encoding normalization, known injection/role/exfiltration rules, abstract hidden-instruction rule, runtime fingerprint and trusted-marker output checks. |
| `app/detectors/content_detector.py` | Lightweight toxicity/harm keyword lists; intentionally small prototype ruleset. |

#### Engine, providers, and services

| File | Usage |
|---|---|
| `app/engine/pipeline.py` | Runs privacy-first pipeline, optional semantic judge, failure handling, risk scoring, arbitration, safe replacement selection. |
| `app/engine/risk_scorer.py` | Weighted risk aggregation, threshold-derived level, block/review score floors. |
| `app/engine/ensemble.py` | Thin `aggregate()` wrapper around risk scoring; legacy/convenience interface. |
| `app/engine/sanitizer.py` | Adapts local PII detector and configured mode into sanitized text + match objects. |
| `app/providers/base.py` | Abstract `LLMProvider.judge(content, policy)` interface. |
| `app/providers/factory.py` | Builds the configured semantic provider; currently only accepts local Ollama. |
| `app/providers/ollama_provider.py` | Local-only Ollama client; checks host constraints, ignores proxy env, sends strict JSON classification request, validates response and health. |
| `app/providers/mock_provider.py` | Simple deterministic/no-op provider for limited development/testing use; not selected by current factory. |
| `app/providers/openai_provider.py` | Experimental OpenAI-compatible chat-completions adapter; not integrated by factory and response shape is not the active judge contract. |
| `app/providers/anthropic_provider.py` | Placeholder subclass of the OpenAI-compatible adapter; not an Anthropic-native API implementation and not active. |
| `app/services/pipeline_service.py` | Orchestrates pipeline call and DB persistence for requests, results, decisions, minimal audit, usage, and human-review rows. |
| `app/services/policy_service.py` | Loads enabled policy rules belonging to the specified tenant and policy. |

### `frontend/`

| File | Usage |
|---|---|
| `frontend/templates/index.html` | Single-page dashboard shell, nav buttons, JWT header input, static CSS/JS references. |
| `frontend/static/css/app.css` | Layout, cards, tables, form, risk/decision colors, responsive presentation. |
| `frontend/static/js/app.js` | Vanilla JS routing/rendering, JWT local-storage handling, fetch helper, CRUD/check actions, escaping dynamic values and safe text rendering. |

### `sdk/`, `examples/`, `scripts/`

| File | Usage |
|---|---|
| `sdk/client.py` | Small synchronous `httpx` client for check input/output/action; wraps JSON response in attribute-access result. |
| `sdk/__init__.py` | Exports `GuardX` as public package entry point. |
| `examples/basic_sdk.py` | Minimal sample showing SDK initialization and an input check. |
| `scripts/seed.py` | Creates fake demo organization/user/application/policy/rules if demo user is absent; prints seeded login credentials. Do not seed real environments. |
| `scripts/__init__.py` | Package marker for `python -m scripts.seed`. |

### `evaluation/`

| File | Usage |
|---|---|
| `evaluation/run.py` | Reads CSV/JSON labeled examples, runs input pipeline, calculates accuracy/precision/recall/F1/FPR/FNR/attack-success/latency, prints JSON report. |
| `evaluation/sample_dataset.json` | Tiny local demonstration fixture. It is not a benchmark and cannot support broad performance claims. |
| `evaluation/__init__.py` | Package marker for `python -m evaluation.run`. |

### `tests/`

| File | Coverage purpose |
|---|---|
| `tests/conftest.py` | Shared test DB/app/client fixtures and test setup/teardown. |
| `tests/unit/test_detectors.py` | PII types, checksums, redaction/pseudonyms, injection normalization/rules, output disclosure, benign controls, optional NER. |
| `tests/unit/test_pipeline.py` | Pipeline allow/block/modify behavior, PII, hidden-instruction regression cases in input/output, benign discussion. |
| `tests/unit/test_semantic_judge.py` | Fake-provider classification, privacy boundary, PII-only no-judge behavior, semantic escalation/failure/validation and Ollama mocked contract. |
| `tests/integration/test_api.py` | Signup/login, endpoint behavior, output PII/disclosure, semantic-provider failure/review integration. |
| `tests/integration/test_api_key_and_action.py` | API key generation/check/revoke/scopes/expiry/app binding and tool action screening. |
| `tests/security/test_auth.py` | Invalid token rejection and cross-organization isolation. |

### `docs/`, `references/`, and legal/support artifacts

| File | Usage |
|---|---|
| `docs/PROJECT_GUIDE.md` | This end-to-end engineering and interview guide. |
| `docs/architecture.md` | Concise architecture summary and pipeline boundaries. |
| `docs/agents.md` | Short agent descriptions. |
| `docs/api.md` | API route overview, trusted output context notes, integration contract. |
| `docs/security.md` | Password/key/JWT/database security notes and deployment hardening caveats. |
| `docs/privacy.md` | PII categories, sanitization flow, semantic-judge privacy boundary, detection limits. |
| `docs/deployment.md` | Local/PostgreSQL/Docker and optional Ollama deployment instructions. |
| `docs/development.md` | Developer commands and extension points for agents, detectors, providers. |
| `docs/evaluation.md` | Benchmark/evaluator usage and metric definitions. |
| `references/guardx_build_prompt.txt` | Supplied project-planning/build brief retained as reference; not application code and not runtime instructions. |
| `references/GuardX_presentation.pptx` | Supplied presentation reference describing project intent; not loaded by the app. |
| `LICENSE` | MIT license. |
| `README.md`, `PROJECT_STATUS.md` | Repository entry point and status snapshot; status notes can become stale as code/environment changes. |

### Local/generated files not treated as source

- `.venv/`: locally installed Python packages and scripts. Recreate from requirements; do not commit.
- `__pycache__/`, `.pytest_cache/`: Python bytecode and pytest cache; disposable generated data.
- `guardx.db`, `test_guardx.db`: SQLite runtime and test state. They may contain identities, audit metadata, keys' digests, and operational history; do not share casually. The actual raw API key should not be persisted in this database.
- Logs/coverage output: generated diagnostics, excluded by `.gitignore`.

## 9. Known limitations and engineering follow-ups

1. **Not foolproof:** an unseen paraphrase, encoding, language, image, audio, or context chain can evade string rules and the small semantic model. False positives are also possible.
2. **Semantic model uncertainty:** even local models hallucinate classifications. Never use a single LLM decision as authorization to expose data or run tools.
3. **PII coverage is finite:** regex/NER cannot guarantee detection of every person, identifier, transliteration, OCR string, or secret format. If spaCy/model is absent, names without contextual clues may be missed.
4. **Policy semantics are basic:** policy category matching is substring-based; per-rule `threshold`/`config` are stored but not enforced. Policy language needs validation, tests, and safe administration controls before production.
5. **Content moderation is minimal:** current content lists are tiny keyword fixtures, not a comprehensive safety taxonomy or moderation model.
6. **Tool check is advisory:** `/check/action` returns a decision but does not execute or sandbox a tool. Integrators must gate execution on the result and use allow-listed tool schemas and authorization.
7. **Production controls are incomplete:** add TLS, hardened secrets, rate limiting, monitoring, database backup/retention, migrations as deployment gate, review authorization, abuse controls, and operational alerting.
8. **Provider support:** despite experimental OpenAI/Anthropic files, only local Ollama is built by current factory. Do not configure a remote provider expecting it to work.
9. **UI/API mismatch:** the API supports review resolution/feedback and key revocation; the small dashboard does not expose all of those operations.
10. **Evaluation scope:** the included fixture is intentionally small. Use versioned, representative, labeled tests and report per-category precision/recall and latency; never infer production accuracy from the tiny sample.

## 10. Interview question bank with answer outlines

The questions below cover the main kinds of technical and product questions likely to be asked about this project. The answer bullets are honest outlines; adapt them to the interviewer's level and distinguish implemented behavior from proposed future work.

### Product and system design

1. **What problem does GuardX solve?** It adds a policy and inspection boundary around LLM input, output, and tool actions to reduce prompt injection, sensitive-data exposure, and configured policy violations.
2. **Where does GuardX sit in an AI application?** Before prompt submission, after model generation, and before tool execution; callers must gate each path on GuardX's decision.
3. **What does “multi-agent” mean here?** Several independent, narrow Python evaluators return signals. It does not mean independent autonomous LLM agents coordinating with tools.
4. **Why use a modular monolith?** Easier local development, deployment, data consistency, and debugging at prototype scale; modules create logical boundaries without operational microservice overhead.
5. **What are the main components?** FastAPI routes, auth/tenant checks, local detectors/agents, optional Ollama judge, risk scorer, deterministic Arbiter, SQLAlchemy persistence, SDK, dashboard.
6. **How does an input differ from an output check?** Same core pipeline; output checks additionally inspect runtime/system disclosures and can compare against trusted `sensitive_context` markers.
7. **How is action screening different?** It serializes the proposed tool and parameters for analysis and supplies structured action context. GuardX does not execute the tool itself.
8. **What are the four decisions?** `ALLOW`, `MODIFY` with a required safe replacement, `BLOCK`, and `HUMAN_REVIEW` for unresolved cases.
9. **Why is the Arbiter deterministic?** To keep final precedence reproducible and prevent weighted averages from overriding a hard security block or review requirement.
10. **How would you scale this design?** External PostgreSQL, multiple stateless API replicas, shared cache/rate limiting, queue-backed review/audit processing where justified, observability, and a separate model service with strict privacy controls.

### Models, NLP, and detection

11. **Which models are trained by GuardX?** None. The project uses hand-authored rules, an optional downloaded local Qwen model for semantic classification, and optional spaCy NER.
12. **What is `qwen2.5:3b` used for?** A local Ollama semantic judge to add contextual attack/policy signals; it is not used to redact PII or make tool authorization decisions.
13. **Why use an LLM if regex rules exist?** Rules are fast, inspectable, and reliable for known formats; an LLM may add semantic recall for paraphrase/context, but introduces latency and classification uncertainty.
14. **Why not rely on the LLM alone?** Models can miss attacks, hallucinate, be manipulated by content, and cannot guarantee policy enforcement. Deterministic controls remain authoritative for known rules.
15. **What is the spaCy model doing?** Optional local PERSON named-entity recognition to find unlabelled names. It is a recall aid, not a general PII solution.
16. **How does PII redaction work?** Find typed spans locally, resolve overlaps, then replace spans from end to start so earlier offsets remain valid.
17. **How are credit cards/Aadhaar candidates validated?** Luhn and Verhoeff checksum validation reduce false matches for those identifier formats.
18. **How does injection normalization help?** It detects some zero-width, compatibility-Unicode, confusable, HTML-escaped, and URL-encoded variants before matching known patterns.
19. **What was the abstract injection issue and its fix?** The semantic model allowed a story-like request to reproduce hidden foundational guidance. A local detector now requires a sensitive instruction-like target plus a reproduce/disclose request and blocks it in input/output tests.
20. **How was PII overblocking fixed?** If local PII is the only local signal and local security finds no attack, the semantic judge is skipped; local privacy policy can redact without a model false positive overriding it.
21. **Can the detector be foolproof?** No. Novel language, indirect context, multimodal content, unrecognized identifiers, and false positives remain. Use least privilege, output gates, tool authorization, review, and continual testing.
22. **What happens when semantic judging fails?** By default it creates a review signal (`HUMAN_REVIEW`); fail mode can be configured to block. A local deterministic block skips the judge.
23. **Does the LLM see sensitive information?** PII detected locally is redacted before the provider call, and selected requests with only PII skip the judge. However, undetected sensitive text could remain; strict no-model-data deployments should disable the judge.
24. **Why only local Ollama?** The current factory deliberately restricts active provider construction to a local endpoint, reducing external data transfer risk. Other provider files are experiments, not supported configured backends.
25. **How would you add multilingual/encoded detection?** Add language-aware normalization/detectors and labeled regression sets, carefully decode bounded encodings, avoid executing payloads, and evaluate both false positives and false negatives.

### Security, identity, and privacy

26. **How are passwords stored?** Argon2 password hashes via argon2-cffi; plaintext is not stored.
27. **How are API keys stored?** High-entropy random values are shown once; SHA-256 digests are stored and the supplied key is hashed for lookup.
28. **How is API-key authorization enforced?** Expiry, revocation, scope, optional application binding, and organization ownership checks are applied on routes.
29. **What is the difference between JWT and API key auth?** JWTs identify interactive users and roles; API keys are long-lived programmatic credentials with scopes and optional app binding.
30. **How is tenant isolation implemented?** Queries and resource validation constrain by organization ID. Integration/security tests cover cross-tenant access cases.
31. **What data is persisted per request?** Hash, request type, decision, risk, categories, timing, tenant/app/policy IDs, agent summary, and audit/usage/review metadata; the original text is not stored in the main request row.
32. **Why pass `sensitive_context`?** An integrator can supply trusted internal strings for output leak matching; it is bounded and should never contain user-controlled markers.
33. **What if `MODIFY` is returned but the caller sends original text anyway?** The gateway cannot enforce behavior outside itself; the integration must use `sanitized_content` or stop delivery.
34. **What are the main security gaps before production?** TLS, secret rotation/management, rate limits, robust role governance, review permissions, monitoring, database retention/backups, and a real threat model/red-team process.
35. **Why is a fast SHA-256 hash okay for API keys but not passwords?** API keys are uniformly random and high entropy, so guessing is infeasible; human passwords have low entropy and need a deliberately slow memory-hard password hash.
36. **What does the development JWT secret imply?** The default is not safe for production. Set a unique high-entropy value, rotate it securely, and avoid exposing it in logs or source control.
37. **Does the database store API-key plaintext?** No, the model stores `key_hash`. The raw key is returned once at creation and must be kept in the caller's secret store.

### Backend, API, and database

38. **Why FastAPI?** Typed request validation, dependency injection, async-capable ASGI architecture, and generated OpenAPI docs.
39. **What does SQLAlchemy do?** Maps Python entities to relational tables and provides database engines/sessions; it supports SQLite development and PostgreSQL deployment.
40. **Why PostgreSQL in Compose?** A more deployment-relevant relational database with concurrency/durability properties beyond a local SQLite file.
41. **What is Alembic used for?** Versioned schema migrations; however, current startup can use `create_all`, so production should formalize migration-driven schema changes.
42. **How is input bounded?** Pydantic schema sets nonempty content and a 50,000-character max, plus bounded sensitive context entries/count.
43. **How does the check response help the caller?** It gives request ID, decision, risk level/score, categories, sanitized content if applicable, per-agent signals, arbiter reason, and latency.
44. **What is in analytics?** Tenant-level request counts/distribution, average risk, high-risk count, and category frequencies derived from stored request rows.
45. **How are errors handled for an invalid API key?** Authentication dependency returns 401; missing check scope returns 403; invalid/cross-tenant resources are rejected.
46. **What indexes exist for audit performance?** Tenant, created-time, request type, decision, risk level, application, and a combined tenant/created-time index.
47. **What is the role of `PipelineService`?** Bridges pure evaluation and persistence: runs pipeline, stores request/agent/decision/audit/usage rows, and queues human-review decisions.

### Frontend, SDK, and integration

48. **What frontend framework is used?** None; a server-served HTML page, CSS, and vanilla JavaScript.
49. **How does browser login work?** Login endpoint returns JWT; JavaScript stores it in local storage and sends it as a Bearer token.
50. **What does the header Connect button do?** Saves a JWT token; it does not accept an API key.
51. **How do UI requests avoid basic HTML injection?** Dynamic text is escaped or set via `textContent`; check results use DOM APIs to render response text safely.
52. **What does the SDK provide?** A small synchronous HTTPX wrapper for the three check endpoints, with attribute-style response access.
53. **How should a service integrate?** Create and store a scoped API key securely, pass input through `/check/input`, pass returned model text through `/check/output`, and gate each tool call with `/check/action`; honor non-ALLOW decisions.
54. **What limitations does the UI have?** It is a demo/management dashboard; some API capabilities, including review resolution and key revocation, are not exposed in the UI.

### Testing, metrics, and evaluation

55. **What test layers exist?** Unit detector/pipeline/provider tests, API integration tests, and auth/tenant security tests.
56. **How is the LLM tested without a live model?** Inject deterministic fake providers and use `httpx.MockTransport` to test the Ollama HTTP contract.
57. **What did the latest run show?** 81 tests passed after the indirect-injection and PII false-positive regressions were added; one framework deprecation warning appeared.
58. **What is the included dataset?** A tiny illustrative fixture, not AdvBench and not evidence of production performance.
59. **What does false-negative rate mean here?** Unsafe examples classified as not unsafe divided by all unsafe examples, under the evaluator's labels and rule mapping.
60. **What is attack-success rate in this evaluator?** The fraction of labeled unsafe examples that are not escalated to `BLOCK` or `HUMAN_REVIEW`; it is a fixture-level measure.
61. **Why is decision consistency null?** The evaluator has no independent multiple annotators/evaluators for each item; it avoids fabricating agreement.
62. **How would you improve evaluation?** Build a versioned representative suite, include paraphrase/language/encoding/quoted-benign cases, label with independent reviewers, track per-category precision/recall/FPR/FNR, and gate releases on regression thresholds.
63. **How do you test that PII never reaches the judge?** Use a fake provider that records received content, submit known sensitive data, and assert raw values and untrusted metadata/markers are absent.

### Trade-offs and future design questions

64. **Why can a semantic model not be the sole source of truth?** It is probabilistic and may be manipulated; security-critical authorization must use deterministic identity, scopes, schemas, and policy gates.
65. **When would you disable the semantic judge?** Strict privacy/no-model-data environments, model outage, or deployments where latency/cost/risk outweigh additional contextual recall.
66. **How would you avoid tool misuse?** Allow-list tools, validate typed arguments, re-check user authorization, restrict credentials and network paths, require approval for consequential effects, and execute in a sandbox.
67. **How would you reduce latency?** Keep local regex checks cheap, precompile rules, cache safe static policy, use bounded low-latency model calls only when eligible, monitor tail latency, and avoid parallelizing before correctness/privacy semantics are clear.
68. **How would you handle model disagreement?** Preserve deterministic hard blocks, route ambiguous/high-risk disagreement to review, log versioned signal summaries, and avoid averaging away severe findings.
69. **How would you evolve the policy engine?** Define typed rule operators and schemas, evaluate thresholds, version policies, test precedence, and ensure tenant admins cannot create unsafe cross-tenant or bypass rules.
70. **How would you support multimodal input?** Add modality-specific extractors (OCR/transcription/metadata) under strict size/time limits, scan extracted text locally, preserve provenance, and avoid treating transcription as authoritative without testing.
71. **What are the most important observability metrics?** Decision counts by category, false positives/negatives from reviewed labels, judge availability/latency, PII redaction rates, review backlog, API errors, key/auth failures, and per-tenant quota use.
72. **What would make this production-ready?** Threat modeling, independent red-team evaluation, hardened auth/secrets/TLS, rate limiting, durable migration process, audit retention, least privilege, monitoring/incident response, secure tool integration, and documented SLAs/limitations.
73. **What is the most important integration mistake to avoid?** Treating the GuardX call as logging-only and forwarding original content after `MODIFY`, `BLOCK`, or `HUMAN_REVIEW`.

## 11. Interview presentation summary

> “GuardX is a FastAPI-based safety gateway for LLM inputs, outputs, and agent actions. It combines local PII/secret and prompt-injection detectors with specialized security, privacy, content, and policy evaluators. A weighted scorer summarizes risk, while a deterministic Arbiter enforces decision precedence. An optional local Ollama model adds semantic classification only after local redaction and only when eligible. The project includes JWT and scoped API-key auth, tenant-scoped persistence/audit, a small dashboard, an SDK, and unit/integration/security tests. It is a security prototype: its detectors are not foolproof, its content/policy rules are intentionally basic, and production deployment needs stronger operational controls and broader independent evaluation.”

That summary separates what is implemented from aspirational claims and is suitable as a starting point for a technical walkthrough.
