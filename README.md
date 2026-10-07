# GuardX — Multi-Agent AI Safety & Guardrail Framework

GuardX is an AI security gateway and REST middleware that evaluates **inputs, LLM outputs, and AI-agent/tool actions** before they are delivered or executed. It combines Security, Privacy, Content, and Policy agents, a risk/ensemble engine, and a deterministic Arbiter producing **ALLOW, MODIFY, BLOCK, or HUMAN_REVIEW**.

The architecture follows the submitted GuardX major-project presentation: four specialized agents, risk aggregation, Arbiter consensus, audit/feedback, and AdvBench evaluation. The implementation adds the engineering detail required for a runnable prototype.

## Quick start

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
copy .env.example .env  # Windows; use cp on Linux/macOS
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000/` for the dashboard and `/docs` for OpenAPI.

For PostgreSQL/Docker:

```bash
docker compose up --build
```

## Demo account

Run `PYTHONPATH=. python -m scripts.seed` to create a fake demo organization/user. The seed command prints the demo credentials; it uses fake data only.

## Architecture

`Client -> GuardX API -> Security/Privacy/Content/Policy -> optional local Semantic Judge -> Risk Scoring -> Ensemble -> Arbiter -> ALLOW/MODIFY/BLOCK/HUMAN_REVIEW -> Audit/Feedback`

Three checks are exposed:

- `POST /api/v1/check/input` — pre-LLM screening.
- `POST /api/v1/check/output` — post-LLM screening.
- `POST /api/v1/check/action` — pre-execution agent/tool screening.

### Privacy boundary

PII and secrets are detected locally before any optional semantic judge. The default pipeline makes no model calls. When enabled, the local Ollama judge receives only locally redacted text and limited policy labels; audit records store hashes/metadata rather than unnecessary raw PII.

### Optional semantic judge (local Ollama)

GuardX can use a local Ollama model for broader, contextual prompt-injection and policy discovery. Install/start Ollama, run `ollama pull qwen2.5:3b`, and configure `.env` with `LLM_PROVIDER=ollama`, `SEMANTIC_JUDGE_ENABLED=true`, and `OLLAMA_MODEL=qwen2.5:3b`. Restart GuardX. The judge receives locally redacted text and minimal policy labels, never trusted context markers or the system prompt. Local blocks cannot be downgraded; judge failures go to human review by default. Setup, privacy behavior, and limits are described in `docs/privacy.md`.

## Agents

- **Security Agent:** prompt injection, jailbreak, malicious/conflicting instructions, suspicious actions.
- **Privacy Agent:** local PII/secret detection, validation and sanitization.
- **Content Agent:** context-aware harmful/toxic content rules with optional judge hook.
- **Policy Agent:** configurable application policy rules.
- **Arbiter:** deterministic precedence + weighted risk for reproducible decisions.

## API authentication

Browser users authenticate with JWT access tokens. Programmatic clients use hashed API keys with scopes (`guard:check`, `guard:read`, `guard:admin`). Keys are shown only once.

## Evaluation

The evaluator accepts CSV/JSON. If AdvBench is not present, provide a local fixture or pass a dataset path. Run:

```bash
python -m evaluation.run --dataset evaluation/sample_dataset.json
```

It reports accuracy, precision, recall, F1, FPR, FNR, attack-success rate, decision consistency and average latency, plus rule-based and single-evaluator baselines where applicable. No benchmark result is fabricated.

## Testing

```bash
pytest -q
```

## Project structure

See `docs/architecture.md`, `docs/agents.md`, `docs/api.md`, `docs/security.md`, `docs/privacy.md`, `docs/evaluation.md`, `docs/deployment.md`, and `docs/development.md`.

## Limitations

GuardX is a security prototype, not a guarantee of safety. It does not claim perfect jailbreak prevention, perfect PII detection, zero false positives/negatives, or complete coverage of adversarial techniques. Rules and thresholds require evaluation and tuning against the target deployment.
