# Architecture

GuardX is a modular monolith. The local Security, Privacy, Content, and Policy agents always run first. When enabled, a local Ollama Semantic Judge analyzes only locally redacted text and minimal policy labels. The Risk/Ensemble stage aggregates agent outputs, and the deterministic Arbiter applies precedence: a semantic judge can raise a decision to BLOCK or HUMAN_REVIEW, but can never lower a local BLOCK. A review decision is persisted to the human-review queue. Audit records are created for every evaluation. The API is the primary integration interface; the web UI is the management dashboard.

With the semantic judge disabled, GuardX runs deterministically with no LLM calls. When enabled, provider failures fail closed to HUMAN_REVIEW by default. The judge cannot rewrite content; a `MODIFY` recommendation therefore becomes HUMAN_REVIEW. See `docs/privacy.md` for the sanitization boundary and deployment settings.
