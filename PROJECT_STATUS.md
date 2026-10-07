# GuardX Project Status

**Updated:** 2026-10-07

## Status

Runnable security prototype for screening LLM inputs, outputs, and proposed tool actions. It uses local deterministic detectors and an optional local Ollama semantic judge. It is not a guarantee of safety and is not production-hardened.

## Verified in this workspace

- The complete automated test suite passes: **81 passed**, with one Starlette/httpx deprecation warning.
- The live app health endpoint reports the application and SQLite database healthy; the semantic judge is enabled with provider `ollama`, configured model `qwen2.5:3b`, and status `available`.
- The web UI has been exercised across its eight sections. Input/output Live Check cases verified benign content, direct and multilingual injection, email/phone PII, runtime disclosure, benign security discussion, and abstract hidden-instruction requests.
- Regression fixes now block the tested story-like abstract request in both input and output modes and allow the local privacy agent to redact PII-only text without a semantic-model false-positive injection block.
- The privacy boundary, fake semantic judge behavior, provider error handling, local Ollama HTTP contract, key scope/expiry/revocation, tenant isolation, and action checks are represented in automated tests.

## Limitations and validation scope

- A local-model health response proves the service/model is available, not that its classifications are accurate.
- The test suite uses deterministic fake providers for most model scenarios. Automated tests do not establish foolproof attack detection.
- The evaluator's bundled dataset is a tiny illustrative fixture, not AdvBench and not a general performance claim.
- Docker image build/startup and production hardening are not claimed by this status snapshot.
- PII and prompt-injection detectors can miss novel, paraphrased, encoded, multimodal, or context-dependent attacks and can produce false positives.
- Review `docs/PROJECT_GUIDE.md` for the architecture, full file map, configuration, interview question bank, and future hardening work.
