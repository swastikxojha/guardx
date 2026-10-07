# Development
Install requirements, run tests with `pytest -q`, start with `uvicorn app.main:app --reload`, and run the evaluator with the command in `docs/evaluation.md`. Add agents by implementing `GuardrailAgent`, detectors by keeping detection interfaces isolated, and providers through `LLMProvider`.

The semantic judge is opt-in. To exercise it with a local Ollama model, follow the setup in `docs/privacy.md`; tests inject a deterministic fake provider, so no LLM service or internet connection is required for CI. The privacy-boundary tests assert that the provider sees redacted content and no trusted context markers.
