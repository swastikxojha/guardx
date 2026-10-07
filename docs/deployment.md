# Deployment

For local development use SQLite or Docker PostgreSQL. For deployment use PostgreSQL, TLS, secret management, request limits, and rate limiting. Run the app with `docker compose up --build`.

## Optional local semantic model

Run Ollama on the host, pull a model (for example `ollama pull qwen2.5:3b`), then set these variables in the Compose `.env` file:

```dotenv
LLM_PROVIDER=ollama
SEMANTIC_JUDGE_ENABLED=true
SEMANTIC_JUDGE_FAIL_MODE=HUMAN_REVIEW
OLLAMA_URL=http://host.docker.internal:11434
OLLAMA_MODEL=qwen2.5:3b
```

Compose forwards these settings to GuardX. The judge remains disabled by default. When enabled, the app connects only to the configured local Ollama endpoint; it does not call a hosted model API.
