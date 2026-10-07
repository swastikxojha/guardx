# Privacy and detection boundaries

GuardX's local agents always run first. An optional semantic judge can add contextual discovery using a local Ollama model. GuardX never sends prompts to a remote LLM: Ollama is restricted to loopback or the named local Docker service and HTTP proxy environment variables are ignored. Local PII/secret matches are replaced before the judge runs. This prevents known matches from reaching the model, though no detector can prove that every sensitive item was recognized.

## Local PII coverage

Detectors cover email, phone, IP, Luhn-valid payment cards, formatted and context-labeled SSNs, date of birth, Aadhaar (Verhoeff validation for unlabeled candidates), PAN, IFSC, GSTIN, contextual names and addresses, labeled bank-account numbers, UPI IDs, passport/driving-license/voter IDs, common API keys, passwords, access tokens, and private-key blocks. Sensitive number patterns use checksum or label context where practical to reduce false positives. Detection results contain offsets and values in memory for redaction; audit logs store only hashes and categories.

For additional local named-entity recall, install the optional dependencies with `pip install -r requirements-ner.txt`, then install spaCy's small English model with `python -m spacy download en_core_web_sm`. GuardX defaults to the locally installed `en_core_web_sm`; override `PII_NER_MODEL` with another local model name/path, or set it blank to disable NER. It never downloads a model at runtime. If the model is unavailable, deterministic detection continues.

The default `PII_MODE=REDACT` locally replaces detections before the caller can pass them onward. `PSEUDONYMIZE` numbers same-type values in text order. `BLOCK` stops matching content. `ALLOW` deliberately disables replacement and should only be used when the application has independently approved the data flow. Unknown modes fail closed for detected PII.

Both `/api/v1/check/input` and `/api/v1/check/output` return the safe replacement in `sanitized_content` when the decision is `MODIFY`. Callers must use that returned value and must not forward the original content after a `MODIFY` or `BLOCK` result.

## Prompt injection and output checks

Injection checks normalize Unicode, zero-width characters, HTML entities, and URL encoding before applying local rules for instruction overrides, prompt exfiltration, role-boundary tokens, jailbreak phrasing, and data exfiltration. Output checks additionally flag direct system-prompt disclosure language and environment fingerprints such as “The system OS is Kali 22.04”. Integrations can pass a bounded `sensitive_context` list to `/check/output`; exact normalized matches of at least 16 characters are blocked as `sensitive_context_leak`. Supply only trusted internal markers, never user-provided text.

These are defense-in-depth detectors, not a proof of safety. Paraphrased secrets, unseen encodings, new jailbreak strategies, unmarked names, and context-dependent meaning can evade rules or produce false positives. Add target-domain regression cases and human review for high-impact applications. No detector can guarantee foolproof coverage.

## Optional semantic judge

Install and start Ollama locally, then download a model such as `qwen2.5:3b` with `ollama pull qwen2.5:3b`. Set `LLM_PROVIDER=ollama`, `SEMANTIC_JUDGE_ENABLED=true`, `OLLAMA_URL=http://127.0.0.1:11434`, and `OLLAMA_MODEL=qwen2.5:3b` in `.env`, then restart GuardX. Without these settings the pipeline remains local-rule-only. `/api/v1/health` reports whether the local service is reachable and the configured model is installed.

The judge receives only the locally redacted text, request type, and allow-listed policy labels. It never receives original PII matches, free-form metadata, the trusted `sensitive_context` markers, or the system/developer prompt. If a deterministic agent blocks, the judge is skipped. The judge can escalate a request to `BLOCK` or `HUMAN_REVIEW`; it cannot downgrade a local block. Its `MODIFY` recommendation becomes `HUMAN_REVIEW` because the judge is not allowed to rewrite user content. Timeout, invalid JSON, or misconfiguration also routes to review (or to `BLOCK` when `SEMANTIC_JUDGE_FAIL_MODE=BLOCK`).

Redaction can remove context that a semantic judge needs, and undetected sensitive text could still be present in the sanitized text. If the deployment requires a strict guarantee that no raw user text reaches any language model, leave `SEMANTIC_JUDGE_ENABLED=false`; use local rules and review instead. Semantic models improve discovery but cannot guarantee safety.
