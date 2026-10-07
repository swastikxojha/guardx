# API
Auth: `/api/v1/auth/signup`, `/api/v1/auth/login`. Checks: `/api/v1/check/input`, `/api/v1/check/output`, `/api/v1/check/action`. Management: applications, API keys, policies, audit, reviews, analytics. OpenAPI is exposed at `/docs`.

Input/output check bodies may include `sensitive_context`: trusted internal strings that must not be repeated in an LLM output. Output checks block exact normalized matches (minimum 16 characters). This field is optional, bounded to 50 entries, and is not persisted. Do not pass user-controlled markers. For `MODIFY`, downstream applications must use `sanitized_content`; for `BLOCK`, they must not deliver the original content.
