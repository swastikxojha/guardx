# Security
Passwords use Argon2id. API keys are SHA-256 hashed and displayed once. JWTs are signed server-side. ORM queries are parameterized. Authorization is organization-scoped. Raw passwords, tokens and unnecessary PII are excluded from audit metadata. This prototype still requires deployment hardening such as TLS, secret management, reverse-proxy controls and rate limiting at scale.
