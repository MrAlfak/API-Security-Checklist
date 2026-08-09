# 🛡️ API Security Checklist

**A practical, auditable, standards-aligned checklist for secure API design, implementation, verification, and operations.**

**چک‌لیست عملی و قابل ممیزی امنیت API برای طراحی، پیاده‌سازی، تست و بهره‌برداری امن.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![OWASP API Top 10](https://img.shields.io/badge/OWASP-API%20Top%2010%202023-blue)](https://owasp.org/API-Security/)
[![ASVS](https://img.shields.io/badge/OWASP%20ASVS-5.0.0-blue)](https://owasp.org/www-project-application-security-verification-standard/)
[![OAuth BCP](https://img.shields.io/badge/OAuth%20Security-RFC%209700-blue)](https://www.rfc-editor.org/rfc/rfc9700.html)
[![JWT BCP](https://img.shields.io/badge/JWT%20Security-RFC%208725-blue)](https://www.rfc-editor.org/rfc/rfc8725.html)

> This project is a security baseline, not a substitute for threat modeling, architecture review, penetration testing, or risk assessment.
>
> این پروژه یک خط مبنای امنیتی است و جایگزین Threat Modeling، بازبینی معماری، تست نفوذ و ارزیابی ریسک نیست.

## What changed

This repository now separates **security requirements** from general API design advice and adds verification criteria so a control can be tested instead of merely checked off.

- OWASP API Security Top 10 2023 coverage
- OWASP ASVS 5.0.0 verification alignment
- OAuth 2.0 Security Best Current Practice (RFC 9700)
- JWT Best Current Practice (RFC 8725)
- DPoP (RFC 9449) and OAuth mTLS (RFC 8705)
- REST, GraphQL, gRPC, WebSocket, webhook, M2M, internal, public, and multi-tenant scopes
- Machine-readable controls under [`checklist/`](checklist/)
- Secure examples in [`EXAMPLES.md`](EXAMPLES.md)
- Threat and vulnerability guidance in [`VULNERABILITIES.md`](VULNERABILITIES.md)
- Standards cross-reference in [`STANDARDS_MAPPING.md`](STANDARDS_MAPPING.md)
- Audit control format in [`AUDIT_CONTROL_TEMPLATE.md`](AUDIT_CONTROL_TEMPLATE.md)

## How to use

1. Identify the API types and trust boundaries in scope.
2. Start with Critical and High controls in `checklist/`.
3. Record evidence for every applicable control.
4. Mark controls `not_applicable` only with a documented reason.
5. Add automated negative tests for security-critical behavior.
6. Re-run the review after material architecture, identity, data-flow, or dependency changes.

### Suggested control status

`not_reviewed` → `applicable` → `implemented` → `verified`

Optional outcomes: `not_applicable`, `accepted_risk`, `failed`.

## Scope matters

Not every browser security control belongs on every API. Apply controls according to the delivery context.

| Scope | Examples | Important security focus |
|---|---|---|
| REST/JSON | public/internal HTTP API | authn/authz, schemas, BOLA, rate limits, inventory |
| Browser/BFF | cookie-authenticated API | CSRF, SameSite, CORS, browser headers where relevant |
| GraphQL | query/mutation APIs | resolver authorization, cost/depth/alias/batch limits |
| gRPC | service-to-service RPC | TLS/mTLS, authz, reflection, deadlines/message limits |
| WebSocket | real-time bidirectional API | handshake + per-message authz, origin, quotas |
| Webhook receiver | third-party callbacks | signature, timestamp, replay window, idempotency |
| M2M | service accounts/workloads | workload identity, scopes/audiences, key rotation |
| Multi-tenant | SaaS APIs | tenant isolation on every object/query/cache/job |

## Priority model

- **Critical** — compromise can directly expose protected data, identities, signing keys, or privileged operations.
- **High** — likely material impact or a major layer of defense.
- **Medium** — important hardening and resilience control.
- **Low** — contextual defense-in-depth; never a substitute for required controls.

---

# Core checklist

## 1. Authentication and account security

- [ ] Use a maintained, well-reviewed identity/authentication implementation; do not invent custom cryptography or token formats.
- [ ] Require MFA or phishing-resistant authentication for privileged and high-impact accounts where feasible.
- [ ] Rate-limit authentication by multiple dimensions (account, source/network, device/session signals) and monitor bypass attempts.
- [ ] Use generic authentication errors that do not reveal whether an account exists.
- [ ] Password reset/recovery tokens are random, one-time, short-lived, securely stored, and invalidated after use.
- [ ] Security-sensitive account changes trigger appropriate re-authentication and invalidate affected sessions/tokens.
- [ ] Detect credential stuffing and abnormal login patterns without relying only on permanent account lockout.

### Passwords — NIST SP 800-63B-4 alignment

- [ ] For single-factor passwords, require a minimum of **15 characters**.
- [ ] If a password is only one factor in MFA, require at least **8 characters**.
- [ ] Permit at least **64 characters** and support spaces/passphrases.
- [ ] Do **not** require arbitrary composition rules such as mandatory uppercase + number + symbol.
- [ ] Block commonly used, expected, and compromised passwords.
- [ ] Do not force periodic password changes without evidence of compromise.
- [ ] Store passwords using a password-specific adaptive hashing/KDF scheme with appropriate parameters and unique salts.

## 2. Authorization and isolation

- [ ] **Deny by default** and authorize every protected operation server-side.
- [ ] Perform object-level authorization on every read, update, delete, download, export, and nested-resource access.
- [ ] Perform property/field-level authorization for both input and output.
- [ ] Perform function-level authorization independently of route naming or client UI visibility.
- [ ] Never trust `userId`, `tenantId`, role, price, balance, owner, or privilege flags supplied by the client.
- [ ] Enforce tenant isolation in database queries, caches, search indexes, object storage, background jobs, exports, logs, and analytics.
- [ ] Test horizontal privilege escalation, vertical privilege escalation, cross-tenant access, and stale-permission behavior.
- [ ] UUIDs may reduce enumeration but **do not fix BOLA/IDOR**; authorization is still mandatory.

## 3. OAuth and OpenID Connect

Use RFC 9700 as the security baseline for OAuth 2.0 deployments.

- [ ] Prefer Authorization Code flows; do not use the Resource Owner Password Credentials grant.
- [ ] Avoid the implicit grant except where a stronger profile/specification explicitly requires and secures it.
- [ ] Authorization servers support PKCE; clients use PKCE with `S256` where applicable.
- [ ] Prevent PKCE downgrade attacks and bind transaction state securely.
- [ ] Use exact redirect URI matching and prevent open redirects.
- [ ] Restrict access tokens to minimum scopes and intended resource-server audiences.
- [ ] Public clients using refresh tokens use **refresh-token rotation** or sender-constrained refresh tokens.
- [ ] Detect refresh-token reuse/replay and revoke the affected token family/grant.
- [ ] Consider DPoP (RFC 9449) or mTLS-bound tokens (RFC 8705) where sender-constrained access tokens are warranted.
- [ ] Treat `state`, PKCE verifier/challenge, OIDC `nonce`, authorization code, and token endpoints as distinct protocol controls; do not substitute one blindly for another.

## 4. JWT / JOSE

Use RFC 8725 as the baseline.

- [ ] Configure an explicit algorithm allowlist; never select verification behavior solely from attacker-controlled `alg`.
- [ ] Bind each key to its intended algorithm/use and reject algorithm/key confusion.
- [ ] Validate signature/MAC and all required cryptographic operations before trusting claims.
- [ ] Validate expected `iss` and `aud`, plus time claims such as `exp` and `nbf` where used.
- [ ] Use explicit token typing (`typ`) and mutually exclusive validation rules when multiple JWT kinds exist.
- [ ] Prevent cross-JWT confusion between access tokens, ID tokens, reset tokens, email-verification tokens, etc.
- [ ] Treat received claims as untrusted until the token type, issuer, audience, signature, and policy checks pass.
- [ ] Keep signing keys out of source code; fail closed if required key material is unavailable.
- [ ] Support key rotation and safe JWKS caching/refresh where asymmetric signing is used.
- [ ] Constrain `kid`/JWK resolution to trusted key sets; do not turn token headers into arbitrary filesystem/network lookups.
- [ ] Keep sensitive plaintext out of ordinary signed JWT payloads; signing is not encryption.

## 5. Sessions and API keys

- [ ] Session identifiers and API keys have cryptographically strong entropy.
- [ ] Session cookies use `Secure`, `HttpOnly`, and an appropriate `SameSite` policy.
- [ ] Implement idle and absolute session expiry where appropriate.
- [ ] Logout and security-sensitive events invalidate relevant server-side session/token state.
- [ ] API keys are scoped, attributable, revocable, rotatable, and never placed in URLs.
- [ ] Store long-lived API credentials hashed or in a secrets-management system where practical.
- [ ] Avoid binding security solely to IP/device identifiers; network properties can change and be spoofed/proxied.

## 6. Input, injection, and data handling

- [ ] Validate request structure, type, length, range, format, enum values, and business semantics using allowlists/schemas.
- [ ] Reject unexpected fields for security-sensitive objects where mass assignment is a risk.
- [ ] SQL injection: use parameterized queries/prepared statements; do not rely on generic sanitization.
- [ ] NoSQL injection: use safe query APIs and restrict operators/structure accepted from clients.
- [ ] OS command injection: avoid shells; use parameterized/safe process APIs and strict allowlists if invocation is unavoidable.
- [ ] XSS: use context-appropriate output encoding; sanitize only when accepting intended HTML/markup.
- [ ] XML: disable unsafe external-entity resolution and dangerous parser features when not required.
- [ ] Path handling: canonicalize/resolve and restrict access to intended roots; do not concatenate untrusted paths.
- [ ] SSRF: prefer destination allowlists; resolve/validate addresses, block internal/link-local metadata ranges, control redirects, protocols, DNS behavior, timeouts, and response sizes.
- [ ] Validate `Content-Type`/`Accept` as protocol constraints, not as proof that the payload is safe.

## 7. File upload and download

- [ ] Allow only business-required extensions/types and enforce strict size/count limits.
- [ ] Do not trust the client-provided MIME type; verify file signatures/content and perform type-specific validation.
- [ ] Generate server-side filenames and do not reuse untrusted path components.
- [ ] Store uploads outside executable/web roots or in isolated object storage.
- [ ] Apply malware scanning/sandboxing and, where appropriate, content disarm/reconstruction before release.
- [ ] Protect archive extraction against traversal, excessive expansion, nested archives, and decompression bombs.
- [ ] Require authorization for private downloads and prevent IDOR/BOLA on file identifiers.
- [ ] For untrusted downloads, use safe content types, `Content-Disposition`, and `X-Content-Type-Options: nosniff` as appropriate.

## 8. Traffic and resource consumption

- [ ] Enforce request body, header, URL, file, decompressed-body, and response limits.
- [ ] Rate-limit based on the actual abuse model (identity, token, IP/network, tenant, endpoint, resource, cost).
- [ ] Set deadlines/timeouts for downstream HTTP, database, queue, and RPC calls.
- [ ] Limit pagination and expensive filter/search operations.
- [ ] Bound concurrency, queue depth, batch size, fan-out, and asynchronous job creation.
- [ ] Return `429` and useful retry semantics where rate limiting applies.
- [ ] Add upstream DDoS protection where the threat model requires it; application rate limiting is not full DDoS mitigation.

## 9. Browser-facing API controls

Apply only where browser behavior is relevant.

- [ ] Configure CORS to the minimum origins/methods/headers required; remember CORS is not authorization.
- [ ] Cookie-authenticated state-changing requests have appropriate CSRF protections.
- [ ] HSTS is enabled on HTTPS browser-facing origins after deployment implications are understood.
- [ ] `X-Content-Type-Options: nosniff` is set where relevant.
- [ ] CSP / `frame-ancestors` / clickjacking controls are applied to rendered web content, not blindly treated as universal JSON API controls.
- [ ] Do not recommend legacy `X-XSS-Protection: 1; mode=block`; modern guidance is to omit it or set `X-XSS-Protection: 0` when needed for legacy behavior control.
- [ ] Sensitive API responses use appropriate `Cache-Control`, commonly `no-store` when storage must be prevented.

## 10. Logging, detection, and audit

- [ ] Never log plaintext passwords, session secrets, access/refresh tokens, API keys, or private keys.
- [ ] Minimize and protect PII in logs; apply retention and access controls.
- [ ] Audit privileged actions, authorization changes, security configuration changes, credential lifecycle events, and high-risk business actions.
- [ ] Include stable correlation/request IDs without accepting attacker-controlled log injection.
- [ ] Alert on meaningful abuse patterns such as repeated authorization failures, token reuse, unusual exports, key changes, and inventory anomalies.
- [ ] Protect log integrity and synchronize time across systems.

## 11. Inventory, documentation, and lifecycle

- [ ] Maintain an inventory of hosts, gateways, versions, endpoints, schemas, owners, data classifications, authentication modes, and exposure level.
- [ ] Detect and remove shadow, zombie, debug, test, and deprecated API deployments.
- [ ] Define deprecation and end-of-life policies and monitor traffic to old versions.
- [ ] OpenAPI/GraphQL schemas do not contain real secrets or sensitive examples.
- [ ] Protect private/internal documentation appropriately, but do not rely on hidden documentation as a security boundary.
- [ ] Detect schema drift between deployed behavior and documented contracts.

## 12. Third-party APIs and webhooks

- [ ] Treat third-party API responses as untrusted input and validate before use.
- [ ] Restrict outbound credentials/scopes and define explicit egress destinations.
- [ ] Apply strict timeouts, response-size limits, TLS validation, and safe redirect behavior.
- [ ] Webhooks verify a cryptographic signature over the expected canonical payload.
- [ ] Webhooks validate signed timestamps/nonces and enforce a replay window.
- [ ] Webhook secrets support rotation and overlap during rollover.
- [ ] Webhook processing is idempotent and safe under duplicate/out-of-order delivery.
- [ ] IP allowlists are defense-in-depth only unless the provider contract guarantees them securely.

## 13. GraphQL

- [ ] Authorize at resolver/object/field level, not only at the top-level endpoint.
- [ ] Enforce query cost/complexity budgets; depth limits alone are insufficient.
- [ ] Bound aliases, batching, list sizes, pagination, fragments, and expensive resolver fan-out.
- [ ] Avoid unconditional recommendations to disable introspection; decide based on exposure model and tooling needs.
- [ ] Protect mutations and subscriptions with the same authorization and abuse controls as REST operations.
- [ ] Prevent N+1/resource-amplification behavior from becoming a DoS primitive.

## 14. gRPC, WebSockets, SSE, and streaming

- [ ] gRPC uses TLS/mTLS as required and authenticates/authorizes each method.
- [ ] Restrict gRPC reflection and administrative services according to exposure requirements.
- [ ] Set message-size limits, deadlines, concurrency limits, and stream quotas.
- [ ] WebSockets authenticate the connection and authorize every sensitive message/action.
- [ ] Browser WebSockets validate allowed origins where applicable.
- [ ] Revalidate authorization for long-lived connections when roles/sessions change.
- [ ] Bound connection counts, message rates, message sizes, subscriptions, and fan-out.
- [ ] SSE/long polling enforce authentication, authorization, timeouts, and resource limits.

## 15. Multi-tenant security

- [ ] Derive authoritative tenant context from trusted identity/session state rather than raw client parameters.
- [ ] Every data-layer query contains/enforces tenant isolation or equivalent row-level policy.
- [ ] Cache keys, object-storage prefixes, search indexes, queues, exports, and background jobs preserve tenant boundaries.
- [ ] Cross-tenant admin/support operations use explicit elevated workflows, short-lived privileges, and audit trails.
- [ ] Automated tests attempt cross-tenant object IDs, filters, batch APIs, exports, and indirect references.

## 16. Cryptography and secrets

- [ ] Use maintained cryptographic libraries and standard protocols; do not design custom encryption/signing schemes.
- [ ] Keys have defined owners, purpose, algorithm, storage, rotation, revocation, archival, and destruction policies.
- [ ] Use KMS/HSM-backed keys where risk warrants it.
- [ ] Never commit production secrets; enable secret scanning and rotate exposed credentials immediately.
- [ ] TLS certificate validation is enabled; do not ship `verify=false`/equivalent production bypasses.
- [ ] Certificate pinning is not a universal requirement; use only when the client threat/operational model justifies it.

## 17. CI/CD and software supply chain

- [ ] Run dependency/SCA and secret scanning on changes and default branches.
- [ ] Pin and review CI actions/build dependencies appropriately.
- [ ] Generate an SBOM for releasable software where appropriate.
- [ ] Scan containers and IaC before deployment and define severity/exception gates.
- [ ] Protect branch/release workflows and production deployment credentials.
- [ ] Produce provenance/sign artifacts when the software supply-chain risk model requires it.
- [ ] Run security regression tests for authentication, BOLA/BFLA, schemas, rate limits, token validation, and tenant isolation.

## 18. Operational security

- [ ] Maintain incident-response runbooks for credential leakage, signing-key compromise, authorization bypass, and data exposure.
- [ ] Backups are encrypted, access-controlled, restorable, and tested.
- [ ] Production debug/admin endpoints are disabled or strongly isolated and authenticated.
- [ ] Apply least-privilege network/IAM policies to services and data stores.
- [ ] Security-sensitive configuration changes are reviewed, logged, and recoverable.
- [ ] Periodically threat-model new high-impact business flows and architecture changes.

---

# راهنمای سریع فارسی

<div dir="rtl">

- احراز هویت و مجوزدهی را دو موضوع جدا در نظر بگیرید؛ ورود موفق به معنی مجاز بودن برای هر آبجکت یا عملیات نیست.
- برای رمز عبور تک‌فاکتوره حداقل ۱۵ کاراکتر در نظر بگیرید، قوانین اجباری ترکیب حروف/عدد/نماد را حذف کنید و رمزهای لو‌رفته یا رایج را Blocklist کنید.
- در OAuth مبنا را RFC 9700 قرار دهید: PKCE، تطبیق دقیق Redirect URI، محدودسازی Scope/Audience و مقابله با Replay توکن‌های Refresh.
- در JWT الگوریتم مجاز را سمت سرور مشخص کنید، `iss` و `aud` و اعتبار زمانی را بررسی کنید و برای انواع مختلف توکن قواعد اعتبارسنجی جدا داشته باشید.
- UUID فقط حدس‌زدن شناسه را سخت‌تر می‌کند و جای Authorization در BOLA را نمی‌گیرد.
- Sanitization عمومی راه‌حل SQL Injection یا XSS نیست؛ برای SQL از Query پارامتری و برای XSS از Output Encoding متناسب با Context استفاده کنید.
- MIME اعلام‌شده توسط کاربر برای آپلود فایل قابل اعتماد نیست؛ Signature/Content فایل را بررسی و فایل را خارج از Web Root نگه‌داری کنید.
- کنترل‌های Browser مثل CSP و Clickjacking را فقط در جایی اعمال کنید که محتوای قابل Render در مرورگر وجود دارد.
- در سیستم Multi-tenant، Tenant Isolation باید در Query، Cache، Storage، Search، Job، Export و Log بررسی شود.
- هر کنترل امنیتی باید Evidence و روش Verification داشته باشد؛ صرفاً تیک‌زدن Checklist کافی نیست.

</div>

## Verification and evidence

For each control, record at least:

- Control ID
- Severity
- Applicability and scope
- Requirement
- Verification steps / negative tests
- Evidence (configuration, test output, logs, architecture reference)
- Standard references
- Owner and review date
- Exception/accepted-risk details where applicable

See [`AUDIT_CONTROL_TEMPLATE.md`](AUDIT_CONTROL_TEMPLATE.md) and the YAML controls under [`checklist/`](checklist/).

## References

Primary references used by this project include:

- OWASP API Security Top 10 2023
- OWASP Application Security Verification Standard 5.0.0
- OWASP Cheat Sheet Series
- NIST SP 800-63B-4
- RFC 9700 — Best Current Practice for OAuth 2.0 Security
- RFC 8725 — JSON Web Token Best Current Practices
- RFC 9449 — OAuth 2.0 Demonstrating Proof of Possession (DPoP)
- RFC 8705 — OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens

See [`STANDARDS_MAPPING.md`](STANDARDS_MAPPING.md) for project-level mappings.

## Contributing

Security guidance becomes stale. Contributions should include a primary/authoritative reference, affected scope, verification method, and both English/Persian wording when practical. See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Security reports

Do not disclose vulnerabilities in this project or its examples through a public issue before coordination. See [`SECURITY.md`](SECURITY.md).

## License

MIT — see [`LICENSE`](LICENSE).
