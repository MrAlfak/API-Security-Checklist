# Machine-Readable Security Controls

This directory is the audit-oriented source for structured API security controls.

All 65 controls are fully bilingual: English and Persian requirements, verification steps, and evidence expectations live together under the same stable control ID.

## Structure

- `controls.yaml` — index, supported scopes, severities, and control files.
- `authentication.yaml` — authentication, passwords, recovery, sessions.
- `authorization.yaml` — object/property/function authorization and privilege elevation.
- `oauth.yaml` — OAuth 2.0 security controls aligned with RFC 9700.
- `jwt.yaml` — JWT/JOSE controls aligned with RFC 8725.
- `input-data.yaml` — validation, injection, XSS, SSRF, uploads, upstream data.
- `resource-transport.yaml` — limits, rate limiting, TLS, browser headers, CORS.
- `graphql.yaml` — resolver authorization, cost, batching, subscriptions.
- `grpc.yaml` — transport, method authorization, reflection, resource limits.
- `websocket.yaml` — handshake, message authorization, origin and resource quotas.
- `webhook.yaml` — signatures, replay protection, rotation, idempotency.
- `multi-tenant.yaml` — tenant context, data, cache/storage, jobs, administration.
- `operations-supply-chain.yaml` — inventory, logging, incident response, SCA, secrets, SBOM, provenance.

## Control format

Each control includes:

- stable `id`,
- `title_en` and `title_fa`,
- `severity`,
- `applies_to` scope tags,
- English `requirement` and Persian `requirement_fa`,
- English `verification` and Persian `verification_fa`,
- English `evidence` and Persian `evidence_fa`,
- authoritative `references`.

The English and Persian verification/evidence arrays must contain the same number of items so both languages describe the same audit procedure.

## قالب دوزبانه فارسی

هر کنترل امنیتی با یک شناسه ثابت نگه‌داری می‌شود و نسخه فارسی و انگلیسی آن در همان رکورد قرار دارد. برای استفاده فارسی:

- `title_fa` عنوان کنترل است.
- `requirement_fa` الزام امنیتی قابل اجرا را مشخص می‌کند.
- `verification_fa` مراحل تست و بازبینی را مشخص می‌کند.
- `evidence_fa` شواهد مورد انتظار برای Audit را مشخص می‌کند.
- `references` مرجع فنی مشترک هر دو زبان است.

ترجمه فارسی نباید معنی یا شدت کنترل انگلیسی را تغییر دهد. اصطلاحات پروتکلی استاندارد مانند OAuth، PKCE، JWT، Scope، Audience، JWKS، GraphQL و gRPC در صورت نیاز به شکل اصلی حفظ می‌شوند.

## Audit workflow

For each applicable control, record an implementation outcome separately from these source files:

- `not_reviewed`
- `implemented`
- `verified`
- `failed`
- `not_applicable`
- `accepted_risk`

A control should not be marked `verified` without retained evidence.

## Validation

Run:

```bash
ruby scripts/validate_controls.rb
```

The validator checks required fields, duplicate IDs, scope names, severity values, indexed control files, Persian content presence, and English/Persian verification/evidence item-count parity. GitHub Actions runs the same validation for changes.

## Adding a control

1. Choose the narrowest relevant control family.
2. Use a stable, unique ID.
3. State a testable security property rather than a vendor/tool preference.
4. Add positive/negative verification steps where meaningful.
5. Add evidence expectations.
6. Cite an authoritative source.
7. Add `title_fa`, `requirement_fa`, `verification_fa`, and `evidence_fa` with equivalent security meaning.
8. Keep Persian verification/evidence arrays aligned item-for-item with the English arrays.

See `AUDIT_CONTROL_TEMPLATE.md` for a full template.
