# Contributing to API Security Checklist

Thank you for helping improve this project. Security guidance can cause real harm when it is stale, ambiguous, or copied without the right scope, so contributions should be evidence-based and testable.

## Before contributing

- Search existing issues and controls to avoid duplicates.
- Prefer primary/authoritative sources: OWASP project documents, NIST publications, IETF RFCs/BCPs, and official platform/framework security documentation.
- Do not weaken an existing recommendation without explaining the threat model and reference supporting the change.
- Never include real API keys, passwords, tokens, private keys, production identifiers, or sensitive user data in examples.

## Changing security guidance

A material recommendation change should include:

1. The affected API scope (REST, browser API, GraphQL, gRPC, WebSocket, webhook, M2M, multi-tenant, etc.).
2. The security property being protected.
3. An authoritative reference.
4. A verification method or negative test.
5. Expected audit evidence where practical.
6. Equivalent English and Persian wording for machine-readable controls.

Avoid universal wording for contextual controls. For example, browser headers and CORS do not apply to every machine-to-machine API.

## Adding or changing machine-readable controls

Controls live under `checklist/` and must follow the bilingual schema documented in `checklist/README.md`.

Required fields:

- `id`
- `title_en`
- `title_fa`
- `severity`
- `applies_to`
- `requirement`
- `requirement_fa`
- `verification`
- `verification_fa`
- `evidence`
- `evidence_fa`
- `references`

The Persian and English text must describe the same security property. `verification_fa` must have the same number of steps as `verification`, and `evidence_fa` must have the same number of items as `evidence`.

Run locally before opening a PR:

```bash
ruby scripts/validate_controls.rb
python3 scripts/security_content_regression.py
```

GitHub Actions runs the same structural/security-content checks plus Markdown linting.

## Code examples

Examples are educational patterns, not framework-complete production applications. New examples should:

- fail closed when security configuration is missing,
- avoid custom cryptography,
- use parameterized/context-safe APIs,
- include relevant authorization boundaries,
- avoid trusting client MIME/type/identity/tenant claims,
- show replay/resource limits where the example needs them,
- include a short note about assumptions or omitted production concerns.

If an example requires a package/library, prefer maintained mainstream components and avoid pinning readers to an obsolete API version.

## Pull requests

1. Fork or branch the repository.
2. Keep the PR focused on one coherent security/documentation change when practical.
3. Use descriptive commit messages.
4. Update `CHANGELOG.md` for material changes.
5. Ensure CI passes.
6. Explain why the change is safer or more accurate, not only what text changed.

## Bilingual support

Machine-readable controls are fully English/Persian. A control is incomplete if it contains only a Persian title. Requirement, verification steps, and evidence expectations must also be present in Persian under the corresponding `_fa` fields.

---

# راهنمای مشارکت فارسی

راهنمای امنیتی این پروژه باید قابل تست، دارای Scope مشخص و مبتنی بر مرجع معتبر باشد. هنگام تغییر یک کنترل توضیح دهید چه ریسکی کاهش پیدا می‌کند و چگونه صحت آن باید بررسی شود.

برای کنترل‌های جدید در پوشه `checklist/` تمام فیلدهای انگلیسی و فارسی را تکمیل کنید:

- `title_en` و `title_fa`
- `requirement` و `requirement_fa`
- `verification` و `verification_fa`
- `evidence` و `evidence_fa`

تعداد مراحل `verification_fa` باید با `verification` و تعداد آیتم‌های `evidence_fa` با `evidence` برابر باشد. معنی امنیتی نسخه فارسی و انگلیسی نیز باید یکسان بماند.

قبل از PR این دستورها را اجرا کنید:

```bash
ruby scripts/validate_controls.rb
python3 scripts/security_content_regression.py
```

هیچ Secret، Token، API Key، کلید خصوصی یا داده واقعی کاربر را در مثال‌ها قرار ندهید.
