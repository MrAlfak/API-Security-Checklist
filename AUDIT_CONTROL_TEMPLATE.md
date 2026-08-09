# Security Control Template

Use this format for new audit-grade controls. Machine-readable controls are fully bilingual; English and Persian fields must express the same security meaning.

```yaml
id: API-AREA-001
title_en: Short English title
title_fa: عنوان کوتاه فارسی
severity: high
applies_to:
  - rest
  - public-api
requirement: >-
  A precise, testable security requirement using unambiguous language.
requirement_fa: >-
  یک الزام امنیتی دقیق، قابل تست و بدون ابهام به زبان فارسی.
verification:
  - Send/construct a positive request and confirm expected authorized behavior.
  - Send at least one relevant negative/bypass case and confirm it is rejected safely.
verification_fa:
  - یک درخواست مثبت بسازید و رفتار مجاز مورد انتظار را بررسی کنید.
  - حداقل یک سناریوی منفی یا Bypass مرتبط را ارسال کنید و رد ایمن آن را بررسی کنید.
evidence:
  - Automated test output
  - Relevant configuration or policy
evidence_fa:
  - خروجی تست خودکار
  - پیکربندی یا سیاست مرتبط
references:
  - OWASP API Security Top 10 2023 APIx
  - OWASP ASVS 5.0.0
owner: optional-team-or-role
review_frequency: after-material-change
```

## Required fields

### `id`

Stable project identifier. IDs should describe the control family, not a specific implementation language.

### `title_en` / `title_fa`

Short equivalent English and Persian control titles.

### `severity`

One of: `critical`, `high`, `medium`, `low`.

### `applies_to`

Use scope tags documented in `STANDARDS_MAPPING.md`. Avoid marking browser-only controls as `all`.

### `requirement` / `requirement_fa`

State the same security property in English and Persian. Describe what must be enforced, not a vendor/tool preference.

### `verification` / `verification_fa`

Describe how a reviewer can prove the control works. Include negative/bypass tests for authorization, identity, isolation, parser, and boundary controls. The Persian array must have the same number of steps as the English array.

### `evidence` / `evidence_fa`

List evidence that can be retained for an audit: automated test results, configuration, policy-as-code, architecture references, sanitized logs, or review output. English and Persian evidence arrays must have matching item counts.

### `references`

Prefer primary/authoritative sources. Use version-qualified ASVS identifiers when citing a specific ASVS requirement.

## راهنمای فارسی کوتاه

در کنترل‌های جدید صرفاً `title_fa` کافی نیست. فیلدهای `requirement_fa`، `verification_fa` و `evidence_fa` نیز اجباری‌اند. اصطلاحات فنی استاندارد را می‌توان به شکل اصلی نگه داشت، اما معنی امنیتی نسخه فارسی باید دقیقاً با نسخه انگلیسی هم‌راستا باشد.

## Review outcome template

For an implementation review, record:

- Status: `not_reviewed`, `implemented`, `verified`, `failed`, `not_applicable`, or `accepted_risk`
- Reviewer
- Date
- Evidence links/IDs
- Environment/version reviewed
- Findings
- Exception owner and expiry date, if applicable

A checked box without verification evidence is not considered an audit result.
