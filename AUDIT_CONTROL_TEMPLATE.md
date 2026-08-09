# Security Control Template

Use this format for new audit-grade controls.

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
verification:
  - Send/construct a positive request and confirm expected authorized behavior.
  - Send at least one relevant negative/bypass case and confirm it is rejected safely.
  - Verify the same behavior at alternate endpoints/batch/nested variants where applicable.
evidence:
  - Automated test output
  - Relevant configuration or policy
  - Sanitized log/audit event
references:
  - OWASP API Security Top 10 2023 APIx
  - OWASP ASVS 5.0.0
owner: optional-team-or-role
review_frequency: after-material-change
```

## Required fields

### `id`

Stable project identifier. IDs should describe the control family, not a specific implementation language.

### `severity`

One of: `critical`, `high`, `medium`, `low`.

### `applies_to`

Use scope tags documented in `STANDARDS_MAPPING.md`. Avoid marking browser-only controls as `all`.

### `requirement`

State the security property to enforce, not a product/tool recommendation. Prefer “The API MUST/SHOULD…” style wording when useful.

### `verification`

Describe how a reviewer can prove the control works. Include negative/bypass tests for authorization, identity, isolation, parser, and boundary controls.

### `evidence`

List evidence that can be retained for an audit: automated test results, configuration, policy-as-code, architecture references, sanitized logs, or review output.

### `references`

Prefer primary/authoritative sources. Use version-qualified ASVS identifiers when citing a specific ASVS requirement.

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
