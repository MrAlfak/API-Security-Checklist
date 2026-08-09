# Machine-Readable Security Controls

This directory is the audit-oriented source for structured API security controls.

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
- English and Persian titles,
- `severity`,
- `applies_to` scope tags,
- precise `requirement`,
- executable/reviewable `verification` steps,
- expected `evidence`,
- authoritative `references`.

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

The validator checks required fields, duplicate IDs, scope names, severity values, and indexed control files. GitHub Actions runs the same validation for changes.

## Adding a control

1. Choose the narrowest relevant control family.
2. Use a stable, unique ID.
3. State a testable security property rather than a vendor/tool preference.
4. Add positive/negative verification steps where meaningful.
5. Add evidence expectations.
6. Cite an authoritative source.
7. Add Persian title text and update broader Persian guidance when the recommendation materially affects it.

See `AUDIT_CONTROL_TEMPLATE.md` for a full template.
