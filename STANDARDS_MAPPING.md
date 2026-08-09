# Security Standards Mapping

This project uses multiple standards because no single document is a complete API verification standard.

## Primary references

| Area | Primary reference | How it is used |
|---|---|---|
| API risk awareness | OWASP API Security Top 10 2023 | Threat categories and common API failure modes |
| Verification requirements | OWASP ASVS 5.0.0 | Testable technical security requirements |
| Password/authenticator policy | NIST SP 800-63B-4 | Password length, blocklists, authenticator requirements |
| OAuth 2.0 security | RFC 9700 / BCP | Authorization flow, PKCE, redirect, replay, refresh-token guidance |
| JWT security | RFC 8725 / BCP 225 | Algorithm, key, issuer/audience, token-type and confusion controls |
| Sender-constrained tokens | RFC 9449 | DPoP proof-of-possession |
| OAuth mutual TLS | RFC 8705 | mTLS client authentication and certificate-bound access tokens |
| Implementation patterns | OWASP Cheat Sheet Series | Practical defensive patterns for specific vulnerability classes |

## OWASP API Top 10 2023 mapping

| OWASP category | Project control families |
|---|---|
| API1 Broken Object Level Authorization | `AUTHZ-*`, `TENANT-*` |
| API2 Broken Authentication | `AUTHN-*`, `OAUTH-*`, `JWT-*` |
| API3 Broken Object Property Level Authorization | `AUTHZ-*`, `INPUT-*` |
| API4 Unrestricted Resource Consumption | `RESOURCE-*`, `GRAPHQL-*`, `GRPC-*` |
| API5 Broken Function Level Authorization | `AUTHZ-*` |
| API6 Unrestricted Access to Sensitive Business Flows | `RESOURCE-*`, operational abuse controls |
| API7 Server Side Request Forgery | `INPUT-SSRF-*` |
| API8 Security Misconfiguration | `TRANSPORT-*`, `OPS-*`, `SUPPLY-*` |
| API9 Improper Inventory Management | `OPS-INVENTORY-*` |
| API10 Unsafe Consumption of APIs | `INPUT-UPSTREAM-*`, `WEBHOOK-*` |

## Scope tags

Machine-readable controls use one or more of these scope tags:

- `all`
- `rest`
- `browser-api`
- `graphql`
- `grpc`
- `websocket`
- `sse`
- `webhook`
- `m2m`
- `public-api`
- `internal-api`
- `multi-tenant`
- `file-api`
- `oauth-client`
- `authorization-server`
- `resource-server`

Controls tagged `browser-api` should not automatically be treated as requirements for non-browser M2M APIs.

## Verification model

Every machine-readable control contains:

- `id`
- `title_en` / `title_fa`
- `severity`
- `applies_to`
- `requirement`
- `verification`
- `evidence`
- `references`

A control is only considered verified when the evidence demonstrates the expected behavior, including meaningful negative tests for security boundaries.

## Reference precision

When mapping to OWASP ASVS, use version-qualified requirement identifiers (`v5.0.0-x.y.z`) whenever a specific ASVS requirement is cited. This avoids ambiguity when requirement numbering changes in later versions.

When an exact ASVS requirement has not been reviewed, use the broader project reference rather than inventing a requirement number.

## Maintenance rule

A contribution that materially changes a security recommendation should include an authoritative reference and should identify which control families/scopes are affected. Security guidance that becomes obsolete should be removed or clearly marked as legacy instead of preserved as a generic recommendation.
