# Security Standards Mapping

## Core References

| Area | Standard |
|---|---|
| API Risks | OWASP API Security Top 10 2023 |
| Verification | OWASP ASVS 5.x |
| OAuth Security | RFC 9700 |
| JWT Security | RFC 8725 |
| DPoP | RFC 9449 |
| mTLS Bound Tokens | RFC 8705 |

## Control Requirements

Every security item should eventually include:

- Control ID
- Severity
- Applicable API type
- Verification method
- Evidence required
- Reference standard

## API Types

Controls should specify scope:

- REST
- GraphQL
- gRPC
- WebSocket
- Webhook
- Machine-to-machine API
- Public API
- Internal API
- Multi-tenant API
