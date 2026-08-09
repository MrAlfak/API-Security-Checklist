# Security Review Record — 2026 Hardening

This document records the repository-wide security-guidance hardening performed in 2026.

## Reviewed areas

- Authentication and password guidance
- Authorization, BOLA/BFLA, property-level authorization
- OAuth 2.0 security
- JWT/JOSE validation and key lifecycle
- Input validation, injection, XSS, SSRF
- File upload/download security
- Resource consumption and rate limiting
- Browser-specific API controls
- GraphQL, gRPC, WebSocket, SSE
- Webhooks and replay protection
- Multi-tenant isolation
- API inventory and lifecycle
- Logging, incident response, secrets, dependencies, SBOM, provenance

## Material corrections

- Replaced password composition rules with NIST SP 800-63B-4 aligned guidance.
- Replaced generic OAuth 2.1 wording with RFC 9700 security guidance.
- Added refresh-token rotation/reuse detection and sender-constrained token options.
- Reworked JWT guidance around RFC 8725.
- Removed UUIDs as a claimed BOLA mitigation.
- Removed generic sanitization as the primary defense for SQL injection/XSS.
- Removed legacy `X-XSS-Protection: 1; mode=block` recommendations.
- Reworked upload examples to avoid trusting client MIME type and unsafe shell construction.
- Added multi-tenant, GraphQL cost, gRPC, WebSocket, webhook replay, inventory, and supply-chain coverage.

## Verification infrastructure

The repository now includes:

- machine-readable control files in `checklist/`,
- `scripts/validate_controls.rb` for structural validation,
- `scripts/security_content_regression.py` for known unsafe-guidance regression checks,
- GitHub Actions for controls/security-content and Markdown validation.

## Limitations

This review validates the repository's guidance and examples; it does not certify any downstream API implementation as secure. Implementers still need system-specific threat modeling, verification evidence, and penetration testing appropriate to risk.
