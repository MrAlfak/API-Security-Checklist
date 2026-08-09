# Changelog

All notable changes to this project are documented here.

The project follows Semantic Versioning for tagged releases.

## [Unreleased]

### Added
- Machine-readable security controls under `checklist/`.
- Verification criteria and evidence requirements for audit use.
- Standards mapping for OWASP API Security Top 10 2023, OWASP ASVS 5.0.0, RFC 9700, RFC 8725, RFC 9449, and RFC 8705.
- Security policy and responsible disclosure guidance.
- CI validation for Markdown and machine-readable controls.
- Coverage for multi-tenant APIs, replay resistance, shadow/zombie APIs, GraphQL cost controls, gRPC, WebSockets, webhooks, and supply-chain security.

### Changed
- Password guidance aligned with NIST SP 800-63B-4: 15-character minimum for single-factor passwords, no composition rules, compromised-password blocklists, and rate limiting.
- OAuth guidance aligned with RFC 9700, including PKCE, exact redirect URI matching, refresh-token replay detection, sender-constrained tokens, and least-privilege audiences/scopes.
- JWT guidance aligned with RFC 8725, including explicit algorithm allowlists, issuer/audience validation, explicit token typing, cross-JWT confusion prevention, and key/algorithm binding.
- Security controls are now scoped by API type instead of treating browser-only controls as universal API requirements.
- Input validation guidance now distinguishes validation from injection prevention and output encoding.

### Fixed
- Removed outdated password complexity guidance.
- Removed `X-XSS-Protection: 1; mode=block` recommendations.
- Removed UUIDs as a claimed mitigation for BOLA; UUIDs are documented only as defense-in-depth against enumeration.
- Removed generic input sanitization as a claimed primary defense for SQL injection and XSS.
- Corrected refresh-token examples to rotate tokens and detect reuse.
- Corrected JWT examples to fail closed when signing keys are missing.
- Corrected file-upload examples to verify content signatures, avoid trusting client MIME types, store outside the web root, and scan before release.
