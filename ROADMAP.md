# Roadmap

This roadmap shows the direction of API Security Checklist. It is intentionally practical: every major addition should improve verification, automation, protocol coverage, or contributor usability.

## Current: v2.x

- [x] Audit-ready control format with stable IDs
- [x] 65 machine-readable controls across 12 control families
- [x] Full English/Persian parity for requirements, verification steps, and evidence
- [x] OWASP API Security Top 10 2023 coverage
- [x] OWASP ASVS 5.0.0 alignment
- [x] OAuth Security BCP (RFC 9700) and JWT BCP (RFC 8725)
- [x] REST, GraphQL, gRPC, WebSocket, webhook, and multi-tenant coverage
- [x] CI validation for control structure and security-guidance regressions
- [x] Versioned GitHub releases

## Next

### Better automation

- [ ] Publish a JSON representation of the YAML control catalog
- [ ] Add JSON Schema for machine validation and editor autocomplete
- [ ] Add a lightweight CLI to filter controls by severity and API scope
- [ ] Export review templates to CSV/JSON for audit workflows
- [ ] Generate a human-readable control catalog from the source YAML

### Better mappings

- [ ] Expand ASVS 5.0 control-level mappings
- [ ] Add CWE mappings where useful and unambiguous
- [ ] Add NIST and selected cloud-security mappings where they improve implementation decisions
- [ ] Add protocol-specific reference mapping for OAuth/OIDC/JOSE controls

### Better protocol coverage

- [ ] Expand OpenID Connect-specific controls
- [ ] Add API gateway and service-mesh control families
- [ ] Add event-driven and asynchronous API security guidance
- [ ] Expand HTTP/2 and HTTP/3 resource-exhaustion considerations
- [ ] Expand signed request and non-repudiation patterns where appropriate

### Better contributor experience

- [ ] Add generated control statistics to releases
- [ ] Add more secure implementation examples across common stacks
- [ ] Add community-requested controls with reproducible verification steps
- [ ] Improve Persian security terminology consistency through contributor review

## How to help

Good contributions are small, testable, and backed by authoritative references. Useful ways to help include:

- propose a missing attack/control,
- improve a verification step,
- add an authoritative reference,
- improve a Persian translation,
- add a secure implementation example,
- report a stale or misleading recommendation.

See [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

If the project is useful to you, starring it helps other developers and security teams discover it.
