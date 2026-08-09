# 🔓 API Vulnerabilities & Abuse Cases

This guide covers the **OWASP API Security Top 10 2023** plus modern API-specific abuse cases that commonly appear in SaaS, multi-tenant, OAuth/JWT, GraphQL, gRPC, WebSocket, webhook, and distributed systems.

## OWASP API Security Top 10 2023

1. Broken Object Level Authorization (BOLA)
2. Broken Authentication
3. Broken Object Property Level Authorization
4. Unrestricted Resource Consumption
5. Broken Function Level Authorization
6. Unrestricted Access to Sensitive Business Flows
7. Server-Side Request Forgery (SSRF)
8. Security Misconfiguration
9. Improper Inventory Management
10. Unsafe Consumption of APIs

---

## 1. Broken Object Level Authorization (BOLA / IDOR)

### What happens

An authenticated caller changes an object reference and obtains an object they are not authorized to access.

```http
GET /api/orders/ORDER_BELONGING_TO_ANOTHER_USER
Authorization: Bearer <valid-user-token>
```

### Important clarification

Sequential IDs make enumeration easier, but replacing them with UUIDs **does not fix BOLA**. The server must authorize every object access.

### Test

- Access another user's object in the same tenant.
- Access another tenant's object.
- Try nested resources, exports, attachments, batch endpoints, and indirect references.
- Repeat tests for GET, PATCH, DELETE, download, search, and asynchronous jobs.

### Mitigation

- Derive authoritative identity/tenant context from trusted authentication state.
- Scope data queries by owner/tenant and apply policy checks.
- Deny by default.
- Apply the same boundary to caches, object storage, search, jobs, and exports.
- Add automated negative authorization tests.

---

## 2. Broken Authentication

### Common failure modes

- credential stuffing and brute force without effective throttling,
- weak recovery flows,
- long-lived or leaked credentials,
- missing MFA for high-impact accounts,
- incomplete token validation,
- sessions not invalidated after sensitive changes,
- insecure password storage/policy.

### Password guidance

For centrally verified single-factor passwords, NIST SP 800-63B-4 requires a minimum of 15 characters and says arbitrary composition rules must not be imposed. Use compromised/common-password blocklists, appropriate password hashing, and online guess throttling.

### Test

- username/account enumeration,
- credential stuffing behavior,
- password-reset token replay,
- MFA bypass/recovery downgrade,
- session survival after password/security changes,
- invalid issuer/audience/token type cases.

---

## 3. Broken Object Property Level Authorization

This combines risks such as excessive data exposure and mass assignment.

### Attack examples

```json
{
  "displayName": "Alice",
  "role": "admin",
  "tenantId": "victim-tenant",
  "balance": 999999
}
```

Or an API returns internal fields that the caller should never see.

### Mitigation

- Use explicit input DTO/schema allowlists.
- Separate read/write models when useful.
- Apply field/property authorization independently from object authorization.
- Use serializers/output schemas to expose only permitted fields.
- Never trust client-supplied privilege, ownership, tenant, price, or balance attributes.

---

## 4. Unrestricted Resource Consumption

### Attack surface

- huge bodies/uploads,
- excessive pagination,
- expensive filters/search/regex,
- decompression bombs,
- GraphQL complexity/aliases/batching,
- high concurrency,
- long-lived streams,
- fan-out to costly downstream services,
- asynchronous job floods.

### Mitigation

Limit:

- body/header/URL/file/decompressed size,
- page/list/batch size,
- query cost and recursion,
- execution time/deadlines,
- downstream response size,
- concurrent requests/streams/jobs,
- per-identity/tenant/resource request rates.

Application rate limiting is not complete DDoS protection; upstream/network controls may also be required.

---

## 5. Broken Function Level Authorization (BFLA)

### Example

```http
DELETE /api/admin/users/123
Authorization: Bearer <normal-user-token>
```

### Root cause

The server assumes route naming, HTTP method, UI visibility, or authentication alone is enough to protect privileged functionality.

### Mitigation

- Central policy enforcement where practical.
- Deny by default.
- Explicit privilege checks for every sensitive operation.
- Short-lived elevated privilege workflows for support/admin actions.
- Audit privileged actions and permission changes.

---

## 6. Unrestricted Access to Sensitive Business Flows

An API can be technically authenticated and authorized but still allow economically harmful automation.

### Examples

- ticket/inventory scalping,
- coupon/referral abuse,
- repeated OTP/SMS/email sends,
- mass account creation,
- scraping high-value data,
- automated reservation/purchase attempts,
- trial/credit abuse.

### Mitigation

Use business-specific abuse controls:

- velocity limits,
- per-account/device/payment/instrument limits,
- risk scoring and anomaly detection,
- proof-of-human/challenges only where justified,
- idempotency,
- transaction limits/holds,
- queue/fairness controls,
- monitoring tied to business impact.

Do not treat CAPTCHA as the only defense.

---

## 7. Server-Side Request Forgery (SSRF)

### Example

A URL-fetch feature is pointed at internal, link-local, metadata, or privileged services.

### Mitigation

- Prefer explicit destination allowlists.
- Restrict protocols.
- Validate DNS resolution and resolved IP ranges.
- Block loopback/private/link-local/metadata targets where not needed.
- Control redirects and revalidate each destination.
- Use egress firewall/network policy.
- Set strict timeouts and response-size limits.
- Avoid forwarding sensitive internal credentials/headers.
- Address DNS rebinding and alternate IP encodings.

---

## 8. Security Misconfiguration

### Examples

- debug/admin endpoints exposed,
- verbose stack traces,
- permissive CORS,
- disabled TLS validation,
- default credentials,
- unnecessary HTTP/gRPC services,
- public storage buckets,
- unsafe cloud/IAM permissions,
- stale middleware or insecure framework modes.

### Mitigation

- secure production configuration baselines,
- IaC review/scanning,
- environment separation,
- least privilege,
- config drift detection,
- automated deployment checks,
- removal/strong isolation of diagnostic endpoints.

Browser-oriented headers should be applied by context; they do not replace API authentication or authorization.

---

## 9. Improper Inventory Management

### Risks

- forgotten versions,
- shadow APIs,
- zombie deployments,
- undocumented endpoints,
- test/staging hosts exposed to production data,
- old authentication schemes still reachable,
- schema drift.

### Maintain an inventory of

- hosts and gateways,
- API versions and endpoints,
- OpenAPI/GraphQL/gRPC schemas,
- service owner,
- authentication mode,
- public/internal exposure,
- data classification,
- deprecation/EOL date,
- upstream/downstream dependencies.

Continuously compare observed traffic/deployments with the expected inventory.

---

## 10. Unsafe Consumption of APIs

Third-party and internal upstream responses are untrusted input.

### Risks

- trusting upstream HTML/JSON without validation,
- following attacker-controlled redirects,
- excessive response sizes,
- missing TLS validation,
- injecting upstream data into SQL/templates/shells,
- leaking high-privilege credentials to unnecessary destinations.

### Mitigation

- validate response schemas and semantics,
- use least-privilege credentials,
- limit destinations, redirects, response size, and timeouts,
- preserve output encoding/parameterization downstream,
- isolate risky integrations,
- monitor dependency/API behavior changes.

---

# Additional modern API threat cases

## 11. OAuth authorization-code interception/injection

Use RFC 9700 guidance:

- PKCE (`S256`) where applicable,
- exact redirect URI matching,
- secure transaction binding,
- avoid open redirects,
- reject PKCE downgrade behavior,
- restrict access-token audience and privileges.

Test modified redirect URIs, missing/mismatched verifier, authorization-code replay, and cross-client code injection.

---

## 12. Refresh-token replay

A stolen refresh token is used by both the attacker and legitimate client.

### Mitigation

For public clients, use one of the RFC 9700 replay-detection approaches:

- refresh-token rotation with family/reuse detection, or
- sender-constrained refresh tokens.

On reuse, revoke the affected active token family/grant and require a fresh authorization as appropriate.

---

## 13. JWT algorithm/key confusion

### Attacks

- accepting `alg=none`,
- HS/RS confusion,
- using attacker-controlled JWK/JWKS URLs,
- unsafe `kid` filesystem/SQL/network resolution,
- using one key across unintended algorithms/purposes.

### Mitigation

- explicit algorithm allowlist,
- fixed trusted key source,
- key-to-algorithm binding,
- issuer/audience verification,
- explicit token-type rules,
- reject all failed crypto operations.

---

## 14. Cross-JWT confusion

A token created for one purpose is accepted by another endpoint, for example an ID token accepted as an API access token or a reset token accepted as an authenticated session token.

### Mitigation

Use mutually exclusive validation policies for each token kind:

- distinct issuers/audiences where appropriate,
- explicit `typ`/purpose,
- distinct claims and keys where useful,
- endpoint-specific validation.

---

## 15. JWKS / key-rotation abuse

### Risks

- trusting arbitrary `jku`/JWK sources,
- cache poisoning,
- accepting stale/removed keys forever,
- refresh storms when an unknown `kid` appears,
- key rollover outages.

### Mitigation

- pin trusted JWKS origins/configuration,
- bounded cache lifetimes and safe refresh behavior,
- rate-limit unknown-key refreshes,
- overlap old/new keys during planned rollover,
- retire compromised keys promptly,
- monitor signing-key lifecycle events.

---

## 16. Multi-tenant isolation failure

### Common leak paths

- DB query missing tenant filter,
- shared cache key missing tenant component,
- object storage path mix-up,
- search index filtering error,
- background job using wrong tenant context,
- export/report joins across tenants,
- support/admin impersonation abuse.

### Test

Create at least two tenants and systematically attempt cross-tenant access through every direct and indirect resource path.

---

## 17. GraphQL batching, aliases, and cost amplification

Depth limits alone can be bypassed by wide queries, aliases, fragments, batching, expensive resolvers, or large lists.

### Mitigation

- complexity/cost budgets,
- alias and batch limits,
- list/page caps,
- resolver-level authorization,
- data-loader/fan-out controls,
- timeouts and concurrency limits.

Disabling introspection is not a substitute for any of these controls and should be a contextual exposure decision.

---

## 18. GraphQL field-level authorization failure

An object may be readable while a specific field (salary, secret key metadata, internal notes, tenant attributes) is not.

Apply authorization at the field/resolver/serialization layer and test fragments, aliases, nested objects, and mutations.

---

## 19. WebSocket authorization drift

Authentication during the handshake is not enough for a long-lived connection.

### Risks

- messages perform actions without per-message authorization,
- a user's role/session is revoked while connection remains privileged,
- unauthorized channel/topic subscription,
- cross-site WebSocket hijacking for browser clients.

### Mitigation

- authorize every sensitive message/subscription,
- revalidate security state as needed,
- validate browser Origin where applicable,
- limit connections, message sizes, rates, subscriptions, and fan-out.

---

## 20. gRPC exposure and resource abuse

### Risks

- unauthenticated methods,
- exposed reflection/admin services,
- missing deadlines,
- unbounded message sizes/streams,
- insecure plaintext internal assumptions.

### Mitigation

- TLS/mTLS according to trust model,
- per-method authorization,
- reflection exposure policy,
- message/deadline/concurrency/stream limits,
- workload identity and least privilege.

---

## 21. Webhook replay and signature confusion

### Risks

- signature not verified over raw/canonical payload,
- old valid request replayed,
- multiple signature schemes parsed ambiguously,
- duplicate events cause duplicate financial/business actions.

### Mitigation

- provider-defined signature verification,
- timing-safe comparison,
- signed timestamp/nonce replay window,
- secret rotation support,
- event-ID idempotency/deduplication,
- log failed signature/replay attempts.

---

## 22. File-upload content spoofing

Trusting `Content-Type` or extension alone lets malicious files masquerade as allowed types.

### Mitigation

- extension allowlist,
- signature/content detection,
- type-specific parsing/decoding,
- generated filenames,
- size/count/decompressed-size limits,
- quarantine outside web root,
- malware scan/sandbox/CDR where appropriate,
- authorization before upload and download.

---

## 23. Archive extraction and decompression bombs

### Attack

A small compressed input expands to enormous size or contains traversal paths such as `../../target`.

### Mitigation

- reject unnecessary archive formats,
- cap entries, nesting, compressed and expanded size,
- canonicalize every extraction destination,
- extract into isolated temporary storage,
- never overwrite application/system paths.

---

## 24. Cache authorization leaks

A response cached without identity/tenant/security context can be returned to another caller.

### Mitigation

- include correct authorization dimensions in cache keys,
- avoid shared caching of sensitive responses unless explicitly designed,
- use appropriate `Cache-Control`,
- invalidate on permission/data changes,
- test cross-user and cross-tenant cache behavior.

---

## 25. API key leakage and over-privilege

### Common paths

- keys in URLs/logs,
- browser/mobile code containing server secrets,
- one global key used by many customers/services,
- no scopes, owner, expiry, or revocation.

### Mitigation

Issue attributable, scoped, revocable credentials; store server credentials securely; rotate exposed keys; use workload identity or short-lived credentials where available.

---

## 26. CI/CD and software supply-chain compromise

### Risks

- malicious dependency/action,
- leaked CI secrets,
- unsigned/untracked artifacts,
- vulnerable containers/IaC,
- unprotected release branch.

### Mitigation

- dependency/SCA and secret scanning,
- pin/review CI dependencies,
- least-privilege workflow tokens,
- SBOM generation,
- container/IaC scanning,
- provenance/signing where required,
- protected release process.

---

## 27. Schema drift and undocumented behavior

A deployed API accepts fields/endpoints/methods not represented by its contract or inventory.

### Mitigation

- contract tests,
- compare gateway/runtime observations with OpenAPI/GraphQL/gRPC definitions,
- reject unknown fields where appropriate,
- alert on newly observed endpoints/versions/hosts.

---

## 28. Logging of security secrets

Never log plaintext passwords, session cookies, access/refresh tokens, API keys, private keys, password-reset tokens, or complete high-risk authentication headers.

Apply structured redaction at ingestion and verify it with tests.

---

# Testing strategy

A security review should combine:

- architecture/threat modeling,
- control verification,
- negative integration tests,
- SAST/SCA/secret scanning,
- API contract testing,
- DAST/fuzzing where suitable,
- authorization/tenant test matrices,
- abuse/business-flow testing,
- penetration testing for high-risk releases,
- monitoring/incident evidence review.

The machine-readable controls in `checklist/` provide the audit baseline; this document explains the threat model behind them.
