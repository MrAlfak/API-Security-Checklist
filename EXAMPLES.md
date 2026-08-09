# 💻 API Security Implementation Examples

These examples illustrate security patterns. They are **not universal drop-in production code**: adapt them to your framework, identity provider, threat model, data classification, and deployment environment, then test the negative cases.

## 1. Fail closed when secrets are missing

Do not silently generate a new production signing secret at process startup. A missing key is a configuration failure.

```javascript
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  throw new Error('JWT_SECRET is required');
}
```

For mature deployments, prefer managed keys/KMS and asymmetric signing with controlled JWKS publication/rotation when it fits the architecture.

## 2. JWT verification with explicit policy

RFC 8725 requires algorithm verification and careful validation rules. Do not trust the token header to choose arbitrary verification behavior.

```javascript
const jwt = require('jsonwebtoken');

const EXPECTED_ISSUER = 'https://identity.example.com';
const EXPECTED_AUDIENCE = 'orders-api';

function verifyAccessToken(token) {
  return jwt.verify(token, process.env.JWT_PUBLIC_KEY, {
    algorithms: ['RS256'],
    issuer: EXPECTED_ISSUER,
    audience: EXPECTED_AUDIENCE,
    clockTolerance: 5,
    complete: false,
  });
}
```

Security notes:

- Maintain different validation policies for access tokens, ID tokens, reset tokens, and other JWT types.
- Validate expected issuer/audience and token purpose, not only signature and expiration.
- Keep key selection restricted to trusted key sets. Do not use attacker-provided `kid`, `jku`, or similar headers as arbitrary file/network locations.
- Signing is not encryption; ordinary JWT payloads can be decoded by their holder.

## 3. Refresh-token rotation with reuse detection

RFC 9700 requires public clients that receive refresh tokens to use sender-constrained refresh tokens or refresh-token rotation for replay detection.

A practical server-side model stores only a hash of each refresh token and tracks its family.

```javascript
const crypto = require('crypto');

function randomToken() {
  return crypto.randomBytes(32).toString('base64url');
}

function tokenHash(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

async function rotateRefreshToken(presentedToken, context) {
  const hash = tokenHash(presentedToken);

  // Must be done transactionally / with an atomic compare-and-update.
  return db.transaction(async (tx) => {
    const current = await tx.refreshTokens.findByHashForUpdate(hash);

    if (!current) {
      throw new Error('invalid_refresh_token');
    }

    if (current.revokedAt || current.usedAt) {
      // Reuse means the token family may be compromised.
      await tx.refreshTokens.revokeFamily(current.familyId, 'refresh_token_reuse');
      throw new Error('refresh_token_reuse_detected');
    }

    if (current.expiresAt <= new Date()) {
      throw new Error('refresh_token_expired');
    }

    if (current.clientId !== context.clientId) {
      throw new Error('invalid_refresh_token');
    }

    await tx.refreshTokens.markUsed(current.id, new Date());

    const nextPlaintext = randomToken();
    await tx.refreshTokens.insert({
      familyId: current.familyId,
      parentId: current.id,
      clientId: current.clientId,
      userId: current.userId,
      tokenHash: tokenHash(nextPlaintext),
      expiresAt: context.nextExpiry,
    });

    return nextPlaintext;
  });
}
```

Important:

- Rotation must be atomic; concurrent reuse should not result in two valid descendants.
- Revoke the affected family/grant when reuse is detected.
- Bind tokens to the expected client and authorized scope/resource.
- For higher-risk cases, consider sender-constrained tokens such as DPoP or mTLS.

## 4. Password validation aligned with NIST SP 800-63B-4

Do not require arbitrary uppercase/lowercase/number/symbol composition rules.

```javascript
const Joi = require('joi');

const passwordSchema = Joi.string()
  .min(15)     // Single-factor password baseline
  .max(128)    // Application choice; allow at least 64
  .required();

async function validateNewPassword(password, accountContext) {
  const { error } = passwordSchema.validate(password);
  if (error) return { ok: false, reason: 'password_length' };

  const normalized = password.normalize('NFC');

  // Implement with a local/approved compromised-password dataset or a
  // privacy-preserving service appropriate for your environment.
  if (await compromisedPasswordBlocklist.contains(normalized, accountContext)) {
    return { ok: false, reason: 'known_or_expected_password' };
  }

  return { ok: true, normalized };
}
```

Also rate-limit online guesses and hash stored passwords with a maintained password-specific scheme such as Argon2id using parameters appropriate for your platform.

## 5. Schema validation is not generic sanitization

Use validation to enforce the expected shape and semantics. Injection prevention remains context-specific.

```javascript
const Joi = require('joi');

const updateProfileSchema = Joi.object({
  displayName: Joi.string().min(1).max(80).required(),
  locale: Joi.string().valid('en', 'fa').required(),
}).unknown(false);

function validateProfile(req, res, next) {
  const { value, error } = updateProfileSchema.validate(req.body, {
    abortEarly: false,
    stripUnknown: false,
  });

  if (error) return res.status(400).json({ error: 'invalid_request' });
  req.validatedBody = value;
  next();
}
```

Use:

- parameterized queries for SQL,
- safe query construction for NoSQL,
- output encoding for XSS,
- a dedicated HTML sanitizer only when intended HTML must be accepted,
- safe process APIs instead of concatenated shell commands.

## 6. Parameterized SQL

```javascript
async function findOrderForTenant(pool, tenantId, orderId) {
  const result = await pool.query(
    `SELECT id, tenant_id, status, total
       FROM orders
      WHERE tenant_id = $1 AND id = $2`,
    [tenantId, orderId]
  );

  return result.rows[0] ?? null;
}
```

The tenant boundary is part of the query. A UUID `orderId` would not remove the need for `tenant_id` authorization.

## 7. Object-level authorization

```javascript
app.get('/api/orders/:id', authenticate, async (req, res) => {
  const order = await findOrderForTenant(
    db,
    req.auth.tenantId,
    req.params.id
  );

  // 404 can be useful when you do not want to disclose object existence.
  if (!order) return res.status(404).json({ error: 'not_found' });

  if (!policy.canReadOrder(req.auth, order)) {
    return res.status(403).json({ error: 'forbidden' });
  }

  res.json(serializeOrderFor(req.auth, order));
});
```

Test at least:

- another user's object in the same tenant,
- another tenant's object,
- privileged vs normal roles,
- deleted/disabled membership,
- nested resources and batch endpoints.

## 8. Browser-facing response headers

Do not use legacy `X-XSS-Protection: 1; mode=block` as a modern security recommendation.

```javascript
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

  // Sensitive authenticated data: prevent storage when required.
  if (req.path.startsWith('/api/private/')) {
    res.setHeader('Cache-Control', 'no-store');
  }

  // If you intentionally set it for legacy behavior, disable the old filter.
  res.setHeader('X-XSS-Protection', '0');

  next();
});
```

CSP and frame protections primarily protect renderable browser content. Do not treat them as substitutes for API authorization.

## 9. CORS with explicit origins

CORS is a browser policy, not an authorization mechanism.

```javascript
const allowedOrigins = new Set([
  'https://app.example.com',
  'https://admin.example.com',
]);

const corsOptions = {
  origin(origin, callback) {
    if (!origin) return callback(null, false);
    return callback(null, allowedOrigins.has(origin));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
};
```

Requests from non-browser clients are not made safe or unsafe by CORS; enforce authentication and authorization independently.

## 10. Secure file upload pipeline

The client-provided MIME type is easy to spoof. Use layered validation and keep files isolated until they pass checks.

```javascript
const fs = require('fs/promises');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');

const QUARANTINE = '/srv/app-upload-quarantine'; // outside web root
const MAX_FILE_SIZE = 5 * 1024 * 1024;

function randomFilename(extension) {
  return `${crypto.randomUUID()}.${extension}`;
}

function detectAllowedType(buffer) {
  // Minimal illustrative signature checks. In production use a maintained
  // file-type parser/library and type-specific decoding/validation.
  if (buffer.length >= 3 &&
      buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) {
    return { mime: 'image/jpeg', extension: 'jpg' };
  }

  if (buffer.length >= 8 &&
      buffer.subarray(0, 8).equals(Buffer.from([0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a]))) {
    return { mime: 'image/png', extension: 'png' };
  }

  return null;
}

function clamscan(filePath) {
  return new Promise((resolve, reject) => {
    // spawn with argument array avoids shell interpolation.
    const child = spawn('clamscan', ['--no-summary', '--', filePath], {
      shell: false,
      stdio: 'ignore',
    });

    child.on('error', reject);
    child.on('close', (code) => resolve(code === 0));
  });
}

async function validateAndQuarantineUpload(upload) {
  if (upload.size > MAX_FILE_SIZE) throw new Error('file_too_large');

  const bytes = await fs.readFile(upload.path);
  const detected = detectAllowedType(bytes);
  if (!detected) throw new Error('unsupported_file_type');

  const safeName = randomFilename(detected.extension);
  const quarantinePath = path.join(QUARANTINE, safeName);

  await fs.rename(upload.path, quarantinePath);

  const clean = await clamscan(quarantinePath);
  if (!clean) {
    await fs.unlink(quarantinePath).catch(() => {});
    throw new Error('malware_detected');
  }

  // For images, decode/re-encode with a maintained image library before
  // publishing. For complex document types, consider CDR/sandboxing.
  return { quarantinePath, safeName, detected };
}
```

A complete upload service should also:

- authorize the uploader,
- limit file count and decompressed size,
- prevent archive traversal/bombs,
- isolate quarantine storage,
- use type-specific parsers,
- publish only after scanning/validation,
- authorize every later download.

## 11. Rate limiting by identity and endpoint

IP-only limiting is often bypassable and can harm users behind shared networks.

```javascript
function rateLimitKey(req) {
  const principal = req.auth?.subject ?? 'anonymous';
  const tenant = req.auth?.tenantId ?? 'none';
  const route = req.route?.path ?? req.path;
  return `${tenant}:${principal}:${req.method}:${route}`;
}
```

Use atomic/distributed counters when the application has multiple instances and add stricter policies for authentication, password reset, exports, expensive search, purchases, and other abuse-sensitive flows.

## 12. Webhook signature + replay protection

```javascript
const crypto = require('crypto');

function timingSafeHexEqual(a, b) {
  const left = Buffer.from(a, 'hex');
  const right = Buffer.from(b, 'hex');
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function verifyWebhook({ rawBody, timestamp, signature, secret }) {
  const ts = Number(timestamp);
  if (!Number.isFinite(ts)) return false;

  const ageSeconds = Math.abs(Date.now() / 1000 - ts);
  if (ageSeconds > 300) return false; // Example replay window

  const signed = `${timestamp}.${rawBody}`;
  const expected = crypto
    .createHmac('sha256', secret)
    .update(signed)
    .digest('hex');

  return timingSafeHexEqual(signature, expected);
}
```

Use the provider's documented canonicalization scheme exactly. Persist an event ID/nonce for idempotency and duplicate/replay detection when available.

## 13. SSRF-safe outbound model

The safest design is usually an explicit destination allowlist rather than accepting arbitrary URLs.

```javascript
const ALLOWED_HOSTS = new Set(['images.example.net', 'partner-api.example.org']);

function validateOutboundUrl(input) {
  const url = new URL(input);
  if (url.protocol !== 'https:') throw new Error('scheme_not_allowed');
  if (!ALLOWED_HOSTS.has(url.hostname)) throw new Error('host_not_allowed');
  if (url.username || url.password) throw new Error('userinfo_not_allowed');
  return url;
}
```

Production SSRF defenses should additionally address DNS resolution/rebinding, redirects, internal/link-local ranges, proxies, metadata services, response limits, and egress network policy.

## 14. GraphQL complexity + resolver authorization

Do not rely only on disabling introspection or limiting depth.

```javascript
const MAX_QUERY_COST = 500;

async function executeGraphQL({ document, auth, variables }) {
  const cost = calculateQueryCost(document, variables);
  if (cost > MAX_QUERY_COST) throw new Error('query_too_expensive');

  // Each resolver still enforces object/field authorization.
  return graphqlExecute({ document, contextValue: { auth }, variableValues: variables });
}
```

Also bound aliases, batching, page sizes, list fields, subscriptions, and expensive resolver fan-out.

## 15. Multi-tenant query pattern

Derive tenant context from trusted identity state, not a raw request parameter.

```javascript
async function getInvoice(req, res) {
  const tenantId = req.auth.tenantId;

  const invoice = await db.invoice.findFirst({
    where: {
      id: req.params.id,
      tenantId,
    },
  });

  if (!invoice) return res.status(404).json({ error: 'not_found' });
  return res.json(invoice);
}
```

Apply the same boundary to caches, search, object storage, exports, analytics, queues, and background jobs.

## 16. Security regression tests

Security controls need executable negative tests.

```javascript
describe('order authorization', () => {
  it('rejects cross-tenant object access', async () => {
    const response = await apiAs(tenantAUser)
      .get(`/api/orders/${tenantBOrder.id}`);

    expect([403, 404]).toContain(response.status);
    expect(response.body).not.toContain(tenantBOrder.secretNote);
  });
});
```

Recommended automated suites include:

- BOLA/BFLA/property authorization,
- tenant isolation,
- invalid issuer/audience/algorithm/token-type cases,
- expired/reused refresh tokens,
- request/schema size boundaries,
- rate-limit enforcement and bypass attempts,
- webhook replay/signature failures,
- unsafe upload types/signatures,
- GraphQL complexity/batch limits.

## References

- OWASP API Security Top 10 2023
- OWASP ASVS 5.0.0
- OWASP Cheat Sheet Series
- NIST SP 800-63B-4
- RFC 9700 (OAuth 2.0 Security Best Current Practice)
- RFC 8725 (JWT Best Current Practices)
- RFC 9449 (DPoP)
- RFC 8705 (OAuth mTLS)
