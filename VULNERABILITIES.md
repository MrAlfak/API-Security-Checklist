# 🔓 Common API Vulnerabilities & Mitigation Guide
### Based on OWASP API Security Top 10 and real-world scenarios

---

## Table of Contents
1. [Broken Object Level Authorization (BOLA)](#1-broken-object-level-authorization-bola)
2. [Broken Authentication](#2-broken-authentication)
3. [Broken Object Property Level Authorization](#3-broken-object-property-level-authorization)
4. [Unrestricted Resource Consumption](#4-unrestricted-resource-consumption)
5. [Broken Function Level Authorization](#5-broken-function-level-authorization)
6. [Unrestricted Access to Sensitive Business Flows](#6-unrestricted-access-to-sensitive-business-flows)
7. [Server Side Request Forgery (SSRF)](#7-server-side-request-forgery-ssrf)
8. [Security Misconfiguration](#8-security-misconfiguration)
9. [Improper Inventory Management](#9-improper-inventory-management)
10. [Unsafe Consumption of APIs](#10-unsafe-consumption-of-apis)

---

## 1. Broken Object Level Authorization (BOLA)

### Description
Also known as IDOR (Insecure Direct Object Reference). Attackers can access or modify objects by manipulating object IDs in API requests.

### Example Attack
```http
GET /api/users/123/profile
Authorization: Bearer <user_456_token>

# Attacker with user 456 token can access user 123's profile
```

### Impact
- Unauthorized data access
- Data modification or deletion
- Privacy violations
- Compliance issues (GDPR, HIPAA)

### Mitigation

#### ❌ Vulnerable Code
```javascript
app.get('/api/documents/:id', authenticateUser, async (req, res) => {
  const document = await Document.findById(req.params.id);
  res.json(document); // No ownership check!
});
```

#### ✅ Secure Code
```javascript
app.get('/api/documents/:id', authenticateUser, async (req, res) => {
  const document = await Document.findById(req.params.id);
  
  // Verify ownership
  if (!document) {
    return res.status(404).json({ error: 'Document not found' });
  }
  
  if (document.userId !== req.user.id && !req.user.isAdmin) {
    return res.status(403).json({ error: 'Access denied' });
  }
  
  res.json(document);
});
```

### Best Practices
- Always verify user authorization for every object access
- Use UUIDs instead of sequential IDs
- Implement proper access control checks
- Log unauthorized access attempts
- Use database-level row security policies

---

## 2. Broken Authentication

### Description
Weak authentication mechanisms allow attackers to compromise authentication tokens or exploit implementation flaws.

### Common Issues
- Weak password requirements
- No rate limiting on login
- Predictable tokens
- Missing MFA
- Insecure password reset
- Token not properly validated

### Example Attack
```python
# Brute force attack without rate limiting
for password in password_list:
    response = requests.post('https://api.example.com/login', 
                            json={'username': 'admin', 'password': password})
    if response.status_code == 200:
        print(f"Password found: {password}")
        break
```

### Impact
- Account takeover
- Identity theft
- Unauthorized access to sensitive data
- Privilege escalation

### Mitigation

#### Implement Strong Password Policy
```javascript
const passwordSchema = Joi.string()
  .min(12)
  .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
  .required()
  .messages({
    'string.min': 'Password must be at least 12 characters',
    'string.pattern.base': 'Password must contain uppercase, lowercase, number, and special character'
  });
```

#### Implement Account Lockout
```javascript
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_DURATION = 15 * 60 * 1000; // 15 minutes

async function checkLoginAttempts(username) {
  const key = `login_attempts:${username}`;
  const attempts = await redis.get(key) || 0;
  
  if (attempts >= MAX_LOGIN_ATTEMPTS) {
    const ttl = await redis.ttl(key);
    throw new Error(`Account locked. Try again in ${Math.ceil(ttl / 60)} minutes`);
  }
  
  return attempts;
}

async function recordFailedLogin(username) {
  const key = `login_attempts:${username}`;
  const attempts = await redis.incr(key);
  
  if (attempts === 1) {
    await redis.expire(key, LOCKOUT_DURATION / 1000);
  }
}
```

### Best Practices
- Enforce strong password policies
- Implement MFA for sensitive accounts
- Use secure password hashing (Argon2, bcrypt)
- Implement rate limiting on authentication endpoints
- Use secure session management
- Implement account lockout after failed attempts
- Use HTTPS for all authentication requests

---

## 3. Broken Object Property Level Authorization

### Description
API exposes more object properties than necessary, or allows modification of properties that should be read-only.

### Example Attack
```http
# Mass assignment attack
PATCH /api/users/123
{
  "name": "John Doe",
  "email": "john@example.com",
  "isAdmin": true,  # Attacker tries to escalate privileges
  "balance": 1000000  # Attacker tries to modify balance
}
```

### Impact
- Privilege escalation
- Data manipulation
- Unauthorized access to sensitive fields

### Mitigation

#### ❌ Vulnerable Code
```javascript
app.patch('/api/users/:id', async (req, res) => {
  // Accepts all fields from request body
  await User.update(req.params.id, req.body);
  res.json({ message: 'Updated' });
});
```

#### ✅ Secure Code
```javascript
app.patch('/api/users/:id', async (req, res) => {
  // Whitelist allowed fields
  const allowedFields = ['name', 'email', 'phone', 'address'];
  const updateData = {};
  
  for (const field of allowedFields) {
    if (req.body[field] !== undefined) {
      updateData[field] = req.body[field];
    }
  }
  
  await User.update(req.params.id, updateData);
  res.json({ message: 'Updated' });
});
```

### Best Practices
- Use DTOs (Data Transfer Objects) to define allowed fields
- Implement field-level authorization
- Separate read and write models
- Never trust client input for sensitive fields
- Use serializers to control response data

---

## 4. Unrestricted Resource Consumption

### Description
API doesn't limit the size or number of resources that can be requested, leading to DoS attacks.

### Example Attack
```http
# Request massive amount of data
GET /api/users?limit=999999999

# Upload huge file
POST /api/upload
Content-Length: 10000000000

# Expensive operation without limit
POST /api/search
{
  "query": ".*",  # Regex that causes catastrophic backtracking
  "depth": 100
}
```

### Impact
- Service unavailability
- Increased costs
- Performance degradation
- Resource exhaustion

### Mitigation

#### Implement Pagination Limits
```javascript
app.get('/api/users', async (req, res) => {
  const DEFAULT_LIMIT = 20;
  const MAX_LIMIT = 100;
  
  let limit = parseInt(req.query.limit) || DEFAULT_LIMIT;
  limit = Math.min(limit, MAX_LIMIT);
  
  const page = parseInt(req.query.page) || 1;
  const offset = (page - 1) * limit;
  
  const users = await User.findAll({ limit, offset });
  const total = await User.count();
  
  res.json({
    data: users,
    pagination: {
      page,
      limit,
      total,
      pages: Math.ceil(total / limit)
    }
  });
});
```

#### Limit Request Size
```javascript
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// For file uploads
const upload = multer({
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB
    files: 5
  }
});
```

### Best Practices
- Implement rate limiting
- Set maximum page size for pagination
- Limit request payload size
- Set timeouts for long-running operations
- Implement query complexity limits (GraphQL)
- Monitor resource usage

---

## 5. Broken Function Level Authorization

### Description
API doesn't properly enforce authorization checks for different user roles and functions.

### Example Attack
```http
# Regular user tries to access admin function
DELETE /api/users/456
Authorization: Bearer <regular_user_token>

# User tries to access internal API
GET /api/internal/metrics
Authorization: Bearer <user_token>
```

### Impact
- Privilege escalation
- Unauthorized administrative actions
- Data manipulation or deletion

### Mitigation

#### ❌ Vulnerable Code
```javascript
app.delete('/api/users/:id', authenticateUser, async (req, res) => {
  // No role check!
  await User.delete(req.params.id);
  res.json({ message: 'User deleted' });
});
```

#### ✅ Secure Code
```javascript
// Role-based middleware
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    
    next();
  };
}

// Usage
app.delete('/api/users/:id', 
  authenticateUser, 
  requireRole('admin', 'superadmin'), 
  async (req, res) => {
    await User.delete(req.params.id);
    res.json({ message: 'User deleted' });
  }
);
```

### Best Practices
- Implement RBAC (Role-Based Access Control)
- Deny by default, allow explicitly
- Separate admin and user routes
- Use middleware for authorization checks
- Log all administrative actions
- Regular audit of permissions

---

## 6. Unrestricted Access to Sensitive Business Flows

### Description
API doesn't protect against automated abuse of sensitive business functions.

### Example Attack
```python
# Automated ticket purchasing
for i in range(1000):
    requests.post('https://api.example.com/tickets/purchase',
                 json={'event_id': 123, 'quantity': 10})

# Automated account creation for spam
for email in email_list:
    requests.post('https://api.example.com/register',
                 json={'email': email, 'password': 'password123'})
```

### Impact
- Business logic abuse
- Financial loss
- Unfair advantage
- Service degradation

### Mitigation

#### Implement CAPTCHA for Sensitive Operations
```javascript
const axios = require('axios');

async function verifyCaptcha(token) {
  const response = await axios.post(
    'https://www.google.com/recaptcha/api/siteverify',
    null,
    {
      params: {
        secret: process.env.RECAPTCHA_SECRET,
        response: token
      }
    }
  );
  
  return response.data.success && response.data.score > 0.5;
}

app.post('/api/tickets/purchase', async (req, res) => {
  const { captchaToken, ...purchaseData } = req.body;
  
  // Verify CAPTCHA
  const isHuman = await verifyCaptcha(captchaToken);
  if (!isHuman) {
    return res.status(400).json({ error: 'CAPTCHA verification failed' });
  }
  
  // Process purchase
  const ticket = await purchaseTicket(purchaseData);
  res.json(ticket);
});
```

#### Implement Device Fingerprinting
```javascript
app.post('/api/sensitive-action', async (req, res) => {
  const fingerprint = req.headers['x-device-fingerprint'];
  const userId = req.user.id;
  
  // Check if this device has performed too many actions
  const key = `device_actions:${fingerprint}`;
  const count = await redis.incr(key);
  
  if (count === 1) {
    await redis.expire(key, 3600); // 1 hour window
  }
  
  if (count > 10) {
    return res.status(429).json({ 
      error: 'Too many requests from this device' 
    });
  }
  
  // Process action
  res.json({ success: true });
});
```

### Best Practices
- Implement CAPTCHA for sensitive operations
- Use device fingerprinting
- Implement velocity checks
- Add delays for suspicious behavior
- Monitor for unusual patterns
- Implement transaction limits

---

## 7. Server Side Request Forgery (SSRF)

### Description
API accepts URLs from users and fetches them without proper validation, allowing attackers to access internal resources.

### Example Attack
```http
POST /api/fetch-url
{
  "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
}

# Or accessing internal services
{
  "url": "http://localhost:6379/CONFIG GET *"
}
```

### Impact
- Access to internal services
- Cloud metadata exposure
- Port scanning
- Data exfiltration

### Mitigation

#### ✅ Secure URL Fetching
```javascript
const axios = require('axios');
const { URL } = require('url');

// Whitelist of allowed domains
const ALLOWED_DOMAINS = [
  'api.example.com',
  'cdn.example.com'
];

// Blacklist of dangerous IPs/ranges
const BLOCKED_IPS = [
  '127.0.0.1',
  '0.0.0.0',
  '169.254.169.254', // AWS metadata
  '::1'
];

function isAllowedURL(urlString) {
  try {
    const url = new URL(urlString);
    
    // Only allow HTTP/HTTPS
    if (!['http:', 'https:'].includes(url.protocol)) {
      return false;
    }
    
    // Check if domain is whitelisted
    if (!ALLOWED_DOMAINS.includes(url.hostname)) {
      return false;
    }
    
    // Check for blocked IPs
    if (BLOCKED_IPS.includes(url.hostname)) {
      return false;
    }
    
    // Check for private IP ranges
    if (url.hostname.startsWith('10.') || 
        url.hostname.startsWith('192.168.') ||
        url.hostname.startsWith('172.')) {
      return false;
    }
    
    return true;
  } catch (error) {
    return false;
  }
}

app.post('/api/fetch-url', async (req, res) => {
  const { url } = req.body;
  
  if (!isAllowedURL(url)) {
    return res.status(400).json({ error: 'Invalid or disallowed URL' });
  }
  
  try {
    const response = await axios.get(url, {
      timeout: 5000,
      maxRedirects: 0, // Don't follow redirects
      maxContentLength: 1024 * 1024 // 1MB limit
    });
    
    res.json({ data: response.data });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch URL' });
  }
});
```

### Best Practices
- Whitelist allowed domains
- Validate and sanitize URLs
- Block access to private IP ranges
- Disable redirects or limit them
- Use network segmentation
- Implement timeout limits

---

## 8. Security Misconfiguration

### Description
Improper security configuration of the API, including default credentials, verbose errors, missing patches, etc.

### Common Issues
- Default credentials
- Unnecessary features enabled
- Missing security headers
- Verbose error messages
- Outdated software
- Exposed debug endpoints

### Example Attack
```http
# Accessing debug endpoint
GET /api/debug/config

# Exploiting verbose errors
GET /api/users/invalid_id
# Response exposes database structure and queries
```

### Impact
- Information disclosure
- Unauthorized access
- System compromise

### Mitigation

#### Secure Configuration Checklist
```javascript
// 1. Disable debug mode in production
if (process.env.NODE_ENV === 'production') {
  app.set('env', 'production');
  app.disable('x-powered-by');
}

// 2. Implement proper error handling
app.use((err, req, res, next) => {
  // Log full error internally
  console.error(err.stack);
  
  // Send generic error to client
  res.status(err.status || 500).json({
    error: process.env.NODE_ENV === 'production' 
      ? 'Internal server error' 
      : err.message
  });
});

// 3. Remove unnecessary endpoints
if (process.env.NODE_ENV === 'production') {
  // Don't register debug routes
} else {
  app.get('/debug/config', (req, res) => {
    res.json(config);
  });
}

// 4. Set security headers
app.use(helmet());

// 5. Validate environment variables
const requiredEnvVars = ['DATABASE_URL', 'JWT_SECRET', 'API_KEY'];
for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    throw new Error(`Missing required environment variable: ${envVar}`);
  }
}
```

### Best Practices
- Use security headers
- Disable unnecessary features
- Keep software updated
- Use environment-specific configurations
- Regular security audits
- Implement proper error handling
- Remove default credentials

---

## 9. Improper Inventory Management

### Description
Lack of proper documentation and inventory of API endpoints, versions, and environments.

### Common Issues
- Undocumented endpoints
- Old API versions still accessible
- Shadow APIs
- Lack of retirement process
- Missing API catalog

### Impact
- Forgotten endpoints remain vulnerable
- Old versions with known vulnerabilities
- Difficulty in security assessment
- Compliance issues

### Mitigation

#### API Inventory Management
```yaml
# api-inventory.yaml
apis:
  - name: User API
    version: v2
    status: active
    endpoints:
      - path: /api/v2/users
        methods: [GET, POST]
        authentication: required
        rate_limit: 100/minute
      - path: /api/v2/users/:id
        methods: [GET, PUT, DELETE]
        authentication: required
        authorization: owner_or_admin
    
  - name: User API
    version: v1
    status: deprecated
    sunset_date: 2024-12-31
    migration_guide: https://docs.example.com/migration/v1-to-v2
```

#### Implement API Versioning
```javascript
// Sunset old API versions
app.use('/api/v1/*', (req, res, next) => {
  res.set('Sunset', 'Sat, 31 Dec 2024 23:59:59 GMT');
  res.set('Deprecation', 'true');
  res.set('Link', '<https://docs.example.com/migration>; rel="sunset"');
  next();
});

// Block access to retired versions
app.use('/api/v0/*', (req, res) => {
  res.status(410).json({
    error: 'This API version has been retired',
    message: 'Please upgrade to v2',
    documentation: 'https://docs.example.com/api/v2'
  });
});
```

### Best Practices
- Maintain API inventory
- Document all endpoints
- Implement versioning strategy
- Set sunset dates for old versions
- Regular API audits
- Automated discovery tools
- Proper retirement process

---

## 10. Unsafe Consumption of APIs

### Description
API consumes data from third-party APIs without proper validation and security checks.

### Example Attack
```javascript
// Vulnerable: Trusting third-party API response
const userData = await thirdPartyAPI.getUser(userId);
await database.query(`INSERT INTO users VALUES ('${userData.name}')`);
// If third-party is compromised, SQL injection possible
```

### Impact
- Data injection
- System compromise
- Chain attacks
- Data corruption

### Mitigation

#### ✅ Secure Third-Party API Consumption
```javascript
const Joi = require('joi');

// Define expected schema for third-party data
const thirdPartyUserSchema = Joi.object({
  id: Joi.string().uuid().required(),
  name: Joi.string().max(100).required(),
  email: Joi.string().email().required(),
  age: Joi.number().integer().min(0).max(150).optional()
});

async function fetchAndValidateUser(userId) {
  try {
    // Fetch from third-party API with timeout
    const response = await axios.get(
      `https://third-party-api.com/users/${userId}`,
      {
        timeout: 5000,
        headers: {
          'Authorization': `Bearer ${process.env.THIRD_PARTY_API_KEY}`
        }
      }
    );
    
    // Validate response structure
    const { error, value } = thirdPartyUserSchema.validate(response.data, {
      stripUnknown: true // Remove unexpected fields
    });
    
    if (error) {
      throw new Error(`Invalid data from third-party API: ${error.message}`);
    }
    
    // Sanitize data before using
    const sanitizedUser = {
      id: value.id,
      name: sanitizeString(value.name),
      email: sanitizeString(value.email),
      age: value.age
    };
    
    return sanitizedUser;
  } catch (error) {
    // Log error but don't expose details
    console.error('Third-party API error:', error);
    throw new Error('Failed to fetch user data');
  }
}

// Use parameterized queries
async function saveUser(user) {
  await database.query(
    'INSERT INTO users (id, name, email, age) VALUES ($1, $2, $3, $4)',
    [user.id, user.name, user.email, user.age]
  );
}
```

### Best Practices
- Validate all third-party data
- Use schema validation
- Implement timeouts
- Sanitize before using
- Use parameterized queries
- Monitor third-party API health
- Have fallback mechanisms
- Verify SSL certificates

---

## Additional Resources

- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [API Security Best Practices](https://apisecurity.io/)
- [CWE Top 25](https://cwe.mitre.org/top25/)

---

**Remember:** Security is an ongoing process, not a one-time task. Regularly review and update your security measures!
