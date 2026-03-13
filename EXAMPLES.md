# 💻 API Security Implementation Examples
### Practical code examples for implementing security measures

---

## Table of Contents
- [Authentication Examples](#authentication-examples)
- [Input Validation Examples](#input-validation-examples)
- [Rate Limiting Examples](#rate-limiting-examples)
- [Security Headers Examples](#security-headers-examples)
- [Database Security Examples](#database-security-examples)
- [JWT Implementation Examples](#jwt-implementation-examples)
- [CORS Configuration Examples](#cors-configuration-examples)
- [File Upload Security Examples](#file-upload-security-examples)

---

## Authentication Examples

### Node.js/Express - JWT Authentication Middleware

```javascript
const jwt = require('jsonwebtoken');

// Middleware to verify JWT token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ['HS256'], // Enforce algorithm
      issuer: 'your-api-name',
      audience: 'your-app-name'
    });
    
    req.user = decoded;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired' });
    }
    return res.status(403).json({ error: 'Invalid token' });
  }
}

// Usage
app.get('/api/protected', authenticateToken, (req, res) => {
  res.json({ message: 'Protected data', user: req.user });
});
```

### Python/Flask - OAuth2 with PKCE

```python
from flask import Flask, request, jsonify
from authlib.integrations.flask_client import OAuth
import secrets

app = Flask(__name__)
oauth = OAuth(app)

# Configure OAuth provider
oauth.register(
    name='provider',
    client_id='YOUR_CLIENT_ID',
    client_secret='YOUR_CLIENT_SECRET',
    authorize_url='https://provider.com/oauth/authorize',
    access_token_url='https://provider.com/oauth/token',
    client_kwargs={
        'scope': 'openid profile email',
        'code_challenge_method': 'S256'  # PKCE
    }
)

@app.route('/login')
def login():
    # Generate code verifier and challenge for PKCE
    code_verifier = secrets.token_urlsafe(64)
    redirect_uri = url_for('authorize', _external=True)
    
    return oauth.provider.authorize_redirect(
        redirect_uri,
        code_verifier=code_verifier
    )
```

---

## Input Validation Examples

### Node.js - Using Joi for Schema Validation

```javascript
const Joi = require('joi');

// Define validation schema
const userSchema = Joi.object({
  username: Joi.string()
    .alphanum()
    .min(3)
    .max(30)
    .required(),
  
  email: Joi.string()
    .email()
    .required(),
  
  password: Joi.string()
    .pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{12,}$'))
    .required()
    .messages({
      'string.pattern.base': 'Password must be at least 12 characters with uppercase, lowercase, number, and special character'
    }),
  
  age: Joi.number()
    .integer()
    .min(18)
    .max(120)
    .optional()
});

// Validation middleware
function validateUser(req, res, next) {
  const { error, value } = userSchema.validate(req.body, {
    abortEarly: false, // Return all errors
    stripUnknown: true // Remove unknown fields
  });

  if (error) {
    return res.status(400).json({
      error: 'Validation failed',
      details: error.details.map(d => ({
        field: d.path.join('.'),
        message: d.message
      }))
    });
  }

  req.validatedData = value;
  next();
}

// Usage
app.post('/api/users', validateUser, async (req, res) => {
  // req.validatedData contains sanitized input
  const user = await createUser(req.validatedData);
  res.status(201).json(user);
});
```

### Python - Input Sanitization

```python
from flask import Flask, request, jsonify
from bleach import clean
import re

app = Flask(__name__)

def sanitize_input(data):
    """Sanitize user input to prevent XSS"""
    if isinstance(data, str):
        # Remove HTML tags and dangerous characters
        return clean(data, tags=[], strip=True)
    elif isinstance(data, dict):
        return {k: sanitize_input(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [sanitize_input(item) for item in data]
    return data

def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

@app.route('/api/contact', methods=['POST'])
def contact():
    data = request.get_json()
    
    # Sanitize all inputs
    sanitized_data = sanitize_input(data)
    
    # Validate email
    if not validate_email(sanitized_data.get('email', '')):
        return jsonify({'error': 'Invalid email format'}), 400
    
    # Process sanitized data
    return jsonify({'message': 'Contact form submitted'}), 200
```

---

## Rate Limiting Examples

### Node.js/Express - Rate Limiting with Redis

```javascript
const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis');
const Redis = require('ioredis');

const redis = new Redis({
  host: process.env.REDIS_HOST,
  port: process.env.REDIS_PORT
});

// Global rate limiter
const globalLimiter = rateLimit({
  store: new RedisStore({
    client: redis,
    prefix: 'rl:global:'
  }),
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per window
  message: 'Too many requests, please try again later',
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    res.status(429).json({
      error: 'Rate limit exceeded',
      retryAfter: req.rateLimit.resetTime
    });
  }
});

// Strict limiter for authentication endpoints
const authLimiter = rateLimit({
  store: new RedisStore({
    client: redis,
    prefix: 'rl:auth:'
  }),
  windowMs: 15 * 60 * 1000,
  max: 5, // Only 5 login attempts per 15 minutes
  skipSuccessfulRequests: true, // Don't count successful logins
  message: 'Too many login attempts, please try again later'
});

// Apply limiters
app.use('/api/', globalLimiter);
app.use('/api/auth/login', authLimiter);
```

### Python/Flask - Custom Rate Limiting

```python
from flask import Flask, request, jsonify
from functools import wraps
import redis
import time

app = Flask(__name__)
redis_client = redis.Redis(host='localhost', port=6379, decode_responses=True)

def rate_limit(max_requests=100, window=60):
    """
    Rate limiting decorator
    max_requests: Maximum number of requests
    window: Time window in seconds
    """
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            # Use IP address as identifier
            identifier = request.remote_addr
            key = f"rate_limit:{identifier}:{f.__name__}"
            
            # Get current request count
            current = redis_client.get(key)
            
            if current is None:
                # First request in window
                redis_client.setex(key, window, 1)
            elif int(current) >= max_requests:
                # Rate limit exceeded
                ttl = redis_client.ttl(key)
                return jsonify({
                    'error': 'Rate limit exceeded',
                    'retry_after': ttl
                }), 429
            else:
                # Increment counter
                redis_client.incr(key)
            
            return f(*args, **kwargs)
        return wrapped
    return decorator

# Usage
@app.route('/api/data')
@rate_limit(max_requests=10, window=60)
def get_data():
    return jsonify({'data': 'some data'})

@app.route('/api/auth/login', methods=['POST'])
@rate_limit(max_requests=5, window=900)  # 5 attempts per 15 minutes
def login():
    # Login logic here
    return jsonify({'token': 'jwt_token'})
```

---

## Security Headers Examples

### Node.js/Express - Using Helmet

```javascript
const helmet = require('helmet');
const express = require('express');

const app = express();

// Apply all helmet defaults
app.use(helmet());

// Custom security headers configuration
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
    scriptSrc: ["'self'"],
    imgSrc: ["'self'", "data:", "https:"],
    connectSrc: ["'self'", "https://api.yourdomain.com"],
    fontSrc: ["'self'", "https://fonts.gstatic.com"],
    objectSrc: ["'none'"],
    mediaSrc: ["'self'"],
    frameSrc: ["'none'"],
  },
}));

// HSTS - Force HTTPS
app.use(helmet.hsts({
  maxAge: 31536000, // 1 year
  includeSubDomains: true,
  preload: true
}));

// Prevent clickjacking
app.use(helmet.frameguard({ action: 'deny' }));

// Disable X-Powered-By header
app.disable('x-powered-by');

// Custom security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  next();
});
```

### Python/Flask - Security Headers

```python
from flask import Flask
from flask_talisman import Talisman

app = Flask(__name__)

# Configure Talisman for security headers
csp = {
    'default-src': "'self'",
    'script-src': "'self'",
    'style-src': ["'self'", "'unsafe-inline'"],
    'img-src': ["'self'", "data:", "https:"],
    'font-src': ["'self'", "https://fonts.gstatic.com"],
    'connect-src': "'self'",
    'frame-ancestors': "'none'",
}

Talisman(app,
    force_https=True,
    strict_transport_security=True,
    strict_transport_security_max_age=31536000,
    content_security_policy=csp,
    content_security_policy_nonce_in=['script-src'],
    referrer_policy='strict-origin-when-cross-origin',
    feature_policy={
        'geolocation': "'none'",
        'microphone': "'none'",
        'camera': "'none'"
    }
)

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response
```

---

## Database Security Examples

### Node.js - Parameterized Queries with PostgreSQL

```javascript
const { Pool } = require('pg');

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
  ssl: {
    rejectUnauthorized: true,
    ca: fs.readFileSync('/path/to/ca-certificate.crt').toString()
  }
});

// ❌ BAD - Vulnerable to SQL Injection
async function getUserBad(userId) {
  const query = `SELECT * FROM users WHERE id = ${userId}`;
  const result = await pool.query(query);
  return result.rows[0];
}

// ✅ GOOD - Using parameterized query
async function getUserGood(userId) {
  const query = 'SELECT * FROM users WHERE id = $1';
  const result = await pool.query(query, [userId]);
  return result.rows[0];
}

// ✅ GOOD - Using ORM (Sequelize)
const { Sequelize, DataTypes } = require('sequelize');

const sequelize = new Sequelize(process.env.DATABASE_URL, {
  dialect: 'postgres',
  dialectOptions: {
    ssl: {
      require: true,
      rejectUnauthorized: true
    }
  },
  logging: false
});

const User = sequelize.define('User', {
  username: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    validate: {
      isEmail: true
    }
  }
});

// Safe query with ORM
async function findUser(username) {
  return await User.findOne({
    where: { username: username }
  });
}
```

### Python - SQLAlchemy ORM

```python
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool
import os

# Database connection with SSL
DATABASE_URL = os.getenv('DATABASE_URL')
engine = create_engine(
    DATABASE_URL,
    connect_args={
        'sslmode': 'require',
        'sslrootcert': '/path/to/ca-certificate.crt'
    },
    poolclass=NullPool,  # Disable connection pooling for security
    echo=False  # Don't log SQL queries in production
)

Base = declarative_base()
Session = sessionmaker(bind=engine)

class User(Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), nullable=False)

# ❌ BAD - Vulnerable to SQL Injection
def get_user_bad(user_id):
    session = Session()
    query = f"SELECT * FROM users WHERE id = {user_id}"
    result = session.execute(query)
    return result.fetchone()

# ✅ GOOD - Using ORM (safe from SQL injection)
def get_user_good(user_id):
    session = Session()
    try:
        user = session.query(User).filter(User.id == user_id).first()
        return user
    finally:
        session.close()

# ✅ GOOD - Using parameterized query
def get_user_parameterized(user_id):
    session = Session()
    try:
        query = "SELECT * FROM users WHERE id = :id"
        result = session.execute(query, {'id': user_id})
        return result.fetchone()
    finally:
        session.close()
```

---

## JWT Implementation Examples

### Node.js - Complete JWT Implementation

```javascript
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Generate secure secret (do this once and store in env)
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || crypto.randomBytes(64).toString('hex');

// Token blacklist (use Redis in production)
const tokenBlacklist = new Set();

function generateAccessToken(user) {
  return jwt.sign(
    {
      userId: user.id,
      email: user.email,
      role: user.role
    },
    JWT_SECRET,
    {
      expiresIn: '15m', // Short-lived access token
      issuer: 'your-api',
      audience: 'your-app',
      algorithm: 'HS256'
    }
  );
}

function generateRefreshToken(user) {
  return jwt.sign(
    {
      userId: user.id,
      tokenVersion: user.tokenVersion // For token revocation
    },
    JWT_REFRESH_SECRET,
    {
      expiresIn: '7d', // Longer-lived refresh token
      issuer: 'your-api',
      audience: 'your-app',
      algorithm: 'HS256'
    }
  );
}

function verifyAccessToken(token) {
  try {
    // Check if token is blacklisted
    if (tokenBlacklist.has(token)) {
      throw new Error('Token has been revoked');
    }

    const decoded = jwt.verify(token, JWT_SECRET, {
      issuer: 'your-api',
      audience: 'your-app',
      algorithms: ['HS256']
    });

    return decoded;
  } catch (error) {
    throw new Error(`Token verification failed: ${error.message}`);
  }
}

function revokeToken(token) {
  tokenBlacklist.add(token);
  // In production, store in Redis with TTL matching token expiration
}

// Login endpoint
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  
  // Verify credentials (implement your logic)
  const user = await authenticateUser(email, password);
  
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const accessToken = generateAccessToken(user);
  const refreshToken = generateRefreshToken(user);

  // Store refresh token in httpOnly cookie
  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: true, // HTTPS only
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
  });

  res.json({ accessToken });
});

// Refresh token endpoint
app.post('/api/auth/refresh', async (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    return res.status(401).json({ error: 'Refresh token required' });
  }

  try {
    const decoded = jwt.verify(refreshToken, JWT_REFRESH_SECRET, {
      issuer: 'your-api',
      audience: 'your-app',
      algorithms: ['HS256']
    });

    // Verify token version (for revocation)
    const user = await getUserById(decoded.userId);
    if (user.tokenVersion !== decoded.tokenVersion) {
      return res.status(401).json({ error: 'Token has been revoked' });
    }

    const newAccessToken = generateAccessToken(user);
    res.json({ accessToken: newAccessToken });
  } catch (error) {
    res.status(403).json({ error: 'Invalid refresh token' });
  }
});

// Logout endpoint
app.post('/api/auth/logout', authenticateToken, (req, res) => {
  const token = req.headers['authorization'].split(' ')[1];
  revokeToken(token);
  
  res.clearCookie('refreshToken');
  res.json({ message: 'Logged out successfully' });
});
```

---

## CORS Configuration Examples

### Node.js/Express - Secure CORS Setup

```javascript
const cors = require('cors');

// ❌ BAD - Allow all origins
app.use(cors());

// ✅ GOOD - Whitelist specific origins
const allowedOrigins = [
  'https://yourdomain.com',
  'https://app.yourdomain.com',
  process.env.NODE_ENV === 'development' ? 'http://localhost:3000' : null
].filter(Boolean);

const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (mobile apps, Postman, etc.)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true, // Allow cookies
  optionsSuccessStatus: 200,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  exposedHeaders: ['X-Total-Count', 'X-Page-Number'],
  maxAge: 86400 // 24 hours
};

app.use(cors(corsOptions));

// Handle preflight requests
app.options('*', cors(corsOptions));
```

### Python/Flask - CORS Configuration

```python
from flask import Flask
from flask_cors import CORS

app = Flask(__name__)

# ❌ BAD - Allow all origins
# CORS(app)

# ✅ GOOD - Whitelist specific origins
allowed_origins = [
    'https://yourdomain.com',
    'https://app.yourdomain.com'
]

if app.config['ENV'] == 'development':
    allowed_origins.append('http://localhost:3000')

CORS(app,
    origins=allowed_origins,
    methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
    allow_headers=['Content-Type', 'Authorization'],
    expose_headers=['X-Total-Count', 'X-Page-Number'],
    supports_credentials=True,
    max_age=86400
)

# Or configure per route
@app.route('/api/public')
@cross_origin(origins=['*'])  # Public endpoint
def public_endpoint():
    return {'data': 'public'}

@app.route('/api/private')
@cross_origin(origins=allowed_origins, supports_credentials=True)
def private_endpoint():
    return {'data': 'private'}
```

---

## File Upload Security Examples

### Node.js/Express - Secure File Upload with Multer

```javascript
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');
const { exec } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);

// Allowed file types
const ALLOWED_TYPES = {
  'image/jpeg': 'jpg',
  'image/png': 'png',
  'image/gif': 'gif',
  'application/pdf': 'pdf'
};

const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB

// Configure storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/temp/'); // Temporary location
  },
  filename: (req, file, cb) => {
    // Generate random filename
    const randomName = crypto.randomBytes(16).toString('hex');
    const ext = ALLOWED_TYPES[file.mimetype];
    cb(null, `${randomName}.${ext}`);
  }
});

// File filter
const fileFilter = (req, file, cb) => {
  if (ALLOWED_TYPES[file.mimetype]) {
    cb(null, true);
  } else {
    cb(new Error('Invalid file type. Only JPEG, PNG, GIF, and PDF are allowed.'), false);
  }
};

const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: MAX_FILE_SIZE,
    files: 1
  }
});

// Virus scan function (using ClamAV)
async function scanFile(filePath) {
  try {
    const { stdout } = await execPromise(`clamscan ${filePath}`);
    return !stdout.includes('FOUND');
  } catch (error) {
    console.error('Virus scan failed:', error);
    return false;
  }
}

// Strip metadata from images
async function stripMetadata(filePath) {
  try {
    await execPromise(`exiftool -all= ${filePath}`);
    return true;
  } catch (error) {
    console.error('Metadata stripping failed:', error);
    return false;
  }
}

// Upload endpoint
app.post('/api/upload', upload.single('file'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  const tempPath = req.file.path;

  try {
    // Scan for viruses
    const isSafe = await scanFile(tempPath);
    if (!isSafe) {
      fs.unlinkSync(tempPath);
      return res.status(400).json({ error: 'File contains malware' });
    }

    // Strip metadata
    await stripMetadata(tempPath);

    // Move to permanent location
    const permanentPath = path.join('uploads/permanent/', req.file.filename);
    fs.renameSync(tempPath, permanentPath);

    res.json({
      message: 'File uploaded successfully',
      filename: req.file.filename,
      size: req.file.size
    });
  } catch (error) {
    // Clean up on error
    if (fs.existsSync(tempPath)) {
      fs.unlinkSync(tempPath);
    }
    res.status(500).json({ error: 'Upload failed' });
  }
});

// Error handling
app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'File too large' });
    }
    if (error.code === 'LIMIT_FILE_COUNT') {
      return res.status(400).json({ error: 'Too many files' });
    }
  }
  res.status(500).json({ error: error.message });
});
```

---

**Note:** These examples are for educational purposes. Always adapt them to your specific use case and conduct thorough security testing before deploying to production.

For more examples and best practices, visit:
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security/)
- [Python Security Best Practices](https://python.readthedocs.io/en/stable/library/security_warnings.html)
