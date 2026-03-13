# 🛡️ Ultimate API Security Checklist
### A comprehensive guide to designing, testing, and releasing secure APIs.
### چک‌لیست جامع امنیت API - راهنمای کامل برای طراحی، تست و انتشار امن.

---

[![GitHub stars](https://img.shields.io/github/stars/MrAlfak/API-Security-Checklist?style=for-the-badge)](https://github.com/MrAlfak/API-Security-Checklist/stargazers)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=for-the-badge)](CONTRIBUTING.md)

## 📖 Table of Contents / فهرست مطالب
- [English Version](#english-version)
    - [Authentication & Authorization](#-authentication--authorization)
    - [JWT Security](#-jwt-json-web-token)
    - [Access & Throttling](#-access--throttling)
    - [Input Validation](#-input-validation)
    - [Output Security](#-output-security)
    - [Database Security](#-database-security)
    - [Logging & Monitoring](#-logging--monitoring)
    - [Infrastructure & CI/CD](#-infrastructure--cicd)
    - [Modern API Tech](#-modern-api-tech-graphqlgrpcwebsockets)
    - [Session & API Key Management](#-session--api-key-management)
    - [CSRF & Clickjacking Protection](#-csrf--clickjacking-protection)
    - [API Versioning & Documentation](#-api-versioning--documentation)
    - [Third-Party & Webhook Security](#-third-party--webhook-security)
    - [Advanced Security Architecture](#-advanced-security-architecture)
    - [Compliance & Privacy](#-compliance--privacy)
    - [Testing & Automation](#-testing--automation)
    - [Operational Security](#-operational-security)
    - [Advanced Technical Controls](#-advanced-technical-controls)
- [نسخه فارسی](#نسخه-فارسی)
    - [احراز هویت و مجوزدهی](#-احراز-هویت-و-مجوزدهی)
    - [امنیت JWT](#-امنیت-jwt)
    - [کنترل دسترسی و ترافیک](#-کنترل-دسترسی-و-ترافیک)
    - [اعتبارسنجی ورودی‌ها](#-اعتبارسنجی-ورودی‌ها)
    - [امنیت خروجی و پاسخ‌ها](#-امنیت-خروجی-و-پاسخ‌ها)
    - [امنیت دیتابیس](#-امنیت-دیتابیس-1)
    - [لاگینگ و مانیتورینگ](#-لاگینگ-و-مانیتورینگ-1)
    - [زیرساخت و CI/CD](#-زیرساخت-و-cicd-1)
    - [تکنولوژی‌های مدرن](#-تکنولوژی‌های-مدرن-graphqlgrpcwebsockets)
    - [مدیریت Session و API Key](#-مدیریت-session-و-api-key)
    - [محافظت CSRF و Clickjacking](#-محافظت-csrf-و-clickjacking)
    - [نسخه‌بندی و مستندات API](#-نسخه‌بندی-و-مستندات-api)
    - [امنیت Third-Party و Webhook](#-امنیت-third-party-و-webhook)
    - [معماری امنیتی پیشرفته](#-معماری-امنیتی-پیشرفته)
    - [انطباق و حریم خصوصی](#-انطباق-و-حریم-خصوصی)
    - [تست و اتوماسیون](#-تست-و-اتوماسیون)
    - [امنیت عملیاتی](#-امنیت-عملیاتی)
    - [کنترل‌های فنی پیشرفته](#-کنترل‌های-فنی-پیشرفته)
- [Priority Levels Guide](#-priority-levels-guide--راهنمای-سطح-اولویت)
- [Common Vulnerabilities](#-common-vulnerabilities--آسیب‌پذیری‌های-رایج)
- [Implementation Examples](#-implementation-examples--مثال‌های-پیاده‌سازی)
- [Quick Start Checklist](#-quick-start-checklist--چک‌لیست-شروع-سریع)
- [Tools & Resources](#-tools--resources--ابزارها-و-منابع)

---

## 🚀 How to Use / نحوه استفاده
- **For Developers:** Use this as a guide during the design and development phase.
- **For Security Auditors:** Use this as a baseline for API security reviews.
- **Interactive:** You can fork this repo and check the boxes as you complete each task in your project!

- **برای توسعه‌دهندگان:** از این لیست به عنوان راهنما در طول فاز طراحی و توسعه استفاده کنید.
- **برای حسابرسان امنیتی:** از این لیست به عنوان پایه برای بررسی‌های امنیتی API استفاده کنید.
- **تعاملی:** می‌توانید این پروژه را Fork کنید و با انجام هر مرحله در پروژه خود، تیک مربوطه را بزنید!

---

<a name="english-version"></a>
## 🇺🇸 English Version

### 🔑 Authentication & Authorization
- [ ] **Don't use `Basic Auth`.** Use standard authentication like OAuth2 or JWT.
- [ ] **Don't reinvent the wheel.** Use well-tested libraries for authentication and password hashing (e.g., Argon2, bcrypt).
- [ ] **Implement Max Retries.** Limit login attempts to prevent Brute-force attacks.
- [ ] **Use MFA.** Implement Multi-Factor Authentication for sensitive accounts.
- [ ] **Secure Password Reset.** Use short-lived, one-time tokens for password recovery.
- [ ] **OAuth 2.1 Best Practices.** Use PKCE for all OAuth flows, even confidential clients.
- [ ] **Account Lockout Policy.** Implement progressive delays or temporary lockouts after failed attempts.
- [ ] **Password Complexity.** Enforce minimum length (12+ chars) and complexity requirements.
- [ ] **RBAC Implementation.** Implement Role-Based Access Control for permission management.
- [ ] **ABAC for Complex Scenarios.** Use Attribute-Based Access Control for fine-grained permissions.
- [ ] **Social Login Security.** Validate OAuth state parameter and verify email from social providers.
- [ ] **Biometric Authentication.** Use platform-specific secure biometric APIs (Face ID, Touch ID, Windows Hello).
- [ ] **Permission Inheritance.** Design clear permission hierarchy and inheritance rules.
- [ ] **Temporary Elevated Privileges.** Implement time-limited privilege escalation with audit logging.

### 🎫 JWT (JSON Web Token)
- [ ] **Strong Secrets.** Use a random, complex secret key (at least 32 characters).
- [ ] **Enforce Algorithm.** Don't trust the `alg` header; enforce `HS256` or `RS256` on the server.
- [ ] **Short TTL.** Keep expiration times (TTL) as short as possible.
- [ ] **Don't Store Secrets in Payload.** JWT payload is easily decoded; never store PII or passwords.
- [ ] **Revocation Strategy.** Implement a blacklist or refresh token mechanism to revoke tokens.
- [ ] **JWT Claims Validation.** Always validate `iss`, `aud`, `exp`, `nbf` claims.
- [ ] **Refresh Token Security.** Store refresh tokens securely, rotate on use, and bind to device/IP.
- [ ] **Token Binding.** Bind tokens to specific clients using thumbprints or device identifiers.

### 🚦 Access & Throttling
- [ ] **Rate Limiting.** Implement Throttling to prevent DDoS and Brute-force.
- [ ] **HTTPS Only.** Use TLS 1.2+ for all communications.
- [ ] **HSTS.** Enable HTTP Strict Transport Security.
- [ ] **CORS.** Only allow trusted domains. Avoid `Access-Control-Allow-Origin: *`.
- [ ] **IP Whitelisting.** For private APIs, restrict access to specific IP ranges.
- [ ] **Adaptive Rate Limiting.** Implement different rate limits based on user tier, endpoint sensitivity.
- [ ] **DDoS Mitigation.** Use CDN with DDoS protection (Cloudflare, Akamai, AWS Shield).
- [ ] **Bot Detection.** Implement bot detection mechanisms (reCAPTCHA, hCaptcha, behavioral analysis).
- [ ] **Geoblocking.** Restrict API access based on geographic location when appropriate.
- [ ] **TLS Configuration.** Disable weak ciphers, use perfect forward secrecy, enable TLS 1.3.

### 📥 Input Validation
- [ ] **Correct HTTP Methods.** Use `GET` for reading, `POST` for creation, `PUT/PATCH` for updates, and `DELETE` for deletion.
- [ ] **Content-Type Validation.** Check `Accept` and `Content-Type` headers.
- [ ] **Sanitize Input.** Prevent XSS, SQL Injection, and NoSQL Injection.
- [ ] **File Uploads.** Validate file types, sizes, and scan for malware.
- [ ] **Limit Request Size.** Prevent large payload attacks.
- [ ] **Schema Validation.** Validate all inputs against strict JSON/XML schemas.
- [ ] **Whitelist Validation.** Use whitelists instead of blacklists for input validation.
- [ ] **Path Traversal Prevention.** Sanitize file paths and prevent directory traversal attacks.
- [ ] **Command Injection Prevention.** Never pass user input directly to system commands.
- [ ] **LDAP Injection Prevention.** Escape special characters in LDAP queries.
- [ ] **XML External Entity (XXE) Prevention.** Disable external entity processing in XML parsers.
- [ ] **Server-Side Request Forgery (SSRF) Prevention.** Validate and whitelist URLs for server-side requests.
- [ ] **File Metadata Sanitization.** Strip metadata from uploaded files (EXIF, IPTC).

### 📤 Output Security
- [ ] **Disable `X-Powered-By`.** Don't leak server technology info.
- [ ] **Generic Error Messages.** Don't expose stack traces or internal DB errors.
- [ ] **Data Masking.** Mask sensitive data (e.g., credit card numbers) in responses.
- [ ] **Security Headers.** Use `X-Content-Type-Options: nosniff`, `X-Frame-Options: deny`.
- [ ] **Consistent Error Format.** Use standardized error response structure across all endpoints.
- [ ] **Error Code Standardization.** Define and document error codes for different scenarios.
- [ ] **Debug Mode Security.** Ensure debug mode is disabled in production environments.
- [ ] **Response Size Limiting.** Limit response payload size to prevent resource exhaustion.
- [ ] **Proper HTTP Status Codes.** Use correct status codes (200, 201, 400, 401, 403, 404, 500, etc.).
- [ ] **Remove Server Fingerprints.** Remove version numbers and server signatures from responses.
- [ ] **Content-Type Enforcement.** Always set correct Content-Type headers for responses.

### 🗄️ Database Security
- [ ] **Parameterized Queries.** Use ORMs or prepared statements to prevent SQL Injection.
- [ ] **Principle of Least Privilege.** API should connect to DB with a user that only has necessary permissions.
- [ ] **Encryption at Rest.** Ensure sensitive data is encrypted in the database.
- [ ] **Audit Logs.** Enable logging for sensitive database operations.
- [ ] **Encryption in Transit.** Use TLS/SSL for database connections.
- [ ] **Database Firewall.** Restrict database access to application servers only.
- [ ] **Connection Pooling Security.** Properly configure and secure database connection pools.
- [ ] **Backup Encryption.** Encrypt database backups and test restoration procedures.
- [ ] **NoSQL Injection Prevention.** Sanitize inputs for MongoDB, Redis, and other NoSQL databases.
- [ ] **Database Activity Monitoring.** Implement real-time monitoring for suspicious database queries.

### 📝 Logging & Monitoring
- [ ] **Don't Log PII.** Never log passwords, tokens, or personal user data.
- [ ] **Centralized Logging.** Use tools like ELK, Splunk, or Datadog.
- [ ] **Alerting.** Set up alerts for suspicious activities (e.g., spike in 401/403 errors).
- [ ] **Audit Trail.** Log who did what and when for all administrative actions.

### ☁️ Infrastructure & CI/CD
- [ ] **Secrets Management.** Use Vault, AWS Secrets Manager, or Environment Variables. Never hardcode keys.
- [ ] **Dependency Scanning.** Use `npm audit` or Snyk to find vulnerable packages.
- [ ] **Container Security.** Scan Docker images for vulnerabilities.
- [ ] **API Gateway.** Use a gateway (e.g., Kong, Nginx) for global security policies.

### 🌐 Modern API Tech (GraphQL/gRPC/WebSockets)
- [ ] **GraphQL: Depth Limiting.** Prevent nested query attacks.
- [ ] **GraphQL: Introspection.** Disable introspection in production.
- [ ] **gRPC: TLS.** Always use TLS for gRPC communication.
- [ ] **WebSockets: Origin Validation.** Always check the `Origin` header to prevent CSWSH attacks.
- [ ] **WebSockets: Authentication.** Authenticate during the initial handshake.

### 🔐 Session & API Key Management
- [ ] **Secure Session Storage.** Store sessions server-side with secure, random session IDs.
- [ ] **Session Timeout.** Implement idle and absolute session timeouts.
- [ ] **Session Invalidation.** Properly invalidate sessions on logout and password change.
- [ ] **API Key Rotation.** Implement automatic key rotation policies (e.g., every 90 days).
- [ ] **API Key Scoping.** Limit API keys to specific endpoints and operations.
- [ ] **Key Storage.** Never expose API keys in client-side code or URLs.
- [ ] **Multiple Keys per User.** Allow users to generate multiple keys for different applications.
- [ ] **Key Revocation.** Provide instant key revocation capability.

### 🛡️ CSRF & Clickjacking Protection
- [ ] **CSRF Tokens.** Implement anti-CSRF tokens for state-changing operations.
- [ ] **SameSite Cookies.** Use `SameSite=Strict` or `SameSite=Lax` for cookies.
- [ ] **Double Submit Cookie.** Implement double-submit cookie pattern for CSRF protection.
- [ ] **X-Frame-Options.** Set to `DENY` or `SAMEORIGIN` to prevent clickjacking.
- [ ] **Content-Security-Policy.** Implement CSP with `frame-ancestors` directive.
- [ ] **Custom Headers.** Require custom headers (e.g., `X-Requested-With`) for API calls.

### 📋 API Versioning & Documentation
- [ ] **Version in URL or Header.** Use `/v1/` in URL or `Accept-Version` header.
- [ ] **Deprecation Policy.** Clearly communicate API deprecation timelines.
- [ ] **Backward Compatibility.** Maintain backward compatibility within major versions.
- [ ] **Secure Documentation.** Protect Swagger/OpenAPI docs with authentication in production.
- [ ] **Remove Sensitive Examples.** Don't include real API keys or credentials in documentation.
- [ ] **API Changelog.** Maintain a public changelog for security-related updates.
- [ ] **Schema Validation.** Validate requests against OpenAPI/JSON Schema definitions.

### 🔗 Third-Party & Webhook Security
- [ ] **Vendor Assessment.** Conduct security assessments of third-party APIs before integration.
- [ ] **Least Privilege Integration.** Request minimum necessary permissions from third-party services.
- [ ] **Webhook Signature Verification.** Verify webhook signatures (e.g., HMAC) before processing.
- [ ] **Webhook IP Whitelisting.** Restrict webhook endpoints to known IP ranges.
- [ ] **Idempotency Keys.** Use idempotency keys to prevent duplicate webhook processing.
- [ ] **Webhook Retry Logic.** Implement exponential backoff for webhook retries.
- [ ] **Timeout Configuration.** Set appropriate timeouts for third-party API calls.
- [ ] **Circuit Breaker Pattern.** Implement circuit breakers to handle third-party failures gracefully.

### 🏗️ Advanced Security Architecture
- [ ] **Zero Trust Model.** Never trust, always verify - authenticate every request.
- [ ] **Service Mesh Security.** Use mTLS between microservices (Istio/Linkerd).
- [ ] **API Gateway Policies.** Centralize authentication, rate limiting, and logging at gateway.
- [ ] **Serverless Security.** Apply least privilege IAM roles for Lambda/Cloud Functions.
- [ ] **API Abuse Detection.** Implement ML-based anomaly detection for unusual patterns.
- [ ] **Distributed Tracing.** Use tools like Jaeger or Zipkin for security audit trails.
- [ ] **Secrets Rotation.** Automate rotation of database credentials and API keys.
- [ ] **Network Segmentation.** Isolate API services in separate network zones.

### ⚖️ Compliance & Privacy
- [ ] **GDPR Compliance.** Implement data subject rights (access, deletion, portability).
- [ ] **Data Minimization.** Only collect and store necessary data.
- [ ] **Consent Management.** Track and honor user consent for data processing.
- [ ] **Right to be Forgotten.** Implement automated data deletion workflows.
- [ ] **Data Retention Policies.** Define and enforce data retention periods.
- [ ] **Privacy by Design.** Build privacy considerations into API design from the start.
- [ ] **Cross-Border Data Transfer.** Ensure compliance with data residency requirements.
- [ ] **Audit Trail for PII.** Log all access to personally identifiable information.
- [ ] **Data Anonymization.** Anonymize data for analytics and testing environments.

### 🧪 Testing & Automation
- [ ] **Penetration Testing.** Conduct regular penetration tests (quarterly or after major changes).
- [ ] **Fuzzing.** Use fuzzing tools to discover input validation vulnerabilities.
- [ ] **Security Regression Testing.** Include security tests in CI/CD pipeline.
- [ ] **Chaos Engineering.** Test API resilience under failure conditions.
- [ ] **Automated Security Scans.** Integrate SAST/DAST tools in CI/CD.
- [ ] **Dependency Scanning.** Automatically scan for vulnerable dependencies on every build.
- [ ] **Container Scanning.** Scan Docker images before deployment.
- [ ] **API Contract Testing.** Validate API responses against defined schemas.
- [ ] **Load Testing.** Test API behavior under high load to identify DoS vulnerabilities.

### 🚨 Operational Security
- [ ] **Incident Response Plan.** Document and practice security incident response procedures.
- [ ] **Security Runbooks.** Create runbooks for common security scenarios.
- [ ] **Disaster Recovery Plan.** Test backup and recovery procedures regularly.
- [ ] **Security Training.** Provide regular security training for development team.
- [ ] **Threat Modeling.** Conduct threat modeling sessions for new features.
- [ ] **Bug Bounty Program.** Consider implementing a responsible disclosure program.
- [ ] **Security Champions.** Designate security champions within development teams.
- [ ] **Post-Mortem Analysis.** Conduct blameless post-mortems after security incidents.
- [ ] **Security Metrics.** Track and report on security KPIs (MTTD, MTTR, vulnerability counts).

### 🔧 Advanced Technical Controls
- [ ] **API Schema Validation.** Validate all requests against OpenAPI/JSON Schema.
- [ ] **Idempotency.** Implement idempotency for POST/PUT/PATCH operations.
- [ ] **Pagination Security.** Limit page size and validate pagination parameters.
- [ ] **Cursor-Based Pagination.** Use cursor-based pagination to prevent data leakage.
- [ ] **Cache Security.** Implement cache-control headers and prevent cache poisoning.
- [ ] **Cache Invalidation.** Properly invalidate cached sensitive data.
- [ ] **API Mocking Security.** Ensure mock environments don't expose production data.
- [ ] **Request Signing.** Implement request signing for high-security operations (AWS Signature v4).
- [ ] **Nonce Usage.** Use nonces to prevent replay attacks.
- [ ] **Time-Based Validation.** Reject requests with timestamps outside acceptable window.
- [ ] **Compression Bomb Protection.** Limit decompressed payload size to prevent DoS.
- [ ] **Unicode Security.** Validate and sanitize Unicode input to prevent homograph attacks.
- [ ] **HATEOAS Implementation.** Include hypermedia links for better API discoverability and security.
- [ ] **Resource Naming Conventions.** Use consistent, predictable resource naming (plural nouns, lowercase).
- [ ] **File Download Security.** Validate file paths, set Content-Disposition headers, scan for malware.
- [ ] **Streaming Security.** Implement proper authentication and rate limiting for streaming endpoints.
- [ ] **Temporary File Cleanup.** Automatically clean up temporary files after processing.
- [ ] **Certificate Pinning (Mobile).** Implement certificate pinning for mobile API clients.
- [ ] **App Attestation.** Verify mobile app authenticity using platform attestation APIs.
- [ ] **Jailbreak/Root Detection.** Detect compromised devices and adjust security accordingly.
- [ ] **Secure Mobile Storage.** Use platform keychain/keystore for sensitive data on mobile.
- [ ] **Server-Sent Events (SSE) Security.** Authenticate SSE connections and validate event sources.
- [ ] **Long Polling Security.** Implement timeouts and authentication for long polling endpoints.
- [ ] **WebRTC Security.** Use TURN/STUN servers with authentication, encrypt media streams.
- [ ] **Cryptographic Algorithm Selection.** Use AES-256-GCM for encryption, SHA-256+ for hashing.
- [ ] **Key Management Lifecycle.** Implement key generation, rotation, revocation, and destruction policies.
- [ ] **Certificate Management.** Automate certificate renewal, monitor expiration dates.
- [ ] **HSM for Sensitive Operations.** Use Hardware Security Modules for cryptographic operations with sensitive keys.

### 🛠️ Security Tools Table
| Category | Tool | Description |
| :--- | :--- | :--- |
| **SAST** | [SonarQube](https://www.sonarqube.org/) | Static code analysis for vulnerabilities. |
| **DAST** | [OWASP ZAP](https://www.zaproxy.org/) | Dynamic testing of running APIs. |
| **DAST** | [Burp Suite](https://portswigger.net/burp) | Professional penetration testing toolkit. |
| **SCA** | [Snyk](https://snyk.io/) | Scans dependencies for known vulnerabilities. |
| **Testing** | [Postman](https://www.postman.com/) | Automated security test scripts. |
| **Scanning** | [Nuclei](https://github.com/projectdiscovery/nuclei) | Fast vulnerability scanner with templates. |
| **Fuzzing** | [ffuf](https://github.com/ffuf/ffuf) | Fast web fuzzer for discovering vulnerabilities. |
| **JWT** | [jwt.io](https://jwt.io/) | JWT debugger and validator. |
| **Rate Limiting** | [Kong](https://konghq.com/) | API Gateway with rate limiting and security policies. |
| **WAF** | [ModSecurity](https://modsecurity.org/) | Open-source Web Application Firewall. |
| **WAF** | [Cloudflare WAF](https://www.cloudflare.com/waf/) | Cloud-based Web Application Firewall. |
| **API Security** | [42Crunch](https://42crunch.com/) | API security platform with automated testing. |
| **Monitoring** | [Datadog](https://www.datadoghq.com/) | Security monitoring and alerting. |
| **Secrets** | [GitGuardian](https://www.gitguardian.com/) | Detect secrets in code repositories. |

---

## 🎯 Priority Levels Guide / راهنمای سطح اولویت

<div dir="ltr">

### 🔴 CRITICAL (Must Have - Implement First)
These are fundamental security requirements that must be implemented before going to production:

- ✅ Use HTTPS/TLS 1.2+ for all communications
- ✅ Implement authentication (OAuth2/JWT, not Basic Auth)
- ✅ Use parameterized queries to prevent SQL Injection
- ✅ Implement rate limiting to prevent DDoS
- ✅ Validate and sanitize all inputs
- ✅ Don't expose sensitive data in responses (stack traces, DB errors)
- ✅ Use strong password hashing (Argon2, bcrypt)
- ✅ Implement proper CORS configuration
- ✅ Never hardcode secrets or API keys
- ✅ Enable HSTS (HTTP Strict Transport Security)

### 🟠 HIGH (Should Have - Implement Soon)
Important security measures that significantly reduce risk:

- ⚠️ Implement MFA for sensitive accounts
- ⚠️ Add comprehensive logging and monitoring
- ⚠️ Implement JWT with proper validation and short TTL
- ⚠️ Add CSRF protection for state-changing operations
- ⚠️ Implement API versioning strategy
- ⚠️ Set up automated dependency scanning
- ⚠️ Configure security headers (CSP, X-Frame-Options, etc.)
- ⚠️ Implement session timeout and invalidation
- ⚠️ Add file upload validation and malware scanning
- ⚠️ Use principle of least privilege for database access

### 🟡 MEDIUM (Nice to Have - Plan for Implementation)
Additional security layers that improve overall security posture:

- 📋 Implement API key rotation policies
- 📋 Add webhook signature verification
- 📋 Set up centralized logging (ELK, Splunk)
- 📋 Implement idempotency for critical operations
- 📋 Add request signing for sensitive operations
- 📋 Configure cache security and invalidation
- 📋 Implement pagination security
- 📋 Add distributed tracing for audit trails
- 📋 Set up automated security testing in CI/CD
- 📋 Implement data masking for sensitive information

### 🟢 LOW (Optional - Advanced Security)
Advanced security features for mature security programs:

- 💡 Implement Zero Trust architecture
- 💡 Add ML-based API abuse detection
- 💡 Set up chaos engineering tests
- 💡 Implement service mesh with mTLS
- 💡 Add certificate pinning for mobile apps
- 💡 Implement HSM for cryptographic operations
- 💡 Set up bug bounty program
- 💡 Add advanced threat modeling
- 💡 Implement behavioral analytics
- 💡 Use WebAuthn for passwordless authentication

</div>

<div dir="rtl">

### 🔴 بحرانی (الزامی - اولویت اول)
این موارد پایه‌ای امنیتی هستند که باید قبل از رفتن به Production پیاده‌سازی شوند:

- ✅ استفاده از HTTPS/TLS 1.2+ برای تمام ارتباطات
- ✅ پیاده‌سازی احراز هویت (OAuth2/JWT، نه Basic Auth)
- ✅ استفاده از پرس‌وجوهای پارامتری برای جلوگیری از SQL Injection
- ✅ پیاده‌سازی Rate Limiting برای جلوگیری از DDoS
- ✅ اعتبارسنجی و پاکسازی تمام ورودی‌ها
- ✅ عدم نمایش داده‌های حساس در پاسخ‌ها (Stack Trace، خطاهای DB)
- ✅ استفاده از هش قوی برای پسوردها (Argon2، bcrypt)
- ✅ پیکربندی صحیح CORS
- ✅ هرگز سکرت‌ها یا API Key را Hardcode نکنید
- ✅ فعال‌سازی HSTS

### 🟠 بالا (باید داشته باشید - پیاده‌سازی زودهنگام)
اقدامات امنیتی مهم که به طور قابل توجهی ریسک را کاهش می‌دهند:

- ⚠️ پیاده‌سازی MFA برای حساب‌های حساس
- ⚠️ افزودن لاگینگ و مانیتورینگ جامع
- ⚠️ پیاده‌سازی JWT با اعتبارسنجی صحیح و TTL کوتاه
- ⚠️ افزودن محافظت CSRF برای عملیات تغییر وضعیت
- ⚠️ پیاده‌سازی استراتژی نسخه‌بندی API
- ⚠️ راه‌اندازی اسکن خودکار وابستگی‌ها
- ⚠️ پیکربندی هدرهای امنیتی (CSP، X-Frame-Options و غیره)
- ⚠️ پیاده‌سازی Timeout و Invalidation برای Session
- ⚠️ افزودن اعتبارسنجی آپلود فایل و اسکن بدافزار
- ⚠️ استفاده از اصل حداقل دسترسی برای دیتابیس

### 🟡 متوسط (خوب است داشته باشید - برنامه‌ریزی برای پیاده‌سازی)
لایه‌های امنیتی اضافی که وضعیت امنیتی کلی را بهبود می‌بخشند:

- 📋 پیاده‌سازی سیاست‌های چرخش API Key
- 📋 افزودن تایید امضای Webhook
- 📋 راه‌اندازی لاگینگ متمرکز (ELK، Splunk)
- 📋 پیاده‌سازی Idempotency برای عملیات بحرانی
- 📋 افزودن امضای درخواست برای عملیات حساس
- 📋 پیکربندی امنیت و Invalidation کش
- 📋 پیاده‌سازی امنیت Pagination
- 📋 افزودن Distributed Tracing برای Audit Trail
- 📋 راه‌اندازی تست امنیتی خودکار در CI/CD
- 📋 پیاده‌سازی ماسک کردن داده‌های حساس

### 🟢 پایین (اختیاری - امنیت پیشرفته)
ویژگی‌های امنیتی پیشرفته برای برنامه‌های امنیتی بالغ:

- 💡 پیاده‌سازی معماری Zero Trust
- 💡 افزودن تشخیص سوء استفاده از API مبتنی بر ML
- 💡 راه‌اندازی تست‌های Chaos Engineering
- 💡 پیاده‌سازی Service Mesh با mTLS
- 💡 افزودن Certificate Pinning برای اپلیکیشن‌های موبایل
- 💡 پیاده‌سازی HSM برای عملیات رمزنگاری
- 💡 راه‌اندازی برنامه Bug Bounty
- 💡 افزودن Threat Modeling پیشرفته
- 💡 پیاده‌سازی تحلیل رفتاری
- 💡 استفاده از WebAuthn برای احراز هویت بدون پسورد

</div>

---

## 📚 Common Vulnerabilities & Prevention / آسیب‌پذیری‌های رایج و پیشگیری

<div dir="ltr">

### 1. SQL Injection
**Risk:** Attackers can execute arbitrary SQL commands.
**Prevention:**
```python
# ❌ BAD - Vulnerable to SQL Injection
query = f"SELECT * FROM users WHERE id = {user_id}"

# ✅ GOOD - Using parameterized query
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))
```

### 2. Broken Authentication
**Risk:** Weak authentication allows unauthorized access.
**Prevention:**
```javascript
// ✅ GOOD - Proper JWT validation
const jwt = require('jsonwebtoken');

function verifyToken(token) {
  try {
    return jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ['HS256'], // Enforce algorithm
      issuer: 'your-api',
      audience: 'your-app'
    });
  } catch (err) {
    throw new Error('Invalid token');
  }
}
```

### 3. Broken Object Level Authorization (BOLA)
**Risk:** Users can access resources they shouldn't.
**Prevention:**
```javascript
// ❌ BAD - No authorization check
app.get('/api/documents/:id', async (req, res) => {
  const doc = await Document.findById(req.params.id);
  res.json(doc);
});

// ✅ GOOD - Verify ownership
app.get('/api/documents/:id', authenticateUser, async (req, res) => {
  const doc = await Document.findById(req.params.id);
  if (doc.userId !== req.user.id) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  res.json(doc);
});
```

### 4. Rate Limiting Bypass
**Risk:** Attackers can overwhelm the API.
**Prevention:**
```javascript
// ✅ GOOD - Implement rate limiting
const rateLimit = require('express-rate-limit');

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests, please try again later.'
});

app.use('/api/', limiter);
```

### 5. Mass Assignment
**Risk:** Users can modify fields they shouldn't.
**Prevention:**
```python
# ❌ BAD - Accepting all fields
user.update(**request.json)

# ✅ GOOD - Whitelist allowed fields
allowed_fields = ['name', 'email', 'phone']
update_data = {k: v for k, v in request.json.items() if k in allowed_fields}
user.update(**update_data)
```

### 6. Security Misconfiguration
**Risk:** Default configurations expose vulnerabilities.
**Prevention:**
```javascript
// ✅ GOOD - Secure headers
const helmet = require('helmet');
app.use(helmet());

app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    styleSrc: ["'self'", "'unsafe-inline'"],
    scriptSrc: ["'self'"],
    imgSrc: ["'self'", "data:", "https:"]
  }
}));
```

### 7. XSS (Cross-Site Scripting)
**Risk:** Malicious scripts executed in user's browser.
**Prevention:**
```javascript
// ✅ GOOD - Sanitize output
const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');

const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

const clean = DOMPurify.sanitize(userInput);
```

### 8. Insecure Direct Object References (IDOR)
**Risk:** Predictable IDs allow enumeration attacks.
**Prevention:**
```python
# ✅ GOOD - Use UUIDs instead of sequential IDs
import uuid

class Document(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
```

</div>

<div dir="rtl">

### ۱. تزریق SQL
**ریسک:** مهاجمان می‌توانند دستورات SQL دلخواه اجرا کنند.
**پیشگیری:** از پرس‌وجوهای پارامتری یا ORM استفاده کنید.

### ۲. احراز هویت شکسته
**ریسک:** احراز هویت ضعیف اجازه دسترسی غیرمجاز می‌دهد.
**پیشگیری:** از JWT با اعتبارسنجی کامل و الگوریتم اجباری استفاده کنید.

### ۳. مجوزدهی سطح شیء شکسته (BOLA)
**ریسک:** کاربران می‌توانند به منابعی که نباید دسترسی داشته باشند.
**پیشگیری:** همیشه مالکیت منبع را قبل از بازگرداندن داده بررسی کنید.

### ۴. دور زدن محدودیت نرخ
**ریسک:** مهاجمان می‌توانند API را تحت فشار قرار دهند.
**پیشگیری:** Rate Limiting مناسب پیاده‌سازی کنید.

### ۵. انتساب دسته‌جمعی
**ریسک:** کاربران می‌توانند فیلدهایی را که نباید تغییر دهند.
**پیشگیری:** فقط فیلدهای مجاز را در Whitelist قرار دهید.

### ۶. پیکربندی نادرست امنیتی
**ریسک:** پیکربندی‌های پیش‌فرض آسیب‌پذیری‌ها را فاش می‌کنند.
**پیشگیری:** از هدرهای امنیتی و پیکربندی‌های سخت‌گیرانه استفاده کنید.

### ۷. XSS (اسکریپت‌نویسی بین‌سایتی)
**ریسک:** اسکریپت‌های مخرب در مرورگر کاربر اجرا می‌شوند.
**پیشگیری:** خروجی را Sanitize کنید و از CSP استفاده کنید.

### ۸. ارجاع مستقیم ناامن به شیء (IDOR)
**ریسک:** IDهای قابل پیش‌بینی اجازه حملات شمارش می‌دهند.
**پیشگیری:** از UUID به جای IDهای ترتیبی استفاده کنید.

</div>

---

## � Common Vulnerabilities / آسیب‌پذیری‌های رایج

For detailed information about common API vulnerabilities and how to prevent them, see:
**[📖 VULNERABILITIES.md](VULNERABILITIES.md)** - Complete guide covering OWASP API Security Top 10

برای اطلاعات دقیق درباره آسیب‌پذیری‌های رایج API و نحوه جلوگیری از آن‌ها، مراجعه کنید به:
**[📖 VULNERABILITIES.md](VULNERABILITIES.md)** - راهنمای کامل شامل OWASP API Security Top 10

---

## 💻 Implementation Examples / مثال‌های پیاده‌سازی

For practical code examples and implementation guides, see:
**[📖 EXAMPLES.md](EXAMPLES.md)** - Real-world code examples in Node.js, Python, and more

برای مثال‌های کد عملی و راهنماهای پیاده‌سازی، مراجعه کنید به:
**[📖 EXAMPLES.md](EXAMPLES.md)** - مثال‌های کد واقعی در Node.js، Python و بیشتر

---

## 🚀 Quick Start Checklist / چک‌لیست شروع سریع

<div dir="ltr">

### For New Projects (Minimum Security Baseline)

#### Week 1: Foundation
- [ ] Set up HTTPS with valid TLS certificate
- [ ] Implement authentication (OAuth2 or JWT)
- [ ] Add input validation for all endpoints
- [ ] Configure CORS properly
- [ ] Set up basic rate limiting
- [ ] Use environment variables for secrets
- [ ] Enable security headers (helmet.js or equivalent)

#### Week 2: Data Protection
- [ ] Implement parameterized database queries
- [ ] Add password hashing (Argon2/bcrypt)
- [ ] Set up database connection with least privilege
- [ ] Implement request size limits
- [ ] Add file upload validation
- [ ] Configure proper error handling (no stack traces in production)

#### Week 3: Monitoring & Testing
- [ ] Set up centralized logging
- [ ] Configure alerts for security events
- [ ] Add dependency scanning to CI/CD
- [ ] Implement automated security tests
- [ ] Document API security requirements
- [ ] Create incident response plan

#### Week 4: Advanced Security
- [ ] Add MFA for admin accounts
- [ ] Implement API versioning
- [ ] Set up automated backups
- [ ] Configure session management
- [ ] Add CSRF protection
- [ ] Conduct initial security audit

</div>

<div dir="rtl">

### برای پروژه‌های جدید (حداقل پایه امنیتی)

#### هفته ۱: پایه‌گذاری
- [ ] راه‌اندازی HTTPS با گواهی TLS معتبر
- [ ] پیاده‌سازی احراز هویت (OAuth2 یا JWT)
- [ ] افزودن اعتبارسنجی ورودی برای تمام Endpointها
- [ ] پیکربندی صحیح CORS
- [ ] راه‌اندازی Rate Limiting پایه
- [ ] استفاده از متغیرهای محیطی برای سکرت‌ها
- [ ] فعال‌سازی هدرهای امنیتی

#### هفته ۲: حفاظت از داده
- [ ] پیاده‌سازی پرس‌وجوهای پارامتری دیتابیس
- [ ] افزودن هش پسورد (Argon2/bcrypt)
- [ ] راه‌اندازی اتصال دیتابیس با حداقل دسترسی
- [ ] پیاده‌سازی محدودیت اندازه درخواست
- [ ] افزودن اعتبارسنجی آپلود فایل
- [ ] پیکربندی مدیریت خطای صحیح

#### هفته ۳: مانیتورینگ و تست
- [ ] راه‌اندازی لاگینگ متمرکز
- [ ] پیکربندی هشدارها برای رویدادهای امنیتی
- [ ] افزودن اسکن وابستگی به CI/CD
- [ ] پیاده‌سازی تست‌های امنیتی خودکار
- [ ] مستندسازی الزامات امنیتی API
- [ ] ایجاد برنامه پاسخ به حوادث

#### هفته ۴: امنیت پیشرفته
- [ ] افزودن MFA برای حساب‌های ادمین
- [ ] پیاده‌سازی نسخه‌بندی API
- [ ] راه‌اندازی پشتیبان‌گیری خودکار
- [ ] پیکربندی مدیریت Session
- [ ] افزودن محافظت CSRF
- [ ] انجام ممیزی امنیتی اولیه

</div>

---

<a name="نسخه-فارسی"></a>
## 🇮🇷 نسخه فارسی

<div dir="rtl">

### 🔑 احراز هویت و مجوزدهی
- [ ] **عدم استفاده از Basic Auth.** از روش‌های استاندارد مثل OAuth2 یا JWT استفاده کنید.
- [ ] **چرخ را دوباره اختراع نکنید.** از کتابخانه‌های تست شده برای هش کردن پسورد (مثل Argon2 یا bcrypt) استفاده کنید.
- [ ] **محدودیت تلاش مجدد.** برای جلوگیری از حملات Brute-force، تعداد دفعات ورود ناموفق را محدود کنید.
- [ ] **احراز هویت چندعاملی (MFA).** برای حساب‌های حساس حتما MFA پیاده‌سازی کنید.
- [ ] **بازیابی امن پسورد.** از توکن‌های یکبار مصرف و کوتاه‌مدت برای بازیابی پسورد استفاده کنید.
- [ ] **بهترین شیوه‌های OAuth 2.1.** از PKCE برای تمام جریان‌های OAuth استفاده کنید.
- [ ] **سیاست قفل حساب.** تاخیرهای تدریجی یا قفل موقت پس از تلاش‌های ناموفق پیاده‌سازی کنید.
- [ ] **پیچیدگی پسورد.** حداقل طول (۱۲+ کاراکتر) و الزامات پیچیدگی را اعمال کنید.
- [ ] **پیاده‌سازی RBAC.** کنترل دسترسی مبتنی بر نقش برای مدیریت مجوزها پیاده‌سازی کنید.
- [ ] **ABAC برای سناریوهای پیچیده.** از کنترل دسترسی مبتنی بر ویژگی برای مجوزهای دقیق استفاده کنید.
- [ ] **امنیت ورود اجتماعی.** پارامتر state در OAuth را اعتبارسنجی کنید و ایمیل را از ارائه‌دهندگان اجتماعی تایید کنید.
- [ ] **احراز هویت بیومتریک.** از APIهای بیومتریک امن خاص پلتفرم استفاده کنید (Face ID، Touch ID، Windows Hello).
- [ ] **وراثت مجوز.** سلسله مراتب و قوانین وراثت مجوز واضح طراحی کنید.
- [ ] **امتیازات افزایش‌یافته موقت.** افزایش امتیاز محدود به زمان با لاگ ممیزی پیاده‌سازی کنید.

### 🎫 امنیت JWT
- [ ] **کلیدهای پیچیده.** از یک Secret Key تصادفی و پیچیده (حداقل ۳۲ کاراکتر) استفاده کنید.
- [ ] **تحمیل الگوریتم.** به هدر توکن اعتماد نکنید و الگوریتم (HS256 یا RS256) را در سمت سرور اجباری کنید.
- [ ] **زمان انقضای کوتاه.** مقدار TTL را تا حد ممکن کوتاه در نظر بگیرید.
- [ ] **عدم ذخیره داده حساس.** پی‌لود JWT به راحتی دکود می‌شود؛ پسوردها یا داده‌های هویتی را در آن قرار ندهید.
- [ ] **استراتژی لغو توکن.** مکانیزم لیست سیاه یا Refresh Token برای لغو توکن‌ها پیاده‌سازی کنید.
- [ ] **اعتبارسنجی Claimهای JWT.** همیشه claimهای `iss`، `aud`، `exp`، `nbf` را اعتبارسنجی کنید.
- [ ] **امنیت Refresh Token.** Refresh Tokenها را به صورت امن ذخیره کنید، در هنگام استفاده چرخش دهید و به دستگاه/IP متصل کنید.
- [ ] **اتصال توکن.** توکن‌ها را با استفاده از اثر انگشت یا شناسه دستگاه به کلاینت‌های خاص متصل کنید.

### 🚦 کنترل دسترسی و ترافیک
- [ ] **Rate Limiting.** برای جلوگیری از حملات DDoS و Brute-force، محدودیت تعداد درخواست بگذارید.
- [ ] **الزام HTTPS.** از TLS 1.2 به بالا برای تمامی ارتباطات استفاده کنید.
- [ ] **استفاده از HSTS.** برای جلوگیری از حملات SSL Strip، هدر HSTS را فعال کنید.
- [ ] **تنظیمات CORS.** فقط به دامنه‌های مورد اعتماد اجازه دسترسی دهید. از `*` استفاده نکنید.
- [ ] **لیست سفید IP.** برای APIهای خصوصی، دسترسی را به محدوده‌های IP خاص محدود کنید.
- [ ] **Rate Limiting تطبیقی.** محدودیت‌های نرخ مختلف بر اساس سطح کاربر و حساسیت Endpoint پیاده‌سازی کنید.
- [ ] **کاهش DDoS.** از CDN با محافظت DDoS استفاده کنید (Cloudflare، Akamai، AWS Shield).
- [ ] **تشخیص ربات.** مکانیزم‌های تشخیص ربات پیاده‌سازی کنید (reCAPTCHA، hCaptcha، تحلیل رفتاری).
- [ ] **مسدودسازی جغرافیایی.** در صورت لزوم، دسترسی API را بر اساس موقعیت جغرافیایی محدود کنید.
- [ ] **پیکربندی TLS.** رمزهای ضعیف را غیرفعال کنید، از Perfect Forward Secrecy استفاده کنید، TLS 1.3 را فعال کنید.

### 📥 اعتبارسنجی ورودی‌ها
- [ ] **متدهای صحیح HTTP.** استفاده درست از GET، POST، PUT و DELETE.
- [ ] **اعتبارسنجی Content-Type.** هدرهای Accept و Content-Type را چک کنید.
- [ ] **پاکسازی ورودی.** جلوگیری از حملات XSS، SQL Injection و NoSQL Injection.
- [ ] **آپلود فایل.** نوع فایل، حجم و محتوای آن را بررسی کنید تا بدافزار نباشد.
- [ ] **محدودیت اندازه درخواست.** از حملات Payload بزرگ جلوگیری کنید.
- [ ] **اعتبارسنجی Schema.** تمام ورودی‌ها را در برابر Schemaهای JSON/XML سخت‌گیرانه اعتبارسنجی کنید.
- [ ] **اعتبارسنجی لیست سفید.** از لیست سفید به جای لیست سیاه برای اعتبارسنجی ورودی استفاده کنید.
- [ ] **جلوگیری از Path Traversal.** مسیرهای فایل را پاکسازی کنید و از حملات Directory Traversal جلوگیری کنید.
- [ ] **جلوگیری از Command Injection.** هرگز ورودی کاربر را مستقیماً به دستورات سیستم منتقل نکنید.
- [ ] **جلوگیری از LDAP Injection.** کاراکترهای خاص را در کوئری‌های LDAP Escape کنید.
- [ ] **جلوگیری از XXE.** پردازش Entity خارجی را در پارسرهای XML غیرفعال کنید.
- [ ] **جلوگیری از SSRF.** URLها را برای درخواست‌های سمت سرور اعتبارسنجی و لیست سفید کنید.
- [ ] **پاکسازی Metadata فایل.** Metadata را از فایل‌های آپلود شده حذف کنید (EXIF، IPTC).

### 📤 امنیت خروجی و پاسخ‌ها
- [ ] **غیرفعال کردن X-Powered-By.** اطلاعات تکنولوژی سرور را لو ندهید.
- [ ] **پیام‌های خطای عمومی.** هرگز Stack Trace یا خطاهای داخلی دیتابیس را به کاربر نمایش ندهید.
- [ ] **ماسک کردن داده‌ها.** داده‌های حساس (مثل شماره کارت) را در پاسخ‌ها ماسک کنید.
- [ ] **هدرهای امنیتی.** از `X-Content-Type-Options: nosniff`، `X-Frame-Options: deny` استفاده کنید.
- [ ] **فرمت خطای یکپارچه.** از ساختار پاسخ خطای استاندارد در تمام Endpointها استفاده کنید.
- [ ] **استانداردسازی کد خطا.** کدهای خطا را برای سناریوهای مختلف تعریف و مستند کنید.
- [ ] **امنیت حالت Debug.** اطمینان حاصل کنید که حالت Debug در محیط Production غیرفعال است.
- [ ] **محدودیت اندازه پاسخ.** اندازه Payload پاسخ را برای جلوگیری از خستگی منابع محدود کنید.
- [ ] **کدهای وضعیت HTTP صحیح.** از کدهای وضعیت صحیح استفاده کنید (200، 201، 400، 401، 403، 404، 500 و غیره).
- [ ] **حذف اثر انگشت سرور.** شماره نسخه و امضاهای سرور را از پاسخ‌ها حذف کنید.
- [ ] **اجبار Content-Type.** همیشه هدرهای Content-Type صحیح را برای پاسخ‌ها تنظیم کنید.

### 🗄️ امنیت دیتابیس
- [ ] **پرس‌وجوهای پارامتری.** از ORMها یا Prepared Statements برای جلوگیری از SQL Injection استفاده کنید.
- [ ] **اصل حداقل دسترسی.** API باید با کاربری به دیتابیس وصل شود که فقط دسترسی‌های ضروری را دارد.
- [ ] **رمزنگاری داده‌های حساس.** اطمینان حاصل کنید که داده‌های حساس در دیتابیس به صورت رمزنگاری شده ذخیره می‌شوند.
- [ ] **لاگ‌های ممیزی.** لاگینگ را برای عملیات حساس دیتابیس فعال کنید.
- [ ] **رمزنگاری در حین انتقال.** از TLS/SSL برای اتصالات دیتابیس استفاده کنید.
- [ ] **فایروال دیتابیس.** دسترسی دیتابیس را فقط به سرورهای اپلیکیشن محدود کنید.
- [ ] **امنیت Connection Pooling.** Connection Poolهای دیتابیس را به درستی پیکربندی و ایمن کنید.
- [ ] **رمزنگاری Backup.** پشتیبان‌های دیتابیس را رمزنگاری کنید و رویه‌های بازیابی را تست کنید.
- [ ] **جلوگیری از NoSQL Injection.** ورودی‌ها را برای MongoDB، Redis و سایر دیتابیس‌های NoSQL پاکسازی کنید.
- [ ] **مانیتورینگ فعالیت دیتابیس.** مانیتورینگ بلادرنگ برای کوئری‌های مشکوک دیتابیس پیاده‌سازی کنید.

### 📝 لاگینگ و مانیتورینگ
- [ ] **عدم ذخیره PII در لاگ.** هرگز پسوردها، توکن‌ها یا داده‌های شخصی کاربران را لاگ نکنید.
- [ ] **لاگینگ متمرکز.** از ابزارهایی مثل ELK، Splunk یا Datadog استفاده کنید.
- [ ] **هشداردهی (Alerting).** برای فعالیت‌های مشکوک (مثلاً افزایش ناگهانی خطاهای 401 یا 403) هشدار تنظیم کنید.
- [ ] **مسیر ممیزی.** برای تمام اقدامات اداری، چه کسی چه کاری و چه زمانی انجام داده را لاگ کنید.

### ☁️ زیرساخت و CI/CD
- [ ] **مدیریت سکرت‌ها.** از Vault یا متغیرهای محیطی استفاده کنید. هرگز کلیدها را در کد قرار ندهید (Hardcode).
- [ ] **اسکن وابستگی‌ها.** از ابزارهایی مثل `npm audit` یا Snyk برای یافتن پکیج‌های آسیب‌پذیر استفاده کنید.
- [ ] **امنیت کانتینر.** ایمیج‌های Docker را برای یافتن آسیب‌پذیری‌ها اسکن کنید.
- [ ] **API Gateway.** از Gateway (مثل Kong، Nginx) برای سیاست‌های امنیتی جهانی استفاده کنید.

### 🌐 تکنولوژی‌های مدرن (GraphQL/gRPC/WebSockets)
- [ ] **GraphQL: محدودیت عمق.** جلوگیری از حملات کوئری‌های تودرتو (Nested Queries).
- [ ] **GraphQL: غیرفعال‌سازی Introspection.** این ویژگی را در محیط Production غیرفعال کنید.
- [ ] **gRPC: الزام TLS.** همیشه از TLS برای ارتباطات gRPC استفاده کنید.
- [ ] **WebSockets: اعتبارسنجی Origin.** هدر Origin را برای جلوگیری از حملات CSWSH چک کنید.
- [ ] **WebSockets: احراز هویت.** در طول Handshake اولیه احراز هویت انجام دهید.

### 🔐 مدیریت Session و API Key
- [ ] **ذخیره‌سازی امن Session.** Sessionها را در سمت سرور با IDهای تصادفی امن ذخیره کنید.
- [ ] **Timeout برای Session.** Timeoutهای Idle و مطلق برای Session پیاده‌سازی کنید.
- [ ] **ابطال Session.** Sessionها را در هنگام خروج و تغییر پسورد به درستی ابطال کنید.
- [ ] **چرخش API Key.** سیاست‌های چرخش خودکار کلید پیاده‌سازی کنید (مثلاً هر ۹۰ روز).
- [ ] **محدوده API Key.** API Keyها را به Endpointها و عملیات خاص محدود کنید.
- [ ] **ذخیره‌سازی کلید.** هرگز API Keyها را در کد سمت کلاینت یا URLها قرار ندهید.
- [ ] **کلیدهای متعدد برای هر کاربر.** به کاربران اجازه دهید کلیدهای متعدد برای اپلیکیشن‌های مختلف تولید کنند.
- [ ] **لغو کلید.** قابلیت لغو فوری کلید را فراهم کنید.

### 🛡️ محافظت CSRF و Clickjacking
- [ ] **توکن‌های CSRF.** توکن‌های ضد CSRF برای عملیات تغییر وضعیت پیاده‌سازی کنید.
- [ ] **کوکی‌های SameSite.** از `SameSite=Strict` یا `SameSite=Lax` برای کوکی‌ها استفاده کنید.
- [ ] **Double Submit Cookie.** الگوی Double Submit Cookie برای محافظت CSRF پیاده‌سازی کنید.
- [ ] **X-Frame-Options.** روی `DENY` یا `SAMEORIGIN` تنظیم کنید تا از Clickjacking جلوگیری شود.
- [ ] **Content-Security-Policy.** CSP را با دستورالعمل `frame-ancestors` پیاده‌سازی کنید.
- [ ] **هدرهای سفارشی.** هدرهای سفارشی (مثل `X-Requested-With`) را برای فراخوانی‌های API الزامی کنید.

### 📋 نسخه‌بندی و مستندات API
- [ ] **نسخه در URL یا Header.** از `/v1/` در URL یا هدر `Accept-Version` استفاده کنید.
- [ ] **سیاست منسوخ شدن.** جدول زمانی منسوخ شدن API را به وضوح اطلاع دهید.
- [ ] **سازگاری با نسخه قبلی.** سازگاری با نسخه قبلی را در نسخه‌های اصلی حفظ کنید.
- [ ] **مستندات امن.** مستندات Swagger/OpenAPI را در Production با احراز هویت محافظت کنید.
- [ ] **حذف مثال‌های حساس.** API Keyها یا اعتبارنامه‌های واقعی را در مستندات قرار ندهید.
- [ ] **Changelog API.** یک Changelog عمومی برای به‌روزرسانی‌های مرتبط با امنیت نگهداری کنید.
- [ ] **اعتبارسنجی Schema.** درخواست‌ها را در برابر تعاریف OpenAPI/JSON Schema اعتبارسنجی کنید.

### 🔗 امنیت Third-Party و Webhook
- [ ] **ارزیابی Vendor.** قبل از ادغام، ارزیابی‌های امنیتی APIهای شخص ثالث انجام دهید.
- [ ] **ادغام با حداقل امتیاز.** حداقل مجوزهای لازم را از سرویس‌های شخص ثالث درخواست کنید.
- [ ] **تایید امضای Webhook.** امضاهای Webhook (مثل HMAC) را قبل از پردازش تایید کنید.
- [ ] **لیست سفید IP برای Webhook.** Endpointهای Webhook را به محدوده‌های IP شناخته شده محدود کنید.
- [ ] **کلیدهای Idempotency.** از کلیدهای Idempotency برای جلوگیری از پردازش تکراری Webhook استفاده کنید.
- [ ] **منطق تلاش مجدد Webhook.** Backoff نمایی برای تلاش‌های مجدد Webhook پیاده‌سازی کنید.
- [ ] **پیکربندی Timeout.** Timeoutهای مناسب برای فراخوانی‌های API شخص ثالث تنظیم کنید.
- [ ] **الگوی Circuit Breaker.** Circuit Breakerها را برای مدیریت شکست‌های شخص ثالث به صورت مناسب پیاده‌سازی کنید.

### 🏗️ معماری امنیتی پیشرفته
- [ ] **مدل Zero Trust.** هرگز اعتماد نکنید، همیشه تایید کنید - هر درخواست را احراز هویت کنید.
- [ ] **امنیت Service Mesh.** از mTLS بین میکروسرویس‌ها استفاده کنید (Istio/Linkerd).
- [ ] **سیاست‌های API Gateway.** احراز هویت، Rate Limiting و لاگینگ را در Gateway متمرکز کنید.
- [ ] **امنیت Serverless.** نقش‌های IAM با حداقل امتیاز را برای Lambda/Cloud Functions اعمال کنید.
- [ ] **تشخیص سوء استفاده از API.** تشخیص ناهنجاری مبتنی بر ML برای الگوهای غیرعادی پیاده‌سازی کنید.
- [ ] **Distributed Tracing.** از ابزارهایی مثل Jaeger یا Zipkin برای مسیرهای ممیزی امنیتی استفاده کنید.
- [ ] **چرخش سکرت‌ها.** چرخش اعتبارنامه‌های دیتابیس و API Keyها را خودکار کنید.
- [ ] **تقسیم‌بندی شبکه.** سرویس‌های API را در مناطق شبکه جداگانه ایزوله کنید.

### ⚖️ انطباق و حریم خصوصی
- [ ] **انطباق GDPR.** حقوق موضوع داده (دسترسی، حذف، قابلیت حمل) را پیاده‌سازی کنید.
- [ ] **به حداقل رساندن داده.** فقط داده‌های لازم را جمع‌آوری و ذخیره کنید.
- [ ] **مدیریت رضایت.** رضایت کاربر را برای پردازش داده پیگیری و رعایت کنید.
- [ ] **حق فراموشی.** گردش‌های کار حذف خودکار داده را پیاده‌سازی کنید.
- [ ] **سیاست‌های نگهداری داده.** دوره‌های نگهداری داده را تعریف و اجرا کنید.
- [ ] **حریم خصوصی از طریق طراحی.** ملاحظات حریم خصوصی را از ابتدا در طراحی API بگنجانید.
- [ ] **انتقال داده بین مرزی.** انطباق با الزامات محل سکونت داده را تضمین کنید.
- [ ] **مسیر ممیزی برای PII.** تمام دسترسی‌ها به اطلاعات شخصی قابل شناسایی را لاگ کنید.
- [ ] **ناشناس‌سازی داده.** داده را برای محیط‌های تحلیل و تست ناشناس کنید.

### 🧪 تست و اتوماسیون
- [ ] **تست نفوذ.** تست‌های نفوذ منظم انجام دهید (سه‌ماهه یا پس از تغییرات عمده).
- [ ] **Fuzzing.** از ابزارهای Fuzzing برای کشف آسیب‌پذیری‌های اعتبارسنجی ورودی استفاده کنید.
- [ ] **تست رگرسیون امنیتی.** تست‌های امنیتی را در Pipeline CI/CD بگنجانید.
- [ ] **Chaos Engineering.** انعطاف‌پذیری API را تحت شرایط شکست تست کنید.
- [ ] **اسکن‌های امنیتی خودکار.** ابزارهای SAST/DAST را در CI/CD ادغام کنید.
- [ ] **اسکن وابستگی.** به طور خودکار وابستگی‌های آسیب‌پذیر را در هر Build اسکن کنید.
- [ ] **اسکن کانتینر.** ایمیج‌های Docker را قبل از استقرار اسکن کنید.
- [ ] **تست قرارداد API.** پاسخ‌های API را در برابر Schemaهای تعریف شده اعتبارسنجی کنید.
- [ ] **تست بار.** رفتار API را تحت بار بالا برای شناسایی آسیب‌پذیری‌های DoS تست کنید.

### 🚨 امنیت عملیاتی
- [ ] **برنامه پاسخ به حوادث.** رویه‌های پاسخ به حوادث امنیتی را مستند و تمرین کنید.
- [ ] **Runbookهای امنیتی.** Runbook برای سناریوهای امنیتی رایج ایجاد کنید.
- [ ] **برنامه بازیابی از بلایا.** رویه‌های پشتیبان‌گیری و بازیابی را به طور منظم تست کنید.
- [ ] **آموزش امنیتی.** آموزش امنیتی منظم برای تیم توسعه ارائه دهید.
- [ ] **مدل‌سازی تهدید.** جلسات مدل‌سازی تهدید برای ویژگی‌های جدید برگزار کنید.
- [ ] **برنامه Bug Bounty.** پیاده‌سازی برنامه افشای مسئولانه را در نظر بگیرید.
- [ ] **قهرمانان امنیتی.** قهرمانان امنیتی را در تیم‌های توسعه تعیین کنید.
- [ ] **تحلیل پس از مرگ.** پس از حوادث امنیتی، تحلیل‌های بدون سرزنش انجام دهید.
- [ ] **معیارهای امنیتی.** KPIهای امنیتی را پیگیری و گزارش کنید (MTTD، MTTR، تعداد آسیب‌پذیری‌ها).

### 🔧 کنترل‌های فنی پیشرفته
- [ ] **اعتبارسنجی Schema API.** تمام درخواست‌ها را در برابر OpenAPI/JSON Schema اعتبارسنجی کنید.
- [ ] **Idempotency.** Idempotency را برای عملیات POST/PUT/PATCH پیاده‌سازی کنید.
- [ ] **امنیت Pagination.** اندازه صفحه را محدود کنید و پارامترهای Pagination را اعتبارسنجی کنید.
- [ ] **Pagination مبتنی بر Cursor.** از Pagination مبتنی بر Cursor برای جلوگیری از نشت داده استفاده کنید.
- [ ] **امنیت Cache.** هدرهای Cache-Control را پیاده‌سازی کنید و از Cache Poisoning جلوگیری کنید.
- [ ] **ابطال Cache.** داده‌های حساس کش شده را به درستی ابطال کنید.
- [ ] **امنیت Mock API.** اطمینان حاصل کنید که محیط‌های Mock داده‌های Production را فاش نمی‌کنند.
- [ ] **امضای درخواست.** امضای درخواست را برای عملیات با امنیت بالا پیاده‌سازی کنید (AWS Signature v4).
- [ ] **استفاده از Nonce.** از Nonceها برای جلوگیری از حملات Replay استفاده کنید.
- [ ] **اعتبارسنجی مبتنی بر زمان.** درخواست‌ها با Timestampهای خارج از پنجره قابل قبول را رد کنید.
- [ ] **محافظت از بمب فشرده‌سازی.** اندازه Payload فشرده‌سازی نشده را برای جلوگیری از DoS محدود کنید.
- [ ] **امنیت Unicode.** ورودی Unicode را برای جلوگیری از حملات Homograph اعتبارسنجی و پاکسازی کنید.
- [ ] **پیاده‌سازی HATEOAS.** لینک‌های Hypermedia را برای قابلیت کشف و امنیت بهتر API بگنجانید.
- [ ] **قراردادهای نام‌گذاری منبع.** از نام‌گذاری منبع یکپارچه و قابل پیش‌بینی استفاده کنید (اسامی جمع، حروف کوچک).
- [ ] **امنیت دانلود فایل.** مسیرهای فایل را اعتبارسنجی کنید، هدرهای Content-Disposition را تنظیم کنید، بدافزار را اسکن کنید.
- [ ] **امنیت Streaming.** احراز هویت و Rate Limiting مناسب برای Endpointهای Streaming پیاده‌سازی کنید.
- [ ] **پاکسازی فایل‌های موقت.** فایل‌های موقت را پس از پردازش به طور خودکار پاک کنید.
- [ ] **Certificate Pinning (موبایل).** Certificate Pinning را برای کلاینت‌های API موبایل پیاده‌سازی کنید.
- [ ] **App Attestation.** اصالت اپلیکیشن موبایل را با استفاده از APIهای Attestation پلتفرم تایید کنید.
- [ ] **تشخیص Jailbreak/Root.** دستگاه‌های به خطر افتاده را تشخیص دهید و امنیت را بر این اساس تنظیم کنید.
- [ ] **ذخیره‌سازی امن موبایل.** از Keychain/Keystore پلتفرم برای داده‌های حساس در موبایل استفاده کنید.
- [ ] **امنیت Server-Sent Events (SSE).** اتصالات SSE را احراز هویت کنید و منابع رویداد را اعتبارسنجی کنید.
- [ ] **امنیت Long Polling.** Timeoutها و احراز هویت را برای Endpointهای Long Polling پیاده‌سازی کنید.
- [ ] **امنیت WebRTC.** از سرورهای TURN/STUN با احراز هویت استفاده کنید، جریان‌های رسانه را رمزنگاری کنید.
- [ ] **انتخاب الگوریتم رمزنگاری.** از AES-256-GCM برای رمزنگاری، SHA-256+ برای هش استفاده کنید.
- [ ] **چرخه عمر مدیریت کلید.** سیاست‌های تولید، چرخش، لغو و نابودی کلید را پیاده‌سازی کنید.
- [ ] **مدیریت گواهی.** تمدید گواهی را خودکار کنید، تاریخ‌های انقضا را مانیتور کنید.
- [ ] **HSM برای عملیات حساس.** از ماژول‌های امنیتی سخت‌افزاری برای عملیات رمزنگاری با کلیدهای حساس استفاده کنید.

### 🛠️ جدول ابزارهای امنیتی
| دسته‌بندی | ابزار | توضیحات |
| :--- | :--- | :--- |
| **SAST** | [SonarQube](https://www.sonarqube.org/) | تحلیل استاتیک کد برای یافتن آسیب‌پذیری‌ها. |
| **DAST** | [OWASP ZAP](https://www.zaproxy.org/) | تست داینامیک APIهای در حال اجرا. |
| **SCA** | [Snyk](https://snyk.io/) | اسکن کتابخانه‌ها برای یافتن نسخه‌های ناامن. |
| **تست** | [Postman](https://www.postman.com/) | اسکریپت‌های تست خودکار امنیت. |

</div>

---

### 🛠️ Tools & Resources / ابزارها و منابع

#### Security Standards & Frameworks
- **[OWASP API Security Top 10](https://owasp.org/www-project-api-security/)** - Top 10 API security risks
- **[OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)** - Application Security Verification Standard
- **[NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)** - Comprehensive security framework
- **[CIS Controls](https://www.cisecurity.org/controls)** - Critical security controls
- **[ISO/IEC 27001](https://www.iso.org/isoiec-27001-information-security.html)** - Information security management
- **[PCI DSS](https://www.pcisecuritystandards.org/)** - Payment Card Industry Data Security Standard
- **[SOC 2](https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/aicpasoc2report.html)** - Service Organization Control 2
- **[GDPR](https://gdpr.eu/)** - General Data Protection Regulation
- **[HIPAA](https://www.hhs.gov/hipaa/index.html)** - Health Insurance Portability and Accountability Act

#### Testing & Scanning Tools
- **[Postman Security Scanner](https://www.postman.com/automated-testing/)** - Automated API security testing
- **[Insomnia Inso](https://insomnia.rest/products/inso)** - CLI tool for API testing
- **[REST Assured](https://rest-assured.io/)** - Java library for REST API testing
- **[Karate DSL](https://github.com/karatelabs/karate)** - API test automation framework
- **[Dredd](https://dredd.org/)** - HTTP API testing framework
- **[Schemathesis](https://schemathesis.readthedocs.io/)** - Property-based testing for APIs

#### API Gateways & Management
- **[Kong](https://konghq.com/)** - Cloud-native API gateway
- **[Tyk](https://tyk.io/)** - Open-source API gateway
- **[AWS API Gateway](https://aws.amazon.com/api-gateway/)** - Managed API gateway service
- **[Azure API Management](https://azure.microsoft.com/en-us/services/api-management/)** - Full lifecycle API management
- **[Apigee](https://cloud.google.com/apigee)** - API management platform
- **[MuleSoft](https://www.mulesoft.com/)** - Integration and API platform

#### Monitoring & Observability
- **[Datadog](https://www.datadoghq.com/)** - Monitoring and security platform
- **[New Relic](https://newrelic.com/)** - Observability platform
- **[Grafana](https://grafana.com/)** - Metrics visualization
- **[Prometheus](https://prometheus.io/)** - Monitoring and alerting toolkit
- **[Jaeger](https://www.jaegertracing.io/)** - Distributed tracing
- **[Zipkin](https://zipkin.io/)** - Distributed tracing system

#### Documentation & Design
- **[Swagger/OpenAPI](https://swagger.io/)** - API documentation standard
- **[Redoc](https://redocly.com/)** - OpenAPI documentation generator
- **[Stoplight](https://stoplight.io/)** - API design and documentation
- **[Postman](https://www.postman.com/)** - API development and documentation

#### Learning Resources
- **[API Security Articles](https://apisecurity.io/)** - Weekly API security newsletter
- **[PortSwigger Web Security Academy](https://portswigger.net/web-security)** - Free online security training
- **[OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)** - Security cheat sheets
- **[HackerOne Hacktivity](https://hackerone.com/hacktivity)** - Real-world vulnerability reports
- **[API Security Best Practices (Microsoft)](https://docs.microsoft.com/en-us/azure/architecture/best-practices/api-design)** - API design guidance

<div dir="rtl">

#### استانداردها و چارچوب‌های امنیتی
- **OWASP API Security Top 10** - ۱۰ ریسک برتر امنیت API
- **ISO/IEC 27001** - مدیریت امنیت اطلاعات
- **PCI DSS** - استاندارد امنیت داده صنعت کارت پرداخت
- **GDPR** - مقررات عمومی حفاظت از داده
- **NIST Cybersecurity Framework** - چارچوب جامع امنیت سایبری

#### ابزارهای تست و اسکن
- **Postman** - تست خودکار امنیت API
- **OWASP ZAP** - تست داینامیک امنیتی
- **Burp Suite** - مجموعه ابزار تست نفوذ
- **Nuclei** - اسکنر سریع آسیب‌پذیری

#### API Gateway و مدیریت
- **Kong** - API Gateway ابری
- **AWS API Gateway** - سرویس مدیریت API
- **Tyk** - API Gateway متن‌باز

#### مانیتورینگ
- **Datadog** - پلتفرم مانیتورینگ و امنیت
- **Grafana** - نمایش متریک‌ها
- **Prometheus** - مانیتورینگ و هشدار

#### منابع یادگیری
- **API Security Articles** - خبرنامه هفتگی امنیت API
- **OWASP Cheat Sheet Series** - برگه‌های تقلب امنیتی
- **PortSwigger Web Security Academy** - آموزش رایگان امنیت

</div>

---

### 🤝 Contributing / مشارکت
Contributions are welcome! If you have a security tip, please open a Pull Request.
مشارکت شما باعث افتخار است! اگر نکته امنیتی دارید، لطفاً یک Pull Request ارسال کنید.

**How to Contribute:**
1. Fork this repository
2. Create a new branch (`git checkout -b feature/security-improvement`)
3. Make your changes
4. Test your changes
5. Commit your changes (`git commit -am 'Add new security checklist item'`)
6. Push to the branch (`git push origin feature/security-improvement`)
7. Create a Pull Request

**Contribution Guidelines:**
- Ensure your suggestion is practical and actionable
- Provide references or sources when possible
- Keep descriptions concise and clear
- Add both English and Persian translations
- Follow the existing format and structure

---

### 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

### ⭐ Show Your Support
If you find this checklist helpful, please give it a star! It helps others discover this resource.

[![GitHub stars](https://img.shields.io/github/stars/MrAlfak/API-Security-Checklist?style=social)](https://github.com/MrAlfak/API-Security-Checklist/stargazers)

---

### 📞 Contact & Support
- **Issues:** [GitHub Issues](https://github.com/MrAlfak/API-Security-Checklist/issues)
- **Discussions:** [GitHub Discussions](https://github.com/MrAlfak/API-Security-Checklist/discussions)
- **Security Vulnerabilities:** Please report security issues privately via GitHub Security Advisories

---

**Disclaimer:** This checklist is provided as a guide and does not guarantee complete security. Always conduct thorough security assessments and stay updated with the latest security practices.

**سلب مسئولیت:** این چک‌لیست به عنوان راهنما ارائه شده و امنیت کامل را تضمین نمی‌کند. همیشه ارزیابی‌های امنیتی کامل انجام دهید و با آخرین روش‌های امنیتی به‌روز باشید.
