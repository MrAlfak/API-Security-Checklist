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
- [نسخه فارسی](#نسخه-فارسی)
    - [احراز هویت و مجوزدهی](#-احراز-هویت-و-مجوزدهی)
    - [امنیت JWT](#-امنیت-jwt)
    - [کنترل دسترسی و ترافیک](#-کنترل-دسترسی-و-ترافیک)
    - [اعتبارسنجی ورودی‌ها](#-اعتبارسنجی-ورودی‌ها)
    - [امنیت خروجی و پاسخ‌ها](#-امنیت-خروجی-و-پاسخ‌ها)
    - [امنیت دیتابیس](#-امنیت-دیتابیس-1)
    - [لاگینگ و مانیتورینگ](#-لاگینگ-و-مانیتورینگ-1)
    - [زیرساخت و CI/CD](#-زیرساخت-و-cicd-1)
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

### 🎫 JWT (JSON Web Token)
- [ ] **Strong Secrets.** Use a random, complex secret key (at least 32 characters).
- [ ] **Enforce Algorithm.** Don't trust the `alg` header; enforce `HS256` or `RS256` on the server.
- [ ] **Short TTL.** Keep expiration times (TTL) as short as possible.
- [ ] **Don't Store Secrets in Payload.** JWT payload is easily decoded; never store PII or passwords.
- [ ] **Revocation Strategy.** Implement a blacklist or refresh token mechanism to revoke tokens.

### 🚦 Access & Throttling
- [ ] **Rate Limiting.** Implement Throttling to prevent DDoS and Brute-force.
- [ ] **HTTPS Only.** Use TLS 1.2+ for all communications.
- [ ] **HSTS.** Enable HTTP Strict Transport Security.
- [ ] **CORS.** Only allow trusted domains. Avoid `Access-Control-Allow-Origin: *`.
- [ ] **IP Whitelisting.** For private APIs, restrict access to specific IP ranges.

### 📥 Input Validation
- [ ] **Correct HTTP Methods.** Use `GET` for reading, `POST` for creation, `PUT/PATCH` for updates, and `DELETE` for deletion.
- [ ] **Content-Type Validation.** Check `Accept` and `Content-Type` headers.
- [ ] **Sanitize Input.** Prevent XSS, SQL Injection, and NoSQL Injection.
- [ ] **File Uploads.** Validate file types, sizes, and scan for malware.
- [ ] **Limit Request Size.** Prevent large payload attacks.

### 📤 Output Security
- [ ] **Disable `X-Powered-By`.** Don't leak server technology info.
- [ ] **Generic Error Messages.** Don't expose stack traces or internal DB errors.
- [ ] **Data Masking.** Mask sensitive data (e.g., credit card numbers) in responses.
- [ ] **Security Headers.** Use `X-Content-Type-Options: nosniff`, `X-Frame-Options: deny`.

### 🗄️ Database Security
- [ ] **Parameterized Queries.** Use ORMs or prepared statements to prevent SQL Injection.
- [ ] **Principle of Least Privilege.** API should connect to DB with a user that only has necessary permissions.
- [ ] **Encryption at Rest.** Ensure sensitive data is encrypted in the database.
- [ ] **Audit Logs.** Enable logging for sensitive database operations.

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

### 🛠️ Security Tools Table
| Category | Tool | Description |
| :--- | :--- | :--- |
| **SAST** | [SonarQube](https://www.sonarqube.org/) | Static code analysis for vulnerabilities. |
| **DAST** | [OWASP ZAP](https://www.zaproxy.org/) | Dynamic testing of running APIs. |
| **SCA** | [Snyk](https://snyk.io/) | Scans dependencies for known vulnerabilities. |
| **Testing** | [Postman](https://www.postman.com/) | Automated security test scripts. |

---

<a name="نسخه-فارسی"></a>
## 🇮🇷 نسخه فارسی

### 🔑 احراز هویت و مجوزدهی
- [ ] **عدم استفاده از Basic Auth.** از روش‌های استاندارد مثل OAuth2 یا JWT استفاده کنید.
- [ ] **چرخ را دوباره اختراع نکنید.** از کتابخانه‌های تست شده برای هش کردن پسورد (مثل Argon2 یا bcrypt) استفاده کنید.
- [ ] **محدودیت تلاش مجدد.** برای جلوگیری از حملات Brute-force، تعداد دفعات ورود ناموفق را محدود کنید.
- [ ] **احراز هویت چندعاملی (MFA).** برای حساب‌های حساس حتما MFA پیاده‌سازی کنید.

### 🎫 امنیت JWT
- [ ] **کلیدهای پیچیده.** از یک Secret Key تصادفی و پیچیده (حداقل ۳۲ کاراکتر) استفاده کنید.
- [ ] **تحمیل الگوریتم.** به هدر توکن اعتماد نکنید و الگوریتم (HS256 یا RS256) را در سمت سرور اجباری کنید.
- [ ] **زمان انقضای کوتاه.** مقدار TTL را تا حد ممکن کوتاه در نظر بگیرید.
- [ ] **عدم ذخیره داده حساس.** پی‌لود JWT به راحتی دکود می‌شود؛ پسوردهای یا داده‌های هویتی را در آن قرار ندهید.

### 🚦 کنترل دسترسی و ترافیک
- [ ] **Rate Limiting.** برای جلوگیری از حملات DDoS و Brute-force، محدودیت تعداد درخواست بگذارید.
- [ ] **الزام HTTPS.** از TLS 1.2 به بالا برای تمامی ارتباطات استفاده کنید.
- [ ] **استفاده از HSTS.** برای جلوگیری از حملات SSL Strip، هدر HSTS را فعال کنید.
- [ ] **تنظیمات CORS.** فقط به دامنه‌های مورد اعتماد اجازه دسترسی دهید. از `*` استفاده نکنید.

### 📥 اعتبارسنجی ورودی‌ها
- [ ] **متدهای صحیح HTTP.** استفاده درست از GET، POST، PUT و DELETE.
- [ ] **اعتبارسنجی Content-Type.** هدرهای Accept و Content-Type را چک کنید.
- [ ] **پاکسازی ورودی.** جلوگیری از حملات XSS، SQL Injection و NoSQL Injection.
- [ ] **آپلود فایل.** نوع فایل، حجم و محتوای آن را بررسی کنید تا بدافزار نباشد.

### 📤 امنیت خروجی و پاسخ‌ها
- [ ] **غیرفعال کردن X-Powered-By.** اطلاعات تکنولوژی سرور را لو ندهید.
- [ ] **پیام‌های خطای عمومی.** هرگز Stack Trace یا خطاهای داخلی دیتابیس را به کاربر نمایش ندهید.
- [ ] **ماسک کردن داده‌ها.** داده‌های حساس (مثل شماره کارت) را در پاسخ‌ها ماسک کنید.

### 🗄️ امنیت دیتابیس
- [ ] **پرس‌وجوهای پارامتری.** از ORMها یا Prepared Statements برای جلوگیری از SQL Injection استفاده کنید.
- [ ] **اصل حداقل دسترسی.** API باید با کاربری به دیتابیس وصل شود که فقط دسترسی‌های ضروری را دارد.
- [ ] **رمزنگاری داده‌های حساس.** اطمینان حاصل کنید که داده‌های حساس در دیتابیس به صورت رمزنگاری شده ذخیره می‌شوند.

### 📝 لاگینگ و مانیتورینگ
- [ ] **عدم ذخیره PII در لاگ.** هرگز پسوردها، توکن‌ها یا داده‌های شخصی کاربران را لاگ نکنید.
- [ ] **لاگینگ متمرکز.** از ابزارهایی مثل ELK، Splunk یا Datadog استفاده کنید.
- [ ] **هشداردهی (Alerting).** برای فعالیت‌های مشکوک (مثلاً افزایش ناگهانی خطاهای 401 یا 403) هشدار تنظیم کنید.

### ☁️ زیرساخت و CI/CD
- [ ] **مدیریت سکرت‌ها.** از Vault یا متغیرهای محیطی استفاده کنید. هرگز کلیدها را در کد قرار ندهید (Hardcode).
- [ ] **اسکن وابستگی‌ها.** از ابزارهایی مثل `npm audit` یا Snyk برای یافتن پکیج‌های آسیب‌پذیر استفاده کنید.
- [ ] **امنیت کانتینر.** ایمیج‌های Docker را برای یافتن آسیب‌پذیری‌ها اسکن کنید.

### 🌐 تکنولوژی‌های مدرن (GraphQL/gRPC/WebSockets)
- [ ] **GraphQL: محدودیت عمق.** جلوگیری از حملات کوئری‌های تودرتو (Nested Queries).
- [ ] **GraphQL: غیرفعال‌سازی Introspection.** این ویژگی را در محیط Production غیرفعال کنید.
- [ ] **gRPC: الزام TLS.** همیشه از TLS برای ارتباطات gRPC استفاده کنید.
- [ ] **WebSockets: اعتبارسنجی Origin.** هدر Origin را برای جلوگیری از حملات CSWSH چک کنید.

### 🛠️ جدول ابزارهای امنیتی
| دسته‌بندی | ابزار | توضیحات |
| :--- | :--- | :--- |
| **SAST** | [SonarQube](https://www.sonarqube.org/) | تحلیل استاتیک کد برای یافتن آسیب‌پذیری‌ها. |
| **DAST** | [OWASP ZAP](https://www.zaproxy.org/) | تست داینامیک APIهای در حال اجرا. |
| **SCA** | [Snyk](https://snyk.io/) | اسکن کتابخانه‌ها برای یافتن نسخه‌های ناامن. |
| **تست** | [Postman](https://www.postman.com/) | اسکریپت‌های تست خودکار امنیت. |

---

### 🛠️ Tools & Resources / ابزارها و منابع
- **[OWASP API Security Top 10](https://owasp.org/www-project-api-security/)**
- **[Postman Security Scanner](https://www.postman.com/automated-testing/)**
- **[Insomnia Inso](https://insomnia.rest/products/inso)**
- **[Snyk](https://snyk.io/)** - Open Source Security Platform

---
### 🤝 Contributing / مشارکت
Contributions are welcome! If you have a security tip, please open a Pull Request.
مشارکت شما باعث افتخار است! اگر نکته امنیتی دارید، لطفاً یک Pull Request ارسال کنید.
