# 🛡️ چک‌لیست امنیت API

[English](README.md) • [کنترل‌های ساختاریافته](checklist/) • [مثال‌ها](EXAMPLES.md) • [آسیب‌پذیری‌ها](VULNERABILITIES.md) • [نسخه‌ها](CHANGELOG.md)

این پروژه یک **چک‌لیست عملی، قابل ممیزی و ماشین‌خوان برای امنیت API** است که برای تیم‌های توسعه، AppSec، DevSecOps، تست نفوذ و معماری نرم‌افزار طراحی شده است.

ویژگی‌های اصلی:

- **۶۵ کنترل امنیتی کاملاً دوزبانه فارسی/انگلیسی** با شناسه ثابت، شدت، دامنه، روش بررسی و شواهد مورد انتظار
- هم‌راستا با **OWASP API Security Top 10 2023** و **OWASP ASVS 5.0.0**
- پوشش **OAuth Security BCP (RFC 9700)** و **JWT BCP (RFC 8725)**
- پشتیبانی از REST، GraphQL، gRPC، WebSocket، Webhook، APIهای داخلی، عمومی و SaaS چندمستاجری
- کنترل‌های Machine-readable در قالب YAML برای استفاده در Audit و ابزارهای خودکار
- مثال‌های امن و قابل استفاده برای پیاده‌سازی و تست

> اگر این پروژه برای شما مفید است، ⭐ Star کردن آن کمک می‌کند افراد بیشتری آن را پیدا کنند و توسعه پروژه سریع‌تر شود.

## شروع سریع

برای بررسی ساختار کنترل‌ها:

```bash
ruby scripts/validate_controls.rb
```

برای کنترل Regression توصیه‌های امنیتی:

```bash
python3 scripts/security_content_regression.py
```

کنترل‌ها در پوشه [`checklist/`](checklist/) قرار دارند و هر کنترل شامل این اطلاعات است:

- عنوان فارسی و انگلیسی
- الزام امنیتی فارسی و انگلیسی
- Severity
- Scope
- مراحل Verification فارسی و انگلیسی
- Evidence فارسی و انگلیسی
- مراجع معتبر

## مناسب چه کسانی است؟

- توسعه‌دهندگان Backend و API
- مهندسان AppSec و Product Security
- تیم‌های DevSecOps
- Penetration Testerها
- Security Auditorها
- تیم‌های SaaS و Multi-tenant
- معماران نرم‌افزار و Tech Leadها

## موضوعات مهم پوشش‌داده‌شده

Authentication، Authorization، BOLA/IDOR، OAuth، OpenID Connect، JWT/JOSE، Password Security، Session Security، API Keys، Input Validation، Injection، XSS، SSRF، File Upload، Rate Limiting، GraphQL، gRPC، WebSocket، Webhook، Multi-tenant Isolation، Logging، Secrets Management، Supply Chain Security و API Inventory.

## مشارکت

پیشنهاد کنترل جدید، اصلاح استانداردها، ترجمه بهتر و مثال‌های امن استقبال می‌شوند. قبل از مشارکت [`CONTRIBUTING.md`](CONTRIBUTING.md) را بخوانید.

برای گزارش آسیب‌پذیری واقعی از روند [`SECURITY.md`](SECURITY.md) استفاده کنید و آن را در Issue عمومی منتشر نکنید.

## مجوز

MIT License — استفاده، Fork و توسعه با رعایت متن مجوز آزاد است.
