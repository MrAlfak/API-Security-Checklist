# Security Policy

## Scope

This repository contains security guidance and illustrative code. A defect in the guidance can itself be security-relevant when it recommends an unsafe pattern, creates a misleading assurance, or contains an example that is likely to be copied into production.

## Reporting a security issue

Please **do not open a public issue** for a vulnerability that could put users at risk before coordinated review.

Use GitHub's private vulnerability reporting / Security Advisory feature for this repository when available. If private reporting is unavailable, contact the repository maintainer through a private channel listed on the maintainer's GitHub profile rather than publishing exploit details.

Include when possible:

- affected file, control ID, or example,
- impact and affected use cases,
- reproduction or failure scenario,
- authoritative reference or standard,
- suggested correction,
- whether the issue is already public elsewhere.

## What counts as a security report

Examples include:

- unsafe authentication/authorization guidance,
- broken OAuth/JWT examples,
- code examples that enable injection, token replay, file-upload bypass, or secret exposure,
- incorrect claims about OWASP/NIST/IETF requirements,
- CI/repository changes that expose credentials or create a supply-chain risk.

Typos, ordinary documentation improvements, and non-security feature requests can use normal issues.

## Project security baseline

Guidance is reviewed against authoritative sources including:

- OWASP API Security Top 10 2023,
- OWASP ASVS 5.0.0,
- OWASP Cheat Sheet Series,
- NIST SP 800-63B-4,
- RFC 9700 (OAuth 2.0 Security BCP),
- RFC 8725 (JWT BCP),
- RFC 9449 (DPoP),
- RFC 8705 (OAuth mTLS).

Security standards change. References and examples should be revalidated when specifications, browser behavior, libraries, or platform guidance materially change.

## Disclosure

The maintainer should validate the report, prepare a correction, and coordinate disclosure when necessary. Public discussion should avoid publishing actionable exploit details before affected users have a reasonable opportunity to update.

## Supported versions

Security corrections are made on the default branch and included in the next tagged release. Older tagged releases may not receive backports unless explicitly stated in release notes.
