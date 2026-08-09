#!/usr/bin/env python3
"""Small regression guard for security guidance that was previously unsafe/outdated."""

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
TARGETS = [
    ROOT / "README.md",
    ROOT / "EXAMPLES.md",
    ROOT / "VULNERABILITIES.md",
]

forbidden = {
    "legacy X-XSS filter enabled": re.compile(r"X-XSS-Protection\s*[:=].*1\s*;\s*mode=block", re.I),
    "random JWT signing-key fallback": re.compile(
        r"process\.env\.JWT_[A-Z_]*\s*\|\|\s*crypto\.randomBytes", re.I
    ),
    "old 12-char composition password policy": re.compile(
        r"(?:Password Complexity|password must).*12.*(?:uppercase|lowercase|special|symbol)", re.I
    ),
    "UUID described as BOLA fix": re.compile(
        r"Use UUIDs instead of sequential IDs", re.I
    ),
}

required_patterns = {
    "README NIST password minimum": (ROOT / "README.md", re.compile(r"minimum of \*\*15 characters\*\*", re.I)),
    "README RFC 9700": (ROOT / "README.md", re.compile(r"RFC 9700")),
    "README RFC 8725": (ROOT / "README.md", re.compile(r"RFC 8725")),
    "examples fail-closed secret": (ROOT / "EXAMPLES.md", re.compile(r"JWT_SECRET is required")),
    "examples refresh reuse detection": (ROOT / "EXAMPLES.md", re.compile(r"refresh_token_reuse_detected")),
    "examples upload content detection": (ROOT / "EXAMPLES.md", re.compile(r"detectAllowedType")),
    "vulnerability multi-tenant coverage": (ROOT / "VULNERABILITIES.md", re.compile(r"Multi-tenant isolation failure", re.I)),
}

errors: list[str] = []

for path in TARGETS:
    text = path.read_text(encoding="utf-8")
    for name, pattern in forbidden.items():
        if pattern.search(text):
            errors.append(f"{path.name}: forbidden regression detected: {name}")

for name, (path, pattern) in required_patterns.items():
    text = path.read_text(encoding="utf-8")
    if not pattern.search(text):
        errors.append(f"{path.name}: required security guidance missing: {name}")

if errors:
    print("Security content regression checks failed:", file=sys.stderr)
    for error in errors:
        print(f"- {error}", file=sys.stderr)
    sys.exit(1)

print("Security content regression checks passed.")
