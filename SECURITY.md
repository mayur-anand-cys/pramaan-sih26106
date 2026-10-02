# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| main    | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability, please do NOT open a public issue.

Open a private security advisory on GitHub instead:
https://github.com/mayur-anand-cys/pramaan-sih26106/security/advisories/new

We will respond within 72 hours and work with you to resolve the issue.

## Scope

This project analyzes potentially malicious emails. All parser and rendering logic is security-sensitive. Report any crash, hang, or data leak in:
- security_hardening.py
- backend/detection/
- report_gen.py and report_*.py
