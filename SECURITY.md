# Security Policy

## Supported Versions

We provide security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 2.0.x   | ✅ Current         |
| < 2.0   | ❌ Not supported   |

## Reporting a Vulnerability

If you discover a security vulnerability within w3af, please send an e-mail to security@w3af.org. All security vulnerabilities should be promptly addressed.

Please include the following information:

- Type of vulnerability
- Full paths of source file(s) related to the vulnerability
- Location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

## Security Best Practices

When using w3af for security testing:

1. **Only test systems you own or have permission to test**
2. **Use isolated environments** for testing when possible
3. **Understand the legal implications** in your jurisdiction
4. **Keep the tool updated** for latest security checks
5. **Review scan results carefully** - false positives are possible

## Dependencies Security

We regularly scan dependencies for vulnerabilities using:
- `safety` - Python dependency vulnerability scanner
- `bandit` - Security issues in Python code
- Dependabot alerts (enabled in repository)

## CREDITS

This security policy is adapted from best practices in the open source community.