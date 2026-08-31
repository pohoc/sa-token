# Security Policy

## Reporting a Vulnerability

This is an authentication and authorization library — security vulnerabilities are taken very seriously.

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to: **po.hoc4@gmail.com**

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Time

- **Acknowledgment**: within 48 hours
- **Initial assessment**: within 7 days
- **Fix timeline**: depends on severity, critical issues will be patched within 72 hours

### Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.1.x (latest) | :white_check_mark: |
| < 0.1.0 | :x: |

> 项目当前处于 0.x 阶段，仅最新 minor 版本接收安全修复。

## Security Considerations

- Token values are generated using cryptographically secure random bytes
- JWT mode uses `firebase/php-jwt` with proper signature verification
- Token storage encryption (AES-256-CBC) uses Encrypt-then-MAC with a dedicated MAC key; SM4 mode uses keyed HMAC-SM3 for integrity
- OAuth2 enforces redirect_uri binding, scope/grant_type whitelists, PKCE (S256) and refresh-token reuse detection
- SSO login callback enforces state validation; check-ticket responses are signature-verified when a clientSecret is configured
- SM2 signatures follow GM/T 0003-2012 standard
- Password-based authentication should always be implemented server-side
- Always use HTTPS in production to protect token transmission
