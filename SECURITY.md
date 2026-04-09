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
| 1.x     | :white_check_mark: |

## Security Considerations

- Token values are generated using cryptographically secure random bytes
- JWT mode uses `firebase/php-jwt` with proper signature verification
- SM4 encryption uses CBC mode with random IV (prepended to ciphertext)
- SM2 signatures follow GM/T 0003-2012 standard
- Password-based authentication should always be implemented server-side
- Always use HTTPS in production to protect token transmission
