# Security Policy

## Supported Versions

We provide security updates and patches for the following versions of `m3c-tools` and `skillctl`:

| Version | Supported          |
| ------- | ------------------ |
| 2.x     | :white_check_mark: |
| 1.x     | :white_check_mark: |
| < 1.0   | :x:                |

## Security Model & Threat Boundaries

- **`skillctl` (Agent Governance & Capability Plane)**:
  - Verifies cryptographic signatures (Ed25519) offline without external authority dependency.
  - Generates and verifies HMAC-based session installation tokens.
  - Implements fail-closed admission and revocation contracts.
- **`m3c-tools` (Multimodal Capture & Sync)**:
  - Protects credentials (ER1 API keys, OAuth tokens) using system keychains (macOS Keychain, Linux Secret Service, Windows Credential Manager) where available, falling back to local user-permission-restricted configuration files (`0600`).
  - Strict host-pinning and TLS validation on outbound connections.

## Reporting a Vulnerability

If you discover a security vulnerability within `m3c-tools` or `skillctl`, please report it responsibly:

1. **Do NOT open a public issue.**
2. Send an email describing the issue, impact, and proof-of-concept to the security team or repository maintainers.
3. We will acknowledge receipt of your vulnerability report within 48 hours and provide a coordinated disclosure timeline.

## Automated Security Audits

This repository executes:
- Continuous secret scanning via `gitleaks`.
- Vulnerability scanning on dependencies via `govulncheck`.
- Concurrency race detection (`-race`) on all cryptographic and security-critical packages.
