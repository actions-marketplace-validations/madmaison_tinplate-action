# Security Policy

Tinplate builds stateless security, guardrail, and compliance micro-APIs. We welcome coordinated vulnerability reports from security researchers and users.

## Supported Versions

| Component | Version | Security Fixes |
| --- | --- | --- |
| Edge Gateway & Web (`edgeguard-gateway`, `edgeguard-web`, `edgeguard-fetcher`) | `1.0.39` | Active |
| TypeScript SDK (`@tinplate/sdk`) | `1.1.7` | Active |
| Python SDK (`tinplate`) | `1.1.7` | Active |

## Reporting a Vulnerability

Please report security vulnerabilities **privately** via encrypted email or review our Trust Center policy:

- Security Email: `security@tinplate.dev` (verified active; encrypt sensitive details using our PGP public key at https://tinplate.dev/.well-known/pgp-key.asc)
- General / Enterprise Support: `support@tinplate.dev` (verified active; https://tinplate.dev/support)
- Public GitHub Action & SDK Issue Tracker: https://github.com/madmaison/tinplate-action/issues (do **not** file security vulnerabilities publicly)

Our RFC 9116 disclosure metadata is published at:

- https://tinplate.dev/.well-known/security.txt

When reporting an issue, please include:

1. A minimal proof-of-concept request or reproduction snippet.
2. The target endpoint or SDK function and `X-Request-Id` response header (if observed in production).
3. Please do not conduct denial-of-service testing, automated high-rate scanning, or SSRF testing against third-party hosts.

**Safe Harbour:** Tinplate supports coordinated vulnerability disclosure and will not pursue legal action for good-faith, non-destructive research that follows these guidelines.

We aim to acknowledge reports within **48 hours** and ship remediation within **7 days**.
