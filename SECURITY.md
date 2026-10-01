# Security policy

## Supported versions

Security fixes are provided for the newest published beta or stable release.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting feature for this repository. Do not open a
public issue containing credentials, tokens, tenant identifiers, exploit details, or other secrets.

Include affected versions, reproduction steps, impact, and any suggested mitigation. You should
receive an acknowledgement within seven days. No guarantee of a bounty is made.

## Credential handling

- Never commit `.env` files, client secrets, token caches, certificates, or private keys.
- Token caches are encrypted through operating-system facilities by default.
- Plaintext cache persistence requires explicit opt-in and is not recommended.
- Prefer certificates or workload identity federation over shared client secrets for production.
