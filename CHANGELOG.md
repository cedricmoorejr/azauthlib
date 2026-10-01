# Changelog

All notable changes follow Keep a Changelog and Python packaging version conventions.

## [1.4.0b1] - 2026-09-30

### Security

- Replace plaintext MSAL serialization with encrypted, locked persistence from MSAL Extensions.
- Store client secrets in the operating-system keyring rather than `.env` files.
- Remove recursive credential-directory deletion and constrain compatibility filesystem helpers.
- Make cache persistence fail closed unless plaintext storage is explicitly requested.

### Changed

- Use a standard `src/` package and `pyproject.toml` build.
- Remove import-time filesystem and logging side effects.
- Require `/.default` resource scopes for client-credentials authentication.
- Make authentication operations synchronous and return MSAL result dictionaries.
- Use typed exceptions for failed or interaction-required authentication.
- Normalize releases on PEP 440 versions such as `v1.4.0b1`.

### Fixed

- Preserve interactive results for logins taking longer than 30 seconds.
- Use MSAL's built-in blocking device-flow polling once rather than nesting it in another loop.
- Resolve directory cache paths to a deterministic `msal-cache.bin` filename.
- Load configuration from one exact path rather than searching for incidental `.env` files.
- Refresh application tokens through the client-credentials flow instead of delegated silent auth.
- Reject control characters in persisted public credential fields.
