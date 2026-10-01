# azauthlib

Secure Microsoft identity platform authentication helpers built on
[MSAL for Python](https://github.com/AzureAD/microsoft-authentication-library-for-python).

> **Beta:** APIs may change before the first stable release. Do not deploy a beta upgrade without
> testing its cache, keyring, and authentication behavior in your environment.

[![PyPI](https://img.shields.io/pypi/v/azauthlib)](https://pypi.org/project/azauthlib/)
[![Python](https://img.shields.io/pypi/pyversions/azauthlib)](https://pypi.org/project/azauthlib/)
[![License](https://img.shields.io/github/license/cedricmoorejr/azauthlib)](LICENSE)

## Features

- Interactive, silent, device-code, and client-credentials authentication.
- Encrypted, cross-process-safe token persistence through MSAL Extensions.
- Client secrets stored in the operating-system credential manager.
- Exact-path `.env` loading; no upward directory search.
- Delegated and application scope handling kept separate.
- No filesystem writes or global logging configuration during import.

## Installation

```bash
python -m pip install azauthlib
```

From a source checkout:

```bash
git clone git@github.com:cedricmoorejr/azauthlib.git
cd azauthlib
python -m pip install .
```

Python 3.10 or newer is required.

## Public-client authentication

```python
from azauthlib import Authentication, InteractionRequiredError

auth = Authentication(scopes=["User.Read"])
auth.Build.WithEntry(
    client_id="00000000-0000-0000-0000-000000000000",
    tenant_id="organizations",
)

try:
    result = auth.Silent()
except InteractionRequiredError:
    result = auth.Interactive()

print(result["token_source"])
# Use auth.access_token only where an Authorization header is required.
```

Silent authentication does not unexpectedly launch a browser. Pass
`fallback_to_interactive=True` if that behavior is explicitly desired.

## Device-code authentication

```python
auth = Authentication(scopes=["Files.Read"])
auth.Build.WithEntry(client_id="...", tenant_id="organizations")
result = auth.DeviceCodeFlow(webbrowser_enabled=True)
```

MSAL controls polling and expiration. The method blocks until authentication completes or fails.

## Client-credentials authentication

Microsoft requires the `/.default` resource scope for client credentials:

```python
auth = Authentication()
auth.Build.WithEntry(
    client_id="...",
    tenant_id="...",
    client_secret="...",
)
result = auth.ClientCredentials()
# Default scope: https://graph.microsoft.com/.default
```

For production workloads, prefer a certificate or workload identity federation over a shared
secret when your deployment architecture supports it.

## Configuration

Environment variables are supported:

```bash
export CLIENT_ID="..."
export TENANT_ID="..."
export CLIENT_SECRET="..." # confidential clients only
```

```python
auth = Authentication(scopes=["User.Read"])
auth.Build.WithOSEnv()
```

`WithOSEnv()` treats mapping values strictly as environment-variable names. Use `WithEntry()` for
literal values.

The optional configuration application stores the client ID and tenant ID in azauthlib's platform
configuration directory. Client secrets go to the operating-system keyring, never the `.env` file:

```bash
azauthlib-app
```

## Token-cache security

Encrypted persistence is the default and fails closed when the OS encryption provider is
unavailable. On Linux, ensure an appropriate Secret Service/LibSecret backend is configured.

Plaintext fallback requires an explicit opt-in:

```python
auth = Authentication(allow_plaintext_cache=True)
```

Only use that option when file permissions and the threat model have been independently reviewed.

## Error handling

Authentication methods return the successful MSAL result dictionary. Failures raise:

- `AuthenticationError` for identity platform or protocol errors.
- `InteractionRequiredError` when silent authentication cannot continue.
- `TokenCacheSecurityError` when secure persistence cannot be established.

Error logs include error codes and correlation IDs, not full response dictionaries or tokens.

## Development

```bash
python -m pip install -e ".[dev]"
ruff check .
ruff format --check .
bandit -c pyproject.toml -r src
pip-audit --skip-editable
pytest
python -m build
twine check dist/*
```

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and
[CHANGELOG.md](CHANGELOG.md). Maintainers should also follow [RELEASING.md](RELEASING.md).

## License

Apache License 2.0. Microsoft, Azure, Entra, and Microsoft Graph are trademarks of Microsoft and
are not affiliated with or endorsed by this project.
