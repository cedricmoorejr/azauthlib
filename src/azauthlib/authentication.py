# -*- coding: utf-8 -*-

#
# doydl's Microsoft Identity Authentication Library — azauthlib
#
# The `azauthlib` module is a secure authentication library for acquiring, caching, and
# refreshing Microsoft identity platform tokens across public and confidential client
# applications — built on MSAL for Python and MSAL Extensions.
#
# Designed for predictable credential handling, `azauthlib` supports interactive, silent,
# device-code, and client-credentials flows — separating delegated scopes from application
# scopes and returning explicit authentication results and typed failures.
#
# The library combines exact-path configuration loading, OS-backed secret storage, and
# encrypted, cross-process-safe token persistence to support Microsoft Graph clients,
# automation services, and desktop applications.
#
# It avoids import-time filesystem side effects, fails closed when secure cache persistence
# is unavailable, and normalizes application data paths consistently across Windows, macOS,
# and Linux.
#
# Whether embedded in command-line tools, desktop applications, background services, or data
# pipelines, `azauthlib` provides a focused security boundary around Microsoft identity
# configuration and token acquisition.
#
# Copyright (c) 2024 by doydl technologies. All rights reserved.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the “Software”), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

"""Microsoft identity platform authentication built on MSAL."""

from __future__ import annotations

import logging
import os
import time
import warnings
import webbrowser
from collections.abc import Mapping
from typing import Any

from dotenv import dotenv_values
from msal import ConfidentialClientApplication, PublicClientApplication

from ._configure import get_settings
from .credentials import load_credentials
from .permissions import application_scope_fmt, scope_fmt
from .tokens import load_token_cache, resolve_token_path, tokentime_fmt

logger = logging.getLogger(__name__)
CLIENT_SECRET_ENV = "CLIENT_" + "SECRET"
INTERACTION_REQUIRED_ERRORS = {
    "consent_required",
    "interaction_required",
    "login_required",
    "no_tokens_found",
}


class AuthenticationError(RuntimeError):
    """Base exception for failed authentication operations."""

    def __init__(self, message: str, *, error=None, correlation_id=None):
        super().__init__(message)
        self.error = error
        self.correlation_id = correlation_id


class InteractionRequiredError(AuthenticationError):
    """Raised when silent authentication requires user interaction."""


def client_secret_valid(secret) -> bool:
    """Perform structural validation without guessing Microsoft's secret format."""
    return isinstance(secret, str) and bool(secret) and not any(ord(char) < 0x20 for char in secret)


class _CredentialBuilder:
    def __init__(self, auth: Authentication):
        self.auth = auth

    def Default(self, authority=None):
        credentials = load_credentials(self.auth.default_env_path)
        if authority:
            credentials["authority"] = authority
        return self.WithEntry(**credentials)

    def WithEntry(self, client_id, tenant_id, client_secret=None, authority=None):
        if not client_id or not tenant_id:
            raise ValueError("client_id and tenant_id are required")
        public_values = {"client_id": client_id, "tenant_id": tenant_id}
        if authority is not None:
            public_values["authority"] = authority
        for name, value in public_values.items():
            if not isinstance(value, str) or any(
                ord(char) < 0x20 or ord(char) == 0x7F for char in value
            ):
                raise ValueError(f"{name} contains invalid control characters")
        if client_secret is not None and not client_secret_valid(client_secret):
            raise ValueError("client_secret contains invalid control characters")
        self.auth.client_id = str(client_id).strip()
        self.auth.tenant_id = str(tenant_id).strip()
        self.auth.client_secret = client_secret
        self.auth.authority = (
            authority or f"https://login.microsoftonline.com/{self.auth.tenant_id}"
        )
        return self.auth

    def WithEnvFile(self, env_path, key_map=None, authority=None):
        selected = os.path.abspath(os.path.expanduser(os.fspath(env_path)))
        if not os.path.isfile(selected):
            raise FileNotFoundError(f"The specified .env file does not exist: {selected}")
        values = dotenv_values(selected)
        mapping = key_map or {
            "client_id": "CLIENT_ID",
            "tenant_id": "TENANT_ID",
            "client_secret": CLIENT_SECRET_ENV,
        }
        unknown = set(mapping) - {"client_id", "tenant_id", "client_secret"}
        if unknown:
            raise ValueError(f"Unsupported credential fields: {', '.join(sorted(unknown))}")
        credentials = {name: values.get(variable) for name, variable in mapping.items()}
        return self.WithEntry(authority=authority, **credentials)

    def WithOSEnv(self, key_map=None, authority=None):
        mapping = key_map or {
            "client_id": "CLIENT_ID",
            "tenant_id": "TENANT_ID",
            "client_secret": CLIENT_SECRET_ENV,
        }
        if isinstance(mapping, list):
            if not 2 <= len(mapping) <= 3:
                raise ValueError("Expected 2 or 3 environment-variable names")
            mapping = dict(zip(("client_id", "tenant_id", "client_secret"), mapping, strict=False))
        if not isinstance(mapping, Mapping):
            raise TypeError("key_map must be a mapping or list of environment-variable names")
        credentials = {}
        for name in ("client_id", "tenant_id", "client_secret"):
            variable = mapping.get(name)
            credentials[name] = os.getenv(variable) if variable else None
        missing = [name for name in ("client_id", "tenant_id") if not credentials[name]]
        if missing:
            raise ValueError(f"Missing required environment variables for: {', '.join(missing)}")
        return self.WithEntry(authority=authority, **credentials)


class Authentication:
    """Acquire Microsoft identity platform tokens using public or confidential flows.

    Token persistence is initialized lazily and is encrypted by default. Set
    ``allow_plaintext_cache=True`` only after making an explicit risk decision.
    """

    def __init__(self, scopes=None, token_path=None, *, allow_plaintext_cache: bool = False):
        settings = get_settings()
        self.client_id: str | None = None
        self.tenant_id: str | None = None
        self.client_secret: str | None = None
        self.authority: str | None = None
        self.default_env_path = str(settings.env_path)
        self.default_token_path = str(settings.token_path)
        self.token_path = resolve_token_path(token_path, default=settings.token_path)
        self.allow_plaintext_cache = allow_plaintext_cache
        self._scopes_explicit = scopes is not None
        self.scopes = scope_fmt(scopes=scopes)
        self.token_result_cache: dict[str, Any] = {}
        self.Build = _CredentialBuilder(self)
        self._token_cache = None
        self._access_token: str | None = None
        self._id_token: str | None = None
        self._token_source: str | None = None
        self._last_flow: str | None = None
        self._issued_at: int | None = None
        self._expires_at: int | None = None

    def _cache(self):
        if self._token_cache is None:
            self._token_cache = load_token_cache(
                self.token_path,
                allow_plaintext=self.allow_plaintext_cache,
            )
        return self._token_cache

    def _require_configuration(self, *, confidential: bool = False) -> None:
        if not self.client_id or not self.authority:
            raise ValueError("Configure client_id and tenant_id/authority before authentication")
        if confidential and not self.client_secret:
            raise ValueError("Client credentials authentication requires a client secret")

    def _public_app(self) -> PublicClientApplication:
        self._require_configuration()
        return PublicClientApplication(
            client_id=self.client_id,
            authority=self.authority,
            token_cache=self._cache(),
        )

    def _update_internal_state(self, result: Mapping[str, Any]) -> None:
        now = int(time.time())
        self.token_result_cache = dict(result)
        self._access_token = result.get("access_token")
        self._id_token = result.get("id_token")
        self._token_source = result.get("token_source")
        claims = result.get("id_token_claims") or {}
        self._issued_at = int(claims.get("iat", now))
        expires_on = result.get("expires_on")
        self._expires_at = int(expires_on) if expires_on else now + int(result.get("expires_in", 0))

    def _successful(
        self,
        result,
        operation: str,
        *,
        flow: str | None = None,
    ) -> dict[str, Any]:
        if result and result.get("access_token"):
            self._update_internal_state(result)
            self._last_flow = flow
            logger.info("%s succeeded", operation)
            return dict(result)
        error = (result or {}).get("error")
        correlation_id = (result or {}).get("correlation_id")
        description = (result or {}).get("error_description") or error or "No token returned"
        logger.error(
            "%s failed: error=%s correlation_id=%s",
            operation,
            error,
            correlation_id,
        )
        raise AuthenticationError(
            f"{operation} failed: {description}",
            error=error,
            correlation_id=correlation_id,
        )

    def Silent(self, scopes=None, *, fallback_to_interactive: bool = False):
        app = self._public_app()
        accounts = app.get_accounts()
        if not accounts:
            if fallback_to_interactive:
                return self.Interactive(scopes=scopes)
            raise InteractionRequiredError("No cached account is available")
        result = app.acquire_token_silent(
            scope_fmt(scopes=scopes or self.scopes), account=accounts[0]
        )
        if result and result.get("access_token"):
            return self._successful(result, "Silent authentication", flow="delegated")
        error = (result or {}).get("error")
        interaction_required = result is None or error in INTERACTION_REQUIRED_ERRORS
        if interaction_required and fallback_to_interactive:
            return self.Interactive(scopes=scopes)
        if interaction_required:
            raise InteractionRequiredError(
                "Silent authentication could not acquire a token",
                error=error,
                correlation_id=(result or {}).get("correlation_id"),
            )
        return self._successful(result, "Silent authentication")

    def Interactive(self, scopes=None, **kwargs):
        app = self._public_app()
        result = app.acquire_token_interactive(
            scopes=scope_fmt(scopes=scopes or self.scopes), **kwargs
        )
        return self._successful(result, "Interactive authentication", flow="delegated")

    def ClientCredentials(self, scopes=None):
        self._require_configuration(confidential=True)
        requested = (
            scopes if scopes is not None else (self.scopes if self._scopes_explicit else None)
        )
        app = ConfidentialClientApplication(
            client_id=self.client_id,
            authority=self.authority,
            client_credential=self.client_secret,
            token_cache=self._cache(),
        )
        result = app.acquire_token_for_client(scopes=application_scope_fmt(requested))
        return self._successful(
            result,
            "Client credentials authentication",
            flow="client_credentials",
        )

    def DeviceCodeFlow(self, scopes=None, webbrowser_enabled=False):
        app = self._public_app()
        flow = app.initiate_device_flow(scopes=scope_fmt(scopes=scopes or self.scopes))
        if "user_code" not in flow:
            return self._successful(flow, "Device code initialization")
        verification_uri = flow.get("verification_uri")
        if webbrowser_enabled and verification_uri:
            webbrowser.open(verification_uri)
        print(flow.get("message") or f"Visit {verification_uri} and enter {flow['user_code']}")
        result = app.acquire_token_by_device_flow(flow)
        return self._successful(result, "Device code authentication", flow="delegated")

    @property
    def access_token(self) -> str:
        if not self._access_token or self.token_expires_in <= 300:
            if self._last_flow == "client_credentials":
                self.ClientCredentials()
            else:
                self.Silent()
        if not self._access_token:
            raise InteractionRequiredError("No access token is available")
        return self._access_token

    @property
    def token_expires_in(self) -> int:
        return max(0, (self._expires_at or 0) - int(time.time()))

    @property
    def token_expires_at(self) -> str | None:
        return tokentime_fmt(self._expires_at)

    @property
    def token_ext_expires_in(self):
        return None

    @property
    def refresh_token_value(self):
        warnings.warn(
            "MSAL manages refresh tokens inside its cache; direct access is unavailable",
            DeprecationWarning,
            stacklevel=2,
        )
        return None

    @property
    def id_token(self):
        return self._id_token

    @property
    def token_source(self):
        return self._token_source

    @property
    def token_issued_at(self):
        return tokentime_fmt(self._issued_at)

    @property
    def token_valid_after(self):
        claims = self.token_result_cache.get("id_token_claims") or {}
        return tokentime_fmt(claims.get("nbf"))

    @property
    def token_expiration(self):
        return tokentime_fmt(self._expires_at)


__all__ = [
    "Authentication",
    "AuthenticationError",
    "InteractionRequiredError",
    "client_secret_valid",
]
