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

"""Exact-path configuration loading and OS-backed secret storage."""

from __future__ import annotations

import os
import tempfile
from contextlib import suppress
from pathlib import Path

import keyring
from dotenv import dotenv_values

from ._configure import get_settings
from .appdata import ensure_private_directory

KEYRING_SERVICE = "azauthlib"


class CredentialStoreError(RuntimeError):
    """Raised when credentials cannot be stored securely."""


def _public_config_value(name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} is required")
    normalized = value.strip()
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in normalized):
        raise ValueError(f"{name} contains invalid control characters")
    return normalized


def load_credentials(path=None) -> dict[str, str | None]:
    """Load credentials from one exact file, environment, and the OS keyring."""
    selected = Path(path or get_settings().env_path).expanduser().resolve()
    file_values = dotenv_values(selected) if selected.is_file() else {}
    client_id = os.getenv("CLIENT_ID") or file_values.get("CLIENT_ID")
    tenant_id = os.getenv("TENANT_ID") or file_values.get("TENANT_ID")
    secret = os.getenv("CLIENT_SECRET")
    if secret is None and client_id:
        try:
            secret = keyring.get_password(KEYRING_SERVICE, client_id)
        except Exception as exc:
            raise CredentialStoreError(
                "Unable to read the client secret from the OS keyring"
            ) from exc
    return {
        "client_id": client_id,
        "tenant_id": tenant_id,
        "client_secret": secret,
        "authority": os.getenv("AZURE_AUTHORITY") or file_values.get("AZURE_AUTHORITY"),
    }


def save_configuration(
    *,
    client_id: str,
    tenant_id: str,
    client_secret: str | None = None,
    authority: str | None = None,
    path=None,
) -> Path:
    """Write non-secret configuration and store the secret in the OS keyring."""
    client_id = _public_config_value("client_id", client_id)
    tenant_id = _public_config_value("tenant_id", tenant_id)
    if authority is not None:
        authority = _public_config_value("authority", authority)
    target = Path(path or get_settings().env_path).expanduser().resolve()
    ensure_private_directory(target.parent)
    if client_secret:
        try:
            keyring.set_password(KEYRING_SERVICE, client_id, client_secret)
        except Exception as exc:
            raise CredentialStoreError(
                "Unable to store the client secret in the OS keyring"
            ) from exc
    lines = [
        "# azauthlib public application configuration",
        f"CLIENT_ID={client_id}",
        f"TENANT_ID={tenant_id}",
    ]
    if authority:
        lines.append(f"AZURE_AUTHORITY={authority}")
    fd, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent, text=True)
    try:
        if os.name != "nt":
            os.chmod(temporary_name, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write("\n".join(lines) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, target)
    except Exception:
        with suppress(FileNotFoundError):
            os.unlink(temporary_name)
        raise
    return target


__all__ = ["CredentialStoreError", "load_credentials", "save_configuration"]
