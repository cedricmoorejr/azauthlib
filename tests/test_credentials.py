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

"""Tests for configuration loading and credential storage."""

import pytest

from azauthlib import credentials


def test_configuration_never_writes_secret(monkeypatch, tmp_path):
    stored = {}
    monkeypatch.setattr(
        credentials.keyring,
        "set_password",
        lambda service, username, password: stored.update(
            service=service, username=username, password=password
        ),
    )
    target = credentials.save_configuration(
        client_id="client-id",
        tenant_id="tenant-id",
        client_secret="top-secret",
        path=tmp_path / ".env",
    )
    text = target.read_text(encoding="utf-8")
    assert "CLIENT_ID=client-id" in text
    assert "CLIENT_SECRET" not in text
    assert "top-secret" not in text
    assert stored["password"] == "top-secret"


def test_load_credentials_uses_one_exact_file(monkeypatch, tmp_path):
    target = tmp_path / "chosen.env"
    target.write_text("CLIENT_ID=file-client\nTENANT_ID=file-tenant\n", encoding="utf-8")
    monkeypatch.delenv("CLIENT_ID", raising=False)
    monkeypatch.delenv("TENANT_ID", raising=False)
    monkeypatch.delenv("CLIENT_SECRET", raising=False)
    monkeypatch.setattr(credentials.keyring, "get_password", lambda *_: "keyring-secret")
    result = credentials.load_credentials(target)
    assert result["client_id"] == "file-client"
    assert result["tenant_id"] == "file-tenant"
    assert result["client_secret"] == "keyring-secret"


def test_keyring_failure_is_actionable(monkeypatch, tmp_path):
    def fail(*_):
        raise RuntimeError("backend unavailable")

    monkeypatch.setattr(credentials.keyring, "set_password", fail)
    with pytest.raises(credentials.CredentialStoreError, match="OS keyring"):
        credentials.save_configuration(
            client_id="client",
            tenant_id="tenant",
            client_secret="secret",
            path=tmp_path / ".env",
        )


def test_load_keyring_failure_is_actionable(monkeypatch, tmp_path):
    target = tmp_path / ".env"
    target.write_text("CLIENT_ID=client\nTENANT_ID=tenant\n", encoding="utf-8")
    monkeypatch.delenv("CLIENT_SECRET", raising=False)
    monkeypatch.setattr(
        credentials.keyring,
        "get_password",
        lambda *_: (_ for _ in ()).throw(RuntimeError("unavailable")),
    )
    with pytest.raises(credentials.CredentialStoreError, match="OS keyring"):
        credentials.load_credentials(target)


def test_configuration_validation_and_authority(monkeypatch, tmp_path):
    with pytest.raises(ValueError, match="required"):
        credentials.save_configuration(client_id="", tenant_id="tenant", path=tmp_path / ".env")
    monkeypatch.setattr(credentials.keyring, "set_password", lambda *_: None)
    target = credentials.save_configuration(
        client_id="client",
        tenant_id="tenant",
        authority="https://authority.example",
        path=tmp_path / ".env",
    )
    assert "AZURE_AUTHORITY=https://authority.example" in target.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("client_id", "client\nINJECTED=value"),
        ("tenant_id", "tenant\rINJECTED=value"),
        ("authority", "https://example.test\x7fmalformed"),
    ],
)
def test_configuration_rejects_control_characters(tmp_path, field, value):
    values = {
        "client_id": "client",
        "tenant_id": "tenant",
        "authority": "https://example.test",
    }
    values[field] = value
    with pytest.raises(ValueError, match="control"):
        credentials.save_configuration(**values, path=tmp_path / ".env")
