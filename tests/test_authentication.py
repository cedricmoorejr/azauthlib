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

"""Tests for Microsoft identity platform authentication flows."""

import logging

import pytest

from azauthlib import Authentication, AuthenticationError, InteractionRequiredError
from azauthlib import authentication as module
from azauthlib.authentication import client_secret_valid
from azauthlib.permissions import GRAPH_DEFAULT_SCOPE


class FakePublicApp:
    def __init__(self, result=None, accounts=None, flow=None):
        self.result = result or {"access_token": "access", "expires_in": 3600}
        self.accounts = [{"id": "account"}] if accounts is None else accounts
        self.flow = flow or {
            "user_code": "ABCD",
            "verification_uri": "https://microsoft.com/devicelogin",
            "message": "Authenticate",
        }

    def get_accounts(self):
        return self.accounts

    def acquire_token_silent(self, scopes, account):
        self.last_scopes = scopes
        self.last_account = account
        return self.result

    def acquire_token_interactive(self, scopes, **kwargs):
        self.last_scopes = scopes
        self.kwargs = kwargs
        return self.result

    def initiate_device_flow(self, scopes):
        self.last_scopes = scopes
        return self.flow

    def acquire_token_by_device_flow(self, flow):
        self.received_flow = flow
        return self.result


def configured_auth(tmp_path, scopes=None):
    auth = Authentication(scopes=scopes, token_path=tmp_path / "cache.bin")
    auth.Build.WithEntry(client_id="client", tenant_id="tenant", client_secret="secret")
    auth._token_cache = object()
    return auth


def test_interactive_is_synchronous_and_returns_result(monkeypatch, tmp_path):
    fake = FakePublicApp()
    auth = configured_auth(tmp_path, ["User.Read"])
    monkeypatch.setattr(auth, "_public_app", lambda: fake)
    result = auth.Interactive(prompt="select_account")
    assert result["access_token"] == "access"
    assert fake.kwargs == {"prompt": "select_account"}


def test_silent_without_account_requires_interaction(monkeypatch, tmp_path):
    auth = configured_auth(tmp_path)
    monkeypatch.setattr(auth, "_public_app", lambda: FakePublicApp(accounts=[]))
    with pytest.raises(InteractionRequiredError, match="No cached account"):
        auth.Silent()


def test_client_credentials_defaults_to_graph_default(monkeypatch, tmp_path):
    captured = {}

    class FakeConfidential:
        def __init__(self, **kwargs):
            captured["constructor"] = kwargs

        def acquire_token_for_client(self, scopes):
            captured["scopes"] = scopes
            return {"access_token": "application-token", "expires_in": 3600}

    monkeypatch.setattr(module, "ConfidentialClientApplication", FakeConfidential)
    auth = configured_auth(tmp_path)
    result = auth.ClientCredentials()
    assert result["access_token"] == "application-token"
    assert captured["scopes"] == [GRAPH_DEFAULT_SCOPE]


def test_client_credentials_rejects_delegated_scope(monkeypatch, tmp_path):
    auth = configured_auth(tmp_path, ["Files.ReadWrite.All"])

    class NeverCalled:
        def acquire_token_for_client(self, scopes):
            raise AssertionError(scopes)

    monkeypatch.setattr(module, "ConfidentialClientApplication", lambda **_: NeverCalled())
    with pytest.raises(ValueError, match="/.default"):
        auth.ClientCredentials()


def test_device_flow_calls_blocking_msal_method_once(monkeypatch, tmp_path, capsys):
    fake = FakePublicApp()
    auth = configured_auth(tmp_path)
    monkeypatch.setattr(auth, "_public_app", lambda: fake)
    result = auth.DeviceCodeFlow()
    assert result["access_token"] == "access"
    assert fake.received_flow is fake.flow
    assert "Authenticate" in capsys.readouterr().out


def test_failure_log_does_not_contain_full_result(caplog, tmp_path):
    auth = configured_auth(tmp_path)
    caplog.set_level(logging.ERROR)
    with pytest.raises(AuthenticationError):
        auth._successful(
            {
                "error": "invalid_grant",
                "error_description": "sanitized description",
                "correlation_id": "correlation",
                "refresh_token": "secret-token",
            },
            "Test operation",
        )
    assert "secret-token" not in caplog.text


def test_os_environment_loading_is_strict(monkeypatch, tmp_path):
    auth = Authentication(token_path=tmp_path / "cache.bin")
    monkeypatch.delenv("MISSING_CLIENT", raising=False)
    monkeypatch.setenv("TENANT", "tenant")
    with pytest.raises(ValueError, match="client_id"):
        auth.Build.WithOSEnv({"client_id": "MISSING_CLIENT", "tenant_id": "TENANT"})


def test_default_builder_uses_exact_loader(monkeypatch, tmp_path):
    auth = Authentication(token_path=tmp_path / "cache.bin")
    monkeypatch.setattr(
        module,
        "load_credentials",
        lambda path: {
            "client_id": "client",
            "tenant_id": "tenant",
            "client_secret": None,
            "authority": None,
        },
    )
    assert auth.Build.Default(authority="https://authority.example").authority.endswith(".example")


def test_env_file_and_environment_list_builders(monkeypatch, tmp_path):
    env_file = tmp_path / "selected.env"
    env_file.write_text("APP_ID=client\nDIRECTORY_ID=tenant\n", encoding="utf-8")
    auth = Authentication(token_path=tmp_path / "cache.bin")
    auth.Build.WithEnvFile(
        env_file,
        {"client_id": "APP_ID", "tenant_id": "DIRECTORY_ID"},
    )
    assert auth.client_id == "client"
    monkeypatch.setenv("APP_ID", "env-client")
    monkeypatch.setenv("DIRECTORY_ID", "env-tenant")
    auth.Build.WithOSEnv(["APP_ID", "DIRECTORY_ID"])
    assert auth.client_id == "env-client"


def test_builder_input_validation(tmp_path):
    auth = Authentication(token_path=tmp_path / "cache.bin")
    with pytest.raises(ValueError, match="required"):
        auth.Build.WithEntry("", "tenant")
    with pytest.raises(ValueError, match="control"):
        auth.Build.WithEntry("client", "tenant", "bad\nsecret")
    with pytest.raises(ValueError, match="client_id.*control"):
        auth.Build.WithEntry("client\nINJECTED=value", "tenant")
    with pytest.raises(ValueError, match="authority.*control"):
        auth.Build.WithEntry("client", "tenant", authority="https://example.test\rmalformed")
    with pytest.raises(FileNotFoundError):
        auth.Build.WithEnvFile(tmp_path / "missing.env")
    with pytest.raises(ValueError, match="Unsupported"):
        env_file = tmp_path / "selected.env"
        env_file.write_text("X=value\n", encoding="utf-8")
        auth.Build.WithEnvFile(env_file, {"unsupported": "X"})
    with pytest.raises(ValueError, match="2 or 3"):
        auth.Build.WithOSEnv(["ONLY_ONE"])
    with pytest.raises(TypeError, match="mapping"):
        auth.Build.WithOSEnv(42)


def test_lazy_cache_and_configuration_validation(monkeypatch, tmp_path):
    sentinel = object()
    monkeypatch.setattr(module, "load_token_cache", lambda *_, **__: sentinel)
    auth = Authentication(token_path=tmp_path / "cache.bin")
    assert auth._cache() is sentinel
    assert auth._cache() is sentinel
    with pytest.raises(ValueError, match="Configure"):
        auth._require_configuration()
    auth.Build.WithEntry("client", "tenant")
    with pytest.raises(ValueError, match="client secret"):
        auth._require_configuration(confidential=True)


def test_public_app_is_constructed_with_cache(monkeypatch, tmp_path):
    captured = {}
    auth = configured_auth(tmp_path)

    def make_app(**kwargs):
        captured.update(kwargs)
        return "application"

    monkeypatch.setattr(module, "PublicClientApplication", make_app)
    assert auth._public_app() == "application"
    assert captured["client_id"] == "client"
    assert captured["token_cache"] is auth._token_cache


def test_silent_success_and_explicit_fallback(monkeypatch, tmp_path):
    auth = configured_auth(tmp_path)
    successful = FakePublicApp()
    monkeypatch.setattr(auth, "_public_app", lambda: successful)
    assert auth.Silent()["access_token"] == "access"

    monkeypatch.setattr(auth, "_public_app", lambda: FakePublicApp(accounts=[]))
    monkeypatch.setattr(auth, "Interactive", lambda scopes=None: {"interactive": scopes})
    assert auth.Silent(scopes=["Mail.Read"], fallback_to_interactive=True) == {
        "interactive": ["Mail.Read"]
    }


def test_silent_preserves_non_interaction_errors(monkeypatch, tmp_path):
    auth = configured_auth(tmp_path)
    failed = FakePublicApp(
        result={
            "error": "invalid_client",
            "error_description": "The client configuration is invalid",
            "correlation_id": "correlation",
        }
    )
    monkeypatch.setattr(auth, "_public_app", lambda: failed)
    monkeypatch.setattr(
        auth,
        "Interactive",
        lambda scopes=None: pytest.fail("must not hide a configuration failure"),
    )
    with pytest.raises(AuthenticationError, match="invalid") as caught:
        auth.Silent(fallback_to_interactive=True)
    assert caught.value.error == "invalid_client"


def test_expiring_app_token_uses_client_credentials_refresh(monkeypatch, tmp_path):
    auth = configured_auth(tmp_path)
    auth._access_token = "expiring"
    auth._expires_at = 1_100
    auth._last_flow = "client_credentials"
    monkeypatch.setattr(module.time, "time", lambda: 1_000)
    calls = []

    def refresh():
        calls.append("client_credentials")
        auth._access_token = "refreshed"
        auth._expires_at = 4_600

    monkeypatch.setattr(auth, "ClientCredentials", refresh)
    monkeypatch.setattr(auth, "Silent", lambda: pytest.fail("wrong refresh flow"))
    assert auth.access_token == "refreshed"
    assert calls == ["client_credentials"]


def test_device_initialization_error_and_browser_open(monkeypatch, tmp_path):
    auth = configured_auth(tmp_path)
    broken = FakePublicApp(flow={"error": "authorization_pending"})
    monkeypatch.setattr(auth, "_public_app", lambda: broken)
    with pytest.raises(AuthenticationError):
        auth.DeviceCodeFlow()

    fake = FakePublicApp()
    opened = []
    monkeypatch.setattr(auth, "_public_app", lambda: fake)
    monkeypatch.setattr(module.webbrowser, "open", opened.append)
    auth.DeviceCodeFlow(webbrowser_enabled=True)
    assert opened == [fake.flow["verification_uri"]]


def test_token_properties(monkeypatch, tmp_path):
    auth = configured_auth(tmp_path)
    monkeypatch.setattr(module.time, "time", lambda: 1_000)
    auth._update_internal_state(
        {
            "access_token": "access",
            "id_token": "id",
            "token_source": "IdentityProvider",
            "expires_on": 2_000,
            "id_token_claims": {"iat": 900, "nbf": 950},
        }
    )
    assert auth.access_token == "access"
    assert auth.token_expires_in == 1_000
    assert auth.token_expires_at == auth.token_expiration
    assert auth.token_ext_expires_in is None
    assert auth.id_token == "id"
    assert auth.token_source == "IdentityProvider"
    assert auth.token_issued_at is not None
    assert auth.token_valid_after is not None
    with pytest.warns(DeprecationWarning):
        assert auth.refresh_token_value is None


def test_client_secret_validation():
    assert client_secret_valid("generated-value=with-symbols")
    assert not client_secret_valid(123)
    assert not client_secret_valid("")
