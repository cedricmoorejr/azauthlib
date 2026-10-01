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

"""Tests for secure token persistence and token utilities."""

import pytest
from msal import SerializableTokenCache

from azauthlib import tokens


def test_resolve_directory_uses_deterministic_filename(tmp_path):
    (tmp_path / "unrelated.json").write_text("{}", encoding="utf-8")
    assert tokens.resolve_token_path(tmp_path) == str((tmp_path / "msal-cache.bin").resolve())


def test_resolve_new_file_path_keeps_requested_name(tmp_path):
    requested = tmp_path / "new" / "custom.cache"
    assert tokens.resolve_token_path(requested) == str(requested.resolve())


def test_encryption_failure_is_closed_by_default(monkeypatch, tmp_path):
    def unavailable(_):
        raise RuntimeError("no backend")

    monkeypatch.setattr(tokens, "build_encrypted_persistence", unavailable)
    with pytest.raises(tokens.TokenCacheSecurityError, match="Encrypted token persistence"):
        tokens.load_token_cache(tmp_path / "cache.bin")


def test_plaintext_requires_explicit_opt_in(monkeypatch, tmp_path):
    monkeypatch.setattr(
        tokens, "build_encrypted_persistence", lambda _: (_ for _ in ()).throw(RuntimeError())
    )
    cache = tokens.load_token_cache(tmp_path / "cache.bin", allow_plaintext=True)
    assert cache is not None


def test_unencrypted_serializable_cache_is_not_written(tmp_path):
    with pytest.raises(tokens.TokenCacheSecurityError, match="Refusing"):
        tokens.save_token_cache(SerializableTokenCache(), tmp_path / "cache.json")


def test_jwt_shape_validation():
    assert tokens.is_valid_JWT("aaa.bbb.ccc")
    assert not tokens.is_valid_JWT("not-a-jwt")


def test_token_time_is_utc_isoformat():
    assert tokens.tokentime_fmt(0) == "1970-01-01T00:00:00+00:00"
    assert tokens.tokentime_fmt(60, start_timestamp=0) == "1970-01-01T00:01:00+00:00"
    assert tokens.tokentime_fmt(None) is None
    assert tokens.tokentime_fmt("invalid") is None


def test_cache_and_path_type_validation():
    assert tokens.resolve_token_path(None) is None
    with pytest.raises(ValueError, match="required"):
        tokens.load_token_cache(None)
    with pytest.raises(TypeError, match="MSAL token cache"):
        tokens.save_token_cache(object())
