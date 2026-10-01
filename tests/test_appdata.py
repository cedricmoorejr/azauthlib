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

"""Tests for application-data paths and filesystem safety helpers."""

from pathlib import Path

import pytest

from azauthlib import appdata


def test_import_helpers_do_not_create_directories(monkeypatch, tmp_path):
    expected = tmp_path / "config"
    monkeypatch.setattr(appdata, "user_config_path", lambda *_, **__: expected)
    assert appdata.get_config_dir(create=False) == expected
    assert not expected.exists()


def test_omit_cannot_escape_application_root(monkeypatch, tmp_path):
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    outside.mkdir()
    monkeypatch.setattr(appdata, "get_config_dir", lambda **_: root)
    manager = appdata.UserDataDirectory("owned")
    with pytest.raises(ValueError, match="outside"):
        manager.Omit(outside)


def test_recursive_cleanup_is_disabled(monkeypatch, tmp_path):
    monkeypatch.setattr(appdata, "get_config_dir", lambda **_: tmp_path)
    manager = appdata.UserDataDirectory("owned")
    with pytest.raises(RuntimeError, match="removed for safety"):
        manager.Clean()


def test_directory_creation_and_compatibility_file_helpers(monkeypatch, tmp_path):
    config = tmp_path / "config"
    cache = tmp_path / "cache"
    monkeypatch.setattr(appdata, "user_config_path", lambda *_, **__: config)
    monkeypatch.setattr(appdata, "user_cache_path", lambda *_, **__: cache)
    assert appdata.get_config_dir(create=True).is_dir()
    assert appdata.get_cache_dir(create=True).is_dir()
    assert appdata.find_default_user_data_dir() == str(config)

    manager = appdata.UserDataDirectory("owned")
    directory = Path(manager.Dir())
    assert manager.Exists(exists_only=True)
    created = Path(manager.DirFile("token", "json"))
    assert created.is_file()
    assert manager.Exists() == str(directory)
    created.unlink()
    manager.Omit(directory)
    assert not directory.exists()


def test_compatibility_wrapper_rejects_unsafe_inputs(monkeypatch, tmp_path):
    monkeypatch.setattr(appdata, "get_config_dir", lambda **_: tmp_path)
    with pytest.raises(ValueError, match="Automatic"):
        appdata.UserDataDirectory("owned", auto_remove=True)
    with pytest.raises(ValueError, match="component"):
        appdata.UserDataDirectory("../escape")
    manager = appdata.UserDataDirectory("owned")
    with pytest.raises(ValueError, match="filename"):
        manager.DirFile("../escape", ".txt")


def test_private_directory_rejects_existing_file(tmp_path):
    existing = tmp_path / "file"
    existing.write_text("data", encoding="utf-8")
    with pytest.raises(FileExistsError):
        appdata.ensure_private_directory(existing)
