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

"""Application data locations and safe filesystem helpers.

Importing this module never creates, modifies, or removes files. Callers must
explicitly request directory creation.
"""

from __future__ import annotations

import os
from pathlib import Path

from platformdirs import user_cache_path, user_config_path

APP_NAME = "azauthlib"
APP_AUTHOR = "DOYDL Technologies"


def get_config_dir(*, create: bool = False) -> Path:
    path = user_config_path(APP_NAME, APP_AUTHOR, roaming=False)
    if create:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    return path


def get_cache_dir(*, create: bool = False) -> Path:
    path = user_cache_path(APP_NAME, APP_AUTHOR)
    if create:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    return path


def ensure_private_directory(path: str | os.PathLike[str]) -> Path:
    directory = Path(path).expanduser().resolve()
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not directory.is_dir():
        raise NotADirectoryError(directory)
    if os.name != "nt":
        directory.chmod(0o700)
    return directory


def ensure_within(path: str | os.PathLike[str], root: str | os.PathLike[str]) -> Path:
    candidate = Path(path).expanduser().resolve()
    boundary = Path(root).expanduser().resolve()
    try:
        candidate.relative_to(boundary)
    except ValueError as exc:
        raise ValueError(f"Path {candidate} is outside the allowed directory {boundary}") from exc
    return candidate


def find_default_user_data_dir() -> str:
    """Compatibility wrapper returning the deterministic configuration directory."""
    return str(get_config_dir(create=False))


class UserDataDirectory:
    """Compatibility wrapper around a deterministic application directory."""

    def __init__(self, dirname: str, auto_remove: bool = False):
        if auto_remove:
            raise ValueError("Automatic recursive deletion is no longer supported")
        if not dirname or Path(dirname).name != dirname:
            raise ValueError("dirname must be one safe path component")
        self.base_user_data_dir = get_config_dir(create=False)
        self.dirname = dirname

    def Dir(self) -> str:
        return str(ensure_private_directory(self.base_user_data_dir / self.dirname))

    def Exists(self, otherdir=None, exists_only=False):
        path = Path(otherdir) if otherdir else self.base_user_data_dir / self.dirname
        path = ensure_within(path, self.base_user_data_dir)
        exists = path.is_dir()
        return exists if exists_only else (str(path) if exists else None)

    def Omit(self, path: str) -> None:
        target = ensure_within(path, self.base_user_data_dir)
        target.rmdir()

    def DirFile(
        self,
        filename: str,
        extension: str,
        existing: bool = False,
        existing_path=None,
        overwrite: bool = False,
    ) -> str:
        del existing
        directory = ensure_private_directory(existing_path or self.Dir())
        if Path(filename).name != filename:
            raise ValueError("filename must not contain path separators")
        suffix = extension if extension.startswith(".") else f".{extension}"
        path = ensure_within(directory / f"{filename}{suffix}", self.base_user_data_dir)
        if overwrite or not path.exists():
            flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if overwrite else os.O_EXCL)
            try:
                fd = os.open(path, flags, 0o600)
            except FileExistsError:
                pass
            else:
                os.close(fd)
        return str(path)

    def Clean(self, alldirs: bool = False) -> None:
        del alldirs
        raise RuntimeError("Recursive application-data cleanup has been removed for safety")
