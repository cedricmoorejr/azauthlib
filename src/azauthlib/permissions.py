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

"""Scope normalization for Microsoft identity platform authentication flows."""

from __future__ import annotations

from collections.abc import Iterable

DEFAULT_DELEGATED_SCOPE = "User.Read"
GRAPH_DEFAULT_SCOPE = "https://graph.microsoft.com/.default"


def _as_scope_list(scopes, *, default: str) -> list[str]:
    if scopes is None:
        values = [default]
    elif isinstance(scopes, str):
        values = scopes.split()
    elif isinstance(scopes, Iterable):
        values = list(scopes)
    else:
        raise TypeError("scopes must be a string, iterable of strings, or None")
    if not values or any(not isinstance(scope, str) or not scope.strip() for scope in values):
        raise ValueError("At least one non-empty scope is required")
    normalized = [scope.strip() for scope in values]
    if any(any(ord(char) < 0x20 for char in scope) for scope in normalized):
        raise ValueError("Scopes must not contain control characters")
    return list(dict.fromkeys(normalized))


def scope_fmt(permissions=None, scopes=None) -> list[str]:
    """Normalize delegated scopes.

    ``permissions`` remains accepted for compatibility but is no longer used.
    Microsoft Graph adds permissions over time, so a bundled allow-list cannot
    safely establish whether a delegated scope is valid.
    """
    del permissions
    result = _as_scope_list(scopes, default=DEFAULT_DELEGATED_SCOPE)
    if any(scope.endswith("/.default") for scope in result) and len(result) > 1:
        raise ValueError("A .default scope cannot be combined with dynamic delegated scopes")
    return result


def application_scope_fmt(scopes=None) -> list[str]:
    """Normalize scopes for client-credentials authentication.

    Microsoft requires ``{resource}/.default`` for this flow.
    """
    result = _as_scope_list(scopes, default=GRAPH_DEFAULT_SCOPE)
    if any(not scope.endswith("/.default") for scope in result):
        raise ValueError("Client credentials scopes must use the {resource}/.default form")
    return result


__all__ = [
    "DEFAULT_DELEGATED_SCOPE",
    "GRAPH_DEFAULT_SCOPE",
    "application_scope_fmt",
    "scope_fmt",
]
