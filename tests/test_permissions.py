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

"""Tests for delegated and application scope normalization."""

import pytest

from azauthlib.permissions import GRAPH_DEFAULT_SCOPE, application_scope_fmt, scope_fmt


def test_delegated_scope_normalization():
    assert scope_fmt(scopes="Mail.Read User.Read Mail.Read") == ["Mail.Read", "User.Read"]


def test_delegated_default():
    assert scope_fmt() == ["User.Read"]


def test_application_scope_default():
    assert application_scope_fmt() == [GRAPH_DEFAULT_SCOPE]


def test_application_scope_rejects_individual_permission():
    with pytest.raises(ValueError, match="/.default"):
        application_scope_fmt("Files.ReadWrite.All")


def test_default_cannot_be_mixed_with_dynamic_scopes():
    with pytest.raises(ValueError, match="cannot be combined"):
        scope_fmt(scopes=[GRAPH_DEFAULT_SCOPE, "User.Read"])
