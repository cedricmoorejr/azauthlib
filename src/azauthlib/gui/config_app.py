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

"""Tk application for storing azauthlib configuration safely."""

from __future__ import annotations

import atexit
import re
import tkinter as tk
from tkinter import messagebox, ttk
from uuid import UUID

from ..appdata import get_config_dir
from ..credentials import CredentialStoreError, save_configuration
from .gui_utils import enforce_single_instance, on_exit

_TENANT_ALIAS = re.compile(r"^(common|organizations|consumers|[A-Za-z0-9.-]+\.[A-Za-z]{2,})$")


def _is_uuid(value: str) -> bool:
    try:
        UUID(value)
    except (ValueError, AttributeError):
        return False
    return True


def validate_client_id(client_id: str) -> bool:
    return _is_uuid(client_id)


def validate_tenant_id(tenant_id: str) -> bool:
    return _is_uuid(tenant_id) or bool(_TENANT_ALIAS.fullmatch(tenant_id))


def validate_client_secret(client_secret: str) -> bool:
    return bool(client_secret) and not any(ord(char) < 0x20 for char in client_secret)


class CredentialsWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Configure Microsoft Graph Credentials")
        self.resizable(False, False)
        self.auth_var = tk.StringVar(value="interactive")
        self._build()
        self.after_idle(self._center)

    def _build(self):
        frame = ttk.Frame(self, padding=20)
        frame.grid()
        ttk.Label(frame, text="Authentication method").grid(row=0, column=0, sticky="w")
        methods = (
            ("Interactive", "interactive"),
            ("Device code", "device_code"),
            ("Client credentials", "client_credentials"),
        )
        for row, (label, value) in enumerate(methods, start=1):
            ttk.Radiobutton(frame, text=label, variable=self.auth_var, value=value).grid(
                row=row, column=0, sticky="w"
            )
        self.tenant_id = self._entry(frame, 4, "Tenant ID")
        self.client_id = self._entry(frame, 5, "Client ID")
        self.client_secret = self._entry(frame, 6, "Client secret", show="*")
        ttk.Label(
            frame,
            text=(
                "Secrets are stored in the operating-system credential manager, not the .env file."
            ),
            wraplength=520,
        ).grid(row=7, column=0, columnspan=2, pady=(10, 0), sticky="w")
        ttk.Button(frame, text="Save", command=self.save_credentials).grid(
            row=8, column=0, columnspan=2, pady=(16, 0)
        )

    @staticmethod
    def _entry(frame, row, label, *, show=None):
        ttk.Label(frame, text=f"{label}:").grid(row=row, column=0, sticky="w", pady=4)
        entry = ttk.Entry(frame, width=64, show=show)
        entry.grid(row=row, column=1, pady=4)
        return entry

    def _center(self):
        self.update_idletasks()
        x = (self.winfo_screenwidth() - self.winfo_width()) // 2
        y = (self.winfo_screenheight() - self.winfo_height()) // 2
        self.geometry(f"+{x}+{y}")

    def save_credentials(self):
        tenant_id = self.tenant_id.get().strip()
        client_id = self.client_id.get().strip()
        client_secret = self.client_secret.get()
        if not validate_tenant_id(tenant_id):
            messagebox.showerror("Invalid tenant", "Enter a tenant UUID, domain, or tenant alias.")
            return
        if not validate_client_id(client_id):
            messagebox.showerror("Invalid client", "Client ID must be a UUID.")
            return
        if self.auth_var.get() == "client_credentials" and not validate_client_secret(
            client_secret
        ):
            messagebox.showerror(
                "Missing secret", "Client credentials authentication requires a secret."
            )
            return
        try:
            save_configuration(
                client_id=client_id,
                tenant_id=tenant_id,
                client_secret=client_secret or None,
            )
        except CredentialStoreError as exc:
            messagebox.showerror("Secure storage unavailable", str(exc))
            return
        messagebox.showinfo("Success", "Configuration was saved securely.")
        self.destroy()


def main():
    lock_path = get_config_dir(create=True) / "azauthlib-app.lock"
    lock = enforce_single_instance(lock_path)
    if lock is None:
        raise SystemExit("Another azauthlib configuration window is already running")
    atexit.register(on_exit, lock)
    try:
        CredentialsWindow().mainloop()
    finally:
        atexit.unregister(on_exit)
        on_exit(lock)


if __name__ == "__main__":
    main()
