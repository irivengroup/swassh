"""Run CI commands with strict failure propagation and account-owned Windows objects.

This is QA infrastructure, never a SWASSH runtime entry point. GitHub's Windows
administrator token can default new objects to the Administrators group; the
production policy intentionally accepts only the account SID. Set the default
owner of this disposable process token, without changing privileges, groups,
existing owners or DACLs. Child commands inherit that creation policy.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


class WindowsObjectOwner:
    """Keep strict account ownership predicates intact on hosted Windows QA."""

    @staticmethod
    def configure():
        if os.name == 'nt':
            WindowsObjectOwner.apply(ctypes.WinDLL('kernel32', use_last_error=True),
                                     ctypes.WinDLL('advapi32', use_last_error=True))

    @staticmethod
    def apply(kernel, advapi):
        """Change only TokenOwner on this process, then verify the copied SID."""
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
        advapi.OpenProcessToken.restype = wintypes.BOOL
        advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                             wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        advapi.GetTokenInformation.restype = wintypes.BOOL
        advapi.SetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        advapi.SetTokenInformation.restype = wintypes.BOOL
        advapi.EqualSid.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        advapi.EqualSid.restype = wintypes.BOOL
        token = wintypes.HANDLE()

        def checked(value):
            if not value:
                raise ctypes.WinError(ctypes.get_last_error())

        try:
            # TOKEN_QUERY | TOKEN_ADJUST_DEFAULT; no privilege/group adjustment.
            checked(advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x88, ctypes.byref(token)))
            size = wintypes.DWORD()
            advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
            user = ctypes.create_string_buffer(size.value)
            checked(advapi.GetTokenInformation(token, 1, user, size, ctypes.byref(size)))
            sid = ctypes.cast(user, ctypes.POINTER(ctypes.c_void_p)).contents.value
            owner = ctypes.c_void_p(sid)
            checked(advapi.SetTokenInformation(token, 4, ctypes.byref(owner), ctypes.sizeof(owner)))
            advapi.GetTokenInformation(token, 4, None, 0, ctypes.byref(size))
            result = ctypes.create_string_buffer(size.value)
            checked(advapi.GetTokenInformation(token, 4, result, size, ctypes.byref(size)))
            copied = ctypes.cast(result, ctypes.POINTER(ctypes.c_void_p)).contents.value
            if not advapi.EqualSid(sid, copied):
                raise OSError('CI default object owner was not set to the account SID')
        finally:
            if token:
                kernel.CloseHandle(token)


class ShellRunner:
    """Preserve bash fail-fast semantics and reject every failed native PS command."""

    def __init__(self, platform=None):
        self.platform = os.name if platform is None else platform

    @staticmethod
    def executable(name):
        path = shutil.which(name)
        if path is None:
            raise OSError('required CI shell is unavailable: ' + name)
        return str(Path(path).resolve(strict=True))

    def run(self, script):
        source = Path(script).resolve(strict=True)
        if not source.is_file():
            raise ValueError('CI command file must be regular')
        if self.platform != 'nt':
            return subprocess.run([self.executable('bash'), '--noprofile', '--norc',
                                   '-e', '-o', 'pipefail', str(source)], check=False).returncode
        WindowsObjectOwner.configure()
        # Custom GitHub shells do not get the built-in PowerShell prelude.
        # Native nonzero codes must not be hidden by a later successful command.
        body = ("$ErrorActionPreference = 'Stop'\n"
                "if ($PSVersionTable.PSVersion -lt [version]'7.4') { throw 'CI requires PowerShell 7.4+' }\n"
                "$PSNativeCommandUseErrorActionPreference = $true\n"
                + source.read_text(encoding='utf-8-sig')
                + "\nif (Test-Path -LiteralPath variable:\\LASTEXITCODE) { exit $LASTEXITCODE }\n")
        with tempfile.TemporaryDirectory(prefix='swassh-ci-shell-') as directory:
            command = Path(directory) / 'command.ps1'
            command.write_text(body, encoding='utf-8')
            return subprocess.run([self.executable('pwsh'), '-NoLogo', '-NoProfile',
                                   '-NonInteractive', '-File', str(command)], check=False).returncode


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('usage: ci_shell.py command-file')
    raise SystemExit(ShellRunner().run(sys.argv[1]))
