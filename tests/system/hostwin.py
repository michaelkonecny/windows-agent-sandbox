"""Host-side Win32 queries for system tests (ctypes only — never imports sbx)."""
from __future__ import annotations

import ctypes
import subprocess
import winreg
from ctypes import wintypes

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
SYNCHRONIZE = 0x00100000
TOKEN_QUERY = 0x0008
TokenUser = 1
TokenElevation = 20
JOB_OBJECT_QUERY = 0x0004
JobObjectBasicProcessIdList = 3
ERROR_ACCESS_DENIED = 5
WAIT_TIMEOUT = 0x102

kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.GetCurrentProcess.restype = wintypes.HANDLE
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
kernel32.WaitForSingleObject.restype = wintypes.DWORD
kernel32.OpenJobObjectW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
kernel32.OpenJobObjectW.restype = wintypes.HANDLE
kernel32.QueryInformationJobObject.argtypes = [
    wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
]
advapi32.OpenProcessToken.argtypes = [
    wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE),
]
advapi32.GetTokenInformation.argtypes = [
    wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
]
advapi32.LookupAccountSidW.argtypes = [
    wintypes.LPCWSTR, ctypes.c_void_p, wintypes.LPWSTR,
    ctypes.POINTER(wintypes.DWORD), wintypes.LPWSTR,
    ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(ctypes.c_int),
]


def _open_process(pid: int, access: int = PROCESS_QUERY_LIMITED_INFORMATION) -> int:
    h = kernel32.OpenProcess(access, False, pid)
    if not h:
        raise ctypes.WinError(ctypes.get_last_error())
    return h


def process_alive(pid: int) -> bool:
    h = kernel32.OpenProcess(SYNCHRONIZE, False, pid)
    if not h:
        # Access denied means it exists; anything else (invalid parameter) means gone.
        return ctypes.get_last_error() == ERROR_ACCESS_DENIED
    try:
        return kernel32.WaitForSingleObject(h, 0) == WAIT_TIMEOUT
    finally:
        kernel32.CloseHandle(h)


def _token_info(process: int, cls: int) -> ctypes.Array:
    tok = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(process, TOKEN_QUERY, ctypes.byref(tok)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        size = wintypes.DWORD()
        advapi32.GetTokenInformation(tok, cls, None, 0, ctypes.byref(size))
        buf = ctypes.create_string_buffer(max(size.value, 4))
        if not advapi32.GetTokenInformation(tok, cls, buf, size, ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        return buf
    finally:
        kernel32.CloseHandle(tok)


def _elevated(process: int) -> bool:
    return bool(ctypes.c_uint32.from_buffer(_token_info(process, TokenElevation)).value)


def _owner(process: int) -> str:
    buf = _token_info(process, TokenUser)
    sid = ctypes.c_void_p.from_buffer(buf).value
    name = ctypes.create_unicode_buffer(256)
    domain = ctypes.create_unicode_buffer(256)
    n, d, use = wintypes.DWORD(256), wintypes.DWORD(256), ctypes.c_int()
    if not advapi32.LookupAccountSidW(
        None, sid, name, ctypes.byref(n), domain, ctypes.byref(d), ctypes.byref(use),
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    return name.value


def current_elevated() -> bool:
    return _elevated(kernel32.GetCurrentProcess())


def process_owner(pid: int) -> str:
    h = _open_process(pid)
    try:
        return _owner(h)
    finally:
        kernel32.CloseHandle(h)


def process_elevated(pid: int) -> bool:
    h = _open_process(pid)
    try:
        return _elevated(h)
    finally:
        kernel32.CloseHandle(h)


def job_pids(job_name: str) -> list[int]:
    job = kernel32.OpenJobObjectW(JOB_OBJECT_QUERY, False, job_name)
    if not job:
        raise ctypes.WinError(ctypes.get_last_error())

    class PidList(ctypes.Structure):
        _fields_ = [
            ("assigned", wintypes.DWORD),
            ("listed", wintypes.DWORD),
            ("pids", ctypes.c_size_t * 256),
        ]

    info = PidList()
    try:
        if not kernel32.QueryInformationJobObject(
            job, JobObjectBasicProcessIdList, ctypes.byref(info),
            ctypes.sizeof(info), None,
        ):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        kernel32.CloseHandle(job)
    return [info.pids[i] for i in range(info.listed)]


def uac_value(name: str) -> int | None:
    key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key) as k:
            return winreg.QueryValueEx(k, name)[0]
    except FileNotFoundError:
        return None


def in_administrators() -> bool:
    """Current user is a member of BUILTIN\\Administrators (the unelevated
    token lists it as deny-only, which still counts)."""
    out = subprocess.run(
        ["whoami", "/groups", "/fo", "csv", "/nh"],
        capture_output=True, text=True, check=True,
    ).stdout
    return "S-1-5-32-544" in out


def account_sid(name: str) -> str | None:
    res = subprocess.run(
        ["powershell", "-NoProfile", "-Command",
         f"(New-Object System.Security.Principal.NTAccount('{name}'))"
         ".Translate([System.Security.Principal.SecurityIdentifier]).Value"],
        capture_output=True, text=True,
    )
    sid = res.stdout.strip()
    return sid if res.returncode == 0 and sid.startswith("S-1-") else None


def firewall_rules_for_sid(sid: str) -> list[str]:
    """Display names of firewall rules whose LocalUser SDDL mentions `sid`."""
    ps = (
        "Get-NetFirewallSecurityFilter -All"
        f" | Where-Object {{ $_.LocalUser -like '*{sid}*' }}"
        " | Get-NetFirewallRule | ForEach-Object { $_.DisplayName }"
    )
    res = subprocess.run(
        ["powershell", "-NoProfile", "-Command", ps],
        capture_output=True, text=True, check=True,
    )
    return [line.strip() for line in res.stdout.splitlines() if line.strip()]


def acl_mentions(path: str, sid: str) -> bool:
    out = subprocess.run(
        ["icacls", path], capture_output=True, text=True, check=True,
    ).stdout
    return sid in out
