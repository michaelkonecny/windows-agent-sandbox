"""Thin ctypes wrapper over Win32 APIs.

Grows incrementally — each phase adds the API calls it needs.
"""

import ctypes
from ctypes import wintypes

# ── DLLs ────────────────────────────────────────────────────

advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
netapi32 = ctypes.WinDLL("netapi32", use_last_error=True)
crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
shell32 = ctypes.WinDLL("shell32", use_last_error=True)

# ── Constants ───────────────────────────────────────────────

SID_REVISION = 1

SECURITY_SANDBOX_AUTHORITY = (0, 0, 0, 0, 0, 42)
SECURITY_NT_AUTHORITY = (0, 0, 0, 0, 0, 5)

SECURITY_BUILTIN_DOMAIN_RID = 32
DOMAIN_ALIAS_RID_USERS = 545
DOMAIN_ALIAS_RID_ADMINS = 544

BUILTIN_USERS_SID = "S-1-5-32-545"
BUILTIN_ADMINS_SID = "S-1-5-32-544"

DISABLE_MAX_PRIVILEGE = 0x1
WRITE_RESTRICTED = 0x8
TOKEN_DUPLICATE = 0x0002
TOKEN_QUERY = 0x0008
TOKEN_ASSIGN_PRIMARY = 0x0001

USER_PRIV_USER = 1
UF_SCRIPT = 0x0001
UF_DONT_EXPIRE_PASSWD = 0x10000
NERR_Success = 0
NERR_UserExists = 2224
NERR_UserNotFound = 2221

SE_FILE_OBJECT = 1
DACL_SECURITY_INFORMATION = 0x00000004
GRANT_ACCESS = 1
NO_MULTIPLE_TRUSTEE = 0
TRUSTEE_IS_SID = 0
TRUSTEE_IS_UNKNOWN = 0
SUB_CONTAINERS_AND_OBJECTS_INHERIT = 0x03
FILE_ALL_ACCESS = 0x001F01FF

BINDFLT_FLAG_READ_ONLY_MAPPING = 0x00000001

LOGON_WITH_PROFILE = 0x00000001
CREATE_NO_WINDOW = 0x08000000
CREATE_UNICODE_ENVIRONMENT = 0x00000400
INFINITE = 0xFFFFFFFF

SEE_MASK_NOCLOSEPROCESS = 0x00000040
SW_HIDE = 0

# ── Structures ──────────────────────────────────────────────


class SID_IDENTIFIER_AUTHORITY(ctypes.Structure):
    _fields_ = [("Value", ctypes.c_ubyte * 6)]


class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Sid", ctypes.c_void_p),
        ("Attributes", wintypes.DWORD),
    ]


class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.c_void_p),
    ]


class USER_INFO_1(ctypes.Structure):
    _fields_ = [
        ("usri1_name", wintypes.LPWSTR),
        ("usri1_password", wintypes.LPWSTR),
        ("usri1_password_age", wintypes.DWORD),
        ("usri1_priv", wintypes.DWORD),
        ("usri1_home_dir", wintypes.LPWSTR),
        ("usri1_comment", wintypes.LPWSTR),
        ("usri1_flags", wintypes.DWORD),
        ("usri1_script_path", wintypes.LPWSTR),
    ]


class SHELLEXECUTEINFOW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("fMask", wintypes.ULONG),
        ("hwnd", wintypes.HANDLE),
        ("lpVerb", wintypes.LPCWSTR),
        ("lpFile", wintypes.LPCWSTR),
        ("lpParameters", wintypes.LPCWSTR),
        ("lpDirectory", wintypes.LPCWSTR),
        ("nShow", ctypes.c_int),
        ("hInstApp", wintypes.HANDLE),
        ("lpIDList", ctypes.c_void_p),
        ("lpClass", wintypes.LPCWSTR),
        ("hkeyClass", ctypes.c_void_p),
        ("dwHotKey", wintypes.DWORD),
        ("hIconOrMonitor", wintypes.HANDLE),
        ("hProcess", wintypes.HANDLE),
    ]


# ── Function prototypes ────────────────────────────────────

# SID
advapi32.AllocateAndInitializeSid.argtypes = [
    ctypes.POINTER(SID_IDENTIFIER_AUTHORITY),
    ctypes.c_ubyte,
    wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
    wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
    ctypes.POINTER(ctypes.c_void_p),
]
advapi32.AllocateAndInitializeSid.restype = wintypes.BOOL

advapi32.FreeSid.argtypes = [ctypes.c_void_p]
advapi32.FreeSid.restype = ctypes.c_void_p

advapi32.ConvertSidToStringSidW.argtypes = [
    ctypes.c_void_p,
    ctypes.POINTER(wintypes.LPWSTR),
]
advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL

advapi32.ConvertStringSidToSidW.argtypes = [
    wintypes.LPCWSTR,
    ctypes.POINTER(ctypes.c_void_p),
]
advapi32.ConvertStringSidToSidW.restype = wintypes.BOOL

# DPAPI
crypt32.CryptProtectData.argtypes = [
    ctypes.POINTER(DATA_BLOB),
    wintypes.LPCWSTR,
    ctypes.POINTER(DATA_BLOB),
    ctypes.c_void_p,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.POINTER(DATA_BLOB),
]
crypt32.CryptProtectData.restype = wintypes.BOOL

crypt32.CryptUnprotectData.argtypes = [
    ctypes.POINTER(DATA_BLOB),
    ctypes.POINTER(wintypes.LPWSTR),
    ctypes.POINTER(DATA_BLOB),
    ctypes.c_void_p,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.POINTER(DATA_BLOB),
]
crypt32.CryptUnprotectData.restype = wintypes.BOOL

# User management
netapi32.NetUserAdd.argtypes = [
    wintypes.LPCWSTR,
    wintypes.DWORD,
    ctypes.POINTER(USER_INFO_1),
    ctypes.POINTER(wintypes.DWORD),
]
netapi32.NetUserAdd.restype = wintypes.DWORD

netapi32.NetUserDel.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
netapi32.NetUserDel.restype = wintypes.DWORD

netapi32.NetUserGetInfo.argtypes = [
    wintypes.LPCWSTR,
    wintypes.LPCWSTR,
    wintypes.DWORD,
    ctypes.POINTER(ctypes.c_void_p),
]
netapi32.NetUserGetInfo.restype = wintypes.DWORD

netapi32.NetApiBufferFree.argtypes = [ctypes.c_void_p]
netapi32.NetApiBufferFree.restype = wintypes.DWORD

# Shell
shell32.ShellExecuteExW.argtypes = [ctypes.POINTER(SHELLEXECUTEINFOW)]
shell32.ShellExecuteExW.restype = wintypes.BOOL

# Kernel helpers
kernel32.GetCurrentProcess.argtypes = []
kernel32.GetCurrentProcess.restype = wintypes.HANDLE

kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL

kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
kernel32.WaitForSingleObject.restype = wintypes.DWORD

kernel32.GetExitCodeProcess.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(wintypes.DWORD),
]
kernel32.GetExitCodeProcess.restype = wintypes.BOOL

kernel32.LocalFree.argtypes = [ctypes.c_void_p]
kernel32.LocalFree.restype = ctypes.c_void_p


# ── Helper functions ────────────────────────────────────────


def is_elevated() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


# SID helpers

def allocate_sid(authority_byte_5: int, sub_count: int, *subs: int) -> int:
    auth = SID_IDENTIFIER_AUTHORITY()
    auth.Value[5] = authority_byte_5
    sid = ctypes.c_void_p()
    padded = list(subs) + [0] * (8 - len(subs))
    ok = advapi32.AllocateAndInitializeSid(
        ctypes.byref(auth), sub_count,
        *[wintypes.DWORD(s) for s in padded],
        ctypes.byref(sid),
    )
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    return sid.value


def free_sid(sid_ptr: int) -> None:
    if sid_ptr:
        advapi32.FreeSid(sid_ptr)


def sid_to_string(sid_ptr: int) -> str:
    out = wintypes.LPWSTR()
    ok = advapi32.ConvertSidToStringSidW(sid_ptr, ctypes.byref(out))
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    result = out.value
    kernel32.LocalFree(out)
    return result


def string_to_sid(sid_string: str) -> int:
    sid = ctypes.c_void_p()
    ok = advapi32.ConvertStringSidToSidW(sid_string, ctypes.byref(sid))
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    return sid.value


# DPAPI helpers

def dpapi_protect(data: bytes) -> bytes:
    buf = ctypes.create_string_buffer(data, len(data))
    in_blob = DATA_BLOB()
    in_blob.cbData = len(data)
    in_blob.pbData = ctypes.cast(buf, ctypes.c_void_p)

    out_blob = DATA_BLOB()
    ok = crypt32.CryptProtectData(
        ctypes.byref(in_blob), None, None, None, None, 0,
        ctypes.byref(out_blob),
    )
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())

    result = ctypes.string_at(out_blob.pbData, out_blob.cbData)
    kernel32.LocalFree(out_blob.pbData)
    return result


def dpapi_unprotect(data: bytes) -> bytes:
    buf = ctypes.create_string_buffer(data, len(data))
    in_blob = DATA_BLOB()
    in_blob.cbData = len(data)
    in_blob.pbData = ctypes.cast(buf, ctypes.c_void_p)

    out_blob = DATA_BLOB()
    ok = crypt32.CryptUnprotectData(
        ctypes.byref(in_blob), None, None, None, None, 0,
        ctypes.byref(out_blob),
    )
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())

    result = ctypes.string_at(out_blob.pbData, out_blob.cbData)
    kernel32.LocalFree(out_blob.pbData)
    return result


# User management helpers

def create_user(name: str, password: str) -> bool:
    ui = USER_INFO_1()
    ui.usri1_name = name
    ui.usri1_password = password
    ui.usri1_priv = USER_PRIV_USER
    ui.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD
    ui.usri1_comment = "sbx sandbox user"

    parm_err = wintypes.DWORD()
    status = netapi32.NetUserAdd(
        None, 1, ctypes.byref(ui), ctypes.byref(parm_err)
    )
    if status == NERR_UserExists:
        return False
    if status != NERR_Success:
        raise OSError(
            f"NetUserAdd failed: status {status}, parm_err {parm_err.value}"
        )
    return True


def delete_user(name: str) -> None:
    status = netapi32.NetUserDel(None, name)
    if status not in (NERR_Success, NERR_UserNotFound):
        raise OSError(f"NetUserDel failed: status {status}")


def user_exists(name: str) -> bool:
    buf = ctypes.c_void_p()
    status = netapi32.NetUserGetInfo(None, name, 0, ctypes.byref(buf))
    if status == NERR_Success:
        netapi32.NetApiBufferFree(buf)
        return True
    return False


# Shell elevation

def shell_execute_elevated(file: str, params: str) -> int:
    sei = SHELLEXECUTEINFOW()
    sei.cbSize = ctypes.sizeof(SHELLEXECUTEINFOW)
    sei.fMask = SEE_MASK_NOCLOSEPROCESS
    sei.lpVerb = "runas"
    sei.lpFile = file
    sei.lpParameters = params
    sei.nShow = SW_HIDE

    ok = shell32.ShellExecuteExW(ctypes.byref(sei))
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    return sei.hProcess


def wait_for_process(handle: int) -> int:
    kernel32.WaitForSingleObject(handle, INFINITE)
    exit_code = wintypes.DWORD()
    kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
    return exit_code.value


def close_handle(handle: int) -> None:
    if handle:
        kernel32.CloseHandle(handle)
