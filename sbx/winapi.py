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
bindfltapi = ctypes.WinDLL("bindfltapi", use_last_error=True)

# ── Constants ───────────────────────────────────────────────

SID_REVISION = 1

SECURITY_SANDBOX_AUTHORITY = (0, 0, 0, 0, 0, 42)
SECURITY_NT_AUTHORITY = (0, 0, 0, 0, 0, 5)

SECURITY_BUILTIN_DOMAIN_RID = 32
DOMAIN_ALIAS_RID_USERS = 545
DOMAIN_ALIAS_RID_ADMINS = 544

BUILTIN_USERS_SID = "S-1-5-32-545"
EVERYONE_SID = "S-1-1-0"
BUILTIN_ADMINS_SID = "S-1-5-32-544"

DISABLE_MAX_PRIVILEGE = 0x1
WRITE_RESTRICTED = 0x8
TOKEN_DUPLICATE = 0x0002
TOKEN_QUERY = 0x0008
TOKEN_ASSIGN_PRIMARY = 0x0001
TOKEN_ADJUST_DEFAULT = 0x0080
WRITE_DAC = 0x00040000

USER_PRIV_USER = 1
UF_SCRIPT = 0x0001
UF_DONT_EXPIRE_PASSWD = 0x10000
NERR_Success = 0
NERR_UserExists = 2224
NERR_UserNotFound = 2221

SE_FILE_OBJECT = 1
DACL_SECURITY_INFORMATION = 0x00000004
PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
GRANT_ACCESS = 1
SET_ACCESS = 2
REVOKE_ACCESS = 4
NO_MULTIPLE_TRUSTEE = 0
TRUSTEE_IS_SID = 0
TRUSTEE_IS_UNKNOWN = 0
SUB_CONTAINERS_AND_OBJECTS_INHERIT = 0x03
FILE_ALL_ACCESS = 0x001F01FF
FILE_GENERIC_READ = 0x00120089
FILE_GENERIC_WRITE = 0x00120116

BINDFLT_FLAG_READ_ONLY_MAPPING = 0x00000001

LOGON_WITH_PROFILE = 0x00000001
CREATE_NO_WINDOW = 0x08000000
CREATE_UNICODE_ENVIRONMENT = 0x00000400
INFINITE = 0xFFFFFFFF

SEE_MASK_NOCLOSEPROCESS = 0x00000040
SW_HIDE = 0

TokenPrivileges = 3
TokenRestrictedSids = 11
SE_PRIVILEGE_ENABLED = 0x00000002

TokenDefaultDacl = 6
TokenPrimary = 1
SecurityImpersonation = 2

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


class TRUSTEE_W(ctypes.Structure):
    _fields_ = [
        ("pMultipleTrustee", ctypes.c_void_p),
        ("MultipleTrusteeOperation", wintypes.DWORD),
        ("TrusteeForm", wintypes.DWORD),
        ("TrusteeType", wintypes.DWORD),
        ("ptstrName", ctypes.c_void_p),
    ]


class EXPLICIT_ACCESS_W(ctypes.Structure):
    _fields_ = [
        ("grfAccessPermissions", wintypes.DWORD),
        ("grfAccessMode", wintypes.DWORD),
        ("grfInheritance", wintypes.DWORD),
        ("Trustee", TRUSTEE_W),
    ]


class LUID(ctypes.Structure):
    _fields_ = [
        ("LowPart", wintypes.DWORD),
        ("HighPart", wintypes.LONG),
    ]


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Luid", LUID),
        ("Attributes", wintypes.DWORD),
    ]


# ── Function prototypes ────────────────────────────────────

# Bind filter
bindfltapi.BfSetupFilter.argtypes = [
    wintypes.HANDLE, wintypes.DWORD,
    wintypes.LPCWSTR, wintypes.LPCWSTR,
    ctypes.c_void_p, wintypes.DWORD,
]
bindfltapi.BfSetupFilter.restype = wintypes.LONG

bindfltapi.BfRemoveMapping.argtypes = [
    wintypes.HANDLE, wintypes.LPCWSTR,
]
bindfltapi.BfRemoveMapping.restype = wintypes.LONG

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

advapi32.LookupAccountNameW.argtypes = [
    wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_void_p,
    ctypes.POINTER(wintypes.DWORD), wintypes.LPWSTR,
    ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
]
advapi32.LookupAccountNameW.restype = wintypes.BOOL

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

# ACL
advapi32.GetNamedSecurityInfoW.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
    ctypes.c_void_p, ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_void_p),
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_void_p),
]
advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD

advapi32.SetEntriesInAclW.argtypes = [
    wintypes.ULONG,
    ctypes.POINTER(EXPLICIT_ACCESS_W),
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_void_p),
]
advapi32.SetEntriesInAclW.restype = wintypes.DWORD

advapi32.SetNamedSecurityInfoW.argtypes = [
    wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD,
    ctypes.c_void_p, ctypes.c_void_p,
    ctypes.c_void_p, ctypes.c_void_p,
]
advapi32.SetNamedSecurityInfoW.restype = wintypes.DWORD

# Token
advapi32.OpenProcessToken.argtypes = [
    wintypes.HANDLE, wintypes.DWORD,
    ctypes.POINTER(wintypes.HANDLE),
]
advapi32.OpenProcessToken.restype = wintypes.BOOL

advapi32.CreateRestrictedToken.argtypes = [
    wintypes.HANDLE, wintypes.DWORD,
    wintypes.DWORD, ctypes.c_void_p,
    wintypes.DWORD, ctypes.c_void_p,
    wintypes.DWORD, ctypes.c_void_p,
    ctypes.POINTER(wintypes.HANDLE),
]
advapi32.CreateRestrictedToken.restype = wintypes.BOOL

advapi32.DuplicateTokenEx.argtypes = [
    wintypes.HANDLE, wintypes.DWORD,
    ctypes.c_void_p, wintypes.DWORD,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.HANDLE),
]
advapi32.DuplicateTokenEx.restype = wintypes.BOOL

advapi32.GetTokenInformation.argtypes = [
    wintypes.HANDLE, wintypes.DWORD,
    ctypes.c_void_p, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
]
advapi32.GetTokenInformation.restype = wintypes.BOOL

advapi32.ImpersonateLoggedOnUser.argtypes = [wintypes.HANDLE]
advapi32.ImpersonateLoggedOnUser.restype = wintypes.BOOL

advapi32.RevertToSelf.argtypes = []
advapi32.RevertToSelf.restype = wintypes.BOOL

# DPAPI
crypt32.CryptProtectData.argtypes = [
    ctypes.POINTER(DATA_BLOB), wintypes.LPCWSTR,
    ctypes.POINTER(DATA_BLOB), ctypes.c_void_p,
    ctypes.c_void_p, wintypes.DWORD,
    ctypes.POINTER(DATA_BLOB),
]
crypt32.CryptProtectData.restype = wintypes.BOOL

crypt32.CryptUnprotectData.argtypes = [
    ctypes.POINTER(DATA_BLOB),
    ctypes.POINTER(wintypes.LPWSTR),
    ctypes.POINTER(DATA_BLOB), ctypes.c_void_p,
    ctypes.c_void_p, wintypes.DWORD,
    ctypes.POINTER(DATA_BLOB),
]
crypt32.CryptUnprotectData.restype = wintypes.BOOL

# User management
netapi32.NetUserAdd.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD,
    ctypes.POINTER(USER_INFO_1),
    ctypes.POINTER(wintypes.DWORD),
]
netapi32.NetUserAdd.restype = wintypes.DWORD

netapi32.NetUserDel.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
netapi32.NetUserDel.restype = wintypes.DWORD

netapi32.NetUserGetInfo.argtypes = [
    wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
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

kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
kernel32.TerminateProcess.restype = wintypes.BOOL

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
    """Returns SID pointer allocated by LocalAlloc. Free with LocalFree."""
    sid = ctypes.c_void_p()
    ok = advapi32.ConvertStringSidToSidW(sid_string, ctypes.byref(sid))
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    return sid.value


# Bind link helpers

def create_bind_link(virtual_path: str, backing_path: str) -> None:
    hr = bindfltapi.BfSetupFilter(
        None, 0, virtual_path, backing_path, None, 0
    )
    if hr < 0:
        raise OSError(
            f"BfSetupFilter failed: HRESULT 0x{hr & 0xFFFFFFFF:08X}"
        )


def remove_bind_link(virtual_path: str) -> None:
    hr = bindfltapi.BfRemoveMapping(None, virtual_path)
    if hr < 0:
        E_INVALIDARG = -2147024809
        NOT_FOUND = -2147024894
        if hr in (NOT_FOUND, E_INVALIDARG):
            return
        raise OSError(
            f"BfRemoveMapping failed: HRESULT 0x{hr & 0xFFFFFFFF:08X}"
        )


def lookup_account_sid(name: str) -> str:
    """Resolve an account name to its SID string.

    Called in a double pass: the first call fails and reports the buffer
    sizes needed, the second fills them.
    """
    sid_size = wintypes.DWORD(0)
    domain_size = wintypes.DWORD(0)
    sid_type = wintypes.DWORD()

    advapi32.LookupAccountNameW(
        None, name, None, ctypes.byref(sid_size),
        None, ctypes.byref(domain_size), ctypes.byref(sid_type),
    )
    if sid_size.value == 0:
        raise ctypes.WinError(ctypes.get_last_error())

    sid_buf = (ctypes.c_byte * sid_size.value)()
    domain_buf = ctypes.create_unicode_buffer(domain_size.value)
    ok = advapi32.LookupAccountNameW(
        None, name, sid_buf, ctypes.byref(sid_size),
        domain_buf, ctypes.byref(domain_size), ctypes.byref(sid_type),
    )
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    return sid_to_string(ctypes.addressof(sid_buf))


# ACL helpers

def grant_sid_access(
    path: str, sid_ptr: int, access_mask: int = FILE_ALL_ACCESS
) -> None:
    dacl = ctypes.c_void_p()
    sd = ctypes.c_void_p()
    err = advapi32.GetNamedSecurityInfoW(
        path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
        None, None, ctypes.byref(dacl), None, ctypes.byref(sd),
    )
    if err != 0:
        raise OSError(f"GetNamedSecurityInfoW failed: error {err}")

    ea = EXPLICIT_ACCESS_W()
    ea.grfAccessPermissions = access_mask
    ea.grfAccessMode = SET_ACCESS
    ea.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT
    ea.Trustee.pMultipleTrustee = None
    ea.Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID
    ea.Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN
    ea.Trustee.ptstrName = sid_ptr

    new_dacl = ctypes.c_void_p()
    err = advapi32.SetEntriesInAclW(
        1, ctypes.byref(ea), dacl, ctypes.byref(new_dacl)
    )
    if err != 0:
        kernel32.LocalFree(sd)
        raise OSError(f"SetEntriesInAclW failed: error {err}")

    path_buf = ctypes.create_unicode_buffer(path)
    err = advapi32.SetNamedSecurityInfoW(
        path_buf, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
        None, None, new_dacl, None,
    )
    kernel32.LocalFree(sd)
    kernel32.LocalFree(new_dacl)
    if err != 0:
        raise OSError(f"SetNamedSecurityInfoW failed: error {err}")


def remove_sid_access(path: str, sid_ptr: int) -> None:
    dacl = ctypes.c_void_p()
    sd = ctypes.c_void_p()
    err = advapi32.GetNamedSecurityInfoW(
        path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
        None, None, ctypes.byref(dacl), None, ctypes.byref(sd),
    )
    if err != 0:
        raise OSError(f"GetNamedSecurityInfoW failed: error {err}")

    ea = EXPLICIT_ACCESS_W()
    ea.grfAccessPermissions = 0
    ea.grfAccessMode = REVOKE_ACCESS
    ea.grfInheritance = 0
    ea.Trustee.pMultipleTrustee = None
    ea.Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID
    ea.Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN
    ea.Trustee.ptstrName = sid_ptr

    new_dacl = ctypes.c_void_p()
    err = advapi32.SetEntriesInAclW(
        1, ctypes.byref(ea), dacl, ctypes.byref(new_dacl)
    )
    if err != 0:
        kernel32.LocalFree(sd)
        raise OSError(f"SetEntriesInAclW failed: error {err}")

    path_buf = ctypes.create_unicode_buffer(path)
    err = advapi32.SetNamedSecurityInfoW(
        path_buf, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
        None, None, new_dacl, None,
    )
    kernel32.LocalFree(sd)
    kernel32.LocalFree(new_dacl)
    if err != 0:
        raise OSError(f"SetNamedSecurityInfoW failed: error {err}")


# Token helpers

def open_process_token(
    access: int = TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT | WRITE_DAC,
) -> int:
    token = wintypes.HANDLE()
    ok = advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(), access, ctypes.byref(token)
    )
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    return token.value


def create_restricted_token(
    token_handle: int,
    flags: int,
    restricted_sid_ptrs: list[int],
) -> int:
    count = len(restricted_sid_ptrs)
    arr = (SID_AND_ATTRIBUTES * count)()
    for i, ptr in enumerate(restricted_sid_ptrs):
        arr[i].Sid = ptr
        arr[i].Attributes = 0

    new_token = wintypes.HANDLE()
    ok = advapi32.CreateRestrictedToken(
        token_handle, flags,
        0, None, 0, None,
        count, ctypes.byref(arr) if count else None,
        ctypes.byref(new_token),
    )
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    return new_token.value


def duplicate_token(
    token_handle: int,
    access: int = TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY,
    token_type: int = TokenPrimary,
) -> int:
    new_token = wintypes.HANDLE()
    ok = advapi32.DuplicateTokenEx(
        token_handle, access, None,
        SecurityImpersonation, token_type,
        ctypes.byref(new_token),
    )
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    return new_token.value


def get_token_restricted_sids(token_handle: int) -> list[str]:
    length = wintypes.DWORD()
    advapi32.GetTokenInformation(
        token_handle, TokenRestrictedSids, None, 0, ctypes.byref(length)
    )

    buf = (ctypes.c_ubyte * length.value)()
    ok = advapi32.GetTokenInformation(
        token_handle, TokenRestrictedSids,
        buf, length.value, ctypes.byref(length),
    )
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())

    count = wintypes.DWORD.from_buffer_copy(buf).value

    class _TOKEN_GROUPS(ctypes.Structure):
        _fields_ = [
            ("GroupCount", wintypes.DWORD),
            ("Groups", SID_AND_ATTRIBUTES * max(count, 1)),
        ]

    tg = _TOKEN_GROUPS.from_buffer_copy(buf)
    return [sid_to_string(tg.Groups[i].Sid) for i in range(count)]


def get_token_enabled_privilege_count(token_handle: int) -> int:
    length = wintypes.DWORD()
    advapi32.GetTokenInformation(
        token_handle, TokenPrivileges, None, 0, ctypes.byref(length)
    )

    buf = (ctypes.c_ubyte * length.value)()
    ok = advapi32.GetTokenInformation(
        token_handle, TokenPrivileges,
        buf, length.value, ctypes.byref(length),
    )
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())

    count = wintypes.DWORD.from_buffer_copy(buf).value

    class _TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = [
            ("PrivilegeCount", wintypes.DWORD),
            ("Privileges", LUID_AND_ATTRIBUTES * max(count, 1)),
        ]

    tp = _TOKEN_PRIVILEGES.from_buffer_copy(buf)
    enabled = 0
    for i in range(count):
        if tp.Privileges[i].Attributes & SE_PRIVILEGE_ENABLED:
            enabled += 1
    return enabled


def impersonate_token(token_handle: int) -> None:
    ok = advapi32.ImpersonateLoggedOnUser(token_handle)
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())


def revert_to_self() -> None:
    ok = advapi32.RevertToSelf()
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())


def set_protected_dacl(
    path: str, sid_access_pairs: list[tuple[int, int]]
) -> None:
    count = len(sid_access_pairs)
    arr = (EXPLICIT_ACCESS_W * count)()
    for i, (sid_ptr, access_mask) in enumerate(sid_access_pairs):
        arr[i].grfAccessPermissions = access_mask
        arr[i].grfAccessMode = SET_ACCESS
        arr[i].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT
        arr[i].Trustee.pMultipleTrustee = None
        arr[i].Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE
        arr[i].Trustee.TrusteeForm = TRUSTEE_IS_SID
        arr[i].Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN
        arr[i].Trustee.ptstrName = sid_ptr

    new_dacl = ctypes.c_void_p()
    err = advapi32.SetEntriesInAclW(
        count, arr, None, ctypes.byref(new_dacl)
    )
    if err != 0:
        raise OSError(f"SetEntriesInAclW failed: error {err}")

    path_buf = ctypes.create_unicode_buffer(path)
    err = advapi32.SetNamedSecurityInfoW(
        path_buf, SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        None, None, new_dacl, None,
    )
    kernel32.LocalFree(new_dacl)
    if err != 0:
        raise OSError(f"SetNamedSecurityInfoW failed: error {err}")


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


def set_user_password(name: str, password: str) -> None:
    class USER_INFO_1003(ctypes.Structure):
        _fields_ = [("usri1003_password", wintypes.LPWSTR)]

    ui = USER_INFO_1003()
    ui.usri1003_password = password
    parm_err = wintypes.DWORD()
    status = netapi32.NetUserSetInfo(
        None, name, 1003, ctypes.byref(ui), ctypes.byref(parm_err),
    )
    if status != NERR_Success:
        raise OSError(
            f"NetUserSetInfo failed: status {status}, parm_err {parm_err.value}"
        )


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


WAIT_TIMEOUT = 0x00000102
STILL_ACTIVE = 259


def wait_for_process(handle: int, timeout_ms: int = INFINITE) -> int:
    """Wait for a process and return its exit code.

    Raises TimeoutError if timeout_ms elapses first.
    """
    if kernel32.WaitForSingleObject(handle, timeout_ms) == WAIT_TIMEOUT:
        raise TimeoutError(f"process did not exit within {timeout_ms} ms")
    exit_code = wintypes.DWORD()
    kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
    return exit_code.value


def process_is_running(handle: int) -> bool:
    exit_code = wintypes.DWORD()
    kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
    return exit_code.value == STILL_ACTIVE


def terminate_process(handle: int, exit_code: int = 1) -> None:
    kernel32.TerminateProcess(handle, exit_code)


def close_handle(handle: int) -> None:
    if handle:
        kernel32.CloseHandle(handle)


# ── Phase 4: Process launch ────────────────────────────────

# Constants

STARTF_USESTDHANDLES = 0x00000100
EXTENDED_STARTUPINFO_PRESENT = 0x00080000
CREATE_NEW_CONSOLE = 0x00000010
CREATE_SUSPENDED = 0x00000004
CREATE_BREAKAWAY_FROM_JOB = 0x01000000

PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE = 0x00020016

JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
JobObjectExtendedLimitInformation = 9
JOB_OBJECT_TERMINATE = 0x00000008
JOB_OBJECT_SET_ATTRIBUTES = 0x00000002
JOB_OBJECT_QUERY = 0x00000004
JOB_OBJECT_ASSIGN_PROCESS = 0x00000001
JOB_OBJECT_ALL_ACCESS = 0x001F001F

PIPE_ACCESS_INBOUND = 0x00000001
PIPE_ACCESS_OUTBOUND = 0x00000002
PIPE_TYPE_BYTE = 0x00000000
PIPE_READMODE_BYTE = 0x00000000
PIPE_WAIT = 0x00000000
PIPE_UNLIMITED_INSTANCES = 255

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3

SECURITY_DESCRIPTOR_REVISION = 1

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

ERROR_PIPE_CONNECTED = 535
ERROR_BROKEN_PIPE = 109
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

# Console modes and std handle ids.
STD_INPUT_HANDLE = -10
STD_OUTPUT_HANDLE = -11
STD_ERROR_HANDLE = -12

# Input modes.  ENABLE_VIRTUAL_TERMINAL_INPUT makes the console deliver
# keystrokes as VT escape sequences instead of INPUT_RECORD key events;
# ENABLE_WINDOW_INPUT delivers resize notifications.
ENABLE_PROCESSED_INPUT = 0x0001
ENABLE_LINE_INPUT = 0x0002
ENABLE_ECHO_INPUT = 0x0004
ENABLE_WINDOW_INPUT = 0x0008
ENABLE_VIRTUAL_TERMINAL_INPUT = 0x0200

# Output modes.  ENABLE_VIRTUAL_TERMINAL_PROCESSING makes the console
# interpret VT sequences written to it rather than printing them.
ENABLE_PROCESSED_OUTPUT = 0x0001
ENABLE_WRAP_AT_EOL_OUTPUT = 0x0002
ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
DISABLE_NEWLINE_AUTO_RETURN = 0x0008

# INPUT_RECORD event types.
KEY_EVENT = 0x0001
WINDOW_BUFFER_SIZE_EVENT = 0x0004


# Structures

class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.c_void_p),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


class STARTUPINFOEXW(ctypes.Structure):
    _fields_ = [
        ("StartupInfo", STARTUPINFOW),
        ("lpAttributeList", ctypes.c_void_p),
    ]


class COORD(ctypes.Structure):
    _fields_ = [
        ("X", wintypes.SHORT),
        ("Y", wintypes.SHORT),
    ]


class SMALL_RECT(ctypes.Structure):
    _fields_ = [
        ("Left", wintypes.SHORT),
        ("Top", wintypes.SHORT),
        ("Right", wintypes.SHORT),
        ("Bottom", wintypes.SHORT),
    ]


class KEY_EVENT_RECORD(ctypes.Structure):
    _fields_ = [
        ("bKeyDown", wintypes.BOOL),
        ("wRepeatCount", wintypes.WORD),
        ("wVirtualKeyCode", wintypes.WORD),
        ("wVirtualScanCode", wintypes.WORD),
        # Union of WCHAR/CHAR in the SDK; we only read the wide form.
        ("UnicodeChar", ctypes.c_wchar),
        ("dwControlKeyState", wintypes.DWORD),
    ]


class WINDOW_BUFFER_SIZE_RECORD(ctypes.Structure):
    _fields_ = [("dwSize", COORD)]


class INPUT_RECORD_EVENT(ctypes.Union):
    _fields_ = [
        ("KeyEvent", KEY_EVENT_RECORD),
        ("WindowBufferSizeEvent", WINDOW_BUFFER_SIZE_RECORD),
    ]


class INPUT_RECORD(ctypes.Structure):
    _fields_ = [
        ("EventType", wintypes.WORD),
        ("Event", INPUT_RECORD_EVENT),
    ]


class CONSOLE_SCREEN_BUFFER_INFO(ctypes.Structure):
    _fields_ = [
        ("dwSize", COORD),
        ("dwCursorPosition", COORD),
        ("wAttributes", wintypes.WORD),
        ("srWindow", SMALL_RECT),
        ("dwMaximumWindowSize", COORD),
    ]


class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("nLength", wintypes.DWORD),
        ("lpSecurityDescriptor", ctypes.c_void_p),
        ("bInheritHandle", wintypes.BOOL),
    ]


class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", wintypes.LARGE_INTEGER),
        ("PerJobUserTimeLimit", wintypes.LARGE_INTEGER),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class IO_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_ulonglong),
        ("WriteOperationCount", ctypes.c_ulonglong),
        ("OtherOperationCount", ctypes.c_ulonglong),
        ("ReadTransferCount", ctypes.c_ulonglong),
        ("WriteTransferCount", ctypes.c_ulonglong),
        ("OtherTransferCount", ctypes.c_ulonglong),
    ]


class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


# Function prototypes

advapi32.CreateProcessWithLogonW.argtypes = [
    wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR,
    wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPWSTR,
    wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR,
    ctypes.POINTER(STARTUPINFOW),
    ctypes.POINTER(PROCESS_INFORMATION),
]
advapi32.CreateProcessWithLogonW.restype = wintypes.BOOL

kernel32.GetStdHandle.argtypes = [wintypes.DWORD]
kernel32.GetStdHandle.restype = wintypes.HANDLE

kernel32.GetConsoleMode.argtypes = [
    wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD),
]
kernel32.GetConsoleMode.restype = wintypes.BOOL

kernel32.SetConsoleMode.argtypes = [wintypes.HANDLE, wintypes.DWORD]
kernel32.SetConsoleMode.restype = wintypes.BOOL

kernel32.GetConsoleScreenBufferInfo.argtypes = [
    wintypes.HANDLE, ctypes.POINTER(CONSOLE_SCREEN_BUFFER_INFO),
]
kernel32.GetConsoleScreenBufferInfo.restype = wintypes.BOOL

kernel32.ReadConsoleInputW.argtypes = [
    wintypes.HANDLE, ctypes.POINTER(INPUT_RECORD),
    wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
]
kernel32.ReadConsoleInputW.restype = wintypes.BOOL

kernel32.CreateProcessW.argtypes = [
    wintypes.LPCWSTR, wintypes.LPWSTR,
    ctypes.c_void_p, ctypes.c_void_p, wintypes.BOOL,
    wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR,
    ctypes.c_void_p,
    ctypes.POINTER(PROCESS_INFORMATION),
]
kernel32.CreateProcessW.restype = wintypes.BOOL

advapi32.CreateProcessAsUserW.argtypes = [
    wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPWSTR,
    ctypes.c_void_p, ctypes.c_void_p, wintypes.BOOL,
    wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR,
    ctypes.c_void_p,
    ctypes.POINTER(PROCESS_INFORMATION),
]
advapi32.CreateProcessAsUserW.restype = wintypes.BOOL

kernel32.CreateJobObjectW.argtypes = [
    ctypes.c_void_p, wintypes.LPCWSTR,
]
kernel32.CreateJobObjectW.restype = wintypes.HANDLE

kernel32.OpenJobObjectW.argtypes = [
    wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR,
]
kernel32.OpenJobObjectW.restype = wintypes.HANDLE

kernel32.SetInformationJobObject.argtypes = [
    wintypes.HANDLE, wintypes.DWORD,
    ctypes.c_void_p, wintypes.DWORD,
]
kernel32.SetInformationJobObject.restype = wintypes.BOOL

kernel32.AssignProcessToJobObject.argtypes = [
    wintypes.HANDLE, wintypes.HANDLE,
]
kernel32.AssignProcessToJobObject.restype = wintypes.BOOL

kernel32.IsProcessInJob.argtypes = [
    wintypes.HANDLE, wintypes.HANDLE,
    ctypes.POINTER(wintypes.BOOL),
]
kernel32.IsProcessInJob.restype = wintypes.BOOL

kernel32.TerminateJobObject.argtypes = [
    wintypes.HANDLE, wintypes.UINT,
]
kernel32.TerminateJobObject.restype = wintypes.BOOL

kernel32.QueryInformationJobObject.argtypes = [
    wintypes.HANDLE, wintypes.DWORD,
    ctypes.c_void_p, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
]
kernel32.QueryInformationJobObject.restype = wintypes.BOOL

kernel32.CreatePseudoConsole.argtypes = [
    COORD, wintypes.HANDLE, wintypes.HANDLE,
    wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p),
]
kernel32.CreatePseudoConsole.restype = wintypes.LONG

kernel32.ResizePseudoConsole.argtypes = [
    ctypes.c_void_p, COORD,
]
kernel32.ResizePseudoConsole.restype = wintypes.LONG

kernel32.ClosePseudoConsole.argtypes = [ctypes.c_void_p]
kernel32.ClosePseudoConsole.restype = None

kernel32.InitializeProcThreadAttributeList.argtypes = [
    ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
    ctypes.POINTER(ctypes.c_size_t),
]
kernel32.InitializeProcThreadAttributeList.restype = wintypes.BOOL

kernel32.UpdateProcThreadAttribute.argtypes = [
    ctypes.c_void_p, wintypes.DWORD, ctypes.c_size_t,
    ctypes.c_void_p, ctypes.c_size_t,
    ctypes.c_void_p, ctypes.c_void_p,
]
kernel32.UpdateProcThreadAttribute.restype = wintypes.BOOL

kernel32.DeleteProcThreadAttributeList.argtypes = [ctypes.c_void_p]
kernel32.DeleteProcThreadAttributeList.restype = None

kernel32.CreatePipe.argtypes = [
    ctypes.POINTER(wintypes.HANDLE),
    ctypes.POINTER(wintypes.HANDLE),
    ctypes.c_void_p, wintypes.DWORD,
]
kernel32.CreatePipe.restype = wintypes.BOOL

kernel32.CreateNamedPipeW.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
    wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
    wintypes.DWORD, ctypes.c_void_p,
]
kernel32.CreateNamedPipeW.restype = wintypes.HANDLE

kernel32.ConnectNamedPipe.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p,
]
kernel32.ConnectNamedPipe.restype = wintypes.BOOL

kernel32.CreateFileW.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
    ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
    wintypes.HANDLE,
]
kernel32.CreateFileW.restype = wintypes.HANDLE

kernel32.ReadFile.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p,
]
kernel32.ReadFile.restype = wintypes.BOOL

kernel32.WriteFile.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p,
]
kernel32.WriteFile.restype = wintypes.BOOL

kernel32.PeekNamedPipe.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    ctypes.POINTER(wintypes.DWORD),
    ctypes.POINTER(wintypes.DWORD),
]
kernel32.PeekNamedPipe.restype = wintypes.BOOL

kernel32.OpenProcess.argtypes = [
    wintypes.DWORD, wintypes.BOOL, wintypes.DWORD,
]
kernel32.OpenProcess.restype = wintypes.HANDLE

kernel32.GetCurrentProcessId.argtypes = []
kernel32.GetCurrentProcessId.restype = wintypes.DWORD

advapi32.InitializeSecurityDescriptor.argtypes = [
    ctypes.c_void_p, wintypes.DWORD,
]
advapi32.InitializeSecurityDescriptor.restype = wintypes.BOOL

advapi32.SetSecurityDescriptorDacl.argtypes = [
    ctypes.c_void_p, wintypes.BOOL, ctypes.c_void_p, wintypes.BOOL,
]
advapi32.SetSecurityDescriptorDacl.restype = wintypes.BOOL


# Helper functions

def create_null_dacl_sa() -> tuple:
    sd = (ctypes.c_byte * 64)()
    ok = advapi32.InitializeSecurityDescriptor(sd, SECURITY_DESCRIPTOR_REVISION)
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    ok = advapi32.SetSecurityDescriptorDacl(sd, True, None, False)
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    sa = SECURITY_ATTRIBUTES()
    sa.nLength = ctypes.sizeof(SECURITY_ATTRIBUTES)
    sa.lpSecurityDescriptor = ctypes.addressof(sd)
    sa.bInheritHandle = True
    return sa, sd


def create_pipe(inheritable: bool = True) -> tuple[int, int]:
    read_h = wintypes.HANDLE()
    write_h = wintypes.HANDLE()
    if inheritable:
        sa, sd = create_null_dacl_sa()
        sa_ptr = ctypes.byref(sa)
    else:
        sa_ptr = None
    ok = kernel32.CreatePipe(
        ctypes.byref(read_h), ctypes.byref(write_h), sa_ptr, 0
    )
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    return read_h.value, write_h.value


def create_named_pipe(
    name: str, open_mode: int, buf_size: int = 4096,
    sa: SECURITY_ATTRIBUTES | None = None,
) -> int:
    handle = kernel32.CreateNamedPipeW(
        name, open_mode,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES, buf_size, buf_size, 0,
        ctypes.byref(sa) if sa else None,
    )
    if handle == INVALID_HANDLE_VALUE:
        raise ctypes.WinError(ctypes.get_last_error())
    return handle


def connect_named_pipe(handle: int) -> None:
    ok = kernel32.ConnectNamedPipe(handle, None)
    if not ok:
        err = ctypes.get_last_error()
        if err != ERROR_PIPE_CONNECTED:
            raise ctypes.WinError(err)


def open_file(path: str, access: int, share: int = 0) -> int:
    handle = kernel32.CreateFileW(
        path, access, share, None, OPEN_EXISTING, 0, None
    )
    if handle == INVALID_HANDLE_VALUE:
        raise ctypes.WinError(ctypes.get_last_error())
    return handle


def read_file(handle: int, size: int) -> bytes:
    # c_char, not c_byte: c_byte is signed, and slicing it yields ints in
    # -128..127, so bytes() rejects anything above 0x7f. This carries the
    # whole pseudoconsole stream, so that would break on the first
    # accented character or box-drawing glyph.
    buf = (ctypes.c_char * size)()
    read = wintypes.DWORD()
    ok = kernel32.ReadFile(handle, buf, size, ctypes.byref(read), None)
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    return buf.raw[:read.value]


def write_file(handle: int, data: bytes) -> int:
    written = wintypes.DWORD()
    ok = kernel32.WriteFile(
        handle, data, len(data), ctypes.byref(written), None
    )
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    return written.value


def get_std_handle(which: int) -> int:
    """GetStdHandle.  `which` is one of the STD_*_HANDLE ids, which are
    negative constants the API takes as an unsigned value."""
    handle = kernel32.GetStdHandle(which & 0xFFFFFFFF)
    if handle == INVALID_HANDLE_VALUE:
        raise ctypes.WinError(ctypes.get_last_error())
    return handle


def get_console_mode(handle: int) -> int:
    mode = wintypes.DWORD()
    if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
        raise ctypes.WinError(ctypes.get_last_error())
    return mode.value


def set_console_mode(handle: int, mode: int) -> None:
    if not kernel32.SetConsoleMode(handle, mode):
        raise ctypes.WinError(ctypes.get_last_error())


def get_console_screen_buffer_info(handle: int) -> tuple[int, int]:
    """Return the console's visible size as (cols, rows).

    Measured from the window rectangle, not the buffer: the buffer is
    typically far taller than the display (it holds the scrollback), and
    a terminal size means what the user can see.
    """
    info = CONSOLE_SCREEN_BUFFER_INFO()
    if not kernel32.GetConsoleScreenBufferInfo(handle, ctypes.byref(info)):
        raise ctypes.WinError(ctypes.get_last_error())
    cols = info.srWindow.Right - info.srWindow.Left + 1
    rows = info.srWindow.Bottom - info.srWindow.Top + 1
    return cols, rows


def read_console_input(handle: int, max_records: int = 32) -> list[INPUT_RECORD]:
    """ReadConsoleInputW — blocks until at least one event is available."""
    buf = (INPUT_RECORD * max_records)()
    count = wintypes.DWORD()
    ok = kernel32.ReadConsoleInputW(
        handle, buf, max_records, ctypes.byref(count)
    )
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    return list(buf[:count.value])


def peek_pipe(handle: int) -> int:
    available = wintypes.DWORD()
    ok = kernel32.PeekNamedPipe(
        handle, None, 0, None, ctypes.byref(available), None
    )
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    return available.value


def create_process_with_logon(
    username: str, domain: str, password: str,
    command_line: str, creation_flags: int = 0,
    env: ctypes.Array | None = None, cwd: str | None = None,
) -> tuple[int, int, int, int]:
    si = STARTUPINFOW()
    si.cb = ctypes.sizeof(STARTUPINFOW)
    pi = PROCESS_INFORMATION()
    cmd = ctypes.create_unicode_buffer(command_line)
    ok = advapi32.CreateProcessWithLogonW(
        username, domain, password,
        LOGON_WITH_PROFILE, None, cmd,
        creation_flags, ctypes.addressof(env) if env else None,
        cwd, ctypes.byref(si), ctypes.byref(pi),
    )
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    return pi.hProcess, pi.hThread, pi.dwProcessId, pi.dwThreadId


# Std handles for a process that must use its own console rather than
# ours.  Left to inherit, a child picks up the parent's std handles and
# writes there — so a pseudoconsole child whose parent has redirected
# stdio (a pipe or file, as under pytest or any CI runner) bypasses the
# pseudoconsole entirely and only its initial frame is ever emitted.
NULL_STD_HANDLES = (0, 0, 0)


def _build_startupinfo(
    attribute_list: int | None,
    std_handles: tuple[int, int, int] | None,
) -> tuple[object, int]:
    """Build the STARTUPINFO for a CreateProcess* call.

    Returns (si_ref, extra_creation_flags).  si_ref is a ctypes byref
    object, which keeps the underlying structure alive for as long as
    the caller holds it.

    An attribute_list forces the EXTENDED_STARTUPINFOEX variant.
    """
    if attribute_list is not None:
        si_ex = STARTUPINFOEXW()
        si_ex.StartupInfo.cb = ctypes.sizeof(STARTUPINFOEXW)
        si_ex.lpAttributeList = attribute_list
        si = si_ex.StartupInfo
        ref, extra_flags = ctypes.byref(si_ex), EXTENDED_STARTUPINFO_PRESENT
    else:
        si = STARTUPINFOW()
        si.cb = ctypes.sizeof(STARTUPINFOW)
        ref, extra_flags = ctypes.byref(si), 0

    if std_handles is not None:
        si.dwFlags |= STARTF_USESTDHANDLES
        si.hStdInput, si.hStdOutput, si.hStdError = std_handles

    return ref, extra_flags


def create_process(
    command_line: str,
    creation_flags: int = 0,
    env: ctypes.Array | None = None, cwd: str | None = None,
    attribute_list: int | None = None,
    std_handles: tuple[int, int, int] | None = None,
    inherit_handles: bool | None = None,
) -> tuple[int, int, int, int]:
    """CreateProcessW — launch as the current user, no token swap.

    inherit_handles defaults to whether std_handles were given; pass it
    explicitly as False alongside NULL_STD_HANDLES, where the point is to
    hand the child nothing rather than to share handles with it.
    """
    if inherit_handles is None:
        inherit_handles = std_handles is not None
    pi = PROCESS_INFORMATION()
    cmd = ctypes.create_unicode_buffer(command_line)
    si_ref, extra_flags = _build_startupinfo(attribute_list, std_handles)
    ok = kernel32.CreateProcessW(
        None, cmd, None, None, inherit_handles,
        creation_flags | extra_flags,
        ctypes.addressof(env) if env else None,
        cwd, si_ref, ctypes.byref(pi),
    )
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    return pi.hProcess, pi.hThread, pi.dwProcessId, pi.dwThreadId


def create_process_as_user(
    token: int, command_line: str,
    creation_flags: int = 0,
    env: ctypes.Array | None = None, cwd: str | None = None,
    attribute_list: int | None = None,
    std_handles: tuple[int, int, int] | None = None,
    inherit_handles: bool | None = None,
) -> tuple[int, int, int, int]:
    if inherit_handles is None:
        inherit_handles = std_handles is not None
    pi = PROCESS_INFORMATION()
    cmd = ctypes.create_unicode_buffer(command_line)
    si_ref, extra_flags = _build_startupinfo(attribute_list, std_handles)
    ok = advapi32.CreateProcessAsUserW(
        token, None, cmd, None, None, inherit_handles,
        creation_flags | extra_flags,
        ctypes.addressof(env) if env else None,
        cwd, si_ref, ctypes.byref(pi),
    )
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    return pi.hProcess, pi.hThread, pi.dwProcessId, pi.dwThreadId


def create_job_object(name: str | None = None, sa=None) -> int:
    handle = kernel32.CreateJobObjectW(
        ctypes.byref(sa) if sa else None, name
    )
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    return handle


def set_job_kill_on_close(job: int) -> None:
    info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    ok = kernel32.SetInformationJobObject(
        job, JobObjectExtendedLimitInformation,
        ctypes.byref(info), ctypes.sizeof(info),
    )
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())


def assign_process_to_job(job: int, process: int) -> None:
    ok = kernel32.AssignProcessToJobObject(job, process)
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())


def is_process_in_job(process: int, job: int | None = None) -> bool:
    result = wintypes.BOOL()
    ok = kernel32.IsProcessInJob(process, job, ctypes.byref(result))
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    return bool(result.value)


def terminate_job_object(job: int, exit_code: int = 1) -> None:
    ok = kernel32.TerminateJobObject(job, exit_code)
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())


def open_job_object(name: str, access: int = JOB_OBJECT_TERMINATE) -> int:
    handle = kernel32.OpenJobObjectW(access, False, name)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    return handle


def create_pseudo_console(
    cols: int, rows: int, h_input: int, h_output: int
) -> int:
    size = COORD()
    size.X = cols
    size.Y = rows
    hpc = ctypes.c_void_p()
    hr = kernel32.CreatePseudoConsole(
        size, h_input, h_output, 0, ctypes.byref(hpc)
    )
    if hr < 0:
        raise OSError(f"CreatePseudoConsole failed: HRESULT 0x{hr & 0xFFFFFFFF:08X}")
    return hpc.value


def close_pseudo_console(hpc: int) -> None:
    if hpc:
        kernel32.ClosePseudoConsole(hpc)


def resize_pseudo_console(hpc: int, cols: int, rows: int) -> None:
    size = COORD()
    size.X = cols
    size.Y = rows
    hr = kernel32.ResizePseudoConsole(hpc, size)
    if hr < 0:
        raise OSError(f"ResizePseudoConsole failed: HRESULT 0x{hr & 0xFFFFFFFF:08X}")


def init_proc_attribute_list(count: int) -> tuple:
    size = ctypes.c_size_t()
    kernel32.InitializeProcThreadAttributeList(None, count, 0, ctypes.byref(size))
    buf = (ctypes.c_byte * size.value)()
    ok = kernel32.InitializeProcThreadAttributeList(
        buf, count, 0, ctypes.byref(size)
    )
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    return buf, ctypes.addressof(buf)


def update_proc_attribute_console(attr_list: int, hpc: int) -> None:
    """Attach a pseudoconsole to a process about to be created.

    PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE is the odd one out among process
    attributes: lpValue is the HPCON itself, not a pointer to it, which is
    what the documented sample passes.  Pass a pointer — the convention
    every other attribute follows — and Windows treats that pointer as the
    console handle.  Every call still reports success, but the child
    silently inherits the parent's console instead of the pseudoconsole,
    and nothing is ever written to the pseudoconsole's pipes.
    """
    ok = kernel32.UpdateProcThreadAttribute(
        attr_list, 0,
        PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
        hpc, ctypes.sizeof(ctypes.c_void_p),
        None, None,
    )
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())


def delete_proc_attribute_list(attr_list: int) -> None:
    kernel32.DeleteProcThreadAttributeList(attr_list)


def make_env_block(env: dict[str, str]) -> ctypes.Array:
    block = "\0".join(f"{k}={v}" for k, v in sorted(env.items())) + "\0\0"
    return ctypes.create_unicode_buffer(block)


def open_process(pid: int, access: int) -> int:
    handle = kernel32.OpenProcess(access, False, pid)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    return handle


def get_current_pid() -> int:
    return kernel32.GetCurrentProcessId()


# ── Phase 5: Network isolation ────────────────────────────

iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)

AF_INET = 2
TCP_TABLE_OWNER_PID_CONNECTIONS = 4


class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwState", wintypes.DWORD),
        ("dwLocalAddr", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("dwRemoteAddr", wintypes.DWORD),
        ("dwRemotePort", wintypes.DWORD),
        ("dwOwningPid", wintypes.DWORD),
    ]


iphlpapi.GetExtendedTcpTable.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), wintypes.BOOL,
    wintypes.ULONG, wintypes.DWORD, wintypes.DWORD,
]
iphlpapi.GetExtendedTcpTable.restype = wintypes.DWORD


def get_tcp_pid(
    remote_ip: str, remote_port: int,
    local_ip: str, local_port: int,
) -> int | None:
    """Find the PID that owns a TCP connection from (remote_ip, remote_port)
    to (local_ip, local_port).

    Scans the TCP table for the entry where the CLIENT's local endpoint
    matches (remote_ip, remote_port) and the CLIENT's remote endpoint
    matches (local_ip, local_port).
    """
    import socket
    import struct as _struct
    target_local = _struct.unpack("<I", socket.inet_aton(remote_ip))[0]
    target_local_port = socket.htons(remote_port)
    target_remote = _struct.unpack("<I", socket.inet_aton(local_ip))[0]
    target_remote_port = socket.htons(local_port)

    buf_size = wintypes.DWORD(0)
    iphlpapi.GetExtendedTcpTable(
        None, ctypes.byref(buf_size), False,
        AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS, 0,
    )
    buf = (ctypes.c_byte * buf_size.value)()
    err = iphlpapi.GetExtendedTcpTable(
        buf, ctypes.byref(buf_size), False,
        AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS, 0,
    )
    if err != 0:
        raise OSError(f"GetExtendedTcpTable failed: error {err}")

    count = wintypes.DWORD.from_buffer_copy(buf).value
    offset = ctypes.sizeof(wintypes.DWORD)
    for i in range(count):
        row = MIB_TCPROW_OWNER_PID.from_buffer_copy(
            buf, offset + i * ctypes.sizeof(MIB_TCPROW_OWNER_PID),
        )
        if (row.dwLocalAddr == target_local
                and row.dwLocalPort == target_local_port
                and row.dwRemoteAddr == target_remote
                and row.dwRemotePort == target_remote_port):
            return row.dwOwningPid
    return None


# ── Token DACL helpers ─────────────────────────────────────

advapi32.SetTokenInformation.argtypes = [
    wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
]
advapi32.SetTokenInformation.restype = wintypes.BOOL

advapi32.SetKernelObjectSecurity.argtypes = [
    wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p,
]
advapi32.SetKernelObjectSecurity.restype = wintypes.BOOL


def set_token_null_default_dacl(token_handle: int) -> None:
    """Set the token's default DACL to NULL so objects created by the
    process are accessible to it.  Cygwin-based shells (git-bash) create
    named pipes for signal handling during init; without this the
    restricted SIDs aren't in the default DACL and creation fails."""
    dacl_ptr = ctypes.c_void_p(0)
    ok = advapi32.SetTokenInformation(
        token_handle, TokenDefaultDacl,
        ctypes.byref(dacl_ptr), ctypes.sizeof(dacl_ptr),
    )
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())


def set_kernel_object_null_dacl(handle: int) -> None:
    """Set a NULL DACL on a kernel object (e.g. a token handle) so the
    process running under restricted SIDs can query it.  Cygwin calls
    NtQueryInformationToken on its own process token during init;
    without this the restricted token's object DACL blocks the query."""
    sd = (ctypes.c_byte * 64)()
    ok = advapi32.InitializeSecurityDescriptor(sd, SECURITY_DESCRIPTOR_REVISION)
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    ok = advapi32.SetSecurityDescriptorDacl(sd, True, None, False)
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    ok = advapi32.SetKernelObjectSecurity(
        handle, DACL_SECURITY_INFORMATION, sd,
    )
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
