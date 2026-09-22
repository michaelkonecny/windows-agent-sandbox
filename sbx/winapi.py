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
FILE_GENERIC_EXECUTE = 0x001200A0

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


advapi32.LookupAccountNameW.argtypes = [
    wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_void_p,
    ctypes.POINTER(wintypes.DWORD), wintypes.LPWSTR,
    ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(ctypes.c_int),
]
advapi32.LookupAccountNameW.restype = wintypes.BOOL


def account_sid(name: str) -> str:
    """S-1-... string SID of a local account."""
    sid = (ctypes.c_byte * 68)()
    sid_len = wintypes.DWORD(ctypes.sizeof(sid))
    domain = ctypes.create_unicode_buffer(256)
    domain_len = wintypes.DWORD(256)
    use = ctypes.c_int()
    ok = advapi32.LookupAccountNameW(
        None, name, sid, ctypes.byref(sid_len),
        domain, ctypes.byref(domain_len), ctypes.byref(use),
    )
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    return sid_to_string(ctypes.addressof(sid))


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


WAIT_TIMEOUT = 0x102


def wait_for_process(handle: int, timeout_ms: int = INFINITE) -> int | None:
    """Wait for a process to exit; return its exit code, or None on timeout."""
    if kernel32.WaitForSingleObject(handle, timeout_ms) == WAIT_TIMEOUT:
        return None
    exit_code = wintypes.DWORD()
    kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
    return exit_code.value


def close_handle(handle: int) -> None:
    if handle:
        kernel32.CloseHandle(handle)


def resume_thread(handle: int) -> int:
    prev = kernel32.ResumeThread(handle)
    if prev == 0xFFFFFFFF:
        raise ctypes.WinError(ctypes.get_last_error())
    return prev


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
PROCESS_TERMINATE = 0x0001
SYNCHRONIZE = 0x00100000

ERROR_PIPE_CONNECTED = 535
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


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


HANDLE_FLAG_INHERIT = 0x00000001

kernel32.SetHandleInformation.argtypes = [
    wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD,
]
kernel32.SetHandleInformation.restype = wintypes.BOOL

kernel32.GetConsoleMode.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
kernel32.GetConsoleMode.restype = wintypes.BOOL


def set_handle_inheritable(handle: int, inheritable: bool) -> None:
    flags = HANDLE_FLAG_INHERIT if inheritable else 0
    if not kernel32.SetHandleInformation(handle, HANDLE_FLAG_INHERIT, flags):
        raise ctypes.WinError(ctypes.get_last_error())


def is_console(handle: int) -> bool:
    """True if handle refers to a console (not a pipe, file or NUL)."""
    mode = wintypes.DWORD()
    return bool(kernel32.GetConsoleMode(handle, ctypes.byref(mode)))


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
    buf = (ctypes.c_byte * size)()
    read = wintypes.DWORD()
    ok = kernel32.ReadFile(handle, buf, size, ctypes.byref(read), None)
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    return bytes(buf[:read.value])


def write_file(handle: int, data: bytes) -> int:
    written = wintypes.DWORD()
    ok = kernel32.WriteFile(
        handle, data, len(data), ctypes.byref(written), None
    )
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    return written.value


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


def create_process_as_user(
    token: int, command_line: str,
    creation_flags: int = 0,
    env: ctypes.Array | None = None, cwd: str | None = None,
    attribute_list: int | None = None,
    std_handles: tuple[int, int, int] | None = None,
    process_sa: SECURITY_ATTRIBUTES | None = None,
) -> tuple[int, int, int, int]:
    pi = PROCESS_INFORMATION()
    cmd = ctypes.create_unicode_buffer(command_line)
    inherit_handles = std_handles is not None
    if attribute_list is not None:
        si_ex = STARTUPINFOEXW()
        si_ex.StartupInfo.cb = ctypes.sizeof(STARTUPINFOEXW)
        si_ex.lpAttributeList = attribute_list
        creation_flags |= EXTENDED_STARTUPINFO_PRESENT
        if std_handles is not None:
            si_ex.StartupInfo.dwFlags |= STARTF_USESTDHANDLES
            si_ex.StartupInfo.hStdInput = std_handles[0]
            si_ex.StartupInfo.hStdOutput = std_handles[1]
            si_ex.StartupInfo.hStdError = std_handles[2]
        si_ptr = ctypes.byref(si_ex)
    else:
        si = STARTUPINFOW()
        si.cb = ctypes.sizeof(STARTUPINFOW)
        if std_handles is not None:
            si.dwFlags |= STARTF_USESTDHANDLES
            si.hStdInput = std_handles[0]
            si.hStdOutput = std_handles[1]
            si.hStdError = std_handles[2]
        si_ptr = ctypes.byref(si)
    ok = advapi32.CreateProcessAsUserW(
        token, None, cmd,
        ctypes.byref(process_sa) if process_sa else None, None, inherit_handles,
        creation_flags, ctypes.addressof(env) if env else None,
        cwd, si_ptr, ctypes.byref(pi),
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


JobObjectBasicProcessIdList = 3


def job_pids(job: int) -> list[int]:
    """PIDs of the processes currently in a Job Object."""

    class JOBOBJECT_BASIC_PROCESS_ID_LIST(ctypes.Structure):
        _fields_ = [
            ("NumberOfAssignedProcesses", wintypes.DWORD),
            ("NumberOfProcessIdsInList", wintypes.DWORD),
            ("ProcessIdList", ctypes.c_size_t * 512),
        ]

    info = JOBOBJECT_BASIC_PROCESS_ID_LIST()
    ok = kernel32.QueryInformationJobObject(
        job, JobObjectBasicProcessIdList,
        ctypes.byref(info), ctypes.sizeof(info), None,
    )
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    return list(info.ProcessIdList[:info.NumberOfProcessIdsInList])


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
    hpc_ref = ctypes.c_void_p(hpc)
    ok = kernel32.UpdateProcThreadAttribute(
        attr_list, 0,
        PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
        ctypes.byref(hpc_ref), ctypes.sizeof(hpc_ref),
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


# Explicit security descriptors (SDDL)

advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD,
    ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.ULONG),
]
advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
advapi32.GetSecurityDescriptorDacl.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL),
    ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.BOOL),
]
advapi32.GetSecurityDescriptorDacl.restype = wintypes.BOOL

SDDL_REVISION_1 = 1
TokenUser = 1


class SecurityDescriptor:
    """A self-relative SD parsed from SDDL; frees itself on close()."""

    def __init__(self, sddl: str) -> None:
        sd = ctypes.c_void_p()
        ok = advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, SDDL_REVISION_1, ctypes.byref(sd), None,
        )
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())
        self.ptr = sd.value

    def dacl(self) -> int:
        present, defaulted = wintypes.BOOL(), wintypes.BOOL()
        acl = ctypes.c_void_p()
        ok = advapi32.GetSecurityDescriptorDacl(
            self.ptr, ctypes.byref(present), ctypes.byref(acl), ctypes.byref(defaulted),
        )
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())
        return acl.value

    def attributes(self, inherit: bool = False) -> SECURITY_ATTRIBUTES:
        sa = SECURITY_ATTRIBUTES()
        sa.nLength = ctypes.sizeof(SECURITY_ATTRIBUTES)
        sa.lpSecurityDescriptor = self.ptr
        sa.bInheritHandle = inherit
        return sa

    def close(self) -> None:
        if self.ptr:
            kernel32.LocalFree(self.ptr)
            self.ptr = None


def set_kernel_object_dacl(handle: int, sddl: str) -> None:
    sd = SecurityDescriptor(sddl)
    try:
        if not advapi32.SetKernelObjectSecurity(handle, DACL_SECURITY_INFORMATION, sd.ptr):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        sd.close()


def set_token_default_dacl(token_handle: int, sddl: str) -> None:
    """Default DACL for objects (incl. child processes) the token creates."""
    sd = SecurityDescriptor(sddl)
    try:
        acl = ctypes.c_void_p(sd.dacl())
        ok = advapi32.SetTokenInformation(
            token_handle, TokenDefaultDacl, ctypes.byref(acl), ctypes.sizeof(acl),
        )
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        sd.close()


def token_user_sid(token_handle: int) -> str:
    size = wintypes.DWORD()
    advapi32.GetTokenInformation(token_handle, TokenUser, None, 0, ctypes.byref(size))
    buf = ctypes.create_string_buffer(size.value)
    if not advapi32.GetTokenInformation(
        token_handle, TokenUser, buf, size, ctypes.byref(size),
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    return sid_to_string(ctypes.c_void_p.from_buffer(buf).value)


TokenGroups = 2
SE_GROUP_LOGON_ID = 0xC0000000


def token_logon_sid(token_handle: int) -> str:
    """S-1-5-5-x-y logon SID of the token's logon session."""
    size = wintypes.DWORD()
    advapi32.GetTokenInformation(token_handle, TokenGroups, None, 0, ctypes.byref(size))
    buf = ctypes.create_string_buffer(size.value)
    if not advapi32.GetTokenInformation(
        token_handle, TokenGroups, buf, size, ctypes.byref(size),
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    count = ctypes.c_uint32.from_buffer(buf).value
    groups = (SID_AND_ATTRIBUTES * count).from_buffer(buf, ctypes.sizeof(ctypes.c_void_p))
    for g in groups:
        if g.Attributes & SE_GROUP_LOGON_ID == SE_GROUP_LOGON_ID:
            return sid_to_string(g.Sid)
    raise OSError("token has no logon SID")


# Local groups

class LOCALGROUP_INFO_1(ctypes.Structure):
    _fields_ = [("lgrpi1_name", wintypes.LPWSTR), ("lgrpi1_comment", wintypes.LPWSTR)]


class LOCALGROUP_MEMBERS_INFO_3(ctypes.Structure):
    _fields_ = [("lgrmi3_domainandname", wintypes.LPWSTR)]


netapi32.NetLocalGroupAdd.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD),
]
netapi32.NetLocalGroupAdd.restype = wintypes.DWORD
netapi32.NetLocalGroupAddMembers.argtypes = [
    wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
]
netapi32.NetLocalGroupAddMembers.restype = wintypes.DWORD
netapi32.NetLocalGroupDel.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
netapi32.NetLocalGroupDel.restype = wintypes.DWORD

ERROR_MEMBER_IN_ALIAS = 1378
ERROR_ALIAS_EXISTS = 1379
ERROR_NO_SUCH_ALIAS = 1376
NERR_GroupExists = 2223
NERR_GroupNotFound = 2220


def create_local_group(name: str, comment: str = "") -> None:
    """Create a local group; no-op if it exists."""
    info = LOCALGROUP_INFO_1(name, comment)
    status = netapi32.NetLocalGroupAdd(None, 1, ctypes.byref(info), None)
    if status not in (NERR_Success, ERROR_ALIAS_EXISTS, NERR_GroupExists):
        raise OSError(f"NetLocalGroupAdd failed: status {status}")


def add_local_group_member(group: str, member: str) -> None:
    """Add an account to a local group; no-op if already a member."""
    info = LOCALGROUP_MEMBERS_INFO_3(member)
    status = netapi32.NetLocalGroupAddMembers(None, group, 3, ctypes.byref(info), 1)
    if status not in (NERR_Success, ERROR_MEMBER_IN_ALIAS):
        raise OSError(f"NetLocalGroupAddMembers failed: status {status}")


def delete_local_group(name: str) -> None:
    status = netapi32.NetLocalGroupDel(None, name)
    if status not in (NERR_Success, ERROR_NO_SUCH_ALIAS, NERR_GroupNotFound):
        raise OSError(f"NetLocalGroupDel failed: status {status}")


# Non-propagating deny ACEs (a top-level directory only)

DENY_ACCESS = 3
NO_INHERITANCE = 0
FILE_ADD_FILE = 0x0002
FILE_ADD_SUBDIRECTORY = 0x0004

advapi32.SetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
advapi32.SetFileSecurityW.restype = wintypes.BOOL


def _edit_dacl_in_place(path: str, ea: EXPLICIT_ACCESS_W) -> None:
    """Merge one entry into a file's DACL via SetFileSecurityW, which —
    unlike SetNamedSecurityInfoW — doesn't walk the subtree."""
    dacl = ctypes.c_void_p()
    sd = ctypes.c_void_p()
    err = advapi32.GetNamedSecurityInfoW(
        path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
        None, None, ctypes.byref(dacl), None, ctypes.byref(sd),
    )
    if err != 0:
        raise OSError(f"GetNamedSecurityInfoW failed: error {err}")
    new_dacl = ctypes.c_void_p()
    try:
        err = advapi32.SetEntriesInAclW(1, ctypes.byref(ea), dacl, ctypes.byref(new_dacl))
        if err != 0:
            raise OSError(f"SetEntriesInAclW failed: error {err}")
        abs_sd = (ctypes.c_byte * 64)()
        if not advapi32.InitializeSecurityDescriptor(abs_sd, SECURITY_DESCRIPTOR_REVISION):
            raise ctypes.WinError(ctypes.get_last_error())
        if not advapi32.SetSecurityDescriptorDacl(abs_sd, True, new_dacl, False):
            raise ctypes.WinError(ctypes.get_last_error())
        if not advapi32.SetFileSecurityW(path, DACL_SECURITY_INFORMATION, abs_sd):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        kernel32.LocalFree(sd)
        if new_dacl:
            kernel32.LocalFree(new_dacl)


def _explicit_access(sid_ptr: int, mode: int, mask: int) -> EXPLICIT_ACCESS_W:
    ea = EXPLICIT_ACCESS_W()
    ea.grfAccessPermissions = mask
    ea.grfAccessMode = mode
    ea.grfInheritance = NO_INHERITANCE
    ea.Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID
    ea.Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN
    ea.Trustee.ptstrName = sid_ptr
    return ea


def deny_create_in_dir(path: str, sid_ptr: int) -> None:
    """Deny creating files and subdirectories directly in `path`."""
    _edit_dacl_in_place(path, _explicit_access(
        sid_ptr, DENY_ACCESS, FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY,
    ))


def remove_dir_aces(path: str, sid_ptr: int) -> None:
    """Remove every explicit ACE for `sid` from `path` itself."""
    _edit_dacl_in_place(path, _explicit_access(sid_ptr, REVOKE_ACCESS, 0))


kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
kernel32.TerminateProcess.restype = wintypes.BOOL


def terminate_process(handle: int, exit_code: int = 1) -> None:
    if not kernel32.TerminateProcess(handle, exit_code):
        raise ctypes.WinError(ctypes.get_last_error())
