"""Windows API wrappers for sandbox PoCs.

Thin ctypes layer over Win32 primitives needed by the PoCs:
bind filter, user management, SIDs, ACLs (via icacls), restricted
tokens, impersonation, and process-as-user launching.

All pointer-returning SID functions return int (the raw address).
Call free_sid() when done.
"""

import ctypes
from ctypes import wintypes
import os
import struct
import subprocess

# ── DLLs ────────────────────────────────────────────────────

advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
netapi32 = ctypes.WinDLL("netapi32", use_last_error=True)
bindfltapi = ctypes.WinDLL("bindfltapi", use_last_error=True)

# ── Constants ───────────────────────────────────────────────

BINDFLT_FLAG_READ_ONLY_MAPPING = 0x00000001

TOKEN_DUPLICATE = 0x0002
TOKEN_QUERY = 0x0008
TOKEN_ASSIGN_PRIMARY = 0x0001
MAXIMUM_ALLOWED = 0x02000000

DISABLE_MAX_PRIVILEGE = 0x1
WRITE_RESTRICTED = 0x8

SID_REVISION = 1

USER_PRIV_USER = 1
UF_SCRIPT = 0x0001
UF_DONT_EXPIRE_PASSWD = 0x10000
NERR_Success = 0
NERR_UserExists = 2224
NERR_UserNotFound = 2221

LOGON_WITH_PROFILE = 0x00000001
CREATE_NO_WINDOW = 0x08000000
CREATE_UNICODE_ENVIRONMENT = 0x00000400

INFINITE = 0xFFFFFFFF

SE_FILE_OBJECT = 1
DACL_SECURITY_INFORMATION = 0x00000004
PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
GRANT_ACCESS = 1
SET_ACCESS = 2
NO_MULTIPLE_TRUSTEE = 0
TRUSTEE_IS_SID = 0
TRUSTEE_IS_UNKNOWN = 0
SUB_CONTAINERS_AND_OBJECTS_INHERIT = 0x03  # CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE
FILE_ALL_ACCESS = 0x001F01FF

# ── Structures ──────────────────────────────────────────────


class SID_IDENTIFIER_AUTHORITY(ctypes.Structure):
    _fields_ = [("Value", ctypes.c_ubyte * 6)]


class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Sid", ctypes.c_void_p),
        ("Attributes", wintypes.DWORD),
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


class TRUSTEE_W(ctypes.Structure):
    _fields_ = [
        ("pMultipleTrustee", ctypes.c_void_p),
        ("MultipleTrusteeOperation", wintypes.DWORD),
        ("TrusteeForm", wintypes.DWORD),
        ("TrusteeType", wintypes.DWORD),
        ("ptstrName", ctypes.c_void_p),  # PSID when TrusteeForm == TRUSTEE_IS_SID
    ]


class EXPLICIT_ACCESS_W(ctypes.Structure):
    _fields_ = [
        ("grfAccessPermissions", wintypes.DWORD),
        ("grfAccessMode", wintypes.DWORD),
        ("grfInheritance", wintypes.DWORD),
        ("Trustee", TRUSTEE_W),
    ]


# ── Function prototypes ────────────────────────────────────

# Bind filter
bindfltapi.BfSetupFilter.argtypes = [
    wintypes.HANDLE,   # JobHandle
    wintypes.DWORD,    # Flags
    wintypes.LPCWSTR,  # VirtualizationRootPath
    wintypes.LPCWSTR,  # VirtualizationTargetPath
    ctypes.c_void_p,   # VirtualizationExceptionPaths (LPCWSTR*)
    wintypes.DWORD,    # VirtualizationExceptionPathCount
]
bindfltapi.BfSetupFilter.restype = wintypes.LONG  # HRESULT

bindfltapi.BfRemoveMapping.argtypes = [
    wintypes.HANDLE,   # JobHandle (NULL for global)
    wintypes.LPCWSTR,  # VirtualizationRootPath
]
bindfltapi.BfRemoveMapping.restype = wintypes.LONG  # HRESULT

# SID
advapi32.AllocateAndInitializeSid.argtypes = [
    ctypes.POINTER(SID_IDENTIFIER_AUTHORITY),
    ctypes.c_ubyte,    # nSubAuthorityCount
    wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
    wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
    ctypes.POINTER(ctypes.c_void_p),  # pSid
]
advapi32.AllocateAndInitializeSid.restype = wintypes.BOOL

advapi32.FreeSid.argtypes = [ctypes.c_void_p]
advapi32.FreeSid.restype = ctypes.c_void_p

advapi32.ConvertSidToStringSidW.argtypes = [
    ctypes.c_void_p,
    ctypes.POINTER(wintypes.LPWSTR),
]
advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL

# ACL
advapi32.GetNamedSecurityInfoW.argtypes = [
    wintypes.LPCWSTR,  # pObjectName
    wintypes.DWORD,    # ObjectType
    wintypes.DWORD,    # SecurityInfo
    ctypes.c_void_p,   # ppsidOwner (NULL)
    ctypes.c_void_p,   # ppsidGroup (NULL)
    ctypes.POINTER(ctypes.c_void_p),  # ppDacl
    ctypes.c_void_p,   # ppSacl (NULL)
    ctypes.POINTER(ctypes.c_void_p),  # ppSecurityDescriptor
]
advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD

advapi32.SetEntriesInAclW.argtypes = [
    wintypes.ULONG,
    ctypes.POINTER(EXPLICIT_ACCESS_W),
    ctypes.c_void_p,   # OldAcl
    ctypes.POINTER(ctypes.c_void_p),  # NewAcl
]
advapi32.SetEntriesInAclW.restype = wintypes.DWORD

advapi32.SetNamedSecurityInfoW.argtypes = [
    wintypes.LPWSTR,   # pObjectName (mutable)
    wintypes.DWORD,    # ObjectType
    wintypes.DWORD,    # SecurityInfo
    ctypes.c_void_p,   # psidOwner
    ctypes.c_void_p,   # psidGroup
    ctypes.c_void_p,   # pDacl
    ctypes.c_void_p,   # pSacl
]
advapi32.SetNamedSecurityInfoW.restype = wintypes.DWORD

# Token
advapi32.OpenProcessToken.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.HANDLE),
]
advapi32.OpenProcessToken.restype = wintypes.BOOL

advapi32.CreateRestrictedToken.argtypes = [
    wintypes.HANDLE,   # ExistingTokenHandle
    wintypes.DWORD,    # Flags
    wintypes.DWORD,    # DisableSidCount
    ctypes.c_void_p,   # SidsToDisable
    wintypes.DWORD,    # DeletePrivilegeCount
    ctypes.c_void_p,   # PrivilegesToDelete
    wintypes.DWORD,    # RestrictedSidCount
    ctypes.c_void_p,   # SidsToRestrict (SID_AND_ATTRIBUTES*)
    ctypes.POINTER(wintypes.HANDLE),  # NewTokenHandle
]
advapi32.CreateRestrictedToken.restype = wintypes.BOOL

# Impersonation
advapi32.ImpersonateLoggedOnUser.argtypes = [wintypes.HANDLE]
advapi32.ImpersonateLoggedOnUser.restype = wintypes.BOOL

advapi32.RevertToSelf.argtypes = []
advapi32.RevertToSelf.restype = wintypes.BOOL

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

# Process creation
advapi32.CreateProcessWithLogonW.argtypes = [
    wintypes.LPCWSTR,  # lpUsername
    wintypes.LPCWSTR,  # lpDomain
    wintypes.LPCWSTR,  # lpPassword
    wintypes.DWORD,    # dwLogonFlags
    wintypes.LPCWSTR,  # lpApplicationName
    wintypes.LPWSTR,   # lpCommandLine (mutable)
    wintypes.DWORD,    # dwCreationFlags
    ctypes.c_void_p,   # lpEnvironment
    wintypes.LPCWSTR,  # lpCurrentDirectory
    ctypes.POINTER(STARTUPINFOW),
    ctypes.POINTER(PROCESS_INFORMATION),
]
advapi32.CreateProcessWithLogonW.restype = wintypes.BOOL

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


# ── Elevation check ────────────────────────────────────────

def is_elevated():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


# ── Bind links ──────────────────────────────────────────────

def create_bind_link(virtual_path, backing_path, read_only=False):
    """Create a bind filter mapping: virtual_path shows backing_path's content.

    Requires elevation. virtual_path must be an existing directory.
    """
    flags = BINDFLT_FLAG_READ_ONLY_MAPPING if read_only else 0
    hr = bindfltapi.BfSetupFilter(None, flags, virtual_path, backing_path, None, 0)
    if hr < 0:
        raise OSError(f"BfSetupFilter failed: HRESULT 0x{hr & 0xFFFFFFFF:08X}")


def remove_bind_link(virtual_path):
    """Remove a bind filter mapping. Ignores 'not found' errors."""
    hr = bindfltapi.BfRemoveMapping(None, virtual_path)
    if hr < 0:
        E_INVALIDARG = -2147024809   # 0x80070057
        NOT_FOUND    = -2147024894   # 0x80070002
        if hr in (NOT_FOUND, E_INVALIDARG):
            return
        raise OSError(f"BfRemoveMapping failed: HRESULT 0x{hr & 0xFFFFFFFF:08X}")


# ── SID helpers ─────────────────────────────────────────────

def _alloc_sid(authority_byte_5, sub_count, *subs):
    """Low-level SID allocation. Returns raw pointer (int)."""
    auth = SID_IDENTIFIER_AUTHORITY()
    auth.Value[5] = authority_byte_5
    sid = ctypes.c_void_p()
    padded = list(subs) + [0] * (8 - len(subs))
    ok = advapi32.AllocateAndInitializeSid(
        ctypes.byref(auth),
        sub_count,
        *[wintypes.DWORD(s) for s in padded],
        ctypes.byref(sid),
    )
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    return sid.value


def create_synthetic_sid():
    """Create a random synthetic SID under authority {0,0,0,0,0,42}.

    Returns raw pointer (int). Call free_sid() when done.
    """
    r = os.urandom(16)
    a, b, c, d = struct.unpack("<IIII", r)
    return _alloc_sid(42, 4, a, b, c, d)


def create_everyone_sid():
    """S-1-1-0 (Everyone). Returns raw pointer (int)."""
    return _alloc_sid(1, 1, 0)


def create_users_sid():
    """S-1-5-32-545 (BUILTIN\\Users). Returns raw pointer (int)."""
    return _alloc_sid(5, 2, 32, 545)


def create_administrators_sid():
    """S-1-5-32-544 (BUILTIN\\Administrators). Returns raw pointer (int)."""
    return _alloc_sid(5, 2, 32, 544)


def free_sid(sid_ptr):
    if sid_ptr:
        advapi32.FreeSid(sid_ptr)


def sid_to_string(sid_ptr):
    """Convert a SID pointer to its string form (S-1-...)."""
    out = wintypes.LPWSTR()
    ok = advapi32.ConvertSidToStringSidW(sid_ptr, ctypes.byref(out))
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    result = out.value
    kernel32.LocalFree(out)
    return result


# ── ACL helpers (via icacls) ────────────────────────────────

def grant_access(path, sid_or_name, perms="(OI)(CI)F"):
    """Add an allow ACE to path's DACL. sid_or_name is a username or *S-1-... SID string."""
    subprocess.run(
        ["icacls", path, "/grant", f"{sid_or_name}:{perms}"],
        check=True, capture_output=True, text=True,
    )


def set_protected_dacl(path, grants):
    """Replace path's DACL: disable inheritance, remove inherited ACEs, add grants.

    grants — list of (sid_or_name, perms) tuples, e.g. [("Administrators", "(OI)(CI)F")].
    """
    subprocess.run(
        ["icacls", path, "/inheritance:r"],
        check=True, capture_output=True, text=True,
    )
    for sid_or_name, perms in grants:
        grant_access(path, sid_or_name, perms)


# ── ACL helpers (via Win32 API, for synthetic SIDs) ────────

def _make_explicit_access(sid_ptr, access_mask):
    ea = EXPLICIT_ACCESS_W()
    ea.grfAccessPermissions = access_mask
    ea.grfAccessMode = SET_ACCESS
    ea.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT
    ea.Trustee.pMultipleTrustee = None
    ea.Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID
    ea.Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN
    ea.Trustee.ptstrName = sid_ptr
    return ea


def grant_sid_access(path, sid_ptr, access_mask=FILE_ALL_ACCESS):
    """Add an allow ACE for sid_ptr to path's existing DACL."""
    dacl = ctypes.c_void_p()
    sd = ctypes.c_void_p()
    err = advapi32.GetNamedSecurityInfoW(
        path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
        None, None, ctypes.byref(dacl), None, ctypes.byref(sd),
    )
    if err != 0:
        raise OSError(f"GetNamedSecurityInfoW failed: error {err}")

    ea = _make_explicit_access(sid_ptr, access_mask)
    new_dacl = ctypes.c_void_p()
    err = advapi32.SetEntriesInAclW(1, ctypes.byref(ea), dacl, ctypes.byref(new_dacl))
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


def set_protected_dacl_sid(path, sid_access_pairs):
    """Replace path's DACL with only the given SID->access entries, disabling inheritance.

    sid_access_pairs — list of (sid_ptr, access_mask) tuples.
    """
    count = len(sid_access_pairs)
    arr = (EXPLICIT_ACCESS_W * count)()
    for i, (sid_ptr, access_mask) in enumerate(sid_access_pairs):
        arr[i] = _make_explicit_access(sid_ptr, access_mask)

    new_dacl = ctypes.c_void_p()
    err = advapi32.SetEntriesInAclW(count, arr, None, ctypes.byref(new_dacl))
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


# ── User management ────────────────────────────────────────

def create_user(name, password):
    """Create a local user account. Returns True if created, False if already existed."""
    ui = USER_INFO_1()
    ui.usri1_name = name
    ui.usri1_password = password
    ui.usri1_password_age = 0
    ui.usri1_priv = USER_PRIV_USER
    ui.usri1_home_dir = None
    ui.usri1_comment = "Sandbox PoC test user"
    ui.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD
    ui.usri1_script_path = None

    parm_err = wintypes.DWORD()
    status = netapi32.NetUserAdd(None, 1, ctypes.byref(ui), ctypes.byref(parm_err))
    if status == NERR_UserExists:
        return False
    if status != NERR_Success:
        raise OSError(f"NetUserAdd failed: status {status}, parm_err {parm_err.value}")
    return True


def delete_user(name):
    """Delete a local user account. No-op if not found."""
    status = netapi32.NetUserDel(None, name)
    if status not in (NERR_Success, NERR_UserNotFound):
        raise OSError(f"NetUserDel failed: status {status}")


# ── Token helpers ───────────────────────────────────────────

def create_restricted_token(restricted_sid_ptrs):
    """Create a fully restricted token from the current process token.

    restricted_sid_ptrs — list of SID pointers (int) to place in the
    RestrictedSids list. The token uses DISABLE_MAX_PRIVILEGE (not
    WRITE_RESTRICTED), so both reads and writes are gated by the
    restricted SID check.

    Returns a token HANDLE (int). Call close_handle() when done.
    """
    proc_token = wintypes.HANDLE()
    ok = advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(),
        TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY,
        ctypes.byref(proc_token),
    )
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())

    count = len(restricted_sid_ptrs)
    arr = (SID_AND_ATTRIBUTES * count)()
    for i, sid_ptr in enumerate(restricted_sid_ptrs):
        arr[i].Sid = sid_ptr
        arr[i].Attributes = 0

    new_token = wintypes.HANDLE()
    ok = advapi32.CreateRestrictedToken(
        proc_token,
        DISABLE_MAX_PRIVILEGE,
        0, None,            # SidsToDisable
        0, None,            # PrivilegesToDelete
        count, ctypes.byref(arr) if count else None,
        ctypes.byref(new_token),
    )
    kernel32.CloseHandle(proc_token)
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    return new_token.value


# ── Impersonation ───────────────────────────────────────────

def impersonate_token(token_handle):
    """Impersonate the given token on the calling thread."""
    ok = advapi32.ImpersonateLoggedOnUser(token_handle)
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())


def revert_to_self():
    ok = advapi32.RevertToSelf()
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())


# ── Process launch ──────────────────────────────────────────

def run_as_user(username, password, command_line, working_dir=None):
    """Launch a process as a different user and wait for exit.

    Uses CreateProcessWithLogonW with LOGON_WITH_PROFILE (creates the
    user profile on first use). Output capture is the caller's
    responsibility (e.g., redirect to a file in command_line).

    Returns the process exit code.
    """
    si = STARTUPINFOW()
    si.cb = ctypes.sizeof(STARTUPINFOW)
    pi = PROCESS_INFORMATION()

    cmd_buf = ctypes.create_unicode_buffer(command_line)

    ok = advapi32.CreateProcessWithLogonW(
        username,
        ".",             # local machine
        password,
        LOGON_WITH_PROFILE,
        None,            # lpApplicationName
        cmd_buf,
        CREATE_NO_WINDOW,
        None,            # lpEnvironment (inherit)
        working_dir,
        ctypes.byref(si),
        ctypes.byref(pi),
    )
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())

    kernel32.WaitForSingleObject(pi.hProcess, INFINITE)

    exit_code = wintypes.DWORD()
    kernel32.GetExitCodeProcess(pi.hProcess, ctypes.byref(exit_code))

    kernel32.CloseHandle(pi.hProcess)
    kernel32.CloseHandle(pi.hThread)

    return exit_code.value


def close_handle(handle):
    if handle:
        kernel32.CloseHandle(handle)
