from __future__ import annotations

import logging

from sbx import winapi
from sbx.errors import TokenError

log = logging.getLogger(__name__)


def own_access_sddl(logon_sid: str, sandbox_sid: str) -> str:
    """ACEs granting full access to SYSTEM and to this sandbox only.

    The logon SID is unique to one runner's logon session and sits in both
    the token's normal groups and its RestrictedSids, so it passes both
    access checks for this sandbox and neither for another."""
    return f"(A;;GA;;;SY)(A;;GA;;;{logon_sid})(A;;GA;;;{sandbox_sid})"


def process_sddl(logon_sid: str, sandbox_sid: str) -> str:
    """SD for a sandbox shell process: own access, plus query/synchronize
    for Everyone so the host can inspect and wait on it."""
    return f"D:{own_access_sddl(logon_sid, sandbox_sid)}(A;;0x101000;;;WD)"


def create_sandbox_token(sandbox_sid: str) -> int:
    """Create the restricted token a sandbox shell runs under.

    DISABLE_MAX_PRIVILEGE strips all privileges except
    SeChangeNotifyPrivilege. RestrictedSids:
      - sandbox_sid — gates the sandbox's own mounts
      - BUILTIN\\Users, Everyone — read access to system paths, and
        process init (STATUS_DLL_INIT_FAILED without Everyone)
      - logon SID — window station / desktop (user32 init), and the
        sandbox's own processes and objects
      - account SID — Cygwin/MSYS2 (git-bash) creates its signal pipe and
        shared memory with DACLs naming only the account; also the
        account's profile (HOME, TEMP)
    Must be called by the runner, i.e. inside sbx-user's logon session.
    """
    try:
        proc_token = winapi.open_process_token()
    except OSError as e:
        raise TokenError(f"failed to open process token: {e}")

    sids: list[int] = []
    try:
        logon_sid = winapi.token_logon_sid(proc_token)
        for s in (sandbox_sid, winapi.BUILTIN_USERS_SID, winapi.EVERYONE_SID,
                  logon_sid, winapi.token_user_sid(proc_token)):
            sids.append(winapi.string_to_sid(s))
        restricted = winapi.create_restricted_token(
            proc_token, winapi.DISABLE_MAX_PRIVILEGE, sids,
        )
    except OSError as e:
        raise TokenError(f"failed to create restricted token: {e}")
    finally:
        winapi.close_handle(proc_token)
        for p in sids:
            winapi.kernel32.LocalFree(p)

    try:
        own = own_access_sddl(logon_sid, sandbox_sid)
        # Everyone may query the token (the host verifies owner/elevation).
        winapi.set_kernel_object_dacl(restricted, f"D:{own}(A;;0x8;;;WD)")
        # Children and objects the shell creates: this sandbox only.
        winapi.set_token_default_dacl(restricted, f"D:{own}")
    except OSError as e:
        winapi.close_handle(restricted)
        raise TokenError(f"failed to set token DACLs: {e}")

    log.info("created restricted token for SID %s", sandbox_sid)
    return restricted
