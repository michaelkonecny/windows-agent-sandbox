from __future__ import annotations

import logging

from sbx import winapi
from sbx.errors import TokenError

log = logging.getLogger(__name__)


def create_sandbox_token(
    sandbox_sid: str,
    *,
    skip_restricted_sids: bool = False,
) -> int:
    """Create a restricted token for a sandbox process.

    Always applies DISABLE_MAX_PRIVILEGE (strips all privileges except
    SeChangeNotifyPrivilege).

    Unless skip_restricted_sids is True, also adds RestrictedSids =
    [sandbox_sid, BUILTIN\\Users, Everyone].  Cygwin/MSYS2 shells are
    incompatible with restricted SIDs — the additional access check
    fails against session-local kernel objects whose DACLs don't
    include the restricted SIDs (shared memory, named pipes used for
    signal handling).  For those shells, pass skip_restricted_sids=True.
    """
    try:
        proc_token = winapi.open_process_token()
    except OSError as e:
        raise TokenError(f"failed to open process token: {e}")

    if skip_restricted_sids:
        restricted_sids: list[int] = []
    else:
        sandbox_sid_ptr = winapi.string_to_sid(sandbox_sid)
        users_sid_ptr = winapi.allocate_sid(5, 2, 32, 545)
        everyone_sid_ptr = winapi.allocate_sid(1, 1, 0)
        restricted_sids = [sandbox_sid_ptr, users_sid_ptr, everyone_sid_ptr]

    try:
        restricted = winapi.create_restricted_token(
            proc_token,
            winapi.DISABLE_MAX_PRIVILEGE,
            restricted_sids,
        )
    except OSError as e:
        raise TokenError(f"failed to create restricted token: {e}")
    finally:
        winapi.close_handle(proc_token)
        if not skip_restricted_sids:
            winapi.free_sid(users_sid_ptr)
            winapi.free_sid(everyone_sid_ptr)
            winapi.kernel32.LocalFree(sandbox_sid_ptr)

    if not skip_restricted_sids:
        try:
            winapi.set_kernel_object_null_dacl(restricted)
            winapi.set_token_null_default_dacl(restricted)
        except OSError as e:
            winapi.close_handle(restricted)
            raise TokenError(f"failed to set token DACLs: {e}")

    log.info(
        "created restricted token for SID %s (restricted_sids=%s)",
        sandbox_sid, not skip_restricted_sids,
    )
    return restricted
