from __future__ import annotations

import logging

from sbx import winapi
from sbx.errors import TokenError

log = logging.getLogger(__name__)


def create_sandbox_token(sandbox_sid: str) -> int:
    """Create a restricted token for a sandbox process.

    Opens the runner's own process token and creates a restricted token
    with DISABLE_MAX_PRIVILEGE. RestrictedSids = [sandbox_sid,
    BUILTIN\\Users, Everyone]. Everyone is required because kernel
    objects (BaseNamedObjects, KnownDlls) carry Everyone ACEs that the
    restricted-SID gate must pass for process initialization.
    """
    sandbox_sid_ptr = winapi.string_to_sid(sandbox_sid)
    users_sid_ptr = winapi.allocate_sid(5, 2, 32, 545)
    everyone_sid_ptr = winapi.allocate_sid(1, 1, 0)

    try:
        proc_token = winapi.open_process_token()
    except OSError as e:
        raise TokenError(f"failed to open process token: {e}")

    try:
        restricted = winapi.create_restricted_token(
            proc_token,
            winapi.DISABLE_MAX_PRIVILEGE,
            [sandbox_sid_ptr, users_sid_ptr, everyone_sid_ptr],
        )
    except OSError as e:
        raise TokenError(f"failed to create restricted token: {e}")
    finally:
        winapi.close_handle(proc_token)
        winapi.free_sid(users_sid_ptr)
        winapi.free_sid(everyone_sid_ptr)
        winapi.kernel32.LocalFree(sandbox_sid_ptr)

    log.info("created restricted token for SID %s", sandbox_sid)
    return restricted
