from __future__ import annotations

import json
import logging
import os
import secrets
import struct
from pathlib import Path

from sbx import winapi
from sbx.errors import IdentityError

log = logging.getLogger(__name__)

SANDBOX_USER = "sbx-user"
# Sole member: sbx-user. Mounts grant it for the normal access check —
# the account SID itself can't be used, because it is in every sandbox's
# RestrictedSids (see tokens).
SANDBOX_GROUP = "sbx-users"


def system_writable_dirs() -> list[Path]:
    """System directories Users (or INTERACTIVE) may create files in."""
    return [
        Path(os.environ.get("ProgramData", r"C:\ProgramData")),
        Path(os.environ.get("PUBLIC", r"C:\Users\Public")),
    ]


def _credentials_path() -> Path:
    return Path(os.environ.get("LOCALAPPDATA", "")) / "sbx" / "credentials.json"


def generate_sid() -> str:
    subs = struct.unpack("<IIII", os.urandom(16))
    return f"S-1-42-{subs[0]}-{subs[1]}-{subs[2]}-{subs[3]}"


def store_credentials(
    username: str, password: str, path: Path | None = None
) -> None:
    creds = json.dumps(
        {"username": username, "password": password}
    ).encode("utf-8")
    encrypted = winapi.dpapi_protect(creds)
    creds_path = path or _credentials_path()
    creds_path.parent.mkdir(parents=True, exist_ok=True)
    creds_path.write_bytes(encrypted)


def get_credentials(path: Path | None = None) -> tuple[str, str]:
    creds_path = path or _credentials_path()
    if not creds_path.exists():
        raise IdentityError(f"credentials not found at {creds_path}")
    encrypted = creds_path.read_bytes()
    try:
        decrypted = winapi.dpapi_unprotect(encrypted)
    except OSError as e:
        raise IdentityError(f"failed to decrypt credentials: {e}")
    data = json.loads(decrypted.decode("utf-8"))
    return data["username"], data["password"]


def install_user(credentials_path: Path | None = None) -> str:
    password = secrets.token_urlsafe(32)
    try:
        created = winapi.create_user(SANDBOX_USER, password)
    except OSError as e:
        raise IdentityError(f"failed to create user {SANDBOX_USER}: {e}")

    if created:
        log.info("created user %s", SANDBOX_USER)
    else:
        winapi.set_user_password(SANDBOX_USER, password)
        log.info("user %s already exists, password reset", SANDBOX_USER)

    winapi.create_local_group(SANDBOX_GROUP, "sbx sandbox account")
    winapi.add_local_group_member(SANDBOX_GROUP, SANDBOX_USER)

    store_credentials(SANDBOX_USER, password, credentials_path)
    return SANDBOX_USER


def runner_paths() -> list[Path]:
    """Paths the runner (engine re-invoked as sbx-user) must read and
    execute: the Python installation and the sbx package root."""
    import sys
    paths = {Path(sys.base_prefix).resolve(), Path(__file__).resolve().parent.parent}
    return sorted(paths)


def _set_runner_access(user_sid: str, grant: bool) -> None:
    sid_ptr = winapi.string_to_sid(user_sid)
    try:
        for path in runner_paths():
            if grant:
                winapi.grant_sid_access(
                    str(path), sid_ptr,
                    winapi.FILE_GENERIC_READ | winapi.FILE_GENERIC_EXECUTE,
                )
            else:
                winapi.remove_sid_access(str(path), sid_ptr)
    finally:
        winapi.kernel32.LocalFree(sid_ptr)


def grant_runner_access(user_sid: str) -> None:
    _set_runner_access(user_sid, grant=True)
    log.info("granted %s read+execute on %s", user_sid, runner_paths())


def revoke_runner_access(user_sid: str) -> None:
    _set_runner_access(user_sid, grant=False)


def lock_system_dirs(group_sid: str) -> None:
    """Deny sbx-users creating files directly in system_writable_dirs —
    system paths are read-only to sandboxes. Idempotent."""
    sid_ptr = winapi.string_to_sid(group_sid)
    try:
        for d in system_writable_dirs():
            winapi.remove_dir_aces(str(d), sid_ptr)
            winapi.deny_create_in_dir(str(d), sid_ptr)
    finally:
        winapi.kernel32.LocalFree(sid_ptr)


def unlock_system_dirs(group_sid: str) -> None:
    sid_ptr = winapi.string_to_sid(group_sid)
    try:
        for d in system_writable_dirs():
            winapi.remove_dir_aces(str(d), sid_ptr)
    finally:
        winapi.kernel32.LocalFree(sid_ptr)


def uninstall_user(credentials_path: Path | None = None) -> None:
    try:
        winapi.delete_user(SANDBOX_USER)
    except OSError as e:
        raise IdentityError(f"failed to delete user {SANDBOX_USER}: {e}")
    winapi.delete_local_group(SANDBOX_GROUP)

    creds_path = credentials_path or _credentials_path()
    if creds_path.exists():
        creds_path.unlink()
    log.info("removed user %s", SANDBOX_USER)
