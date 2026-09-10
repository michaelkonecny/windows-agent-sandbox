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
        log.info("user %s already exists", SANDBOX_USER)

    store_credentials(SANDBOX_USER, password, credentials_path)
    return SANDBOX_USER


def uninstall_user(credentials_path: Path | None = None) -> None:
    try:
        winapi.delete_user(SANDBOX_USER)
    except OSError as e:
        raise IdentityError(f"failed to delete user {SANDBOX_USER}: {e}")

    creds_path = credentials_path or _credentials_path()
    if creds_path.exists():
        creds_path.unlink()
    log.info("removed user %s", SANDBOX_USER)
