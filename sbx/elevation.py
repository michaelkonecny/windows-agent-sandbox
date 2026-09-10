from __future__ import annotations

import json
import logging
import sys
import tempfile
from pathlib import Path
from typing import Callable

from sbx import winapi
from sbx.errors import ElevationError

log = logging.getLogger(__name__)

_OPERATIONS: dict[str, Callable] = {}


def register(name: str):
    def decorator(fn: Callable) -> Callable:
        _OPERATIONS[name] = fn
        return fn
    return decorator


def run_elevated(operation: str, args: dict | None = None) -> dict:
    args = args or {}

    args_path = Path(tempfile.mktemp(suffix=".json"))
    result_path = Path(tempfile.mktemp(suffix=".json"))

    try:
        args_path.write_text(
            json.dumps({"operation": operation, "args": args}),
            encoding="utf-8",
        )
        result_path.write_text("", encoding="utf-8")

        python = sys.executable
        params = f'-m sbx _elevate "{args_path}" "{result_path}"'

        handle = winapi.shell_execute_elevated(python, params)
        winapi.wait_for_process(handle)
        winapi.close_handle(handle)

        raw = result_path.read_text(encoding="utf-8")
        if not raw.strip():
            raise ElevationError("elevated subprocess produced no output")

        result = json.loads(raw)
        if "error" in result:
            raise ElevationError(result["error"])

        return result.get("result", {})
    finally:
        args_path.unlink(missing_ok=True)
        result_path.unlink(missing_ok=True)


def execute(args_path: str, result_path: str) -> None:
    payload = json.loads(Path(args_path).read_text(encoding="utf-8"))
    operation = payload["operation"]
    op_args = payload.get("args", {})

    try:
        handler = _OPERATIONS.get(operation)
        if handler is None:
            raise ElevationError(
                f"unknown elevated operation: {operation}"
            )
        result = handler(**op_args)
        Path(result_path).write_text(
            json.dumps({"result": result}), encoding="utf-8"
        )
    except Exception as e:
        Path(result_path).write_text(
            json.dumps({"error": str(e)}), encoding="utf-8"
        )


@register("ping")
def _op_ping(**kwargs) -> dict:
    return {"pong": True}


@register("fail")
def _op_fail(**kwargs) -> dict:
    raise ElevationError("intentional failure")


@register("install_user")
def _op_install_user(**kwargs) -> dict:
    from sbx.identity import install_user

    credentials_path = kwargs.get("credentials_path")
    if credentials_path:
        from pathlib import Path
        credentials_path = Path(credentials_path)
    install_user(credentials_path=credentials_path)
    return {"installed": True}


@register("grant_access")
def _op_grant_access(**kwargs) -> dict:
    import subprocess
    path = kwargs["path"]
    user = kwargs.get("user", "sbx-user")
    subprocess.run(
        ["icacls", path, "/grant", f"{user}:(OI)(CI)RX", "/T"],
        check=True, capture_output=True, text=True,
    )
    return {"granted": True}


@register("setup_test_env")
def _op_setup_test_env(**kwargs) -> dict:
    import secrets
    import subprocess
    from sbx import winapi
    from sbx.identity import SANDBOX_USER

    password = secrets.token_urlsafe(32)
    created = winapi.create_user(SANDBOX_USER, password)
    if not created:
        winapi.set_user_password(SANDBOX_USER, password)

    user = kwargs.get("user", SANDBOX_USER)
    for path in kwargs.get("grant_paths", []):
        subprocess.run(
            ["icacls", path, "/grant", f"{user}:(OI)(CI)RX", "/T"],
            check=True, capture_output=True, text=True,
        )
    return {"password": password}
