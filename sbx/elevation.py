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
