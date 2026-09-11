"""How a privileged operation is handed to the elevated helper.

The helper runs as administrator and performs whichever operation the
args file names, so that file is the boundary worth pinning: it must be
created exclusively, carry exactly what was asked for, and be gone
afterwards whichever way the call went.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sbx import elevation
from sbx.elevation import _exclusive_temp_file, run_elevated
from sbx.errors import ElevationError


def test_temp_file_exists_once_created():
    """mkstemp creates it; mktemp only returned a name, leaving a window
    for another process to get there first."""
    path = _exclusive_temp_file(".json")
    try:
        assert path.exists()
        assert path.read_text() == ""
    finally:
        path.unlink(missing_ok=True)


def test_two_temp_files_are_distinct():
    first = _exclusive_temp_file(".json")
    second = _exclusive_temp_file(".json")
    try:
        assert first != second
    finally:
        first.unlink(missing_ok=True)
        second.unlink(missing_ok=True)


@pytest.fixture
def captured(monkeypatch):
    """Intercept the elevation, recording what the helper would have read."""
    seen: dict = {}

    def fake_elevate(executable: str, params: str) -> int:
        args_path = Path(params.split('"')[1])
        result_path = Path(params.split('"')[3])
        seen["executable"] = executable
        seen["payload"] = json.loads(args_path.read_text(encoding="utf-8"))
        seen["args_path"] = args_path
        seen["result_path"] = result_path
        result_path.write_text(
            json.dumps({"result": {"ok": True}}), encoding="utf-8"
        )
        return 1234

    monkeypatch.setattr(elevation.winapi, "shell_execute_elevated", fake_elevate)
    monkeypatch.setattr(elevation.winapi, "wait_for_process", lambda h: 0)
    monkeypatch.setattr(elevation.winapi, "close_handle", lambda h: None)
    return seen


def test_the_operation_and_args_reach_the_helper(captured):
    result = run_elevated("destroy_mounts", {"sandbox_name": "demo"})

    assert result == {"ok": True}
    assert captured["payload"] == {
        "operation": "destroy_mounts",
        "args": {"sandbox_name": "demo"},
    }


def test_both_temp_files_are_removed_afterwards(captured):
    run_elevated("ping")

    assert not captured["args_path"].exists()
    assert not captured["result_path"].exists()


def test_temp_files_are_removed_even_when_the_helper_reports_an_error(
    monkeypatch,
):
    paths: dict = {}

    def failing_elevate(executable: str, params: str) -> int:
        paths["args"] = Path(params.split('"')[1])
        paths["result"] = Path(params.split('"')[3])
        paths["result"].write_text(
            json.dumps({"error": "boom"}), encoding="utf-8"
        )
        return 1234

    monkeypatch.setattr(
        elevation.winapi, "shell_execute_elevated", failing_elevate
    )
    monkeypatch.setattr(elevation.winapi, "wait_for_process", lambda h: 0)
    monkeypatch.setattr(elevation.winapi, "close_handle", lambda h: None)

    with pytest.raises(ElevationError, match="boom"):
        run_elevated("ping")

    assert not paths["args"].exists()
    assert not paths["result"].exists()


def test_an_empty_result_is_an_error_not_a_silent_success(monkeypatch):
    """The helper writes nothing if it crashed before dispatching — which
    is what happens when `python -m sbx` is not importable from its
    working directory."""
    monkeypatch.setattr(
        elevation.winapi, "shell_execute_elevated", lambda e, p: 1234
    )
    monkeypatch.setattr(elevation.winapi, "wait_for_process", lambda h: 0)
    monkeypatch.setattr(elevation.winapi, "close_handle", lambda h: None)

    with pytest.raises(ElevationError, match="no output"):
        run_elevated("ping")
