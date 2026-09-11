"""A sandbox can end without the engine being told.

The store records what the engine last did. When the user types `exit`,
or the shell dies, the sandbox is gone and nothing writes to the store —
so a stored "running" outlives the sandbox.  `list` and `status` have to
report what is actually true.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest

from sbx import engine as engine_module
from sbx.engine import Engine
from sbx.store import SandboxRecord, SandboxState, Store


@pytest.fixture
def engine_with_record(tmp_path, monkeypatch):
    store = Store(tmp_path / "sandboxes.json")
    project = (tmp_path / "project").resolve()
    project.mkdir()

    store.add(SandboxRecord(
        project_path=project,
        name="demo",
        config_path=project / ".sandbox" / "config.json",
        synthetic_sid="S-1-42-1-2-3-4",
        state=SandboxState.running,
        created_at=datetime.now(),
        pids=[4321],
        job_handle=None,
    ))

    engine = Engine()
    engine.store = store
    return engine, project


def set_running(monkeypatch, running: bool):
    monkeypatch.setattr(
        engine_module, "sandbox_is_running", lambda name: running
    )


def test_status_reports_stopped_when_the_sandbox_is_gone(
    engine_with_record, monkeypatch
):
    engine, project = engine_with_record
    set_running(monkeypatch, False)

    assert engine.status(project)["state"] == "stopped"


def test_status_still_reports_running_while_it_runs(
    engine_with_record, monkeypatch
):
    engine, project = engine_with_record
    set_running(monkeypatch, True)

    info = engine.status(project)
    assert info["state"] == "running"
    assert info["pids"] == [4321]


def test_status_omits_pids_once_the_sandbox_is_gone(
    engine_with_record, monkeypatch
):
    """Stale PIDs are worse than none — they may name another process."""
    engine, project = engine_with_record
    set_running(monkeypatch, False)

    assert "pids" not in engine.status(project)


def test_list_reports_the_live_state(engine_with_record, monkeypatch):
    engine, _ = engine_with_record
    set_running(monkeypatch, False)

    assert [r.state for r in engine.list()] == [SandboxState.stopped]


def test_a_created_sandbox_is_not_reported_as_running(
    engine_with_record, monkeypatch
):
    """Only a stored 'running' can be stale; 'created' must stay put even
    if some unrelated job of the same name exists."""
    engine, project = engine_with_record
    engine.store.update(project, state=SandboxState.created)
    set_running(monkeypatch, True)

    assert engine.status(project)["state"] == "created"


def test_destroy_does_not_stop_a_sandbox_that_already_ended(
    engine_with_record, monkeypatch
):
    """Stopping an already-gone sandbox only logs a failure to open a Job
    Object that no longer exists."""
    engine, project = engine_with_record
    set_running(monkeypatch, False)

    stopped = []
    monkeypatch.setattr(Engine, "stop", lambda self, p: stopped.append(p))
    monkeypatch.setattr(engine_module, "run_elevated", lambda *a, **k: {})

    engine.destroy(project)

    assert stopped == []
    assert engine.list() == []


def test_destroy_stops_a_sandbox_that_is_still_running(
    engine_with_record, monkeypatch
):
    engine, project = engine_with_record
    set_running(monkeypatch, True)

    stopped = []
    monkeypatch.setattr(Engine, "stop", lambda self, p: stopped.append(p))
    monkeypatch.setattr(engine_module, "run_elevated", lambda *a, **k: {})

    engine.destroy(project)

    assert stopped == [project]
