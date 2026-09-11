"""The proxy keys network policy by Job Object name.

Registration and deregistration have to agree on that key. They did not:
start registered the job name while stop passed the sandbox name, so the
policy was never removed. Since start only registers when the preset is
not `none`, a stale entry could then outlive its sandbox and still be
matched by a later sandbox of the same name — one deliberately configured
with no network would have silently inherited the old policy, because the
Job Object name is derived from the sandbox name and so repeats.
"""

from __future__ import annotations

from datetime import datetime

import pytest

from sbx import engine as engine_module
from sbx.config import NetworkPreset
from sbx.engine import Engine
from sbx.process import sandbox_job_name
from sbx.store import SandboxRecord, SandboxState, Store


@pytest.fixture
def engine_with_running_sandbox(tmp_path):
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


def test_job_name_is_derived_from_the_sandbox_name():
    assert sandbox_job_name("demo") == "Global\\sbx-job-demo"


def test_stop_deregisters_under_the_key_start_registered(
    engine_with_running_sandbox, monkeypatch
):
    engine, project = engine_with_running_sandbox

    registered: list[str] = []
    deregistered: list[str] = []
    monkeypatch.setattr(
        engine_module, "sandbox_is_running", lambda name: False
    )
    monkeypatch.setattr(
        "sbx.network.deregister_sandbox", lambda key: deregistered.append(key)
    )
    monkeypatch.setattr(
        "sbx.network.register_sandbox",
        lambda key, preset, *a, **k: registered.append(key),
    )
    monkeypatch.setattr(
        "sbx.process.stop_sandbox", lambda name: None
    )

    from sbx.network import register_sandbox

    register_sandbox(sandbox_job_name("demo"), NetworkPreset.all)
    engine.stop(project)

    assert deregistered == registered == [sandbox_job_name("demo")], (
        "stop must remove the policy under the key start created it with"
    )
