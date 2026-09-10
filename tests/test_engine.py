import json
import shutil
from datetime import datetime
from pathlib import Path
from unittest import mock

import pytest

from sbx.config import NetworkPreset, ShellKind
from sbx.engine import Engine
from sbx.errors import SandboxError
from sbx.store import SandboxRecord, SandboxState, Store


@pytest.fixture
def tmp_store(tmp_path):
    return Store(tmp_path / "test-store.json")


@pytest.fixture
def engine(tmp_store):
    return Engine(store=tmp_store)


@pytest.fixture
def tmp_project(tmp_path):
    project = tmp_path / "myproject"
    project.mkdir()
    return project.resolve()


@pytest.fixture
def config_path(tmp_project):
    config_dir = tmp_project / ".sandbox"
    config_dir.mkdir()
    config_file = config_dir / "config.json"
    config_file.write_text(json.dumps({
        "mounts": [{"source": str(tmp_project), "target": "repo"}],
        "shell": "cmd",
        "network": "none",
    }))
    return config_file


def _make_record(project_path, name="test", state=SandboxState.created):
    return SandboxRecord(
        project_path=Path(project_path),
        name=name,
        state=state,
        synthetic_sid="S-1-42-1-2-3-4",
        config_path=Path(project_path) / ".sandbox" / "config.json",
        pids=[],
        job_handle=None,
        created_at=datetime.now(),
    )


def test_init_and_create(engine, tmp_project):
    """Test 58: Init scaffolds config, create reads it back."""
    engine.init(tmp_project)
    config_file = tmp_project / ".sandbox" / "config.json"
    assert config_file.exists()

    with mock.patch("sbx.engine.run_elevated", return_value={"created": True}):
        record = engine.create(config_file)

    assert record.name == tmp_project.name
    assert record.state == SandboxState.created
    assert record.synthetic_sid.startswith("S-1-42-")


def test_create_invalid_config(engine, tmp_path):
    """Test 59: Create with invalid config path fails before touching state."""
    with pytest.raises(SandboxError, match="config not found"):
        engine.create(tmp_path / "nonexistent" / "config.json")


def test_create_duplicate_name(engine, config_path, tmp_path):
    """Test 60: Create with duplicate sandbox name is rejected."""
    with mock.patch("sbx.engine.run_elevated", return_value={"created": True}):
        engine.create(config_path, name="dupe")

    config2_dir = tmp_path / "proj2" / ".sandbox"
    config2_dir.mkdir(parents=True)
    config2 = config2_dir / "config.json"
    config2.write_text(json.dumps({
        "mounts": [{"source": str(tmp_path / "proj2"), "target": "repo"}],
        "shell": "cmd",
        "network": "none",
    }))
    (tmp_path / "proj2").mkdir(exist_ok=True)

    with mock.patch("sbx.engine.run_elevated", return_value={"created": True}):
        with pytest.raises(SandboxError, match="already exists"):
            engine.create(config2, name="dupe")


def test_start_missing_shell(engine, config_path, tmp_project):
    """Test 61: Start with missing shell refuses with message."""
    config_path.write_text(json.dumps({
        "mounts": [{"source": str(tmp_project), "target": "repo"}],
        "shell": "pwsh",
        "network": "none",
    }))

    with mock.patch("sbx.engine.run_elevated", return_value={"created": True}):
        engine.create(config_path)

    with mock.patch("sbx.process.resolve_shell", side_effect=SandboxError("shell not found: pwsh")):
        with pytest.raises(SandboxError, match="shell not found"):
            engine.start(tmp_project)


def test_destroy_running_sandbox(engine, config_path, tmp_project):
    """Test 62: Destroy a running sandbox stops it first."""
    with mock.patch("sbx.engine.run_elevated", return_value={"created": True}):
        engine.create(config_path)

    engine.store.update(tmp_project, state=SandboxState.running, pids=[9999])

    with mock.patch.object(engine, "stop") as mock_stop:
        with mock.patch("sbx.engine.run_elevated", return_value={"destroyed": True}):
            engine.destroy(tmp_project)

    mock_stop.assert_called_once()
    assert engine.store.get(tmp_project) is None


def test_list_sandboxes(engine, config_path, tmp_project, tmp_path):
    """Test 63: List returns all sandboxes with correct states."""
    with mock.patch("sbx.engine.run_elevated", return_value={"created": True}):
        engine.create(config_path, name="sb1")

    records = engine.list()
    assert len(records) == 1
    assert records[0].name == "sb1"
    assert records[0].state == SandboxState.created


def test_status_running(engine, config_path, tmp_project):
    """Test 64: Status on a running sandbox includes live PIDs."""
    with mock.patch("sbx.engine.run_elevated", return_value={"created": True}):
        engine.create(config_path)

    engine.store.update(tmp_project, state=SandboxState.running, pids=[1234, 5678])

    info = engine.status(tmp_project)
    assert info["state"] == "running"
    assert info["pids"] == [1234, 5678]


def test_install_warns_missing_shells(engine):
    """Test 65: Install reports warnings for shells not found."""
    with mock.patch("sbx.engine.run_elevated", return_value={"installed": True}):
        with mock.patch("shutil.which", return_value=None):
            result = engine.install()

    assert len(result["warnings"]) > 0
    assert any("shell not found" in w for w in result["warnings"])
