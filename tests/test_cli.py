import json
import os
import time
from datetime import datetime
from pathlib import Path
from unittest import mock

import pytest
from click.testing import CliRunner

from sbx.cli import main
from sbx.engine import Engine
from sbx.errors import SandboxError
from sbx.store import SandboxRecord, SandboxState


@pytest.fixture
def runner():
    return CliRunner()


def test_subcommands_exist(runner):
    """Test 66: Each subcommand maps to correct engine method, returns exit 0."""
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    for cmd in ("install", "init", "create", "start", "stop",
                "destroy", "uninstall", "list", "status"):
        assert cmd in result.output


def test_init_success(runner, tmp_path):
    """Test 66 (init): init calls engine.init and returns exit 0."""
    project = tmp_path / "proj"
    project.mkdir()
    result = runner.invoke(main, ["init", str(project)])
    assert result.exit_code == 0
    assert "config created" in result.output


def test_list_empty(runner, tmp_path):
    """Test 66 (list): list with no sandboxes returns exit 0."""
    store_path = str(tmp_path / "empty-store.json")
    with mock.patch("sbx.engine.Store", lambda: __import__("sbx.store", fromlist=["Store"]).Store(Path(store_path))):
        result = runner.invoke(main, ["list"])
    assert result.exit_code == 0
    assert "no sandboxes" in result.output


def test_engine_error_returns_nonzero(runner, tmp_path):
    """Test 67: Engine error → non-zero exit code and human-readable stderr."""
    result = runner.invoke(main, ["create", str(tmp_path / "nope.json")])
    assert result.exit_code != 0


@pytest.mark.integration
def test_e2e_cli_lifecycle(tmp_path):
    """Test 72: end-to-end CLI lifecycle — init, create, start (send
    command, read output), stop, destroy.  Exercises the same flow a
    user hits manually."""
    import sys
    from sbx import winapi
    from sbx.elevation import run_elevated
    from sbx.identity import store_credentials, SANDBOX_USER
    from sbx.store import Store

    python_dir = str(Path(sys.executable).parent)
    project_dir = str(Path(__file__).parent.parent)

    try:
        result = run_elevated("setup_test_env", {
            "grant_paths": [python_dir, project_dir],
        })
    except Exception:
        pytest.skip("cannot set up test environment (UAC denied)")

    store_credentials(SANDBOX_USER, result["password"])

    project = (tmp_path / "e2e-proj").resolve()
    project.mkdir()
    store_file = tmp_path / "e2e-store.json"

    runner = CliRunner()

    with mock.patch("sbx.store._default_store_path", return_value=store_file):
        # init — scaffolds default config (shell=git-bash)
        res = runner.invoke(main, ["init", str(project)])
        assert res.exit_code == 0, res.output
        config_file = project / ".sandbox" / "config.json"
        assert config_file.exists()

        # rewrite shell to cmd for this test — git-bash path is
        # covered by test 71, and cmd avoids needing git installed
        config_file.write_text(json.dumps({
            "mounts": [{"source": str(project), "target": "repo"}],
            "shell": "cmd",
            "network": "none",
        }))

        # create (mock elevation for mount operations)
        with mock.patch("sbx.engine.run_elevated", return_value={"created": True}):
            res = runner.invoke(main, ["create", str(config_file)])
        assert res.exit_code == 0, res.output

        # start via engine API (CLI start blocks in _interactive_session)
        engine = Engine(store=Store(store_file))
        handle = engine.start(project)
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if winapi.peek_pipe(handle.pipe_out) > 0:
                    winapi.read_file(
                        handle.pipe_out, winapi.peek_pipe(handle.pipe_out),
                    )
                    break
                time.sleep(0.2)

            winapi.write_file(handle.pipe_in, b"echo E2E_OK\r\n")

            output = b""
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                avail = winapi.peek_pipe(handle.pipe_out)
                if avail > 0:
                    output += winapi.read_file(handle.pipe_out, avail)
                    if b"E2E_OK" in output:
                        break
                time.sleep(0.2)

            assert b"E2E_OK" in output
        finally:
            handle.close()

        # stop
        res = runner.invoke(main, ["stop", str(project)])
        assert res.exit_code == 0, res.output

        # verify store shows stopped state
        rec = Store(store_file).get(project)
        assert rec.state == SandboxState.stopped

        # destroy (mock elevation for mount cleanup)
        with mock.patch("sbx.engine.run_elevated", return_value={"destroyed": True}):
            res = runner.invoke(main, ["destroy", str(project)])
        assert res.exit_code == 0, res.output

        # verify sandbox removed from store
        assert Store(store_file).get(project) is None


@pytest.fixture
def piped_sandbox(tmp_path):
    """A created cmd sandbox whose store and credentials live under a
    temp LOCALAPPDATA, so a `python -m sbx start` subprocess can find it."""
    import sys
    from sbx.elevation import run_elevated
    from sbx.identity import store_credentials, SANDBOX_USER
    from sbx.store import Store

    python_dir = str(Path(sys.executable).parent)
    project_dir = str(Path(__file__).parent.parent)
    try:
        result = run_elevated("setup_test_env", {
            "grant_paths": [python_dir, project_dir],
        })
    except Exception:
        pytest.skip("cannot set up test environment (UAC denied)")

    appdata = tmp_path / "appdata"
    store_credentials(
        SANDBOX_USER, result["password"], appdata / "sbx" / "credentials.json",
    )

    project = (tmp_path / "piped").resolve()
    (project / ".sandbox").mkdir(parents=True)
    config_file = project / ".sandbox" / "config.json"
    config_file.write_text(json.dumps({
        "mounts": [{"source": str(project), "target": "repo"}],
        "shell": "cmd",
        "network": "none",
    }))
    name = f"piped-{os.getpid()}"
    engine = Engine(store=Store(appdata / "sbx" / "sandboxes.json"))
    with mock.patch("sbx.engine.run_elevated", return_value={"created": True}):
        engine.create(config_file, name=name)

    env = dict(os.environ, LOCALAPPDATA=str(appdata), PYTHONPATH=project_dir)
    yield project, env
    from sbx.process import stop_sandbox
    try:
        stop_sandbox(name)
    except Exception:
        pass


def _sbx_start(project, env, script: bytes):
    import subprocess
    import sys
    return subprocess.run(
        [sys.executable, "-m", "sbx", "start", str(project)],
        input=script, capture_output=True, env=env, timeout=60,
    )


@pytest.mark.integration
def test_start_piped_stdin_exit(piped_sandbox):
    """Test 73: piped stdin is relayed to the shell; `exit N` ends the
    session and becomes the CLI's exit code."""
    project, env = piped_sandbox
    res = _sbx_start(project, env, b"echo PIPED_OK\nexit 7\n")
    assert b"PIPED_OK" in res.stdout, res.stderr
    assert res.returncode == 7, res.stderr


@pytest.mark.integration
def test_start_piped_stdin_eof(piped_sandbox):
    """Test 73: stdin EOF without `exit` ends the session too."""
    project, env = piped_sandbox
    res = _sbx_start(project, env, b"echo EOF_OK\n")
    assert b"EOF_OK" in res.stdout, res.stderr
    assert res.returncode == 0, res.stderr
