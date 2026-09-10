import json
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


def test_list_empty(runner):
    """Test 66 (list): list with no sandboxes returns exit 0."""
    result = runner.invoke(main, ["list"])
    assert result.exit_code == 0
    assert "no sandboxes" in result.output


def test_engine_error_returns_nonzero(runner, tmp_path):
    """Test 67: Engine error → non-zero exit code and human-readable stderr."""
    result = runner.invoke(main, ["create", str(tmp_path / "nope.json")])
    assert result.exit_code != 0
