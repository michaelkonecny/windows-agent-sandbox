"""Behaviour the spec promises that had no code behind it.

Each of these was found by cross-checking specs/spec.md against the
implementation rather than by a failing test.
"""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from unittest import mock

import pytest
from click.testing import CliRunner

from sbx.cli import main
from sbx.engine import Engine
from sbx.errors import SandboxError
from sbx.store import SandboxRecord, SandboxState, Store


def make_record(project: Path, name: str, sid: str) -> SandboxRecord:
    return SandboxRecord(
        project_path=project,
        name=name,
        config_path=project / ".sandbox" / "config.json",
        synthetic_sid=sid,
        state=SandboxState.created,
        created_at=datetime.now(),
        pids=[],
        job_handle=None,
    )


# ── `sbx create` defaults to the project's own config ────────


def test_create_defaults_to_the_conventional_config_path():
    """The spec documents `sbx create [--name alias]` with no path, and
    every sibling command defaults its path argument."""
    with mock.patch.object(Engine, "create") as created:
        created.return_value = mock.Mock(name="sb", synthetic_sid="S-1-42-1")
        result = CliRunner().invoke(main, ["create"])

    assert result.exit_code == 0, result.output
    assert created.call_args.args[0] == ".sandbox/config.json"


def test_create_still_accepts_an_explicit_path():
    with mock.patch.object(Engine, "create") as created:
        created.return_value = mock.Mock(name="sb", synthetic_sid="S-1-42-1")
        result = CliRunner().invoke(main, ["create", "other/config.json"])

    assert result.exit_code == 0, result.output
    assert created.call_args.args[0] == "other/config.json"


# ── synthetic SID collisions are checked for ─────────────────


@pytest.fixture
def engine(tmp_path):
    engine = Engine()
    engine.store = Store(tmp_path / "sandboxes.json")
    return engine


def test_a_fresh_sid_is_used_as_is(engine, tmp_path):
    with mock.patch("sbx.engine.generate_sid", side_effect=["S-1-42-new"]):
        assert engine._unused_sid() == "S-1-42-new"


def test_a_colliding_sid_is_regenerated(engine, tmp_path, caplog):
    engine.store.add(make_record(tmp_path / "a", "a", "S-1-42-taken"))

    with caplog.at_level(logging.WARNING, logger="sbx.engine"):
        with mock.patch(
            "sbx.engine.generate_sid",
            side_effect=["S-1-42-taken", "S-1-42-free"],
        ):
            assert engine._unused_sid() == "S-1-42-free"

    assert any("collision" in r.message for r in caplog.records)


def test_giving_up_rather_than_reusing_a_sid(engine, tmp_path):
    """Reusing one would silently give two sandboxes each other's files —
    the opposite of what the SID is for."""
    engine.store.add(make_record(tmp_path / "a", "a", "S-1-42-taken"))

    with mock.patch("sbx.engine.generate_sid", return_value="S-1-42-taken"):
        with pytest.raises(SandboxError, match="unused synthetic SID"):
            engine._unused_sid(attempts=3)
