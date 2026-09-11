"""The registry is the only record of what exists.

Everything destroy and uninstall clean up — bind links, ACLs, the
workspace — is found through it, so quietly reporting an empty store is
worse than failing: the sandboxes stay on disk and nothing knows to
remove them.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest

from sbx.errors import StoreError
from sbx.store import SandboxRecord, SandboxState, Store


@pytest.fixture
def store_path(tmp_path):
    return tmp_path / "sandboxes.json"


@pytest.fixture
def store(store_path):
    return Store(store_path)


def a_record(project: Path, name: str = "demo") -> SandboxRecord:
    return SandboxRecord(
        project_path=project,
        name=name,
        config_path=project / ".sandbox" / "config.json",
        synthetic_sid="S-1-42-1-2-3-4",
        state=SandboxState.created,
        created_at=datetime.now(),
        pids=[],
        job_handle=None,
    )


def test_a_missing_file_is_an_empty_store(store):
    assert store.list() == []


def test_an_empty_file_is_an_empty_store(store, store_path):
    """`_locked` creates the file before anything is written, so zero
    bytes is a legitimate state rather than damage."""
    store_path.write_text("", encoding="utf-8")
    assert store.list() == []


def test_whitespace_only_is_an_empty_store(store, store_path):
    store_path.write_text("   \n", encoding="utf-8")
    assert store.list() == []


def test_a_corrupt_registry_is_reported_not_silently_emptied(
    store, store_path
):
    """Returning {} here would tell the caller there are no sandboxes,
    and `create` would then happily reuse a name that is still in use."""
    store_path.write_text('{"broken": ', encoding="utf-8")

    with pytest.raises(StoreError, match="unreadable"):
        store.list()


def test_a_corrupt_registry_is_reported_on_lookup_too(store, store_path):
    store_path.write_text("not json at all", encoding="utf-8")

    with pytest.raises(StoreError):
        store.get(Path(r"C:\anywhere"))


def test_a_corrupt_registry_blocks_mutation(store, store_path, tmp_path):
    """Adding to a store we cannot read would overwrite whatever was
    there."""
    store_path.write_text("{{{", encoding="utf-8")

    with pytest.raises(StoreError):
        store.add(a_record(tmp_path / "project"))


def test_round_trip_through_the_file(store, tmp_path):
    project = tmp_path / "project"
    store.add(a_record(project))

    reloaded = Store(store._path)
    found = reloaded.get(project)
    assert found is not None
    assert found.name == "demo"
    assert found.state == SandboxState.created


def test_a_half_written_file_is_never_seen_as_empty(store, store_path, tmp_path):
    """A reader that catches a write in progress must not conclude the
    store is empty — it would report every sandbox as gone."""
    store.add(a_record(tmp_path / "project"))
    whole = store_path.read_text(encoding="utf-8")

    # Every prefix of a real store file: either readable, or an error.
    for cut in range(1, len(whole)):
        store_path.write_text(whole[:cut], encoding="utf-8")
        try:
            records = store.list()
        except StoreError:
            continue
        if records:
            continue
        assert whole[:cut].strip() == "", (
            f"a {cut}-byte prefix parsed as an empty store"
        )
