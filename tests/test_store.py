import msvcrt
import os
import pytest
from datetime import datetime, timezone
from pathlib import Path

from sbx.store import Store, SandboxRecord, SandboxState
from sbx.errors import StoreError


def _make_record(project_path=None, name="test-sandbox", **kwargs):
    defaults = dict(
        project_path=project_path or Path("C:/test/project"),
        name=name,
        state=SandboxState.created,
        synthetic_sid="S-1-0-42-1-2-3-4",
        config_path=Path("C:/test/project/.sandbox/config.json"),
        pids=[],
        job_handle=None,
        created_at=datetime.now(timezone.utc),
    )
    defaults.update(kwargs)
    return SandboxRecord(**defaults)


def test_add_and_get(store):
    rec = _make_record()
    store.add(rec)
    got = store.get(rec.project_path)
    assert got is not None
    assert got.name == rec.name
    assert got.synthetic_sid == rec.synthetic_sid


def test_get_by_name(store):
    rec = _make_record(name="my-sandbox")
    store.add(rec)
    got = store.get_by_name("my-sandbox")
    assert got is not None
    assert got.project_path == rec.project_path


def test_duplicate_name_rejected(store):
    store.add(_make_record(project_path=Path("C:/a"), name="dupe"))
    with pytest.raises(StoreError, match="dupe"):
        store.add(_make_record(project_path=Path("C:/b"), name="dupe"))


def test_list(store):
    assert store.list() == []
    store.add(_make_record(project_path=Path("C:/a"), name="a"))
    store.add(_make_record(project_path=Path("C:/b"), name="b"))
    assert len(store.list()) == 2


def test_update(store):
    rec = _make_record()
    store.add(rec)
    store.update(rec.project_path, state=SandboxState.running, pids=[1234])
    got = store.get(rec.project_path)
    assert got.state == SandboxState.running
    assert got.pids == [1234]


def test_remove(store):
    rec = _make_record()
    store.add(rec)
    store.remove(rec.project_path)
    assert store.get(rec.project_path) is None


def test_concurrent_lock(store, store_path):
    store_path.parent.mkdir(parents=True, exist_ok=True)
    store_path.write_text("{}")

    fd = os.open(str(store_path), os.O_RDWR | os.O_BINARY)
    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
    try:
        with pytest.raises(StoreError, match="locked"):
            store.add(_make_record())
    finally:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        os.close(fd)
