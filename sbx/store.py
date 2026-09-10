from __future__ import annotations

import enum
import json
import logging
import msvcrt
import os
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from sbx.errors import StoreError

log = logging.getLogger(__name__)


class SandboxState(enum.Enum):
    created = "created"
    running = "running"
    stopped = "stopped"


@dataclass
class SandboxRecord:
    project_path: Path
    name: str
    state: SandboxState
    synthetic_sid: str
    config_path: Path
    pids: list[int]
    job_handle: int | None
    created_at: datetime


def _default_store_path() -> Path:
    return Path(os.environ.get("LOCALAPPDATA", "")) / "sbx" / "sandboxes.json"


def _serialize(rec: SandboxRecord) -> dict:
    return {
        "project_path": str(rec.project_path),
        "name": rec.name,
        "state": rec.state.value,
        "synthetic_sid": rec.synthetic_sid,
        "config_path": str(rec.config_path),
        "pids": rec.pids,
        "job_handle": rec.job_handle,
        "created_at": rec.created_at.isoformat(),
    }


def _deserialize(d: dict) -> SandboxRecord:
    return SandboxRecord(
        project_path=Path(d["project_path"]),
        name=d["name"],
        state=SandboxState(d["state"]),
        synthetic_sid=d["synthetic_sid"],
        config_path=Path(d["config_path"]),
        pids=d.get("pids", []),
        job_handle=d.get("job_handle"),
        created_at=datetime.fromisoformat(d["created_at"]),
    )


def _serialize_value(v):
    if isinstance(v, Path):
        return str(v)
    if isinstance(v, SandboxState):
        return v.value
    if isinstance(v, datetime):
        return v.isoformat()
    return v


class Store:
    def __init__(self, path: Path | None = None):
        self._path = path or _default_store_path()

    def get(self, project_path: Path) -> SandboxRecord | None:
        data = self._read_all()
        key = str(project_path)
        if key not in data:
            return None
        return _deserialize(data[key])

    def get_by_name(self, name: str) -> SandboxRecord | None:
        for rec in self._read_all().values():
            if rec["name"] == name:
                return _deserialize(rec)
        return None

    def list(self) -> list[SandboxRecord]:
        return [_deserialize(rec) for rec in self._read_all().values()]

    def add(self, record: SandboxRecord) -> None:
        def _add(data: dict) -> None:
            key = str(record.project_path)
            if key in data:
                raise StoreError(f"sandbox already exists for {key}")
            for rec in data.values():
                if rec["name"] == record.name:
                    raise StoreError(
                        f"sandbox name '{record.name}' already exists"
                    )
            data[key] = _serialize(record)

        self._mutate(_add)

    def update(self, project_path: Path, **fields) -> None:
        def _update(data: dict) -> None:
            key = str(project_path)
            if key not in data:
                raise StoreError(f"no sandbox found for {key}")
            for k, v in fields.items():
                data[key][k] = _serialize_value(v)

        self._mutate(_update)

    def remove(self, project_path: Path) -> None:
        def _remove(data: dict) -> None:
            key = str(project_path)
            if key not in data:
                raise StoreError(f"no sandbox found for {key}")
            del data[key]

        self._mutate(_remove)

    def _read_all(self) -> dict:
        if not self._path.exists():
            return {}
        try:
            return json.loads(self._path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}

    @contextmanager
    def _locked(self):
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(
            str(self._path), os.O_RDWR | os.O_CREAT | os.O_BINARY, 0o644
        )
        try:
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        except (IOError, OSError):
            os.close(fd)
            raise StoreError("store is locked by another process")
        try:
            yield fd
        finally:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            os.close(fd)

    def _mutate(self, fn):
        with self._locked() as fd:
            os.lseek(fd, 0, os.SEEK_SET)
            raw = os.read(fd, 1024 * 1024)
            data = json.loads(raw.decode("utf-8")) if raw.strip() else {}
            fn(data)
            out = json.dumps(data, indent=2).encode("utf-8")
            os.lseek(fd, 0, os.SEEK_SET)
            os.write(fd, out)
            os.ftruncate(fd, len(out))
