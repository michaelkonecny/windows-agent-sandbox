from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path

from sbx import winapi
from sbx.errors import MountError

log = logging.getLogger(__name__)

SANDBOX_USER_HOME = Path("C:/Users/sbx-user")


@dataclass
class MountSpec:
    source: Path
    target: str
    sandbox_sid: str


def _workspace(
    sandbox_name: str, workspace_root: Path | None = None
) -> Path:
    return (workspace_root or SANDBOX_USER_HOME) / sandbox_name


def _meta_dir(meta_root: Path | None = None) -> Path:
    return meta_root or (
        Path(os.environ.get("LOCALAPPDATA", "")) / "sbx" / "mounts"
    )


def _meta_path(
    sandbox_name: str, meta_root: Path | None = None
) -> Path:
    return _meta_dir(meta_root) / f"{sandbox_name}.json"


def _save_meta(
    sandbox_name: str,
    specs: list[MountSpec],
    meta_root: Path | None = None,
) -> None:
    meta = _meta_path(sandbox_name, meta_root)
    meta.parent.mkdir(parents=True, exist_ok=True)
    meta.write_text(
        json.dumps(
            [
                {
                    "source": str(s.source),
                    "target": s.target,
                    "sandbox_sid": s.sandbox_sid,
                }
                for s in specs
            ]
        ),
        encoding="utf-8",
    )


def _load_meta(
    sandbox_name: str, meta_root: Path | None = None
) -> list[dict] | None:
    meta = _meta_path(sandbox_name, meta_root)
    if not meta.exists():
        return None
    return json.loads(meta.read_text(encoding="utf-8"))


def create(
    sandbox_name: str,
    specs: list[MountSpec],
    workspace_root: Path | None = None,
    meta_root: Path | None = None,
) -> None:
    ws = _workspace(sandbox_name, workspace_root)

    for spec in specs:
        target_path = ws / spec.target
        target_path.mkdir(parents=True, exist_ok=True)

        try:
            winapi.remove_bind_link(str(target_path))
        except OSError:
            pass

        try:
            winapi.create_bind_link(str(target_path), str(spec.source))
        except OSError as e:
            raise MountError(
                f"failed to create bind link {target_path} -> {spec.source}: {e}"
            )
        log.info("bind link %s -> %s", target_path, spec.source)

        sid_ptr = winapi.string_to_sid(spec.sandbox_sid)
        try:
            winapi.grant_sid_access(str(spec.source), sid_ptr)
        except OSError as e:
            winapi.remove_bind_link(str(target_path))
            raise MountError(
                f"failed to set ACL on {spec.source}: {e}"
            )
        finally:
            winapi.kernel32.LocalFree(sid_ptr)
        log.info("granted SID %s access to %s", spec.sandbox_sid, spec.source)

    _save_meta(sandbox_name, specs, meta_root)


def destroy(
    sandbox_name: str,
    workspace_root: Path | None = None,
    meta_root: Path | None = None,
) -> None:
    info = _load_meta(sandbox_name, meta_root)
    ws = _workspace(sandbox_name, workspace_root)

    if info:
        for entry in info:
            target_path = ws / entry["target"]
            try:
                winapi.remove_bind_link(str(target_path))
            except OSError as e:
                log.warning("failed to remove bind link %s: %s", target_path, e)

            sid_ptr = winapi.string_to_sid(entry["sandbox_sid"])
            try:
                winapi.remove_sid_access(str(entry["source"]), sid_ptr)
            except OSError as e:
                log.warning(
                    "failed to remove ACL from %s: %s", entry["source"], e
                )
            finally:
                winapi.kernel32.LocalFree(sid_ptr)

    if ws.exists():
        try:
            _rmtree(ws)
        except OSError as e:
            log.warning("failed to remove workspace %s: %s", ws, e)

    meta = _meta_path(sandbox_name, meta_root)
    if meta.exists():
        meta.unlink()


def verify(
    sandbox_name: str,
    workspace_root: Path | None = None,
    meta_root: Path | None = None,
) -> list[str]:
    info = _load_meta(sandbox_name, meta_root)
    if not info:
        return ["no mount metadata found"]

    issues: list[str] = []
    ws = _workspace(sandbox_name, workspace_root)
    for entry in info:
        target_path = ws / entry["target"]
        if not target_path.exists():
            issues.append(f"bind link missing: {target_path}")
    return issues


def _rmtree(path: Path) -> None:
    import shutil
    shutil.rmtree(path, ignore_errors=True)
