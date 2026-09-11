from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path

from sbx import winapi
from sbx.errors import MountError
from sbx.identity import SANDBOX_USER

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
    user_sid: str | None = None,
) -> None:
    ws = _workspace(sandbox_name, workspace_root)
    sandbox_user_sid = _sandbox_user_sid(user_sid)

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

        # Two ACEs, because a fully restricted token is checked twice and
        # has to pass both: the sandbox user satisfies the ordinary check,
        # the per-sandbox synthetic SID satisfies the restricted one.
        # Granting only the synthetic SID leaves the backing path
        # unreachable; granting only sbx-user would drop the isolation
        # between sandboxes, since they all run as that one account.
        for sid_string in (spec.sandbox_sid, sandbox_user_sid):
            sid_ptr = winapi.string_to_sid(sid_string)
            try:
                winapi.grant_sid_access(str(spec.source), sid_ptr)
            except OSError as e:
                winapi.remove_bind_link(str(target_path))
                raise MountError(f"failed to set ACL on {spec.source}: {e}")
            finally:
                winapi.kernel32.LocalFree(sid_ptr)
            log.info("granted SID %s access to %s", sid_string, spec.source)

    _save_meta(sandbox_name, specs, meta_root)


def destroy(
    sandbox_name: str,
    workspace_root: Path | None = None,
    meta_root: Path | None = None,
    user_sid: str | None = None,
) -> None:
    info = _load_meta(sandbox_name, meta_root)
    ws = _workspace(sandbox_name, workspace_root)

    if info:
        still_in_use = _sources_used_by_others(sandbox_name, meta_root)
        # Resolved once, and tolerantly: the account may already be gone
        # (an uninstall, or a half-finished one), and teardown has to
        # finish regardless — otherwise bind links and the metadata file
        # outlive the sandbox.
        try:
            shared_sid = _sandbox_user_sid(user_sid)
        except OSError as e:
            log.warning("cannot resolve %s, leaving its ACEs: %s",
                        SANDBOX_USER, e)
            shared_sid = None

        for entry in info:
            target_path = ws / entry["target"]
            try:
                winapi.remove_bind_link(str(target_path))
            except OSError as e:
                log.warning("failed to remove bind link %s: %s", target_path, e)

            revoke = [entry["sandbox_sid"]]
            if _normalise(entry["source"]) not in still_in_use:
                if shared_sid:
                    revoke.append(shared_sid)
            else:
                log.info(
                    "keeping %s access to %s — another sandbox mounts it",
                    SANDBOX_USER, entry["source"],
                )

            for sid_string in revoke:
                sid_ptr = winapi.string_to_sid(sid_string)
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


def _sandbox_user_sid(user_sid: str | None = None) -> str:
    """The SID that satisfies the ordinary access check on a backing path.

    Resolved from the account name unless a caller supplies one, which
    keeps mount handling testable without depending on the machine
    actually having the account.
    """
    return user_sid or winapi.lookup_account_sid(SANDBOX_USER)


def _normalise(source: str) -> str:
    """A comparable spelling of a backing path.

    Windows paths are case-insensitive and admit several spellings of the
    same directory. Comparing them raw would miss a match and revoke the
    shared ACE out from under another sandbox, which would silently cost
    it access to its own mount.
    """
    return os.path.normcase(os.path.abspath(source))


def _sources_used_by_others(
    sandbox_name: str, meta_root: Path | None = None
) -> set[str]:
    """Backing paths still mounted by some other sandbox.

    The sandbox user's ACE is shared, so it can only be revoked once no
    other sandbox is relying on it.
    """
    sources: set[str] = set()
    meta_dir = _meta_dir(meta_root)
    if not meta_dir.exists():
        return sources

    for meta in meta_dir.glob("*.json"):
        if meta.stem == sandbox_name:
            continue
        try:
            entries = json.loads(meta.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        sources.update(_normalise(entry["source"]) for entry in entries)
    return sources


def _rmtree(path: Path) -> None:
    import shutil
    shutil.rmtree(path, ignore_errors=True)
