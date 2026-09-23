from __future__ import annotations

import logging
import shutil
from datetime import datetime
from pathlib import Path

from sbx.config import (
    CONFIG_DIR,
    CONFIG_FILE,
    Mount,
    NetworkPreset,
    SandboxConfig,
    ShellKind,
    load_config,
    scaffold_config,
)
from sbx.elevation import run_elevated
from sbx.errors import SandboxError
from sbx.identity import generate_sid
from sbx.mounts import MountSpec
from sbx.process import SHELL_EXECUTABLES, StartHandle, resolve_shell
from sbx.store import SandboxRecord, SandboxState, Store

log = logging.getLogger(__name__)


class Engine:
    def __init__(self, store: Store | None = None) -> None:
        self.store = store or Store()
        self._handles: dict[str, StartHandle] = {}

    def install(self) -> dict:
        run_elevated("install")
        warnings = []
        for kind in ShellKind:
            path = SHELL_EXECUTABLES.get(kind)
            if path and not Path(path).is_file():
                found = shutil.which(path)
                if not found:
                    warnings.append(f"shell not found: {kind.value} ({path})")
        if warnings:
            for w in warnings:
                log.warning(w)
        return {"warnings": warnings}

    def init(self, project_path: str | Path) -> Path:
        return scaffold_config(Path(project_path))

    def create(
        self,
        project_path: str | Path = ".",
        config_path: str | Path | None = None,
        name: str | None = None,
    ) -> SandboxRecord:
        """Set up the sandbox for a project folder. The config defaults to
        <project>/.sandbox/config.json; `.` in its mounts is the folder."""
        project_path = Path(project_path).resolve()
        if project_path.is_file():
            raise SandboxError(
                f"{project_path} is a file — pass the project folder, "
                f"or the config file with --config"
            )
        if not project_path.is_dir():
            raise SandboxError(f"project folder not found: {project_path}")
        config_path = Path(
            config_path or project_path / CONFIG_DIR / CONFIG_FILE
        ).resolve()
        if not config_path.exists():
            raise SandboxError(f"config not found: {config_path}")

        cfg = load_config(config_path, project_root=project_path)

        if name is None:
            name = project_path.name

        existing = self.store.get_by_name(name)
        if existing is not None:
            raise SandboxError(f"sandbox name '{name}' already exists")

        sid = generate_sid()

        specs = [
            MountSpec(source=m.source, target=m.target, sandbox_sid=sid)
            for m in cfg.mounts
        ]
        run_elevated("create_mounts", {
            "sandbox_name": name,
            "specs": [
                {"source": str(s.source), "target": s.target, "sandbox_sid": s.sandbox_sid}
                for s in specs
            ],
        })

        record = SandboxRecord(
            project_path=project_path,
            name=name,
            state=SandboxState.created,
            synthetic_sid=sid,
            config_path=config_path,
            pids=[],
            job_handle=None,
            created_at=datetime.now(),
        )
        self.store.add(record)
        log.info("created sandbox %s (SID %s)", name, sid)
        return record

    def start(
        self, sandbox: str | Path, size: tuple[int, int] | None = None,
    ) -> StartHandle:
        """size: the host terminal's (cols, rows); None for the default."""
        from sbx.network import register_sandbox
        from sbx.process import start_sandbox

        record = self._resolve(sandbox)
        project_path = record.project_path

        cfg = load_config(record.config_path, project_root=record.project_path)
        shell_path = resolve_shell(cfg.shell)

        proxy_port = None
        if cfg.network != NetworkPreset.none:
            from sbx.network import ensure_proxy_running
            ctl = ensure_proxy_running()
            from sbx.proxy import read_pid_file
            info = read_pid_file()
            if info:
                proxy_port = info.get("proxy_port")

        handle = start_sandbox(
            sandbox_name=record.name,
            sandbox_sid=record.synthetic_sid,
            shell=shell_path,
            network_preset=cfg.network,
            proxy_port=proxy_port,
            **({"size": size} if size else {}),
        )

        if cfg.network != NetworkPreset.none:
            register_sandbox(handle.job_name, cfg.network)

        self.store.update(
            project_path,
            state=SandboxState.running,
            pids=[handle.runner_pid],
        )
        self._handles[record.name] = handle
        log.info("started sandbox %s", record.name)
        return handle

    def stop(self, sandbox: str | Path) -> None:
        from sbx.network import deregister_sandbox
        from sbx.process import _job_name, stop_sandbox

        record = self._resolve(sandbox)
        project_path = record.project_path

        if record.name in self._handles:
            self._handles[record.name].close()
            del self._handles[record.name]

        try:
            deregister_sandbox(_job_name(record.name))
        except Exception:
            pass

        try:
            stop_sandbox(record.name)
        except Exception as e:
            log.warning("stop_sandbox failed: %s", e)

        self.store.update(
            project_path,
            state=SandboxState.stopped,
            pids=[],
        )
        log.info("stopped sandbox %s", record.name)

    def session_ended(self, sandbox: str | Path) -> None:
        """Record that the shell of a started sandbox has exited."""
        from sbx.network import deregister_sandbox
        from sbx.process import _job_name

        try:
            record = self._resolve(sandbox)
        except SandboxError:
            return
        if record.state != SandboxState.running:
            return
        project_path = record.project_path
        self._handles.pop(record.name, None)
        try:
            deregister_sandbox(_job_name(record.name))
        except Exception as e:
            log.warning("deregister failed: %s", e)
        self.store.update(project_path, state=SandboxState.stopped, pids=[])

    def destroy(self, sandbox: str | Path) -> None:
        record = self._resolve(sandbox)
        project_path = record.project_path

        if record.state == SandboxState.running:
            self.stop(record.name)

        run_elevated("destroy_mounts", {"sandbox_name": record.name})
        self.store.remove(project_path)
        log.info("destroyed sandbox %s", record.name)

    def uninstall(self) -> None:
        for record in self.store.list():
            try:
                self.destroy(record.project_path)
            except Exception as e:
                log.warning("failed to destroy %s: %s", record.name, e)

        from sbx.network import stop_proxy
        stop_proxy()
        run_elevated("uninstall_cleanup")
        log.info("uninstalled sbx")

    def _resolve(self, sandbox: str | Path) -> SandboxRecord:
        """Find a sandbox by name, project path, or the project's config path."""
        record = self.store.get_by_name(str(sandbox))
        if record is not None:
            return record
        path = Path(sandbox).resolve()
        candidates = [path]
        if path.parent.name == CONFIG_DIR:
            candidates.append(path.parent.parent)
        for candidate in candidates:
            record = self.store.get(candidate)
            if record is not None:
                return record
        raise SandboxError(f"no sandbox named or at {sandbox}")

    def list(self) -> list[SandboxRecord]:
        return self.store.list()

    def status(self, sandbox: str | Path) -> dict:
        record = self._resolve(sandbox)
        project_path = record.project_path

        result = {
            "name": record.name,
            "state": record.state.value,
            "sid": record.synthetic_sid,
            "project_path": str(record.project_path),
            "config_path": str(record.config_path),
            "created_at": record.created_at.isoformat(),
        }
        if record.state == SandboxState.running:
            from sbx.process import sandbox_pids
            live = [p for p in sandbox_pids(record.name) if p not in record.pids]
            result["pids"] = record.pids + live
        return result
