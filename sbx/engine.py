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
        run_elevated("install_user")
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
        config_path: str | Path,
        name: str | None = None,
    ) -> SandboxRecord:
        config_path = Path(config_path).resolve()
        if not config_path.exists():
            raise SandboxError(f"config not found: {config_path}")

        cfg = load_config(config_path)
        project_path = config_path.parent.parent

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

    def start(self, project_path: str | Path) -> StartHandle:
        from sbx.network import register_sandbox
        from sbx.process import start_sandbox

        project_path = Path(project_path).resolve()
        record = self.store.get(project_path)
        if record is None:
            raise SandboxError(f"no sandbox for {project_path}")

        cfg = load_config(record.config_path)
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

    def stop(self, project_path: str | Path) -> None:
        from sbx.network import deregister_sandbox
        from sbx.process import stop_sandbox

        project_path = Path(project_path).resolve()
        record = self.store.get(project_path)
        if record is None:
            raise SandboxError(f"no sandbox for {project_path}")

        if record.name in self._handles:
            self._handles[record.name].close()
            del self._handles[record.name]

        try:
            deregister_sandbox(record.name)
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

    def destroy(self, project_path: str | Path) -> None:
        project_path = Path(project_path).resolve()
        record = self.store.get(project_path)
        if record is None:
            raise SandboxError(f"no sandbox for {project_path}")

        if record.state == SandboxState.running:
            self.stop(project_path)

        run_elevated("destroy_mounts", {"sandbox_name": record.name})
        self.store.remove(project_path)
        log.info("destroyed sandbox %s", record.name)

    def uninstall(self) -> None:
        for record in self.store.list():
            try:
                self.destroy(record.project_path)
            except Exception as e:
                log.warning("failed to destroy %s: %s", record.name, e)

        run_elevated("uninstall_cleanup")
        log.info("uninstalled sbx")

    def list(self) -> list[SandboxRecord]:
        return self.store.list()

    def status(self, project_path: str | Path) -> dict:
        project_path = Path(project_path).resolve()
        record = self.store.get(project_path)
        if record is None:
            raise SandboxError(f"no sandbox for {project_path}")

        result = {
            "name": record.name,
            "state": record.state.value,
            "sid": record.synthetic_sid,
            "project_path": str(record.project_path),
            "config_path": str(record.config_path),
            "created_at": record.created_at.isoformat(),
        }
        if record.state == SandboxState.running:
            result["pids"] = record.pids
        return result
