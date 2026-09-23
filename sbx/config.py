from __future__ import annotations

import enum
import json
import logging
from dataclasses import dataclass
from pathlib import Path

from sbx.errors import ConfigError

log = logging.getLogger(__name__)

CONFIG_DIR = ".sandbox"
CONFIG_FILE = "config.json"


class ShellKind(enum.Enum):
    git_bash = "git-bash"
    cmd = "cmd"
    powershell = "powershell"
    pwsh = "pwsh"


class NetworkPreset(enum.Enum):
    none = "none"
    claude_api_only = "claude-api-only"
    all = "all"


@dataclass(frozen=True)
class Mount:
    source: Path
    target: str


@dataclass(frozen=True)
class SandboxConfig:
    mounts: tuple[Mount, ...]
    shell: ShellKind
    network: NetworkPreset


_DEFAULT_CONFIG = {
    "mounts": [{"source": ".", "target": "repo"}],
    "shell": "git-bash",
    "network": "none",
}


def scaffold_config(project_path: Path) -> Path:
    project_path = Path(project_path)
    config_dir = project_path / CONFIG_DIR
    config_file = config_dir / CONFIG_FILE

    if config_file.exists():
        raise ConfigError(f"config already exists: {config_file}")

    config_dir.mkdir(parents=True, exist_ok=True)
    config_file.write_text(
        json.dumps(_DEFAULT_CONFIG, indent=2), encoding="utf-8"
    )
    log.info("created %s", config_file)
    return config_file


def load_config(config_path: Path, project_root: Path | None = None) -> SandboxConfig:
    """`.` in mount sources resolves to project_root — by default the
    config's grandparent (<project>/.sandbox/config.json)."""
    config_path = Path(config_path).resolve()
    project_root = Path(project_root).resolve() if project_root else config_path.parent.parent

    try:
        raw = config_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise ConfigError(f"config file not found: {config_path}")

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ConfigError(
            f"invalid JSON in {config_path.name}: {e.msg} "
            f"(line {e.lineno}, column {e.colno})"
        )

    mounts = _parse_mounts(data.get("mounts", []), project_root)
    shell = _parse_shell(data.get("shell"))
    network = _parse_network(data.get("network"))

    return SandboxConfig(mounts=tuple(mounts), shell=shell, network=network)


def _parse_mounts(
    raw_mounts: list[dict], project_root: Path
) -> list[Mount]:
    mounts: list[Mount] = []
    targets_seen: set[str] = set()

    for entry in raw_mounts:
        source_str = entry.get("source", "")
        target = entry.get("target", "")

        if source_str.startswith("~"):
            source_path = Path(source_str).expanduser().resolve()
        elif not Path(source_str).is_absolute():
            source_path = (project_root / source_str).resolve()
        else:
            source_path = Path(source_str).resolve()

        if not source_path.exists():
            raise ConfigError(f"mount source does not exist: {source_path}")

        if target in targets_seen:
            raise ConfigError(f"duplicate mount target: {target}")
        targets_seen.add(target)

        mounts.append(Mount(source=source_path, target=target))

    return mounts


def _parse_shell(raw: str | None) -> ShellKind:
    if raw is None:
        return ShellKind.git_bash
    try:
        return ShellKind(raw)
    except ValueError:
        raise ConfigError(f"unknown shell: {raw}")


def _parse_network(raw: str | None) -> NetworkPreset:
    if raw is None:
        return NetworkPreset.none
    try:
        return NetworkPreset(raw)
    except ValueError:
        raise ConfigError(f"unknown network preset: {raw}")
