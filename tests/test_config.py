import json
import pytest
from pathlib import Path

from sbx.config import (
    load_config,
    scaffold_config,
    ShellKind,
    NetworkPreset,
    SandboxConfig,
)
from sbx.errors import ConfigError


def test_scaffold_creates_parseable_config(tmp_path):
    config_path = scaffold_config(tmp_path)
    config = load_config(config_path)
    assert isinstance(config, SandboxConfig)
    assert len(config.mounts) > 0


def test_scaffold_creates_directory(tmp_path):
    scaffold_config(tmp_path)
    assert (tmp_path / ".sandbox").is_dir()


def test_scaffold_raises_if_config_exists(tmp_path):
    sandbox_dir = tmp_path / ".sandbox"
    sandbox_dir.mkdir()
    (sandbox_dir / "config.json").write_text("{}")
    with pytest.raises(ConfigError):
        scaffold_config(tmp_path)


def test_parse_full_config(tmp_path):
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    config_dir = tmp_path / ".sandbox"
    config_dir.mkdir()
    config_path = config_dir / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "mounts": [{"source": str(source_dir), "target": "code"}],
                "shell": "cmd",
                "network": "claude-api-only",
            }
        )
    )
    config = load_config(config_path)
    assert len(config.mounts) == 1
    assert config.mounts[0].source == source_dir.resolve()
    assert config.mounts[0].target == "code"
    assert config.shell == ShellKind.cmd
    assert config.network == NetworkPreset.claude_api_only
    with pytest.raises(AttributeError):
        config.shell = ShellKind.pwsh


def test_dot_resolves_to_project_root(tmp_path):
    config_dir = tmp_path / ".sandbox"
    config_dir.mkdir()
    config_path = config_dir / "config.json"
    config_path.write_text(
        json.dumps({"mounts": [{"source": ".", "target": "repo"}]})
    )
    config = load_config(config_path)
    assert config.mounts[0].source == tmp_path.resolve()


def test_tilde_resolves_to_home(tmp_path):
    config_dir = tmp_path / ".sandbox"
    config_dir.mkdir()
    config_path = config_dir / "config.json"
    config_path.write_text(
        json.dumps({"mounts": [{"source": "~", "target": "home"}]})
    )
    config = load_config(config_path)
    assert config.mounts[0].source == Path.home().resolve()


def test_defaults(tmp_path):
    config_dir = tmp_path / ".sandbox"
    config_dir.mkdir()
    config_path = config_dir / "config.json"
    config_path.write_text(
        json.dumps({"mounts": [{"source": ".", "target": "repo"}]})
    )
    config = load_config(config_path)
    assert config.shell == ShellKind.git_bash
    assert config.network == NetworkPreset.none


def test_duplicate_targets(tmp_path):
    config_dir = tmp_path / ".sandbox"
    config_dir.mkdir()
    config_path = config_dir / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "mounts": [
                    {"source": ".", "target": "repo"},
                    {"source": ".", "target": "repo"},
                ],
            }
        )
    )
    with pytest.raises(ConfigError, match="repo"):
        load_config(config_path)


def test_nonexistent_source(tmp_path):
    bad_path = tmp_path / "does_not_exist"
    config_dir = tmp_path / ".sandbox"
    config_dir.mkdir()
    config_path = config_dir / "config.json"
    config_path.write_text(
        json.dumps({"mounts": [{"source": str(bad_path), "target": "nope"}]})
    )
    with pytest.raises(ConfigError, match="does_not_exist"):
        load_config(config_path)


def test_invalid_json(tmp_path):
    config_dir = tmp_path / ".sandbox"
    config_dir.mkdir()
    config_path = config_dir / "config.json"
    config_path.write_text("not json {{{")
    with pytest.raises(ConfigError, match="(?i)json"):
        load_config(config_path)


def test_unknown_keys_ignored(tmp_path):
    config_dir = tmp_path / ".sandbox"
    config_dir.mkdir()
    config_path = config_dir / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "mounts": [{"source": ".", "target": "repo"}],
                "future_key": "future_value",
                "another": 42,
            }
        )
    )
    config = load_config(config_path)
    assert len(config.mounts) == 1
