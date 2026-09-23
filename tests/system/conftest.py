"""System-test harness: opt-in gate, de-elevation, preconditions, and the
session-wide installed world. See README.md."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import pytest

import hostwin
from probes import SHELLS
from syshelp import SBX_HOME, sbx, sbx_list, write_config

HERE = Path(__file__).resolve().parent
OPT_IN = "SBX_SYSTEM_TESTS"
RELAUNCHED = "SBX_SYSTEM_RELAUNCHED"

CHANGES = """\
The system tests change this machine. They are meant for a disposable VM.
They:
  - create and delete the local account sbx-user (via sbx install / uninstall)
  - add and remove Windows Firewall rules scoped to sbx-user
  - create bind links under C:\\Users\\sbx-user
  - edit ACLs on fixture directories under %TEMP% and your home directory
  - wipe any existing sbx state at session start (sbx uninstall, delete %LOCALAPPDATA%\\sbx)
  - uninstall sbx at session end
Set SBX_SYSTEM_TESTS=1 to acknowledge and run them."""


def _is_system(item: pytest.Item) -> bool:
    return HERE in Path(str(item.fspath)).resolve().parents


def _number(item: pytest.Item) -> int:
    m = re.match(r"test_(\d+)_", item.name)
    n = int(m.group(1)) if m else 0
    return 10_000 if n == 80 else n  # uninstall runs last



def pytest_collection_modifyitems(session, config, items) -> None:
    slots = [i for i, it in enumerate(items) if _is_system(it)]
    if not slots:
        return
    system = sorted((items[i] for i in slots), key=_number)
    for i, it in zip(slots, system):
        items[i] = it
        it.add_marker(pytest.mark.system)

    if os.environ.get(OPT_IN) != "1":
        skip = pytest.mark.skip(reason=f"{OPT_IN} not set to 1.\n{CHANGES}")
        for it in system:
            it.add_marker(skip)
        return

    if hostwin.current_elevated() and not os.environ.get(RELAUNCHED):
        pytest.exit("relaunched unprivileged", returncode=_relaunch_unprivileged(config))


def _relaunch_unprivileged(config: pytest.Config) -> int:
    """Rerun this pytest invocation through a one-shot LIMITED scheduled task
    as the logged-on user; relay its output; return its exit code."""
    work = Path(tempfile.mkdtemp(prefix="sbxsys-relaunch-"))
    out, rc = work / "out.txt", work / "rc.txt"
    args = " ".join(f'"{a}"' for a in config.invocation_params.args)
    wrapper = work / "run.cmd"
    wrapper.write_text(
        "@echo off\r\n"
        f'cd /d "{config.invocation_params.dir}"\r\n'
        f"set {OPT_IN}=1\r\n"
        f"set {RELAUNCHED}=1\r\n"
        f'"{sys.executable}" -m pytest {args} > "{out}" 2>&1\r\n'
        f'> "{rc}" echo %ERRORLEVEL%\r\n',  # `echo 0>` would redirect fd 0
        encoding="utf-8",
    )
    task = f"sbxsys-relaunch-{uuid.uuid4().hex[:8]}"
    tw = config.get_terminal_writer()
    tw.line(f"elevated — relaunching unprivileged via scheduled task {task}")
    try:
        subprocess.run(
            ["schtasks", "/create", "/tn", task, "/tr", f'"{wrapper}"',
             "/sc", "once", "/st", "00:00", "/rl", "LIMITED", "/it", "/f"],
            check=True, capture_output=True,
        )
        subprocess.run(["schtasks", "/run", "/tn", task], check=True, capture_output=True)
        pos = 0
        while True:
            done = rc.exists() and rc.read_text().strip()
            if out.exists():
                with out.open("rb") as f:
                    f.seek(pos)
                    chunk = f.read()
                pos += len(chunk)
                if chunk:
                    sys.stdout.write(chunk.decode("utf-8", "replace"))
                    sys.stdout.flush()
            if done:
                return int(rc.read_text().strip())
            time.sleep(0.5)
    finally:
        subprocess.run(["schtasks", "/delete", "/tn", task, "/f"], capture_output=True)
        shutil.rmtree(work, ignore_errors=True)


def _check_preconditions() -> None:
    problems = []
    if hostwin.uac_value("EnableLUA") != 1:
        problems.append("EnableLUA must be 1 — run tests/system/setup_vm.py elevated, then reboot")
    if hostwin.uac_value("ConsentPromptBehaviorAdmin") != 0:
        problems.append("ConsentPromptBehaviorAdmin must be 0 — run tests/system/setup_vm.py elevated")
    if not hostwin.in_administrators():
        problems.append("current user must be in Administrators — add it and log on again")
    if hostwin.current_elevated():
        problems.append("suite is still elevated after relaunch — run it from an unprivileged shell")
    if problems:
        pytest.exit("system-test preconditions failed:\n  " + "\n  ".join(problems), returncode=3)


@dataclass
class Project:
    path: Path
    token: str

    @property
    def name(self) -> str:
        return self.path.name

    @property
    def secret(self) -> Path:
        return self.path / "secret.txt"

    @property
    def config(self) -> Path:
        return self.path / ".sandbox" / "config.json"


@dataclass
class World:
    root: Path
    a: Project
    b: Project
    host_secret: Path
    host_token: str
    cfg_file: Path
    cfg_token: str
    sibling: Path
    sibling_token: str
    shared: Path
    installed: bool = False
    notes: dict = field(default_factory=dict)

    def project(self, name: str) -> Project:
        path = self.root / name
        path.mkdir(exist_ok=True)
        token = f"TOKEN-{name}-{uuid.uuid4().hex[:8]}"
        (path / "secret.txt").write_text(token + "\n", encoding="utf-8")
        return Project(path, token)


def _token(label: str) -> str:
    return f"TOKEN-{label}-{uuid.uuid4().hex[:8]}"


def _wipe() -> None:
    sbx("uninstall", timeout=300)
    shutil.rmtree(SBX_HOME, ignore_errors=True)


@pytest.fixture(scope="session", autouse=True)
def world(request) -> World:
    _check_preconditions()
    reporter = request.config.pluginmanager.get_plugin("terminalreporter")
    for line in ("", "=" * 70, *CHANGES.splitlines()[:-1], "=" * 70):
        reporter.write_line(line)

    _wipe()

    home = Path.home()
    # Not mkdtemp: its DACL grants OWNER RIGHTS, so files the sandbox
    # (as sbx-user) creates there would be unreadable to the host.
    root = Path(tempfile.gettempdir()) / f"sbxsys-run-{uuid.uuid4().hex[:8]}"
    root.mkdir()
    w = World(
        root=root,
        a=None, b=None,  # type: ignore[arg-type]
        host_secret=home / "sbxsys-host-secret.txt", host_token=_token("host"),
        cfg_file=home / "sbxsys-cfg.json", cfg_token=_token("cfg"),
        sibling=home / "sbxsys-cfg-sibling.txt", sibling_token=_token("sibling"),
        shared=root / "sbxsys-shared",
    )
    w.a, w.b = w.project("sbxsys-a"), w.project("sbxsys-b")
    w.host_secret.write_text(w.host_token + "\n", encoding="utf-8")
    w.cfg_file.write_text(f'{{"token": "{w.cfg_token}"}}\n', encoding="utf-8")
    w.sibling.write_text(w.sibling_token + "\n", encoding="utf-8")
    w.shared.mkdir()

    yield w

    sbx("uninstall", timeout=300)
    shutil.rmtree(root, ignore_errors=True)
    for f in (w.host_secret, w.cfg_file, w.sibling):
        f.unlink(missing_ok=True)


@pytest.fixture(scope="session")
def installed(world: World) -> World:
    """sbx is installed (by test 74, or here if that didn't run)."""
    if not world.installed:
        sbx("install", check=True, timeout=300)
        world.installed = True
    return world


def _recreate(project: Project, mounts: list[dict], network: str) -> None:
    if project.name in sbx_list():
        sbx("destroy", str(project.path), check=True)
    write_config(project.path, mounts, "cmd", network)
    sbx("create", str(project.config), check=True)


@pytest.fixture(scope="session")
def pair(installed: World) -> World:
    """sbxsys-a (network none, plus a single-file mount) and sbxsys-b
    (claude-api-only), both freshly created."""
    w = installed
    _recreate(w.a, [
        {"source": ".", "target": "repo"},
        {"source": "~/sbxsys-cfg.json", "target": "config/tool.json"},
    ], "none")
    _recreate(w.b, [{"source": ".", "target": "repo"}], "claude-api-only")
    return w


@pytest.fixture(params=SHELLS, ids=lambda s: s.name)
def shell(request):
    if not request.param.installed():
        pytest.skip(f"shell not installed: {request.param.name}")
    return request.param


_VIA_TESTS = re.compile(r"test_(8[1-9]|9[0-8])_")  # test 107: 81-96 and 98 again, typed


def pytest_generate_tests(metafunc) -> None:
    if "via" in metafunc.fixturenames and _VIA_TESTS.match(metafunc.function.__name__):
        metafunc.parametrize("via", ["piped", "console"], indirect=True)


@pytest.fixture(autouse=True)
def via(request):
    """How this test's sessions reach the sandbox: piped stdin, or typed
    into a hosted cmd (test 107). Tests outside 81-98 always pipe."""
    import syshelp

    syshelp.VIA = getattr(request, "param", "piped")
    yield syshelp.VIA
    syshelp.VIA = "piped"
