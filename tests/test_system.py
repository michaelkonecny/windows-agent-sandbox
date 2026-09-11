"""System tests — the full stack, driven from outside.

A ConPtyShell stands in for the user's terminal: it launches the `sbx`
CLI inside a pseudoconsole, types at it, and asserts on what gets
rendered.  Nothing here reaches into the engine to do the work;
everything goes through the command line, so the CLI, the terminal relay
and the OS-level isolation are all exercised together.

Both the host and the sandbox run cmd, whose prompts are identical and
which repaint the screen as they go, so a bare "wait for a prompt" cannot
say which shell answered.  The sandbox's prompt is therefore renamed to
SBX> once it starts, leaving the ordinary drive-letter prompt to mean the
host.  Renaming the *host* prompt would not work: the sandbox shell
inherits the host process's environment, PROMPT included, so both shells
would end up looking the same again.

Scenarios come from specs/tests/system.md.  Groups whose prerequisites
fall outside this iteration are listed at the bottom of the file rather
than silently omitted.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import uuid
from pathlib import Path

import pytest

from conpty_harness import ConPtyShell
from sbx import winapi
from sbx.identity import SANDBOX_USER, _credentials_path, store_credentials
from sbx.process import stop_sandbox

pytestmark = pytest.mark.system

REPO_ROOT = Path(__file__).parent.parent

# git-bash under a restricted token is slow to reach its first prompt.
PROMPT_TIMEOUT = 25.0
STEP_TIMEOUT = 15.0

CMD_PROMPT = r"[A-Za-z]:\\[^\n]*>"  # an unrenamed cmd prompt: the host
SANDBOX_PROMPT = r"SBX>"
GIT_BASH = r"C:\Program Files\Git\bin\bash.exe"


def sbx(*args: str) -> str:
    """The CLI command line, run out of the repo so `-m sbx` resolves."""
    return f'"{sys.executable}" -m sbx ' + " ".join(args)


@pytest.fixture(scope="module")
def sandbox_user_ready():
    """Give sbx-user a known password and access to what it needs.

    Stores the credentials where the CLI looks for them, which is what
    `sbx install` would have done.  An existing install is left alone —
    overwriting its credentials would desynchronise them from the real
    account password.
    """
    if not winapi.is_elevated():
        pytest.skip("needs elevation to prepare the sandbox user")

    from sbx.elevation import run_elevated

    if _credentials_path().exists():
        return

    try:
        result = run_elevated("setup_test_env", {
            "grant_paths": [str(Path(sys.executable).parent), str(REPO_ROOT)],
        })
    except Exception as e:
        pytest.skip(f"cannot prepare the sandbox user: {e}")

    store_credentials(SANDBOX_USER, result["password"])


def make_project(shell: str = "cmd", network: str = "none") -> Path:
    project = Path(tempfile.gettempdir()) / f"sbx-sys-{uuid.uuid4().hex[:8]}"
    (project / ".sandbox").mkdir(parents=True)
    (project / "work").mkdir()
    (project / "work" / "from_host.txt").write_text("HOSTFILE_CONTENT")
    (project / ".sandbox" / "config.json").write_text(
        json.dumps({
            "mounts": [{"source": ".", "target": "repo"}],
            "shell": shell,
            "network": network,
        }, indent=2),
        encoding="utf-8",
    )
    return project


def create_sandbox(project: Path) -> None:
    from sbx.engine import Engine

    Engine().create(str(project / ".sandbox" / "config.json"))


def teardown_sandbox(project: Path) -> None:
    from sbx.engine import Engine

    stop_quietly(project.name)
    try:
        Engine().destroy(str(project))
    except Exception:
        pass
    shutil.rmtree(project, ignore_errors=True)


def stop_quietly(name: str) -> None:
    try:
        stop_sandbox(name)
    except Exception:
        pass  # already stopped


@pytest.fixture
def sandbox(sandbox_user_ready):
    """A created-but-not-started sandbox, torn down afterwards."""
    project = make_project()
    create_sandbox(project)
    try:
        yield project
    finally:
        teardown_sandbox(project)


def host_terminal(**kwargs) -> ConPtyShell:
    """A terminal sitting at the host prompt, `sbx start` not yet run."""
    term = ConPtyShell("cmd.exe", cwd=str(REPO_ROOT), **kwargs)
    term.start()
    term.expect(CMD_PROMPT, timeout=STEP_TIMEOUT)
    return term


def enter_sandbox(term: ConPtyShell, project: Path) -> None:
    """Run `sbx start` and wait until the sandbox shell is ready."""
    term.send_line(sbx("start", str(project)))
    term.expect(CMD_PROMPT, timeout=PROMPT_TIMEOUT)
    term.send_line("prompt SBX$G")
    term.expect(SANDBOX_PROMPT, timeout=STEP_TIMEOUT)


def sandbox_mount(project: Path) -> str:
    return rf"C:\Users\{SANDBOX_USER}\{project.name}\repo"


# ── Shell integration ────────────────────────────────────────


def test_shell_opens_and_runs_commands(sandbox):
    """The headline behaviour: `sbx start` drops the user into a working
    shell that is running as the sandbox user."""
    with host_terminal() as term:
        enter_sandbox(term, sandbox)
        # `whoami` cannot run once privileges are stripped, so the
        # username comes from the environment instead.
        term.send_line("echo USER=%username%")
        term.expect(r"USER=sbx-user", timeout=STEP_TIMEOUT)


def test_exit_returns_to_host_shell(sandbox):
    with host_terminal() as term:
        enter_sandbox(term, sandbox)
        term.send_line("exit")

        # Only the host still shows a drive-letter prompt, so this waits
        # for the host rather than for whichever shell repaints first.
        term.expect(CMD_PROMPT, timeout=PROMPT_TIMEOUT)
        term.send_line("echo AFTER=%username%")
        match = term.expect(r"AFTER=(\S+)", timeout=STEP_TIMEOUT)
        assert match.group(1).lower() != SANDBOX_USER


def test_stop_from_outside_ends_the_session(sandbox):
    """`sbx stop` from another process returns the terminal to the host."""
    with host_terminal() as term:
        enter_sandbox(term, sandbox)
        term.send_line("echo READY=%username%")
        term.expect(r"READY=sbx-user", timeout=STEP_TIMEOUT)

        stop_sandbox(sandbox.name)

        term.expect(CMD_PROMPT, timeout=PROMPT_TIMEOUT)
        term.send_line("echo AFTER=%username%")
        match = term.expect(r"AFTER=(\S+)", timeout=STEP_TIMEOUT)
        assert match.group(1).lower() != SANDBOX_USER


@pytest.mark.xfail(
    reason="ConPTY does not turn an 0x03 byte on its input pipe into a "
           "CTRL_C_EVENT for the attached client, so the running command "
           "is not interrupted. Reproduced with no sandbox involved: a "
           "bare ConPtyShell writing 0x03 leaves `ping -t` running. The "
           "spec's Ctrl+C edge case assumes otherwise; see specs/notes-2.md.",
    strict=True,
)
def test_ctrl_c_interrupts_the_sandbox_command(sandbox):
    with host_terminal() as term:
        enter_sandbox(term, sandbox)
        term.send_line("ping -t 127.0.0.1")
        term.expect(r"Reply from|Pinging", timeout=STEP_TIMEOUT)

        term.write("\x03")

        # ping stops, cmd prints a fresh prompt, and the shell lives on.
        term.expect(SANDBOX_PROMPT, timeout=STEP_TIMEOUT)
        term.send_line("echo STILL=%RANDOM%")
        term.expect(r"STILL=\d+", timeout=STEP_TIMEOUT)


def test_colour_and_screen_clearing_render(sandbox):
    """Proves the sandbox shell has a real console rather than a pipe:
    `cls` erases the screen and `color` emits real SGR attributes."""
    pytest.importorskip("pyte")
    with host_terminal(capture_screen=True) as term:
        enter_sandbox(term, sandbox)
        term.send_line("cls")
        term.send_line("color 0A")
        term.send_line("echo GREEN=%RANDOM%")
        term.expect(r"GREEN=\d+", timeout=STEP_TIMEOUT)

        screen = term.screen()
        rendered = "\n".join(screen.display)
        assert "GREEN=" in rendered
        # cls cleared what came before it, including the command that
        # started the sandbox — the byte stream still holds it.
        assert "-m sbx start" not in rendered
        assert "-m sbx start" in term.read_all()

        foregrounds = {
            char.fg for line in screen.buffer.values()
            for char in line.values() if char.data.strip()
        }
        # ConPTY emits colour as a truecolor SGR, so pyte reports a hex
        # value rather than a palette name.
        assert foregrounds & {"green", "00ff00"}, sorted(foregrounds)


def test_resize_propagates_into_the_sandbox(sandbox):
    with host_terminal(cols=120, rows=40) as term:
        enter_sandbox(term, sandbox)

        term.resize(90, 28)
        term.send_line("mode con")
        term.expect(r"Lines:\s+28", timeout=STEP_TIMEOUT)
        term.expect(r"Columns:\s+90", timeout=STEP_TIMEOUT)


@pytest.mark.skipif(
    not os.path.isfile(GIT_BASH), reason="git-bash not installed"
)
def test_git_bash_under_conpty(sandbox_user_ready):
    """git-bash is the default shell and the awkward one: Cygwin based, so
    it runs without restricted SIDs and needs a real console to start."""
    project = make_project(shell="git-bash")
    create_sandbox(project)
    try:
        with host_terminal() as term:
            term.send_line(sbx("start", str(project)))
            term.expect(r"\$", timeout=PROMPT_TIMEOUT)
            term.send_line("echo SHELL_IS=$0")
            term.expect(r"SHELL_IS=\S*bash", timeout=STEP_TIMEOUT)
    finally:
        teardown_sandbox(project)


# ── Filesystem isolation ─────────────────────────────────────


@pytest.mark.xfail(
    reason="setup_mounts grants only the per-sandbox synthetic SID on the "
           "backing path, never sbx-user. A fully restricted token has to "
           "pass both the user check and the restricted-SID check, so a "
           "project whose backing path does not already grant sbx-user "
           "(anything under the host user's profile, including %TEMP%) is "
           "unreadable through its own mount. Needs a decision on the "
           "filesystem mechanism; see specs/notes-2.md.",
    strict=True,
)
def test_mount_is_readable_and_writable(sandbox):
    """The project appears at its mount target inside the sandbox, and
    writes there land back on the host path."""
    with host_terminal() as term:
        enter_sandbox(term, sandbox)
        mount = sandbox_mount(sandbox)

        term.send_line(rf"type {mount}\work\from_host.txt")
        term.expect(r"HOSTFILE_CONTENT", timeout=STEP_TIMEOUT)

        term.send_line(rf"echo SANDBOX_WROTE_IT> {mount}\work\out.txt")
        term.send_line("echo WROTE=%RANDOM%")
        term.expect(r"WROTE=\d+", timeout=STEP_TIMEOUT)

    written = sandbox / "work" / "out.txt"
    assert written.exists(), "the sandbox write never reached the host path"
    assert "SANDBOX_WROTE_IT" in written.read_text()


def test_paths_outside_any_mount_are_denied(sandbox):
    """The sandbox user's own home is outside every mount, so the fully
    restricted token refuses it even though the account owns it.

    Weaker than it looks while the mount ACL bug above stands: right now
    reads are denied everywhere outside the system paths.  It regains its
    teeth once mounts are readable.
    """
    with host_terminal() as term:
        enter_sandbox(term, sandbox)
        term.send_line(rf"echo nope> C:\Users\{SANDBOX_USER}\outside.txt")
        term.expect(r"(?i)denied", timeout=STEP_TIMEOUT)


# ── Job Object containment ───────────────────────────────────


def test_stop_terminates_the_process_tree(sandbox):
    """Children join the sandbox's Job Object, so stopping it takes the
    whole tree rather than just the shell."""
    job_name = f"Global\\sbx-job-{sandbox.name}"
    with host_terminal() as term:
        enter_sandbox(term, sandbox)
        term.send_line("start /b ping -t 127.0.0.1")
        term.send_line("echo SPAWNED=%RANDOM%")
        term.expect(r"SPAWNED=\d+", timeout=STEP_TIMEOUT)

        job = winapi.open_job_object(job_name, winapi.JOB_OBJECT_QUERY)
        winapi.close_handle(job)

        stop_sandbox(sandbox.name)
        term.expect(CMD_PROMPT, timeout=PROMPT_TIMEOUT)

    with pytest.raises(OSError):
        winapi.open_job_object(job_name)


# ── Lifecycle ────────────────────────────────────────────────


def test_start_after_stop(sandbox):
    """A stopped sandbox restarts cleanly — the named pipes and Job Object
    from the previous run must not linger."""
    for attempt in ("first", "second"):
        with host_terminal() as term:
            enter_sandbox(term, sandbox)
            term.send_line(f"echo RUN={attempt}")
            term.expect(rf"RUN={attempt}", timeout=STEP_TIMEOUT)
            term.send_line("exit")
            term.expect(CMD_PROMPT, timeout=PROMPT_TIMEOUT)
        stop_quietly(sandbox.name)


def test_full_round_trip():
    """create, start, stop, destroy — after which the Job Object is gone
    and the mount point no longer exists."""
    project = make_project()
    create_sandbox(project)
    mount_root = Path(rf"C:\Users\{SANDBOX_USER}") / project.name
    assert (mount_root / "repo").exists(), "create did not set up the mount"

    try:
        with host_terminal() as term:
            enter_sandbox(term, project)
            term.send_line("echo ROUNDTRIP=%username%")
            term.expect(r"ROUNDTRIP=sbx-user", timeout=STEP_TIMEOUT)
            term.send_line("exit")
            term.expect(CMD_PROMPT, timeout=PROMPT_TIMEOUT)

        stop_quietly(project.name)

        from sbx.engine import Engine
        Engine().destroy(str(project))

        with pytest.raises(OSError):
            winapi.open_job_object(f"Global\\sbx-job-{project.name}")
        assert not (mount_root / "repo").exists()
    finally:
        teardown_sandbox(project)


# ── Not covered here ─────────────────────────────────────────
#
# Network isolation (presets none/claude-api-only/all, the WFP backstop,
# DNS blocking, proxy-crash fallback) needs a verified proxy and WFP rule
# set, which specs/plan.md places outside this iteration.
#
# The remaining privilege scenarios (taskkill against a host PID,
# `net user /add`, registry writes) and deep process-tree tracking are
# deferred too: test_paths_outside_any_mount_are_denied and
# test_stop_terminates_the_process_tree already cover those mechanisms,
# one level less deep.
