"""Interactive-console system tests (100-106): `sbx start` typed into a
real cmd window (cmd hosted in a ConPTY), the way a person uses it.
Test 107 is the console variant of tests 81-98 (see the `via` fixture)."""
from __future__ import annotations

import re

import pytest

from console import BACKSPACE, CTRL_C, TAB, UP
from probes import Shell
from syshelp import (
    SBX_TYPED, configure, enter_sandbox, leave_sandbox, open_console, sbx, sbx_list,
)

CMD = Shell("cmd")


@pytest.fixture
def console():
    c = open_console()
    yield c
    c.close()


def _no_traceback(c) -> None:
    assert "Traceback" not in c.text(), c.text()[-3000:]


def test_100_journey(installed, console):
    """init, create, start, work in the sandbox, exit with a code, destroy —
    all typed into cmd."""
    c = console
    project = installed.project("sbxsys-console")
    default_shell = Shell("git-bash")  # what `sbx init` scaffolds
    try:
        c.line(f"{SBX_TYPED} init {project.path}")
        c.expect("config created")
        c.line(f"{SBX_TYPED} create {project.path}")
        c.expect("sandbox created", 120)
        enter_sandbox(c, project.path, default_shell)
        c.line(default_shell.calc(6, 7))
        c.expect(r"^42\s*$")
        c.line("exit 3")
        c.expect("HOST>", 60)
        c.line("echo rc=%errorlevel%")
        c.expect(r"rc=3\b")
        c.line(f"{SBX_TYPED} destroy {project.path}")
        c.expect("sandbox destroyed", 120)
        _no_traceback(c)
    finally:
        if project.name in sbx_list():
            sbx("destroy", str(project.path))


def test_101_addressing(pair, console):
    """start by name and by config path; an unknown name is a one-line error."""
    c = console
    configure(pair.a.path, shell=CMD.name)
    for ref in (pair.a.name, pair.a.config):
        enter_sandbox(c, ref, CMD)
        assert leave_sandbox(c, CMD) == 0
    c.line(f"{SBX_TYPED} start sbxsys-no-such-sandbox")
    c.expect(r"^error: .*sbxsys-no-such-sandbox")
    c.line("echo rc=%errorlevel%")
    c.expect(r"rc=1\b")
    _no_traceback(c)


def test_102_line_editing(pair, console, shell):
    """Typed text echoes before Enter; Backspace edits; Up recalls; Tab completes."""
    c = console
    configure(pair.a.path, shell=shell.name)
    enter_sandbox(c, pair.a.path, shell)

    typed = shell.calc(6, 7) + "5"  # a stray trailing 5
    c.type(typed)
    c.expect(re.escape(typed))  # echoed before Enter
    c.type(BACKSPACE + "\r")  # remove it
    c.expect(r"^42\s*$")

    c.type(UP + "\r")  # the edited command again
    c.expect(r"^42\s*$")

    c.type(shell.complete_windows() + TAB + "\r")
    c.expect(r"(?i)^system32\s*$")
    assert leave_sandbox(c, shell) == 0


def test_103_ctrl_c(pair, console, shell):
    """Ctrl+C stops the running command; the session carries on."""
    c = console
    configure(pair.a.path, shell=shell.name)
    enter_sandbox(c, pair.a.path, shell)
    c.line("ping -t 127.0.0.1")
    c.expect(r"Reply from 127\.0\.0\.1")
    c.type(CTRL_C)
    c.expect("SBX>")
    c.line(shell.calc(7, 11))
    c.expect(r"^77\s*$")
    leave_sandbox(c, shell)  # exit code may carry the interrupted command's


def test_104_colour(pair, console, shell):
    """A colour escape from the sandbox reaches the host terminal."""
    c = console
    configure(pair.a.path, shell=shell.name)
    enter_sandbox(c, pair.a.path, shell)
    c.line(shell.colour("COLOURTEST"))
    c.line(shell.calc(3, 3))
    c.expect(r"^9\s*$")
    # Colour is set by an SGR escape; the host terminal may move the cursor
    # or start a new line before printing the text itself.
    red = re.compile(rb"\x1b\[([0-9;]*)m(?:\x1b\[[0-9;?]*[A-Za-z]|\r|\n)*COLOURTEST")
    params = [m.group(1).split(b";") for m in red.finditer(c.raw())]
    assert any(b"31" in p or b"91" in p or b"38" in p for p in params), \
        f"no red escape before COLOURTEST: {params}"
    leave_sandbox(c, shell)


def test_105_resize(pair, console, shell):
    """Resizing the host window resizes the sandbox's terminal."""
    c = console
    configure(pair.a.path, shell=shell.name)
    enter_sandbox(c, pair.a.path, shell)
    c.resize(150, 40)
    # The resize crosses two terminals (this one, then the sandbox's);
    # ask again until it has landed.
    for _ in range(10):
        c.line(shell.width_query())
        try:
            c.expect(r"\b150\b", timeout=1.5)
            break
        except TimeoutError:
            continue
    else:
        pytest.fail(f"sandbox never reported width 150:\n{c.text()[-2000:]}")
    assert leave_sandbox(c, shell) == 0


def test_106_console_modes_restored(pair, console):
    """After the sandbox exits, the host cmd's line editing still works."""
    c = console
    configure(pair.a.path, shell=CMD.name)
    enter_sandbox(c, pair.a.path, CMD)
    leave_sandbox(c, CMD)
    c.type("echo typed-chexk")
    c.expect("typed-chexk")  # echoed before Enter
    c.type(BACKSPACE * 2 + "ck\r")
    c.expect(r"^typed-check\s*$")
