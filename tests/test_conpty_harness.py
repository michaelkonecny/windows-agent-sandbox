"""Validates the ConPtyShell harness itself.

These tests are the go/no-go gate for the ConPTY approach: a previous
iteration recorded zero output from ConPTY under this Windows build and
fell back to anonymous pipes.  Here the harness runs as the current user
with an unrestricted token, which separates a ctypes marshalling fault
from anything the restricted token does later.
"""

from __future__ import annotations

import pytest

from conpty_harness import ConPtyShell

pytestmark = pytest.mark.integration


def test_conpty_produces_output():
    """The bare minimum: a ConPTY yields bytes at all."""
    with ConPtyShell("cmd.exe") as sh:
        sh.expect_prompt()
        sh.write("echo HELLO\r\n")
        sh.expect("HELLO")


def test_output_distinguishable_from_echo():
    """ConPTY echoes typed input, so a naive match can pass on the echo
    alone.  Arithmetic gives an answer that appears nowhere in the typed
    text, so matching it proves the shell actually ran the command."""
    with ConPtyShell("cmd.exe") as sh:
        sh.expect_prompt()
        sh.write("set /a 6*7\r\n")
        sh.expect(r"\b42\b")


def test_expect_timeout_reports_buffer():
    with ConPtyShell("cmd.exe") as sh:
        sh.expect_prompt()
        with pytest.raises(TimeoutError) as excinfo:
            sh.expect("THIS_NEVER_APPEARS", timeout=2)
        assert "buffer" in str(excinfo.value).lower()


def test_exit_code_after_shell_exits():
    with ConPtyShell("cmd.exe") as sh:
        sh.expect_prompt()
        sh.write("exit 7\r\n")
        assert sh.wait(timeout=10) == 7


def test_resize_reported_by_shell():
    """`mode con` prints the console dimensions ConPTY reports."""
    with ConPtyShell("cmd.exe", cols=120, rows=40) as sh:
        sh.expect_prompt()
        sh.resize(80, 24)
        sh.write("mode con\r\n")
        # `mode con` reports Lines before Columns.
        sh.expect(r"Lines:\s+24")
        sh.expect(r"Columns:\s+80")


def test_screen_text_renders_cursor_addressing():
    """pyte turns the raw VT stream into a screen buffer.  `cls` clears
    and homes the cursor, so the marker written afterwards lands on the
    first row."""
    pytest.importorskip("pyte")
    with ConPtyShell("cmd.exe", capture_screen=True) as sh:
        sh.expect_prompt()
        sh.write("cls\r\n")
        sh.write("set /a 111+222\r\n")
        sh.expect(r"\b333\b")
        rendered = sh.screen_text()
        assert "333" in rendered
        # The banner is still in the byte stream, but `cls` erased it from
        # the screen — so rendering differs from concatenating the output,
        # which is the whole reason pyte is here.
        assert "Microsoft Windows" in sh.read_all()
        assert "Microsoft Windows" not in rendered


# ── escape stripping, exercised without a live shell ─────────


def offline_shell() -> ConPtyShell:
    """A harness instance that is never started — enough to feed bytes
    through the escape stripping."""
    return ConPtyShell("cmd.exe")


def test_escape_split_across_reads_is_still_stripped():
    sh = offline_shell()
    sh._feed(b"a\x1b[")
    sh._feed(b"31mred")
    assert sh.read_all() == "ared"


def test_crlf_split_across_reads_becomes_one_newline():
    sh = offline_shell()
    sh._feed(b"line\r")
    sh._feed(b"\nnext")
    assert sh.read_all() == "line\nnext"


def test_unrecognised_escape_does_not_wedge_the_stream():
    """A sequence the stripper does not know — DCS here, but sixel or a
    terminal-query reply would do — must degrade to noise in the buffer
    rather than swallowing everything after it, which would make every
    later expect() time out with a stale dump."""
    sh = offline_shell()
    sh._feed(b"before\x1bP1$r")
    sh._feed(b"after" * 30)
    assert "before" in sh.read_all()
    assert "after" in sh.read_all()


def test_multibyte_character_split_across_reads():
    sh = offline_shell()
    encoded = "héllo".encode("utf-8")
    sh._feed(encoded[:2])
    sh._feed(encoded[2:])
    assert sh.read_all() == "héllo"
