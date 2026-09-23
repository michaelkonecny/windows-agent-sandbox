"""Piped stdin to a pseudo-console: in a console, Enter is CR. Scripts end
lines with LF or CRLF, so both must arrive as exactly one CR."""

from __future__ import annotations

from sbx.cli import PipedNewlines


def feed(*chunks: bytes) -> bytes:
    t = PipedNewlines()
    return b"".join(t.feed(c) for c in chunks)


def test_lf_becomes_cr():
    assert feed(b"echo a\necho b\n") == b"echo a\recho b\r"


def test_crlf_becomes_one_cr():
    assert feed(b"echo a\r\necho b\r\n") == b"echo a\recho b\r"


def test_crlf_split_across_reads_is_one_cr():
    assert feed(b"echo a\r", b"\necho b") == b"echo a\recho b"


def test_bare_cr_passes_through():
    assert feed(b"a\rb") == b"a\rb"
