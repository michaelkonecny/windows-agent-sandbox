"""Pipe I/O carries arbitrary bytes.

read_file is the single read path for the whole pseudoconsole stream, so
anything it cannot represent breaks the terminal rather than one command:
the relay threads catch OSError only, so a different exception kills the
thread and the session goes quiet with the shell still running.
"""

from __future__ import annotations

import pytest

from sbx import winapi

pytestmark = pytest.mark.integration


@pytest.fixture
def pipe():
    read_handle, write_handle = winapi.create_pipe(inheritable=False)
    yield read_handle, write_handle
    winapi.close_handle(read_handle)
    winapi.close_handle(write_handle)


def roundtrip(pipe, payload: bytes) -> bytes:
    read_handle, write_handle = pipe
    winapi.write_file(write_handle, payload)
    return winapi.read_file(read_handle, max(len(payload), 1) + 16)


def test_ascii_roundtrip(pipe):
    assert roundtrip(pipe, b"hello") == b"hello"


def test_utf8_roundtrip(pipe):
    """Accented filenames, box drawing, a shell's fancy quotes — all of
    it arrives as bytes above 0x7f."""
    payload = "héllo ✓ ┌─┐ …".encode("utf-8")
    assert roundtrip(pipe, payload) == payload


def test_high_bytes_roundtrip(pipe):
    payload = bytes(range(256))
    assert roundtrip(pipe, payload) == payload


def test_vt_sequence_roundtrip(pipe):
    payload = b"\x1b[?25l\x1b[2J\x1b[m\x1b[H\x1b]0;title\x07"
    assert roundtrip(pipe, payload) == payload


def test_read_returns_only_what_arrived(pipe):
    read_handle, write_handle = pipe
    winapi.write_file(write_handle, b"abc")
    assert winapi.read_file(read_handle, 4096) == b"abc"
