"""Console mode and size wrappers.

These open CONOUT$/CONIN$ directly rather than using the std handles: a
test runner usually has stdio redirected to a pipe or file, and console
APIs reject a handle that is not a console.
"""

from __future__ import annotations

import pytest

from sbx import winapi

pytestmark = pytest.mark.integration


@pytest.fixture
def conout():
    try:
        handle = winapi.open_file(
            "CONOUT$", winapi.GENERIC_READ | winapi.GENERIC_WRITE, share=3
        )
    except OSError:
        pytest.skip("no console attached to this process")
    yield handle
    winapi.close_handle(handle)


@pytest.fixture
def conin():
    try:
        handle = winapi.open_file(
            "CONIN$", winapi.GENERIC_READ | winapi.GENERIC_WRITE, share=3
        )
    except OSError:
        pytest.skip("no console attached to this process")
    yield handle
    winapi.close_handle(handle)


def test_get_std_handle_returns_a_handle():
    handle = winapi.get_std_handle(winapi.STD_OUTPUT_HANDLE)
    assert isinstance(handle, int)
    assert handle not in (0, winapi.INVALID_HANDLE_VALUE)


def test_get_console_mode_returns_flags(conout):
    assert isinstance(winapi.get_console_mode(conout), int)


def test_set_console_mode_roundtrip(conout):
    original = winapi.get_console_mode(conout)
    try:
        winapi.set_console_mode(
            conout, original | winapi.ENABLE_VIRTUAL_TERMINAL_PROCESSING
        )
        assert (winapi.get_console_mode(conout)
                & winapi.ENABLE_VIRTUAL_TERMINAL_PROCESSING)
    finally:
        winapi.set_console_mode(conout, original)
    assert winapi.get_console_mode(conout) == original


def test_vt_input_mode_can_be_enabled(conin):
    original = winapi.get_console_mode(conin)
    try:
        winapi.set_console_mode(
            conin,
            winapi.ENABLE_VIRTUAL_TERMINAL_INPUT | winapi.ENABLE_WINDOW_INPUT,
        )
        mode = winapi.get_console_mode(conin)
        assert mode & winapi.ENABLE_VIRTUAL_TERMINAL_INPUT
        assert mode & winapi.ENABLE_WINDOW_INPUT
    finally:
        winapi.set_console_mode(conin, original)


def test_get_console_screen_buffer_info_gives_positive_size(conout):
    cols, rows = winapi.get_console_screen_buffer_info(conout)
    assert cols > 0
    assert rows > 0


def test_console_mode_rejects_non_console_handle():
    read_handle, write_handle = winapi.create_pipe(inheritable=False)
    try:
        with pytest.raises(OSError):
            winapi.get_console_mode(read_handle)
    finally:
        winapi.close_handle(read_handle)
        winapi.close_handle(write_handle)
