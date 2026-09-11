"""Telling a live process from a finished one.

Used to decide whether a handle is safe to close and whether a sandbox
shell is still up, so a wrong answer either leaks or closes too early.
"""

from __future__ import annotations

import time

import pytest

from sbx import winapi

pytestmark = pytest.mark.integration


def test_a_running_process_is_reported_running():
    # ping keeps going without stdin, unlike `cmd /k`, which sees EOF and
    # exits immediately when launched with no console.
    proc, thread, _pid, _ = winapi.create_process("ping -t 127.0.0.1")
    try:
        time.sleep(1)
        assert winapi.process_is_running(proc)
    finally:
        winapi.terminate_process(proc)
        winapi.close_handle(proc)
        winapi.close_handle(thread)


def test_a_terminated_process_is_reported_finished():
    proc, thread, _pid, _ = winapi.create_process("ping -t 127.0.0.1")
    try:
        time.sleep(0.5)
        winapi.terminate_process(proc)
        time.sleep(0.5)
        assert not winapi.process_is_running(proc)
    finally:
        winapi.close_handle(proc)
        winapi.close_handle(thread)


def test_exit_code_259_is_not_mistaken_for_still_running():
    """259 is STILL_ACTIVE, so comparing exit codes would call this
    process alive forever."""
    proc, thread, _pid, _ = winapi.create_process("cmd.exe /c exit 259")
    try:
        assert winapi.wait_for_process(proc, 10000) == 259
        assert not winapi.process_is_running(proc)
    finally:
        winapi.close_handle(proc)
        winapi.close_handle(thread)


def test_wait_for_process_times_out_rather_than_hanging():
    proc, thread, _pid, _ = winapi.create_process("ping -t 127.0.0.1")
    try:
        with pytest.raises(TimeoutError):
            winapi.wait_for_process(proc, 500)
    finally:
        winapi.terminate_process(proc)
        winapi.close_handle(proc)
        winapi.close_handle(thread)
