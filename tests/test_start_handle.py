"""StartHandle owns three Windows handles and is closed by two owners.

The CLI closes it when the interactive session ends; the engine keeps the
same object and closes it again on stop. Closing a handle twice is not
harmless — Windows reuses handle numbers, so the second close can land on
an unrelated object.
"""

from __future__ import annotations

import pytest

from sbx import process as process_module
from sbx.process import StartHandle


@pytest.fixture
def closed_handles(monkeypatch):
    closed: list[int] = []
    monkeypatch.setattr(
        process_module.winapi, "close_handle", lambda h: closed.append(h)
    )
    return closed


def make_handle() -> StartHandle:
    return StartHandle(
        runner_process=11, runner_pid=222, pipe_in=33, pipe_out=44,
        job_name="Global\\sbx-job-demo",
    )


def test_close_releases_every_handle(closed_handles):
    make_handle().close()
    assert sorted(closed_handles) == [11, 33, 44]


def test_closing_twice_does_not_close_anything_again(closed_handles):
    handle = make_handle()
    handle.close()
    closed_handles.clear()

    handle.close()

    assert closed_handles == [0, 0, 0], (
        "a second close must not pass real handle values to CloseHandle"
    )


def test_close_clears_the_fields(closed_handles):
    handle = make_handle()
    handle.close()
    assert (handle.runner_process, handle.pipe_in, handle.pipe_out) == (0, 0, 0)
    # The pid is a number, not a handle, so it stays for diagnostics.
    assert handle.runner_pid == 222
