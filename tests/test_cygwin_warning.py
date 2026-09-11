"""A Cygwin shell trades away filesystem isolation, so starting one has
to say so out loud.

Cygwin/MSYS2 shells cannot run under restricted SIDs — their init fails
creating a signal pipe with ERROR_ACCESS_DENIED — so they get privilege
stripping only.  Every sandbox runs as the same account and backing paths
grant that account, which leaves such a shell able to reach every other
sandbox's mounts.  git-bash is the default shell, so silence here would be
the worst outcome.
"""

from __future__ import annotations

import logging

import pytest

from sbx.process import _is_cygwin_shell

GIT_BASH = r"C:\Program Files\Git\bin\bash.exe"


@pytest.mark.skipif(
    not __import__("os").path.isfile(GIT_BASH),
    reason="git-bash not installed",
)
def test_git_bash_is_detected_as_cygwin():
    assert _is_cygwin_shell(GIT_BASH)


@pytest.mark.parametrize(
    "shell", [r"C:\Windows\System32\cmd.exe",
              r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"]
)
def test_native_shells_are_not_cygwin(shell):
    assert not _is_cygwin_shell(shell)


def test_starting_a_cygwin_shell_warns(monkeypatch, caplog):
    """The warning is emitted before the runner launches, so it shows up
    even when the launch itself then fails."""
    from sbx import process

    monkeypatch.setattr(process, "_is_cygwin_shell", lambda path: True)
    monkeypatch.setattr(
        process, "get_credentials", lambda path: ("sbx-user", "pw")
    )

    def refuse_pipe(*args, **kwargs):
        raise OSError("stop here: the warning has already been logged")

    monkeypatch.setattr(process.winapi, "create_named_pipe", refuse_pipe)

    with caplog.at_level(logging.WARNING, logger="sbx.process"):
        with pytest.raises(OSError):
            process.start_sandbox("demo", "S-1-42-1-2-3-4", "bash.exe")

    warnings = [r.message for r in caplog.records if r.levelno >= logging.WARNING]
    assert any("without filesystem isolation" in m for m in warnings), warnings


def test_native_shell_does_not_warn(monkeypatch, caplog):
    from sbx import process

    monkeypatch.setattr(process, "_is_cygwin_shell", lambda path: False)
    monkeypatch.setattr(
        process, "get_credentials", lambda path: ("sbx-user", "pw")
    )
    monkeypatch.setattr(
        process.winapi, "create_named_pipe",
        lambda *a, **k: (_ for _ in ()).throw(OSError("stop here")),
    )

    with caplog.at_level(logging.WARNING, logger="sbx.process"):
        with pytest.raises(OSError):
            process.start_sandbox("demo", "S-1-42-1-2-3-4", "cmd.exe")

    assert not [
        r for r in caplog.records
        if "without filesystem isolation" in r.message
    ]
