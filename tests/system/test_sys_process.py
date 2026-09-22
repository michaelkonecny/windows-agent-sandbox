"""Process isolation system tests (98-99)."""
from __future__ import annotations

from syshelp import configure, run_session


def test_98_host_env_not_inherited(pair, shell):
    """The shell gets sbx-user's environment, not the host's: host env vars
    (secrets) don't leak, and TEMP / USERPROFILE are writable."""
    configure(pair.a.path, shell=shell.name)
    res = run_session(pair.a.path, shell, [
        shell.env_set("host-var", "SBXSYS_HOST_SECRET"),
        shell.write_in_env_dir("temp", "TEMP", "x"),
        shell.write_in_env_dir("home", "USERPROFILE", "x"),
    ], env={"SBXSYS_HOST_SECRET": "leaked"})
    res.expect("host-var", "DENIED")
    res.expect("temp", "OK")
    res.expect("home", "OK")
