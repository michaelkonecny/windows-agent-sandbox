"""Process isolation system tests (98-99)."""
from __future__ import annotations

import os
import re

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


def test_99_runner_dacls_exclude_sandbox(pair):
    """The runner holds an unrestricted sbx-user token, so neither its
    process nor its token may grant sbx-user (which every sandbox's
    RestrictedSids contain). Checked host-side by reading the DACLs."""
    import hostwin
    from probes import Shell
    from syshelp import LiveSession, sbx_status

    cmd = Shell("cmd")
    configure(pair.a.path, shell=cmd.name)
    s = LiveSession(pair.a.path, cmd)
    try:
        s.send([cmd.ready()])
        assert s.wait_probe("ready") == "OK"
        runner = sbx_status(pair.a.path)["pids"][0]
        sbx_user = hostwin.account_sid("sbx-user")
        allowed = {"SY", hostwin.account_sid(os.environ["USERNAME"])}
        for what, sddl in (("process", hostwin.process_dacl(runner)),
                           ("token", hostwin.process_token_dacl(runner))):
            trustees = set(re.findall(r"\([^;]*;[^;]*;[^;]*;[^;]*;[^;]*;([^)]*)\)", sddl))
            assert trustees <= allowed, f"runner {what} DACL grants {trustees - allowed}: {sddl}"
    finally:
        s.close()
