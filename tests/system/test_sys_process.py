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
    """The runner and its pseudo-console host hold unrestricted sbx-user
    tokens, so neither their processes nor their tokens may grant sbx-user
    (which every sandbox's RestrictedSids contain). Checked host-side by
    reading the DACLs."""
    import hostwin
    from probes import Shell
    from syshelp import LiveSession, job_name, sbx_status

    cmd = Shell("cmd")
    configure(pair.a.path, shell=cmd.name)
    s = LiveSession(pair.a.path, cmd)
    try:
        s.send([cmd.ready()])
        assert s.wait_probe("ready") == "OK"
        runner = sbx_status(pair.a.path)["pids"][0]
        sbx_user = hostwin.account_sid("sbx-user")
        allowed = {"SY", hostwin.account_sid(os.environ["USERNAME"])}
        # Unrestricted helpers: the runner and its pseudo-console host —
        # every child of the runner that isn't in the sandbox's job.
        in_job = set(hostwin.job_pids(job_name(pair.a.name)))
        helpers = [runner] + [p for p, parent in hostwin.parent_pids().items()
                              if parent == runner and p not in in_job]
        assert len(helpers) >= 2, f"no pseudo-console host found under runner {runner}"
        checks = [(f"{what} of {pid}", read(pid)) for pid in helpers
                  for what, read in (("process", hostwin.process_dacl),
                                     ("token", hostwin.process_token_dacl))]
        for what, sddl in checks:
            trustees = set(re.findall(r"\([^;]*;[^;]*;[^;]*;[^;]*;[^;]*;([^)]*)\)", sddl))
            assert trustees <= allowed, f"runner {what} DACL grants {trustees - allowed}: {sddl}"
    finally:
        s.close()
