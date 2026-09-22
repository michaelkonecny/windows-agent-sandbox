"""Lifecycle system tests (74-80). Ordered by number; 80 runs last."""
from __future__ import annotations

import hashlib
import time
from pathlib import Path

import pytest

import hostwin
from probes import Shell
from syshelp import (
    SBX_HOME, WORKSPACE, LiveSession, host_curl, job_name, sbx, sbx_list,
    sbx_status, wait_until,
)

DEFAULT_SHELL = Shell("git-bash")  # what `sbx init` scaffolds


def _snapshot(root: Path) -> dict[str, str]:
    return {
        str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(root.rglob("*")) if p.is_file()
    }


def _sbx_rules(sid: str) -> list[str]:
    return sorted(hostwin.firewall_rules_for_sid(sid))


def test_74_install(world):
    res = sbx("install", timeout=300)
    assert res.returncode == 0, res.stderr
    world.installed = True

    sid = hostwin.account_sid("sbx-user")
    assert sid, "sbx-user account missing after install"
    assert (SBX_HOME / "credentials.json").is_file()
    rules = _sbx_rules(sid)
    assert rules, f"no firewall rules scoped to sbx-user ({sid})"
    world.notes["user_sid"] = sid
    world.notes["rules"] = rules


def test_75_install_again(installed):
    res = sbx("install", timeout=300)
    assert res.returncode == 0, res.stderr
    sid = hostwin.account_sid("sbx-user")
    assert sid == installed.notes.get("user_sid"), "sbx-user was recreated"
    assert _sbx_rules(sid) == installed.notes["rules"], "firewall rules changed or duplicated"


def test_76_init_create(installed):
    a = installed.a
    installed.notes["a_before"] = None
    res = sbx("init", str(a.path))
    assert res.returncode == 0, res.stderr
    installed.notes["a_before"] = _snapshot(a.path)

    res = sbx("create", str(a.config))
    assert res.returncode == 0, res.stderr

    listing = {p.name for p in (WORKSPACE / a.name / "repo").iterdir()}
    assert {"secret.txt", ".sandbox"} <= listing
    assert sbx_list().get(a.name) == "created"


def test_77_start_unprivileged(installed):
    a = installed.a
    s = LiveSession(a.path, DEFAULT_SHELL)
    try:
        s.send([DEFAULT_SHELL.ready()])
        assert s.wait_probe("ready") == "OK"

        pids = sbx_status(a.path).get("pids")
        assert pids, "sbx status lists no PIDs for a running sandbox"
        runner = pids[0]
        assert hostwin.process_owner(runner).lower() == "sbx-user"
        in_job = hostwin.job_pids(job_name(a.name))
        assert set(in_job) <= set(pids), f"status PIDs {pids} miss job PIDs {in_job}"
        parents = hostwin.parent_pids()
        shells = [p for p in pids if parents.get(p) == runner]
        assert len(shells) == 1, f"expected one shell under runner {runner}, got {shells}"
        shell = shells[0]
        assert shell in in_job, "shell is not in the sandbox Job Object"
        assert hostwin.process_owner(shell).lower() == "sbx-user"
        assert not hostwin.process_elevated(shell)
    except BaseException:
        s.kill()
        raise
    assert s.close() == 0


def test_78_stop_kills_tree(installed):
    a = installed.a
    s = LiveSession(a.path, DEFAULT_SHELL)
    try:
        s.send([DEFAULT_SHELL.background_child(), DEFAULT_SHELL.ready()])
        assert s.wait_probe("ready") == "OK"
        assert wait_until(lambda: len(hostwin.job_pids(job_name(a.name))) >= 2, 5), \
            "background child never joined the Job Object"
        pids = set(sbx_status(a.path)["pids"]) | set(hostwin.job_pids(job_name(a.name)))

        res = sbx("stop", str(a.path))
        assert res.returncode == 0, res.stderr
        alive = lambda: [p for p in pids if hostwin.process_alive(p)]
        assert wait_until(lambda: not alive(), 5), f"still alive after stop: {alive()}"
        assert sbx_list().get(a.name) == "stopped"
    finally:
        s.kill()


def test_79_destroy(installed):
    a = installed.a
    sid = sbx_status(a.path)["sid"]
    assert hostwin.acl_mentions(str(a.path), sid), "sandbox SID never granted on project dir"

    res = sbx("destroy", str(a.path))
    assert res.returncode == 0, res.stderr

    assert not (WORKSPACE / a.name / "repo").exists(), "bind link survived destroy"
    assert not hostwin.acl_mentions(str(a.path), sid), "sandbox SID ACE survived destroy"
    assert a.name not in sbx_list()
    assert _snapshot(a.path) == installed.notes["a_before"], "project files changed"


def test_80_uninstall(installed):
    sid = hostwin.account_sid("sbx-user")
    proxy_pid = None
    pid_file = SBX_HOME / "proxy.pid"
    if pid_file.exists():
        import json
        proxy_pid = json.loads(pid_file.read_text()).get("pid")

    res = sbx("uninstall", timeout=300)
    assert res.returncode == 0, res.stderr

    assert hostwin.account_sid("sbx-user") is None, "sbx-user still exists"
    assert not _sbx_rules(sid), "firewall rules scoped to sbx-user remain"
    assert not (SBX_HOME / "credentials.json").exists()
    if proxy_pid:
        assert wait_until(lambda: not hostwin.process_alive(proxy_pid), 5), "proxy still running"
    assert not pid_file.exists(), "proxy PID file remains"
    leftovers = list(WORKSPACE.glob("sbxsys-*")) if WORKSPACE.exists() else []
    assert not leftovers, f"sbxsys- bind links left: {leftovers}"

    # Test 95, second half: host egress works after uninstall.
    assert host_curl("https://example.com") == 0
