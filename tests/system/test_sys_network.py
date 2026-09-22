"""Network isolation system tests (88-96), per shell unless noted."""
from __future__ import annotations

import json
import subprocess

import pytest

import hostwin
from syshelp import (
    SBX_HOME, LiveSession, configure, host_curl, run_session, wait_until,
)

API = "https://api.anthropic.com"
OTHER = "https://example.com"


def _proxy_info() -> dict:
    try:
        return json.loads((SBX_HOME / "proxy.pid").read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _proxy_up(w, shell) -> int:
    """Start the proxy (a claude-api-only session does) and return its port.
    It then idles for 60 s before exiting."""
    configure(w.b.path, shell=shell.name)
    run_session(w.b.path, shell, [shell.ready()]).expect("ready", "OK")
    port = _proxy_info().get("proxy_port")
    assert port, "proxy did not start for a claude-api-only sandbox"
    return port


def test_88_none_no_egress(pair, shell):
    configure(pair.a.path, shell=shell.name)
    res = run_session(pair.a.path, shell, [
        shell.env_set("proxy-env", "HTTPS_PROXY"),
        shell.http("direct", OTHER, via="direct"),
    ])
    res.expect("proxy-env", "DENIED")
    res.expect("direct", "DENIED")


def test_89_none_proxy_rejects(pair, shell):
    port = _proxy_up(pair, shell)
    configure(pair.a.path, shell=shell.name)
    res = run_session(pair.a.path, shell, [
        shell.http("via-proxy", OTHER, via=f"http://127.0.0.1:{port}"),
    ])
    res.expect("via-proxy", "DENIED")


def test_90_claude_api_only_allowlist(pair, shell):
    configure(pair.b.path, shell=shell.name)
    res = run_session(pair.b.path, shell, [
        shell.env_set("proxy-env", "HTTPS_PROXY"),
        shell.http("api", API),
        shell.http("other", OTHER),
    ])
    res.expect("proxy-env", "OK")
    res.expect("api", "OK")
    res.expect("other", "DENIED")


def test_91_claude_api_only_no_bypass(pair, shell):
    configure(pair.b.path, shell=shell.name)
    res = run_session(pair.b.path, shell, [shell.http("bypass", API, via="direct")])
    res.expect("bypass", "DENIED")


def test_92_all(pair, shell):
    configure(pair.b.path, shell=shell.name, network="all")
    try:
        res = run_session(pair.b.path, shell, [shell.http("other", OTHER)])
    finally:
        configure(pair.b.path, network="claude-api-only")
    res.expect("other", "OK")


def _live(project, shell) -> LiveSession:
    s = LiveSession(project.path, shell)
    s.send([shell.ready()])
    assert s.wait_probe("ready") == "OK"
    return s


def test_93_concurrent_policies(pair, shell):
    configure(pair.a.path, shell=shell.name)
    configure(pair.b.path, shell=shell.name)
    a = _live(pair.a, shell)
    try:
        b = _live(pair.b, shell)
        try:
            port = _proxy_info().get("proxy_port")
            a.send([shell.http("a-api", API),
                    shell.http("a-api-proxy", API, via=f"http://127.0.0.1:{port}")])
            b.send([shell.http("b-api", API)])
            assert a.wait_probe("a-api") == "DENIED"
            assert a.wait_probe("a-api-proxy") == "DENIED"
            assert b.wait_probe("b-api") == "OK"
        finally:
            b.close()
    finally:
        a.close()


def test_94_proxy_killed_fails_closed(pair, shell):
    configure(pair.b.path, shell=shell.name)
    b = _live(pair.b, shell)
    try:
        pid = _proxy_info().get("pid")
        assert pid, "proxy not running for a claude-api-only sandbox"
        subprocess.run(["taskkill", "/f", "/pid", str(pid)], capture_output=True)
        assert wait_until(lambda: not hostwin.process_alive(pid), 5), "proxy survived kill"
        b.send([shell.http("api", API), shell.http("api-direct", API, via="direct")])
        assert b.wait_probe("api") == "DENIED"
        assert b.wait_probe("api-direct") == "DENIED"
    finally:
        b.close()


def test_95_host_egress_unaffected(pair, shell):
    configure(pair.b.path, shell=shell.name)
    b = _live(pair.b, shell)
    try:
        assert host_curl(OTHER) == 0, "host lost egress while a sandbox runs"
    finally:
        b.close()
    # The after-uninstall half runs in test_80_uninstall.


def test_96_control_port_rejects_sandbox(pair):
    """A sandbox that reaches the proxy's control port (loopback isn't
    firewalled) can neither widen its own policy nor stop the proxy."""
    from probes import CURL, Shell
    from syshelp import WORKSPACE, job_name

    cmd = Shell("cmd")
    b = pair.b
    configure(b.path, shell=cmd.name)
    s = _live(b, cmd)
    try:
        info = _proxy_info()
        attacks = {
            "widen": {"cmd": "register", "job_name": job_name(b.name), "preset": "all"},
            "stop": {"cmd": "stop"},
        }
        lines = []
        for name, msg in attacks.items():
            (b.path / f"{name}.json").write_text(json.dumps(msg) + "\n", encoding="utf-8")
            lines.append(
                f'{CURL} -s --max-time 3 telnet://127.0.0.1:{info["control_port"]}'
                f' < "{WORKSPACE / b.name / "repo" / f"{name}.json"}"'
            )
        s.send([*lines, cmd.http("other", OTHER), cmd.http("api", API)])
        assert s.wait_probe("other") == "DENIED", "sandbox widened its own policy"
        assert s.wait_probe("api") == "OK"
        assert hostwin.process_alive(info["pid"]), "sandbox stopped the proxy"
    finally:
        s.close()
