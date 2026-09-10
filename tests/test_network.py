import json
import os
import socket
import subprocess
import threading
import time
from pathlib import Path
from unittest import mock

import pytest

from sbx.config import NetworkPreset
from sbx.network import (
    WFP_ALLOW_RULE,
    WFP_BLOCK_RULE,
    _is_process_alive,
    install_wfp_rules,
    uninstall_wfp_rules,
)
from sbx.proxy import ProxyControl, ProxyServer, read_pid_file


# ── WFP rule tests (require elevation) ────────────────────


@pytest.mark.elevation
def test_wfp_install():
    """Test 52: WFP rules install successfully via netsh."""
    sid = "S-1-5-21-0-0-0-0"
    install_wfp_rules(sid, 8443)

    result = subprocess.run(
        ["netsh", "advfirewall", "firewall", "show", "rule",
         f"name={WFP_BLOCK_RULE}"],
        capture_output=True, text=True,
    )
    assert WFP_BLOCK_RULE in result.stdout

    result = subprocess.run(
        ["netsh", "advfirewall", "firewall", "show", "rule",
         f"name={WFP_ALLOW_RULE}"],
        capture_output=True, text=True,
    )
    assert WFP_ALLOW_RULE in result.stdout

    uninstall_wfp_rules()


@pytest.mark.elevation
def test_wfp_uninstall():
    """Test 53: WFP rules uninstall cleanly."""
    sid = "S-1-5-21-0-0-0-0"
    install_wfp_rules(sid, 8443)
    uninstall_wfp_rules()

    for name in (WFP_BLOCK_RULE, WFP_ALLOW_RULE):
        result = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule",
             f"name={name}"],
            capture_output=True, text=True,
        )
        assert name not in result.stdout or "No rules match" in result.stdout


@pytest.mark.elevation
def test_wfp_reinstall_idempotent():
    """Test 54: Reinstalling WFP rules is idempotent."""
    sid = "S-1-5-21-0-0-0-0"
    install_wfp_rules(sid, 8443)
    install_wfp_rules(sid, 9443)

    result = subprocess.run(
        ["netsh", "advfirewall", "firewall", "show", "rule",
         f"name={WFP_ALLOW_RULE}"],
        capture_output=True, text=True,
    )
    assert WFP_ALLOW_RULE in result.stdout

    uninstall_wfp_rules()


# ── Proxy lifecycle tests ─────────────────────────────────


def test_ensure_proxy_starts():
    """Test 55: ensure_proxy_running starts proxy when not running."""
    import asyncio

    server = ProxyServer()
    loop = asyncio.new_event_loop()
    ready = threading.Event()

    def run_loop():
        asyncio.set_event_loop(loop)
        loop.run_until_complete(server.start())
        ready.set()
        loop.run_forever()

    t = threading.Thread(target=run_loop, daemon=True)
    t.start()
    ready.wait(timeout=5)

    try:
        from sbx.proxy import PID_FILE, _write_pid_file
        _write_pid_file(os.getpid(), server.proxy_port, server.control_port)

        ctl = ProxyControl(server.control_port)
        resp = ctl.ping()
        assert resp["ok"]
    finally:
        loop.call_soon_threadsafe(loop.stop)
        t.join(timeout=5)
        try:
            PID_FILE.unlink()
        except FileNotFoundError:
            pass


def test_ensure_proxy_stale_pid():
    """Test 56: ensure_proxy_running detects stale PID file."""
    from sbx.proxy import PID_FILE, _write_pid_file

    PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    _write_pid_file(99999, 0, 55555)

    info = read_pid_file()
    assert info is not None
    assert info["pid"] == 99999

    alive = _is_process_alive(99999)
    assert not alive

    try:
        PID_FILE.unlink()
    except FileNotFoundError:
        pass
