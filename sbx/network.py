from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from pathlib import Path

from sbx.config import NetworkPreset
from sbx.errors import NetworkError
from sbx.proxy import ProxyControl, ProxyServer, read_pid_file

log = logging.getLogger(__name__)

WFP_RULE_PREFIX = "sbx-"
WFP_BLOCK_RULE = f"{WFP_RULE_PREFIX}block-egress"
WFP_ALLOW_RULE = f"{WFP_RULE_PREFIX}allow-proxy"


def install_wfp_rules(user_sid: str, proxy_port: int) -> None:
    """Install WFP firewall rules scoped to sbx-user.

    Blocks all outbound traffic for the user except loopback to proxy_port.
    Uses Windows Firewall via netsh (backed by WFP internally).
    Requires elevation.
    """
    _remove_rules_quiet()

    _run_netsh([
        "advfirewall", "firewall", "add", "rule",
        f"name={WFP_BLOCK_RULE}",
        "dir=out", "action=block",
        "protocol=any",
        f"localip=any",
        f"remoteip=any",
    ], user_sid)

    _run_netsh([
        "advfirewall", "firewall", "add", "rule",
        f"name={WFP_ALLOW_RULE}",
        "dir=out", "action=allow",
        "protocol=tcp",
        f"remoteip=127.0.0.1",
        f"remoteport={proxy_port}",
    ], user_sid)

    log.info("WFP rules installed for SID %s, proxy port %d", user_sid, proxy_port)


def uninstall_wfp_rules() -> None:
    """Remove WFP firewall rules. Requires elevation."""
    _remove_rules_quiet()
    log.info("WFP rules removed")


def _run_netsh(args: list[str], user_sid: str | None = None) -> None:
    cmd = ["netsh"] + args
    if user_sid:
        cmd.extend([f"/localuser={user_sid}"])
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        raise NetworkError(f"netsh failed: {e.stderr.strip()}")


def _remove_rules_quiet() -> None:
    for name in (WFP_BLOCK_RULE, WFP_ALLOW_RULE):
        try:
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule",
                 f"name={name}"],
                capture_output=True, text=True,
            )
        except subprocess.CalledProcessError:
            pass


def _is_process_alive(pid: int) -> bool:
    try:
        from sbx import winapi
        h = winapi.open_process(pid, winapi.PROCESS_QUERY_LIMITED_INFORMATION)
        winapi.close_handle(h)
        return True
    except OSError:
        return False


def ensure_proxy_running() -> ProxyControl:
    """Start the proxy if not already alive. Return a ProxyControl client."""
    info = read_pid_file()
    if info is not None:
        pid = info.get("pid", 0)
        control_port = info.get("control_port", 0)
        if pid and control_port and _is_process_alive(pid):
            try:
                ctl = ProxyControl(control_port)
                resp = ctl.ping()
                if resp.get("ok"):
                    log.info("proxy already running, pid=%d", pid)
                    return ctl
            except (ConnectionError, OSError):
                pass
        log.info("stale PID file, starting fresh proxy")

    return _start_proxy()


def _start_proxy() -> ProxyControl:
    """Launch the proxy as a subprocess."""
    python = sys.executable
    cmd = [python, "-m", "sbx", "_proxy"]
    proc = subprocess.Popen(
        cmd,
        creationflags=subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    log.info("started proxy subprocess, pid=%d", proc.pid)

    import time
    for _ in range(50):
        time.sleep(0.1)
        info = read_pid_file()
        if info and info.get("control_port"):
            ctl = ProxyControl(info["control_port"])
            try:
                resp = ctl.ping()
                if resp.get("ok"):
                    return ctl
            except (ConnectionError, OSError):
                pass

    raise NetworkError("proxy failed to start within 5 seconds")


def register_sandbox(
    job_name: str, preset: NetworkPreset,
    allowed_domains: list[str] | None = None,
) -> None:
    ctl = ensure_proxy_running()
    ctl.register(job_name, preset, allowed_domains)
    log.info("registered sandbox %s with preset %s", job_name, preset.value)


def deregister_sandbox(job_name: str) -> None:
    info = read_pid_file()
    if info is None:
        return
    try:
        ctl = ProxyControl(info["control_port"])
        ctl.deregister(job_name)
        log.info("deregistered sandbox %s", job_name)
    except (ConnectionError, OSError):
        log.warning("proxy not reachable for deregister of %s", job_name)
