from __future__ import annotations

import asyncio
import json
import logging
import os
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path

from sbx.config import NetworkPreset
from sbx.errors import ProxyError

log = logging.getLogger(__name__)

ANTHROPIC_DOMAINS = [
    "api.anthropic.com",
    "sentry.io",
    "statsigapi.net",
]

PID_FILE = Path(os.environ.get("LOCALAPPDATA", "")) / "sbx" / "proxy.pid"
IDLE_TIMEOUT = 60


@dataclass
class NetworkPolicy:
    preset: NetworkPreset
    allowed_domains: list[str] | None = None


def is_domain_allowed(domain: str, policy: NetworkPolicy) -> bool:
    if policy.preset == NetworkPreset.all:
        return True
    if policy.preset == NetworkPreset.none:
        return False
    domains = policy.allowed_domains or ANTHROPIC_DOMAINS
    return any(domain == d or domain.endswith("." + d) for d in domains)


def parse_sni(data: bytes) -> str | None:
    """Extract SNI hostname from a TLS ClientHello message."""
    if len(data) < 5 or data[0] != 0x16:
        return None
    pos = 5
    if pos >= len(data) or data[pos] != 0x01:
        return None
    pos += 4
    pos += 34
    if pos >= len(data):
        return None
    session_len = data[pos]
    pos += 1 + session_len
    if pos + 2 > len(data):
        return None
    cipher_len = int.from_bytes(data[pos:pos + 2], "big")
    pos += 2 + cipher_len
    if pos >= len(data):
        return None
    comp_len = data[pos]
    pos += 1 + comp_len
    if pos + 2 > len(data):
        return None
    ext_total = int.from_bytes(data[pos:pos + 2], "big")
    pos += 2
    ext_end = pos + ext_total
    while pos + 4 <= ext_end:
        ext_type = int.from_bytes(data[pos:pos + 2], "big")
        ext_len = int.from_bytes(data[pos + 2:pos + 4], "big")
        pos += 4
        if ext_type == 0x0000:
            if pos + 2 > ext_end:
                return None
            sni_pos = pos + 2
            sni_list_len = int.from_bytes(data[pos:pos + 2], "big")
            sni_end = pos + 2 + sni_list_len
            while sni_pos + 3 <= sni_end:
                name_type = data[sni_pos]
                name_len = int.from_bytes(data[sni_pos + 1:sni_pos + 3], "big")
                sni_pos += 3
                if name_type == 0x00:
                    return data[sni_pos:sni_pos + name_len].decode("ascii")
                sni_pos += name_len
            return None
        pos += ext_len
    return None


def parse_connect_request(line: bytes) -> tuple[str, int] | None:
    """Parse 'CONNECT host:port HTTP/1.x' → (host, port)."""
    try:
        parts = line.decode("ascii").strip().split()
        if len(parts) < 3 or parts[0] != "CONNECT":
            return None
        host_port = parts[1]
        if ":" in host_port:
            host, port_s = host_port.rsplit(":", 1)
            return host, int(port_s)
        return host_port, 443
    except (ValueError, UnicodeDecodeError):
        return None


class ProxyServer:
    def __init__(self) -> None:
        self.policies: dict[str, NetworkPolicy] = {}
        self._proxy_server: asyncio.Server | None = None
        self._control_server: asyncio.Server | None = None
        self._shutdown_event = asyncio.Event()
        self._idle_task: asyncio.Task | None = None
        self.proxy_port: int = 0
        self.control_port: int = 0

    def _lookup_policy_for_pid(self, pid: int) -> NetworkPolicy | None:
        if not self.policies:
            return None
        try:
            from sbx import winapi
            proc_h = winapi.open_process(
                pid, winapi.PROCESS_QUERY_LIMITED_INFORMATION,
            )
        except OSError:
            return None
        try:
            for job_name, policy in self.policies.items():
                try:
                    job_h = winapi.open_job_object(
                        job_name, winapi.JOB_OBJECT_QUERY,
                    )
                except OSError:
                    continue
                try:
                    if winapi.is_process_in_job(proc_h, job_h):
                        return policy
                finally:
                    winapi.close_handle(job_h)
        finally:
            winapi.close_handle(proc_h)
        return None

    def _resolve_pid(self, peername: tuple[str, int]) -> int | None:
        try:
            from sbx import winapi
            return winapi.get_tcp_pid(
                peername[0], peername[1], "127.0.0.1", self.proxy_port,
            )
        except Exception:
            return None

    async def _connect_upstream(self, host: str, port: int):
        return await asyncio.open_connection(host, port)

    async def _handle_proxy(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
    ) -> None:
        peername = writer.get_extra_info("peername")
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=10)
        except (asyncio.TimeoutError, ConnectionError):
            writer.close()
            return
        parsed = parse_connect_request(line)
        if parsed is None:
            writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            await writer.drain()
            writer.close()
            return
        target_host, target_port = parsed

        while True:
            try:
                hdr = await asyncio.wait_for(reader.readline(), timeout=5)
            except (asyncio.TimeoutError, ConnectionError):
                writer.close()
                return
            if hdr in (b"\r\n", b"\n", b""):
                break

        pid = self._resolve_pid(peername) if peername else None
        policy = self._lookup_policy_for_pid(pid) if pid else None
        if policy is None:
            log.info("deny (no policy): %s:%d pid=%s", target_host, target_port, pid)
            writer.write(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            await writer.drain()
            writer.close()
            return
        if not is_domain_allowed(target_host, policy):
            log.info("deny (policy): %s:%d pid=%s", target_host, target_port, pid)
            writer.write(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            await writer.drain()
            writer.close()
            return

        try:
            up_reader, up_writer = await asyncio.wait_for(
                self._connect_upstream(target_host, target_port), timeout=10,
            )
        except Exception:
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            await writer.drain()
            writer.close()
            return

        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        log.info("tunnel: %s:%d pid=%s", target_host, target_port, pid)

        await asyncio.gather(
            _relay_stream(reader, up_writer),
            _relay_stream(up_reader, writer),
            return_exceptions=True,
        )
        up_writer.close()
        writer.close()

    async def _handle_control(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
    ) -> None:
        try:
            data = await asyncio.wait_for(reader.readline(), timeout=5)
            msg = json.loads(data)
            cmd = msg.get("cmd")
            if cmd == "register":
                job_name = msg["job_name"]
                preset = NetworkPreset(msg["preset"])
                allowed = msg.get("allowed_domains")
                self.policies[job_name] = NetworkPolicy(preset, allowed)
                self._reset_idle()
                resp = {"ok": True}
            elif cmd == "deregister":
                self.policies.pop(msg["job_name"], None)
                self._reset_idle()
                resp = {"ok": True}
            elif cmd == "stop":
                resp = {"ok": True}
                writer.write(json.dumps(resp).encode() + b"\n")
                await writer.drain()
                writer.close()
                self._shutdown_event.set()
                return
            elif cmd == "ping":
                resp = {"ok": True, "sandboxes": len(self.policies)}
            else:
                resp = {"ok": False, "error": f"unknown command: {cmd}"}
        except Exception as e:
            resp = {"ok": False, "error": str(e)}
        writer.write(json.dumps(resp).encode() + b"\n")
        await writer.drain()
        writer.close()

    def _reset_idle(self) -> None:
        if self._idle_task and not self._idle_task.done():
            self._idle_task.cancel()
        self._idle_task = asyncio.get_event_loop().create_task(self._idle_watchdog())

    async def _idle_watchdog(self) -> None:
        while True:
            await asyncio.sleep(IDLE_TIMEOUT)
            if not self.policies:
                log.info("idle timeout, shutting down")
                self._shutdown_event.set()
                return

    async def start(self, proxy_port: int = 0, control_port: int = 0) -> None:
        self._proxy_server = await asyncio.start_server(
            self._handle_proxy, "127.0.0.1", proxy_port,
        )
        self._control_server = await asyncio.start_server(
            self._handle_control, "127.0.0.1", control_port,
        )
        self.proxy_port = self._proxy_server.sockets[0].getsockname()[1]
        self.control_port = self._control_server.sockets[0].getsockname()[1]

    async def run(self, proxy_port: int = 0, control_port: int = 0) -> None:
        await self.start(proxy_port, control_port)
        log.info(
            "proxy listening: proxy=%d control=%d",
            self.proxy_port, self.control_port,
        )
        _write_pid_file(os.getpid(), self.proxy_port, self.control_port)
        self._reset_idle()
        await self._shutdown_event.wait()
        self._proxy_server.close()
        self._control_server.close()
        _remove_pid_file()
        log.info("proxy shutdown")

    async def stop(self) -> None:
        self._shutdown_event.set()


async def _relay_stream(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
) -> None:
    try:
        while True:
            data = await reader.read(8192)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionError, asyncio.CancelledError):
        pass


def _write_pid_file(pid: int, proxy_port: int, control_port: int) -> None:
    PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    PID_FILE.write_text(json.dumps({
        "pid": pid, "proxy_port": proxy_port, "control_port": control_port,
    }))


def _remove_pid_file() -> None:
    try:
        PID_FILE.unlink()
    except FileNotFoundError:
        pass


def read_pid_file() -> dict | None:
    try:
        return json.loads(PID_FILE.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return None


class ProxyControl:
    """Client stub for communicating with a running proxy."""

    def __init__(self, control_port: int) -> None:
        self.control_port = control_port

    def _send(self, msg: dict) -> dict:
        import socket
        with socket.create_connection(("127.0.0.1", self.control_port), timeout=5) as s:
            s.sendall(json.dumps(msg).encode() + b"\n")
            data = s.recv(4096)
            return json.loads(data)

    def register(
        self, job_name: str, preset: NetworkPreset,
        allowed_domains: list[str] | None = None,
    ) -> None:
        msg: dict = {"cmd": "register", "job_name": job_name, "preset": preset.value}
        if allowed_domains is not None:
            msg["allowed_domains"] = allowed_domains
        resp = self._send(msg)
        if not resp.get("ok"):
            raise ProxyError(f"register failed: {resp.get('error')}")

    def deregister(self, job_name: str) -> None:
        resp = self._send({"cmd": "deregister", "job_name": job_name})
        if not resp.get("ok"):
            raise ProxyError(f"deregister failed: {resp.get('error')}")

    def ping(self) -> dict:
        return self._send({"cmd": "ping"})

    def stop(self) -> None:
        try:
            self._send({"cmd": "stop"})
        except (ConnectionError, OSError):
            pass


def run_proxy_main() -> None:
    """Entry point when proxy is launched as a subprocess."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[
            logging.FileHandler(
                Path(os.environ.get("LOCALAPPDATA", "")) / "sbx" / "proxy.log",
            ),
        ],
    )
    server = ProxyServer()
    asyncio.run(server.run())
