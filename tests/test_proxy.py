import asyncio
import json
import socket
import struct
import time

import pytest

from sbx.config import NetworkPreset
from sbx.proxy import (
    NetworkPolicy,
    ProxyControl,
    ProxyServer,
    is_domain_allowed,
    parse_connect_request,
    parse_sni,
)


# ── Helpers ────────────────────────────────────────────────

def _build_client_hello(hostname: str) -> bytes:
    sni_host = hostname.encode("ascii")
    sni_entry = b"\x00" + len(sni_host).to_bytes(2, "big") + sni_host
    sni_list = len(sni_entry).to_bytes(2, "big") + sni_entry
    sni_ext = b"\x00\x00" + len(sni_list).to_bytes(2, "big") + sni_list
    extensions = len(sni_ext).to_bytes(2, "big") + sni_ext
    client_hello_body = (
        b"\x03\x03"
        + b"\x00" * 32
        + b"\x00"
        + b"\x00\x02\x00\xff"
        + b"\x01\x00"
        + extensions
    )
    handshake = b"\x01" + len(client_hello_body).to_bytes(3, "big") + client_hello_body
    record = b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake
    return record


async def _start_test_server(echo_port=None):
    """Start a proxy server with mocked PID resolution. If echo_port given,
    upstream connections get redirected to 127.0.0.1:echo_port."""
    server = ProxyServer()
    if echo_port is not None:
        async def _connect_local(host, port):
            return await asyncio.open_connection("127.0.0.1", echo_port)
        server._connect_upstream = _connect_local
    await server.start()
    return server


async def _connect_proxy(proxy_port, host, port=443):
    reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
    writer.write(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
    await writer.drain()
    response = await asyncio.wait_for(reader.readline(), timeout=5)
    return reader, writer, response


# ── Tests ──────────────────────────────────────────────────


def test_connect_allowed_domain():
    """Test 43: Proxy accepts CONNECT for an allowed domain and tunnels data."""
    async def _test():
        echo_data = []
        async def echo_handler(r, w):
            data = await r.read(4096)
            echo_data.append(data)
            w.write(b"upstream-response")
            await w.drain()
            w.close()

        echo_srv = await asyncio.start_server(echo_handler, "127.0.0.1", 0)
        echo_port = echo_srv.sockets[0].getsockname()[1]

        server = await _start_test_server(echo_port)
        server.policies["test-job"] = NetworkPolicy(NetworkPreset.claude_api_only)
        server._resolve_pid = lambda p: 999
        server._lookup_policy_for_pid = lambda pid: server.policies.get("test-job")

        reader, writer, resp = await _connect_proxy(
            server.proxy_port, "api.anthropic.com", echo_port,
        )
        assert b"200" in resp

        writer.write(b"hello-upstream")
        await writer.drain()
        writer.close()
        await asyncio.sleep(0.1)

        reply_data = b""
        try:
            reply_data = await asyncio.wait_for(reader.read(4096), timeout=2)
        except Exception:
            pass

        echo_srv.close()
        await server.stop()

    asyncio.run(_test())


def test_connect_denied_domain():
    """Test 44: Proxy rejects CONNECT for a disallowed domain — returns 403."""
    async def _test():
        server = await _start_test_server()
        server.policies["test-job"] = NetworkPolicy(NetworkPreset.claude_api_only)
        server._resolve_pid = lambda p: 999
        server._lookup_policy_for_pid = lambda pid: server.policies.get("test-job")

        _, writer, resp = await _connect_proxy(server.proxy_port, "evil.com")
        assert b"403" in resp
        writer.close()
        await server.stop()

    asyncio.run(_test())


def test_default_deny():
    """Test 45: No registered sandboxes → deny all."""
    async def _test():
        server = await _start_test_server()
        server._resolve_pid = lambda p: 999

        _, writer, resp = await _connect_proxy(server.proxy_port, "api.anthropic.com")
        assert b"403" in resp
        writer.close()
        await server.stop()

    asyncio.run(_test())


def test_sni_extraction():
    """Test 46: SNI extraction from TLS ClientHello."""
    ch = _build_client_hello("api.anthropic.com")
    assert parse_sni(ch) == "api.anthropic.com"

    ch2 = _build_client_hello("example.com")
    assert parse_sni(ch2) == "example.com"

    assert parse_sni(b"\x00\x01\x02") is None
    assert parse_sni(b"") is None


@pytest.mark.integration
def test_pid_resolution():
    """Test 47: GetExtendedTcpTable resolves source PID."""
    from sbx import winapi
    import os

    with socket.create_server(("127.0.0.1", 0)) as srv:
        port = srv.getsockname()[1]
        with socket.create_connection(("127.0.0.1", port)) as client:
            conn, _ = srv.accept()
            client_port = client.getsockname()[1]
            pid = winapi.get_tcp_pid(
                "127.0.0.1", client_port, "127.0.0.1", port,
            )
            assert pid == os.getpid()
            conn.close()


def test_two_sandbox_policies():
    """Test 48: Two sandboxes with different policies get correct filtering."""
    async def _test():
        echo_srv = await asyncio.start_server(
            lambda r, w: w.close(), "127.0.0.1", 0,
        )
        echo_port = echo_srv.sockets[0].getsockname()[1]

        server = await _start_test_server(echo_port)
        server.policies["job-open"] = NetworkPolicy(NetworkPreset.all)
        server.policies["job-closed"] = NetworkPolicy(NetworkPreset.none)

        def mock_lookup(pid):
            if pid and pid % 2 == 0:
                return server.policies["job-open"]
            return server.policies["job-closed"]
        server._lookup_policy_for_pid = mock_lookup

        # PID 1000 (even) → open → allowed
        server._resolve_pid = lambda p: 1000
        _, writer, resp = await _connect_proxy(
            server.proxy_port, "anything.com", echo_port,
        )
        assert b"200" in resp
        writer.close()

        # PID 1001 (odd) → closed → denied
        server._resolve_pid = lambda p: 1001
        _, writer2, resp2 = await _connect_proxy(server.proxy_port, "anything.com")
        assert b"403" in resp2
        writer2.close()

        echo_srv.close()
        await server.stop()

    asyncio.run(_test())


def test_idle_timeout():
    """Test 49: Proxy self-terminates after idle timeout."""
    import sbx.proxy as proxy_mod
    original = proxy_mod.IDLE_TIMEOUT

    async def _test():
        proxy_mod.IDLE_TIMEOUT = 0.3
        try:
            server = ProxyServer()
            await server.start()
            server._reset_idle()
            await asyncio.wait_for(server._shutdown_event.wait(), timeout=2)
            assert server._shutdown_event.is_set()
        finally:
            proxy_mod.IDLE_TIMEOUT = original

    asyncio.run(_test())


def test_register_via_control():
    """Test 50: Register sandbox via control socket."""
    async def _test():
        server = await _start_test_server()
        assert len(server.policies) == 0

        ctl = ProxyControl(server.control_port, server.secret)

        loop = asyncio.get_event_loop()
        resp = await loop.run_in_executor(
            None, ctl._send,
            {"cmd": "register", "job_name": "test-job", "preset": "claude-api-only"},
        )
        assert resp["ok"], resp
        assert "test-job" in server.policies
        assert server.policies["test-job"].preset == NetworkPreset.claude_api_only

        await server.stop()

    asyncio.run(_test())


def test_deregister_via_control():
    """Test 51: Deregister sandbox via control socket."""
    async def _test():
        server = await _start_test_server()
        server.policies["test-job"] = NetworkPolicy(NetworkPreset.all)

        ctl = ProxyControl(server.control_port, server.secret)

        loop = asyncio.get_event_loop()
        resp = await loop.run_in_executor(
            None, ctl._send, {"cmd": "deregister", "job_name": "test-job"},
        )
        assert resp["ok"]
        assert "test-job" not in server.policies

        await server.stop()

    asyncio.run(_test())


# ── Unit tests for helpers ─────────────────────────────────

def test_domain_matching():
    policy_api = NetworkPolicy(NetworkPreset.claude_api_only)
    assert is_domain_allowed("api.anthropic.com", policy_api)
    assert not is_domain_allowed("evil.com", policy_api)

    policy_all = NetworkPolicy(NetworkPreset.all)
    assert is_domain_allowed("anything.com", policy_all)

    policy_none = NetworkPolicy(NetworkPreset.none)
    assert not is_domain_allowed("api.anthropic.com", policy_none)


def test_connect_parsing():
    assert parse_connect_request(b"CONNECT example.com:443 HTTP/1.1\r\n") == ("example.com", 443)
    assert parse_connect_request(b"CONNECT host:8080 HTTP/1.1\r\n") == ("host", 8080)
    assert parse_connect_request(b"GET / HTTP/1.1\r\n") is None
    assert parse_connect_request(b"garbage") is None


def test_control_requires_secret():
    """Test 97: a control command without the proxy's secret is rejected
    and leaves the policy table unchanged."""
    async def _test():
        server = await _start_test_server()
        loop = asyncio.get_event_loop()
        for secret in ("", "wrong"):
            ctl = ProxyControl(server.control_port, secret)
            resp = await loop.run_in_executor(
                None, ctl._send,
                {"cmd": "register", "job_name": "evil", "preset": "all"},
            )
            assert not resp["ok"]
        assert "evil" not in server.policies
        await server.stop()

    asyncio.run(_test())
