"""Filesystem isolation system tests (81-87), per shell."""
from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from syshelp import WORKSPACE, configure, run_session, sbx, sbx_list, write_config

SYSTEM_DIRS = [r"C:\Windows", r"C:\Program Files", r"C:\ProgramData", r"C:\Users\Public"]


def _in_sandbox(name: str, *parts: str) -> str:
    return str(WORKSPACE.joinpath(name, *parts))


def test_81_own_mount(pair, shell):
    a = pair.a
    configure(a.path, shell=shell.name)
    content = f"written-by-{shell.name}-{uuid.uuid4().hex[:8]}"
    probe_file = f"probe-{shell.name}.txt"
    res = run_session(a.path, shell, [
        shell.read("read", _in_sandbox(a.name, "repo", "secret.txt"), a.token),
        shell.write("write", _in_sandbox(a.name, "repo", probe_file), content),
    ])
    res.expect("read", "OK")
    res.expect("write", "OK")
    host_copy = a.path / probe_file
    assert host_copy.is_file(), "write didn't reach the host project dir"
    assert content in host_copy.read_text(encoding="utf-8", errors="replace")


def test_82_system_paths_readable(pair, shell):
    configure(pair.a.path, shell=shell.name)
    res = run_session(pair.a.path, shell, [
        shell.read("winini", r"C:\Windows\win.ini", "fonts"),
    ])
    res.expect("winini", "OK")


def test_83_host_secret_denied(pair, shell):
    configure(pair.a.path, shell=shell.name)
    res = run_session(pair.a.path, shell, [
        shell.read("secret", pair.host_secret, pair.host_token),
    ])
    res.expect("secret", "DENIED")


def test_84_other_sandbox_denied(pair, shell):
    a, b = pair.a, pair.b
    configure(a.path, shell=shell.name)
    res = run_session(a.path, shell, [
        shell.read("mount-read", _in_sandbox(b.name, "repo", "secret.txt"), b.token),
        shell.write("mount-write", _in_sandbox(b.name, "repo", "from-a.txt"), "x"),
        shell.read("host-read", b.secret, b.token),
        shell.write("host-write", b.path / "from-a.txt", "x"),
    ])
    for pid in ("mount-read", "mount-write", "host-read", "host-write"):
        res.expect(pid, "DENIED")
    assert not (b.path / "from-a.txt").exists()


def test_85_system_paths_read_only(pair, shell):
    configure(pair.a.path, shell=shell.name)
    name = f"sbxsys-probe-{shell.name}.txt"
    res = run_session(pair.a.path, shell, [
        shell.write(f"w{i}", Path(d) / name, "x") for i, d in enumerate(SYSTEM_DIRS)
    ])
    for i, d in enumerate(SYSTEM_DIRS):
        assert res.probes.get(f"w{i}") == "DENIED", f"sandbox could write to {d}\n{res.stdout[-2000:]}"


def test_86_single_file_mount(pair, shell):
    configure(pair.a.path, shell=shell.name)
    res = run_session(pair.a.path, shell, [
        shell.read("mounted", _in_sandbox(pair.a.name, "config", "tool.json"), pair.cfg_token),
        shell.read("sibling", pair.sibling, pair.sibling_token),
    ])
    res.expect("mounted", "OK")
    res.expect("sibling", "DENIED")


def test_87_shared_source(installed, shell):
    w = installed
    c, d = w.project("sbxsys-c"), w.project("sbxsys-d")
    for p in (c, d):
        if p.name in sbx_list():
            sbx("destroy", str(p.path), check=True)
        write_config(p.path, [
            {"source": ".", "target": "repo"},
            {"source": str(w.shared), "target": "shared"},
        ], shell.name, "none")
        sbx("create", str(p.config), check=True)
    tag = f"{shell.name}-{uuid.uuid4().hex[:6]}"
    try:
        res = run_session(c.path, shell, [
            shell.write("c-write", _in_sandbox(c.name, "shared", f"c-{tag}.txt"), f"C{tag}"),
        ])
        res.expect("c-write", "OK")
        res = run_session(d.path, shell, [
            shell.read("d-read", _in_sandbox(d.name, "shared", f"c-{tag}.txt"), f"C{tag}"),
            shell.write("d-write", _in_sandbox(d.name, "shared", f"d-{tag}.txt"), f"D{tag}"),
        ])
        res.expect("d-read", "OK")
        res.expect("d-write", "OK")

        sbx("destroy", str(c.path), check=True)
        res = run_session(d.path, shell, [
            shell.read("after-read", _in_sandbox(d.name, "shared", f"d-{tag}.txt"), f"D{tag}"),
            shell.write("after-write", _in_sandbox(d.name, "shared", f"d2-{tag}.txt"), "x"),
        ])
        res.expect("after-read", "OK")
        res.expect("after-write", "OK")
    finally:
        for p in (c, d):
            if p.name in sbx_list():
                sbx("destroy", str(p.path))
