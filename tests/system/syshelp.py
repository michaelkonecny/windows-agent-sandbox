"""Drive the `sbx` CLI as a subprocess and run probe sessions."""
from __future__ import annotations

import ast
import json
import os
import queue
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

import pytest

import probes
from probes import Shell

REPO = Path(__file__).resolve().parents[2]
SESSION_TIMEOUT = 60
SBX_HOME = Path(os.environ.get("LOCALAPPDATA", "")) / "sbx"
WORKSPACE = Path(r"C:\Users\sbx-user")
JOB_PREFIX = "Global\\sbx-job-"


def _env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = dict(os.environ)
    env.pop("HTTPS_PROXY", None)
    env.update(extra or {})
    return env


def sbx(*args: str, timeout: float = 120, check: bool = False) -> subprocess.CompletedProcess:
    """Run `python -m sbx <args>` from the repo root."""
    res = subprocess.run(
        [sys.executable, "-m", "sbx", *args],
        cwd=REPO, env=_env(), capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=timeout,
    )
    if check:
        assert res.returncode == 0, _describe(args, res)
    return res


def _describe(args, res) -> str:
    return (
        f"sbx {' '.join(map(str, args))} → exit {res.returncode}\n"
        f"stdout:\n{res.stdout}\nstderr:\n{res.stderr}"
    )


def sbx_list() -> dict[str, str]:
    """name → state, parsed from `sbx list`."""
    out = sbx("list", check=True).stdout
    rows = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].startswith("sbxsys-"):
            rows[parts[0]] = parts[1]
    return rows


def sbx_status(project: Path) -> dict[str, object]:
    out = sbx("status", str(project), check=True).stdout
    info: dict[str, object] = {}
    for line in out.splitlines():
        key, sep, value = line.strip().partition(": ")
        if sep:
            info[key] = value
    if "pids" in info:
        info["pids"] = ast.literal_eval(str(info["pids"]))
    return info


def configure(project: Path, **changes) -> None:
    """Rewrite keys of the project's .sandbox/config.json in place."""
    path = project / ".sandbox" / "config.json"
    cfg = json.loads(path.read_text(encoding="utf-8"))
    cfg.update(changes)
    path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")


def write_config(project: Path, mounts: list[dict], shell: str, network: str) -> Path:
    path = project / ".sandbox" / "config.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(
        {"mounts": mounts, "shell": shell, "network": network}, indent=2,
    ), encoding="utf-8")
    return path


def job_name(sandbox: str) -> str:
    return JOB_PREFIX + sandbox


@dataclass
class SessionResult:
    returncode: int
    stdout: str
    stderr: str
    probes: dict[str, str] = field(default_factory=dict)

    def expect(self, pid: str, verdict: str) -> None:
        got = self.probes.get(pid)
        assert got == verdict, (
            f"probe {pid}: expected {verdict}, got {got}\n"
            f"--- stdout ---\n{self.stdout[-3000:]}\n--- stderr ---\n{self.stderr[-2000:]}"
        )


def _script(shell: Shell, lines: list[str]) -> bytes:
    body = [*shell.preamble(), *lines, shell.exit()]
    return ("\n".join(body) + "\n").encode("utf-8")


def run_session(
    project: Path, shell: Shell, lines: list[str],
    env: dict[str, str] | None = None,
) -> SessionResult:
    """One `sbx start` with a probe script on stdin, ending with `exit`.
    `env` adds variables to the host-side `sbx start` process."""
    try:
        res = subprocess.run(
            [sys.executable, "-m", "sbx", "start", str(project)],
            cwd=REPO, env=_env(env), input=_script(shell, lines),
            capture_output=True, timeout=SESSION_TIMEOUT,
        )
    except subprocess.TimeoutExpired as e:
        sbx("stop", str(project))
        out = (e.stdout or b"").decode("utf-8", "replace")
        pytest.fail(f"session timed out after {SESSION_TIMEOUT}s\n{out[-3000:]}")
    out = res.stdout.decode("utf-8", "replace")
    err = res.stderr.decode("utf-8", "replace")
    return SessionResult(res.returncode, out, err, probes.parse(out))


class LiveSession:
    """A `sbx start` kept open so the host can inspect it mid-session."""

    def __init__(self, project: Path, shell: Shell) -> None:
        self.project = project
        self.shell = shell
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "sbx", "start", str(project)],
            cwd=REPO, env=_env(), stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.deadline = time.monotonic() + SESSION_TIMEOUT
        self.output = ""
        self._chunks: queue.Queue[bytes] = queue.Queue()
        threading.Thread(target=self._read, daemon=True).start()
        self.send(shell.preamble())

    def _read(self) -> None:
        for chunk in iter(lambda: self.proc.stdout.read1(4096), b""):
            self._chunks.put(chunk)

    def send(self, lines: list[str]) -> None:
        if lines:
            self.proc.stdin.write(("\n".join(lines) + "\n").encode("utf-8"))
            self.proc.stdin.flush()

    def probes(self) -> dict[str, str]:
        while not self._chunks.empty():
            self.output += self._chunks.get().decode("utf-8", "replace")
        return probes.parse(self.output)

    def wait_probe(self, pid: str) -> str:
        """Block until probe `pid` reports; fail the test at the session deadline."""
        while time.monotonic() < self.deadline:
            got = self.probes().get(pid)
            if got is not None:
                return got
            if self.proc.poll() is not None and self._chunks.empty():
                break
            time.sleep(0.1)
        self.kill()
        pytest.fail(f"probe {pid} never reported\n{self.output[-3000:]}\n"
                    f"stderr:\n{self._stderr()}")

    def _stderr(self) -> str:
        try:
            return self.proc.stderr.read().decode("utf-8", "replace")[-2000:]
        except Exception:
            return ""

    def close(self) -> int:
        """Send `exit`, wait for the session to end; return its exit code."""
        try:
            self.send([self.shell.exit()])
            self.proc.stdin.close()
        except OSError:
            pass
        try:
            return self.proc.wait(timeout=max(1, self.deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            self.kill()
            pytest.fail(f"session did not exit before its {SESSION_TIMEOUT}s limit")

    def kill(self) -> None:
        sbx("stop", str(self.project))
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def wait_until(cond, timeout: float, step: float = 0.2) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if cond():
            return True
        time.sleep(step)
    return cond()


def host_curl(url: str) -> int:
    return subprocess.run(
        [probes.CURL, *probes.CURL_OPTS.split(), url], capture_output=True,
    ).returncode
