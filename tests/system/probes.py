"""Probe snippets per shell.

A probe is one shell command that prints exactly one line,
`PROBE <id> OK` or `PROBE <id> DENIED`. OK means the attempted access
succeeded. Tests assert on these lines only.
"""
from __future__ import annotations

import re
import shutil
from dataclasses import dataclass
from pathlib import Path

CURL = r"C:\Windows\System32\curl.exe"
CURL_OPTS = "-s -o NUL --connect-timeout 5 --max-time 10"

_LINE = re.compile(r"^PROBE (\S+) (OK|DENIED)\s*$", re.MULTILINE)


def parse(output: str) -> dict[str, str]:
    return {m.group(1): m.group(2) for m in _LINE.finditer(output)}


def _curl_args(url: str, via: str) -> str:
    """via: 'env' — honour HTTPS_PROXY; 'direct' — bypass any proxy;
    anything else — explicit proxy URL."""
    if via == "env":
        return f"{CURL_OPTS} {url}"
    if via == "direct":
        return f'{CURL_OPTS} --noproxy "*" {url}'
    return f"{CURL_OPTS} -x {via} {url}"


@dataclass(frozen=True)
class Shell:
    name: str

    def installed(self) -> bool:
        if self.name == "git-bash":
            return Path(r"C:\Program Files\Git\bin\bash.exe").is_file()
        exe = {"cmd": "cmd.exe", "powershell": "powershell.exe", "pwsh": "pwsh.exe"}
        return shutil.which(exe[self.name]) is not None

    @property
    def _ps(self) -> bool:
        return self.name in ("powershell", "pwsh")

    def preamble(self) -> list[str]:
        return ["@echo off"] if self.name == "cmd" else []

    def _verdict(self, pid: str, cond: str) -> str:
        """Shell snippet: print OK if the command `cond` succeeds."""
        if self.name == "cmd":
            return f"{cond} && echo PROBE {pid} OK || echo PROBE {pid} DENIED"
        if self.name == "git-bash":
            return f'{cond} && echo "PROBE {pid} OK" || echo "PROBE {pid} DENIED"'
        return (
            f"try {{ {cond}; if ($?) {{ 'PROBE {pid} OK' }} "
            f"else {{ 'PROBE {pid} DENIED' }} }} catch {{ 'PROBE {pid} DENIED' }}"
        )

    def read(self, pid: str, path: str | Path, token: str) -> str:
        """OK iff `path` is readable and contains `token`."""
        p = str(path)
        if self.name == "cmd":
            return self._verdict(pid, f'findstr /c:"{token}" "{p}" >nul 2>&1')
        if self.name == "git-bash":
            return self._verdict(pid, f"grep -q '{token}' '{_posix(p)}' 2>/dev/null")
        return (
            f"try {{ if ((Get-Content -Raw -LiteralPath '{p}' -ErrorAction Stop)"
            f" -match '{token}') {{ 'PROBE {pid} OK' }} else {{ 'PROBE {pid} DENIED' }} }}"
            f" catch {{ 'PROBE {pid} DENIED' }}"
        )

    def write(self, pid: str, path: str | Path, content: str) -> str:
        """OK iff `content` could be written to `path`."""
        p = str(path)
        if self.name == "cmd":
            return self._verdict(pid, f'(echo {content})>"{p}" 2>nul')
        if self.name == "git-bash":
            return self._verdict(pid, f"printf '%s\\n' '{content}' 2>/dev/null >'{_posix(p)}'")
        return self._verdict(
            pid, f"Set-Content -LiteralPath '{p}' -Value '{content}' -ErrorAction Stop",
        )

    def list_dir(self, pid: str, path: str | Path, entry: str) -> str:
        """OK iff directory `path` lists an entry named `entry`."""
        p = str(path)
        if self.name == "cmd":
            return self._verdict(pid, f'dir /b "{p}" 2>nul | findstr /x /c:"{entry}" >nul')
        if self.name == "git-bash":
            return self._verdict(pid, f"ls -1 '{_posix(p)}' 2>/dev/null | grep -qx '{entry}'")
        return (
            f"if (Get-ChildItem -LiteralPath '{p}' -Name -ErrorAction SilentlyContinue"
            f" | Where-Object {{ $_ -eq '{entry}' }}) {{ 'PROBE {pid} OK' }}"
            f" else {{ 'PROBE {pid} DENIED' }}"
        )

    def http(self, pid: str, url: str, via: str = "env") -> str:
        """OK iff curl gets any HTTP response (see `_curl_args` for `via`)."""
        args = _curl_args(url, via)
        if self.name == "cmd":
            return self._verdict(pid, f"{CURL} {args}")
        args = args.replace('"*"', "'*'")  # no globbing/expansion of *
        if self.name == "git-bash":
            return self._verdict(pid, f"'{_posix(CURL)}' {args}")
        return (
            f"& '{CURL}' {args}; "
            f"if ($LASTEXITCODE -eq 0) {{ 'PROBE {pid} OK' }} else {{ 'PROBE {pid} DENIED' }}"
        )

    def env_set(self, pid: str, var: str) -> str:
        """OK iff environment variable `var` is set and non-empty."""
        if self.name == "cmd":
            return f"if defined {var} (echo PROBE {pid} OK) else (echo PROBE {pid} DENIED)"
        if self.name == "git-bash":
            return self._verdict(pid, f'[ -n "${var}" ]')
        return f"if ($env:{var}) {{ 'PROBE {pid} OK' }} else {{ 'PROBE {pid} DENIED' }}"

    def ready(self, pid: str = "ready") -> str:
        """Always prints OK — marks that the shell got this far."""
        if self._ps:
            return f"'PROBE {pid} OK'"
        if self.name == "cmd":
            return f"echo PROBE {pid} OK"
        return f'echo "PROBE {pid} OK"'

    def background_child(self) -> str:
        """Start a long-running child that outlives the command."""
        if self.name == "cmd":
            return 'start "" /b ping -n 600 127.0.0.1 >nul'
        if self.name == "git-bash":
            return "sleep 600 &"
        return "$null = Start-Process ping.exe -ArgumentList '-n','600','127.0.0.1' -NoNewWindow -PassThru"

    def exit(self) -> str:
        return "exit"


def _posix(path: str) -> str:
    return path.replace("\\", "/")


SHELLS = [Shell(n) for n in ("git-bash", "cmd", "powershell", "pwsh")]
