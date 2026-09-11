from __future__ import annotations

import logging
import os
import re
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

from sbx import winapi
from sbx.config import NetworkPreset, ShellKind
from sbx.errors import ProcessError
from sbx.identity import get_credentials

log = logging.getLogger(__name__)

PIPE_PREFIX = r"\\.\pipe\sbx-"
JOB_PREFIX = r"Global\sbx-job-"

RELAY_BUF = 4096

# Terminal size used when the caller gives none and the host has no
# console to measure (a redirected or non-interactive invocation).
DEFAULT_SIZE = (120, 30)

# Resize requests travel in band on the input pipe as a private-use OSC
# sequence, which avoids a third pipe and its connection handshake.  9999
# is unregistered, so it cannot collide with a real terminal escape.
RESIZE_OSC = re.compile(rb"\x1b\]9999;(\d+);(\d+)\x07")
RESIZE_INTRODUCER = b"\x1b]9999;"
# The longest request worth waiting for: introducer, two five-digit
# dimensions and the terminator.
MAX_HELD_FRAGMENT = len(RESIZE_INTRODUCER) + len("99999;99999\x07")


def resize_request(cols: int, rows: int) -> bytes:
    """The in-band message the host sends to resize the pseudoconsole.

    Both sides go through here so the wire format cannot drift.
    """
    return f"\x1b]9999;{cols};{rows}\x07".encode()


def host_terminal_size() -> tuple[int, int]:
    """The host console's visible size, or DEFAULT_SIZE if there is none."""
    try:
        return winapi.get_console_screen_buffer_info(
            winapi.get_std_handle(winapi.STD_OUTPUT_HANDLE)
        )
    except OSError:
        return DEFAULT_SIZE

SHELL_EXECUTABLES = {
    ShellKind.cmd: "cmd.exe",
    ShellKind.powershell: "powershell.exe",
    ShellKind.pwsh: "pwsh.exe",
    ShellKind.git_bash: r"C:\Program Files\Git\bin\bash.exe",
}

def _is_cygwin_shell(shell_path: str) -> bool:
    """Detect if a shell is Cygwin/MSYS2-based by checking for the
    runtime DLLs near the executable.  Git for Windows keeps the
    real bash in usr/bin/ while bin/bash.exe is a tiny wrapper, so
    we check the parent directory and the sibling usr/bin/ tree."""
    p = Path(shell_path).resolve()
    dirs = [p.parent]
    usr_bin = p.parent.parent / "usr" / "bin"
    if usr_bin.is_dir():
        dirs.append(usr_bin)
    return any(
        (d / dll).exists()
        for d in dirs
        for dll in ("msys-2.0.dll", "cygwin1.dll")
    )


def _pipe_names(sandbox_name: str) -> tuple[str, str]:
    return (
        f"{PIPE_PREFIX}{sandbox_name}-in",
        f"{PIPE_PREFIX}{sandbox_name}-out",
    )


def _job_name(sandbox_name: str) -> str:
    return f"{JOB_PREFIX}{sandbox_name}"


def resolve_shell(shell: ShellKind) -> str:
    path = SHELL_EXECUTABLES.get(shell)
    if path and os.path.isfile(path):
        return path
    found = shutil.which(path or shell.value)
    if found:
        return found
    raise ProcessError(f"shell not found: {shell.value}")


def _runner_cmd(
    sandbox_name: str, sandbox_sid: str, shell_path: str,
    cols: int, rows: int,
) -> str:
    python = sys.executable
    return (
        f'"{python}" -m sbx _run {sandbox_name} {sandbox_sid} '
        f'"{shell_path}" {cols} {rows}'
    )


def build_env(
    network_preset: NetworkPreset,
    proxy_port: int | None = None,
    base_env: dict[str, str] | None = None,
) -> dict[str, str]:
    env = dict(base_env if base_env is not None else os.environ)
    if network_preset in (NetworkPreset.claude_api_only, NetworkPreset.all):
        if proxy_port is not None:
            env["HTTPS_PROXY"] = f"http://127.0.0.1:{proxy_port}"
    else:
        env.pop("HTTPS_PROXY", None)
    project_root = str(Path(__file__).parent.parent)
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{project_root};{existing}" if existing else project_root
    return env


@dataclass
class StartHandle:
    runner_process: int
    runner_pid: int
    pipe_in: int
    pipe_out: int
    job_name: str

    def close(self) -> None:
        winapi.close_handle(self.runner_process)
        winapi.close_handle(self.pipe_in)
        winapi.close_handle(self.pipe_out)


def start_sandbox(
    sandbox_name: str,
    sandbox_sid: str,
    shell: ShellKind | str,
    network_preset: NetworkPreset = NetworkPreset.none,
    proxy_port: int | None = None,
    credentials_path: Path | None = None,
    cols: int | None = None,
    rows: int | None = None,
) -> StartHandle:
    if cols is None or rows is None:
        host_cols, host_rows = host_terminal_size()
        cols = cols or host_cols
        rows = rows or host_rows

    if isinstance(shell, ShellKind):
        shell_path = resolve_shell(shell)
    else:
        shell_path = shell

    if _is_cygwin_shell(shell_path):
        # Cygwin shells cannot start under restricted SIDs at all — init
        # fails creating a signal pipe with ERROR_ACCESS_DENIED — so they
        # run with privileges stripped but no synthetic SID. Every sandbox
        # runs as the same account and backing paths grant that account,
        # so such a shell reaches every other sandbox's mounts. Warn
        # before anything is created, so the message survives a later
        # failure.
        log.warning(
            "%s is Cygwin-based, so this sandbox runs without filesystem "
            "isolation: it can read and write other sandboxes' mounts. "
            "Use cmd, powershell or pwsh for an isolated sandbox.",
            shell_path,
        )

    username, password = get_credentials(credentials_path)

    pipe_in_name, pipe_out_name = _pipe_names(sandbox_name)
    sa, _sd = winapi.create_null_dacl_sa()

    pipe_in = winapi.create_named_pipe(
        pipe_in_name, winapi.PIPE_ACCESS_OUTBOUND, sa=sa,
    )
    pipe_out = winapi.create_named_pipe(
        pipe_out_name, winapi.PIPE_ACCESS_INBOUND, sa=sa,
    )

    env = build_env(network_preset, proxy_port)
    env["USERNAME"] = username
    env_block = winapi.make_env_block(env)

    cmd = _runner_cmd(sandbox_name, sandbox_sid, shell_path, cols, rows)
    log.info("launching runner: %s", cmd)

    try:
        proc_h, thread_h, pid, _ = winapi.create_process_with_logon(
            username, ".", password, cmd,
            creation_flags=(
                winapi.CREATE_UNICODE_ENVIRONMENT | winapi.CREATE_NO_WINDOW
            ),
            env=env_block,
        )
    except OSError as e:
        winapi.close_handle(pipe_in)
        winapi.close_handle(pipe_out)
        raise ProcessError(f"failed to launch runner: {e}")

    winapi.close_handle(thread_h)

    import threading

    connect_errors: list[str] = []

    def _connect_with_timeout(pipe, name):
        try:
            winapi.connect_named_pipe(pipe)
        except OSError as e:
            connect_errors.append(f"{name}: {e}")

    t_in = threading.Thread(target=_connect_with_timeout, args=(pipe_in, "in"))
    t_out = threading.Thread(target=_connect_with_timeout, args=(pipe_out, "out"))
    t_in.start()
    t_out.start()

    t_in.join(timeout=15)
    t_out.join(timeout=15)

    if t_in.is_alive() or t_out.is_alive() or connect_errors:
        winapi.close_handle(proc_h)
        winapi.close_handle(pipe_in)
        winapi.close_handle(pipe_out)
        if connect_errors:
            raise ProcessError(f"pipe connect failed: {connect_errors}")
        raise ProcessError("runner did not connect to pipes within 15s")

    log.info("runner connected, pid=%d", pid)
    return StartHandle(
        runner_process=proc_h,
        runner_pid=pid,
        pipe_in=pipe_in,
        pipe_out=pipe_out,
        job_name=_job_name(sandbox_name),
    )


def sandbox_is_running(sandbox_name: str) -> bool:
    """Whether a sandbox currently has a live runner.

    The Job Object is created by the runner with kill-on-close, so it
    exists exactly while the sandbox is up.
    """
    try:
        job = winapi.open_job_object(
            _job_name(sandbox_name), winapi.JOB_OBJECT_QUERY
        )
    except OSError:
        return False
    winapi.close_handle(job)
    return True


def stop_sandbox(sandbox_name: str) -> None:
    name = _job_name(sandbox_name)
    try:
        job = winapi.open_job_object(name, winapi.JOB_OBJECT_TERMINATE)
    except OSError as e:
        raise ProcessError(f"cannot open Job Object {name}: {e}")
    try:
        winapi.terminate_job_object(job)
    except OSError as e:
        raise ProcessError(f"cannot terminate Job Object: {e}")
    finally:
        winapi.close_handle(job)
    log.info("terminated sandbox %s", sandbox_name)


def execute_runner(
    sandbox_name: str, sandbox_sid: str, shell_path: str,
    cols: int = DEFAULT_SIZE[0], rows: int = DEFAULT_SIZE[1],
) -> None:
    import ctypes
    SEM_FAILCRITICALERRORS = 0x0001
    SEM_NOGPFAULTERRORBOX = 0x0002
    ctypes.windll.kernel32.SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX)

    log_path = Path(r"C:\Users\Public") / "sbx-runner.log"
    _log_file = None
    try:
        _log_file = open(log_path, "w", encoding="utf-8")
    except OSError:
        pass

    def _log(msg: str) -> None:
        if _log_file:
            try:
                _log_file.write(msg + "\n")
                _log_file.flush()
            except OSError:
                pass

    try:
        _execute_runner_inner(
            sandbox_name, sandbox_sid, shell_path, cols, rows, _log
        )
    except Exception:
        import traceback
        _log(traceback.format_exc())
        raise
    finally:
        if _log_file:
            _log_file.close()


def split_resize_requests(
    data: bytes,
) -> tuple[bytes, list[tuple[int, int]], bytes]:
    """Pull resize requests out of a host-to-shell byte stream.

    Returns (payload, resizes, held).  payload is what the shell should
    see, resizes are the (cols, rows) pairs found in order, and held is a
    trailing fragment that could still grow into a resize sequence and so
    must wait for the next read.  Without holding it back, a sequence
    split across two reads would reach the shell as garbage.
    """
    payload = bytearray()
    resizes: list[tuple[int, int]] = []
    pos = 0
    for match in RESIZE_OSC.finditer(data):
        payload += data[pos:match.start()]
        resizes.append((int(match.group(1)), int(match.group(2))))
        pos = match.end()

    rest = data[pos:]
    start = rest.rfind(b"\x1b]")
    if start != -1 and _could_still_become_a_resize(rest[start:]):
        return bytes(payload + rest[:start]), resizes, bytes(rest[start:])
    return bytes(payload + rest), resizes, b""


def _could_still_become_a_resize(fragment: bytes) -> bool:
    """Whether waiting for more bytes could complete a resize request.

    Only a fragment that might still be one is worth holding.  Holding
    anything that merely starts with ESC-] means a stray Alt+] swallows
    every keystroke after it and the sandbox's keyboard goes dead, with
    nothing logged.  Everything else is forwarded straight away —
    delivering it in two pieces costs nothing, since the shell is reading
    a byte stream.
    """
    if len(fragment) >= MAX_HELD_FRAGMENT:
        return False
    if len(fragment) < len(RESIZE_INTRODUCER):
        return RESIZE_INTRODUCER.startswith(fragment)
    return fragment.startswith(RESIZE_INTRODUCER) and all(
        byte in b"0123456789;" for byte in fragment[len(RESIZE_INTRODUCER):]
    )


def _relay_output(src: int, dst: int, _log) -> None:
    """ConPTY to host.  Blocking reads — no polling.

    Ends when either pipe breaks: the ConPTY side closes when the shell
    exits, the host side when the user's session goes away.
    """
    total = 0
    while True:
        try:
            data = winapi.read_file(src, RELAY_BUF)
        except OSError as e:
            _log(f"output relay ended after {total} bytes: {e}")
            return
        if not data:
            _log(f"output relay saw end of stream after {total} bytes")
            return
        try:
            winapi.write_file(dst, data)
        except OSError as e:
            _log(f"output relay write ended after {total} bytes: {e}")
            return
        total += len(data)


def _relay_input(src: int, dst: int, hpc: int, _log) -> None:
    """Host to ConPTY, applying resize requests found in the stream."""
    held = b""
    while True:
        try:
            data = winapi.read_file(src, RELAY_BUF)
        except OSError as e:
            _log(f"input relay ended: {e}")
            return
        if not data:
            return

        payload, resizes, held = split_resize_requests(held + data)
        for cols, rows in resizes:
            _log(f"resizing pseudoconsole to {cols}x{rows}")
            try:
                winapi.resize_pseudo_console(hpc, cols, rows)
            except OSError as e:
                _log(f"resize failed: {e}")
        if not payload:
            continue
        try:
            winapi.write_file(dst, payload)
        except OSError as e:
            _log(f"input relay write ended: {e}")
            return


def _execute_runner_inner(
    sandbox_name: str, sandbox_sid: str, shell_path: str,
    cols: int, rows: int,
    _log,
) -> None:
    import threading

    _log(f"runner start: name={sandbox_name} sid={sandbox_sid} "
         f"shell={shell_path} size={cols}x{rows}")

    pipe_in_name, pipe_out_name = _pipe_names(sandbox_name)
    job_name_str = _job_name(sandbox_name)

    _log(f"opening pipes: in={pipe_in_name} out={pipe_out_name}")
    pipe_in = winapi.open_file(pipe_in_name, winapi.GENERIC_READ)
    pipe_out = winapi.open_file(pipe_out_name, winapi.GENERIC_WRITE)
    _log(f"pipes opened: in={pipe_in} out={pipe_out}")

    # The ConPTY pipe pair.  Nothing is inherited — the pseudoconsole
    # duplicates what it needs into its own conhost.
    pty_in_read, pty_in_write = winapi.create_pipe(inheritable=False)
    pty_out_read, pty_out_write = winapi.create_pipe(inheritable=False)

    hpc = winapi.create_pseudo_console(cols, rows, pty_in_read, pty_out_write)
    _log(f"pseudoconsole created: {hpc}")
    # The ConPTY owns these ends now.  Holding them open here would stop
    # the output pipe ever reporting end-of-stream.
    winapi.close_handle(pty_in_read)
    winapi.close_handle(pty_out_write)

    _log(f"creating Job Object: {job_name_str}")
    sa, _sd = winapi.create_null_dacl_sa()
    job = winapi.create_job_object(job_name_str, sa=sa)
    winapi.set_job_kill_on_close(job)
    _log(f"Job Object created: {job}")

    cygwin = _is_cygwin_shell(shell_path)
    _log(f"creating restricted token (cygwin={cygwin})")
    from sbx.tokens import create_sandbox_token
    token = create_sandbox_token(sandbox_sid, skip_restricted_sids=cygwin)
    _log(f"token created: {token}")

    _log(f"launching shell: {shell_path}")
    # attr_buf holds the attribute list's memory; it must stay referenced
    # until the list is deleted.
    attr_buf, attr_addr = winapi.init_proc_attribute_list(1)
    winapi.update_proc_attribute_console(attr_addr, hpc)
    try:
        # NULL std handles, not the runner's: a child that inherits std
        # handles writes to them instead of to its pseudoconsole.
        proc_h, thread_h, shell_pid, _ = winapi.create_process_as_user(
            token, shell_path,
            attribute_list=attr_addr,
            std_handles=winapi.NULL_STD_HANDLES,
            inherit_handles=False,
        )
    except OSError as e:
        _log(f"shell launch failed: {e}")
        winapi.close_pseudo_console(hpc)
        for handle in (job, token, pty_in_write, pty_out_read,
                       pipe_in, pipe_out):
            winapi.close_handle(handle)
        raise ProcessError(f"failed to launch shell: {e}")
    finally:
        winapi.delete_proc_attribute_list(attr_addr)

    _log(f"shell launched, pid={shell_pid}")
    winapi.assign_process_to_job(job, proc_h)
    winapi.close_handle(thread_h)

    relay_in = threading.Thread(
        target=_relay_input, args=(pipe_in, pty_in_write, hpc, _log),
        daemon=True,
    )
    relay_out = threading.Thread(
        target=_relay_output, args=(pty_out_read, pipe_out, _log),
        daemon=True,
    )
    relay_in.start()
    relay_out.start()
    _log("relay threads started")

    _log("waiting for shell to exit")
    exit_code = winapi.wait_for_process(proc_h)
    _log(f"shell exited with code {exit_code}")

    # Closing the pseudoconsole breaks the output pipe, which is what
    # releases the output relay from its blocking read.
    _log("closing pseudoconsole")
    winapi.close_pseudo_console(hpc)
    relay_out.join(timeout=2)
    _log(f"output relay joined (alive={relay_out.is_alive()})")

    # The input relay is parked in a blocking read on pipe_in.  Closing
    # that handle from here waits for the pending read to finish, which
    # never happens while the host holds its end open — so leave it to
    # process exit, which the daemon thread cannot delay.  Closing
    # pipe_out matters though: it is how the host learns the shell is
    # gone, via ERROR_BROKEN_PIPE on its reader.
    winapi.close_handle(proc_h)
    for handle in (token, job, pty_in_write, pty_out_read, pipe_out):
        winapi.close_handle(handle)
    _log("runner cleanup done")
