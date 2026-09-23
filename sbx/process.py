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
RELAY_BUF = 4096

# Pseudo-console size when the host has no console to measure (piped
# stdin, tests). Wide, so long command lines don't wrap in the output.
DEFAULT_SIZE = (200, 50)

# Resize requests travel in band on the input pipe as a private-use OSC
# sequence — no third pipe needed. 9999 is unregistered, so it can't
# collide with a real terminal escape.
RESIZE_OSC = re.compile(rb"\x1b\]9999;(\d+);(\d+)\x07")


def resize_request(cols: int, rows: int) -> bytes:
    """The in-band message the host sends to resize the pseudo-console.
    Both sides go through here so the wire format can't drift."""
    return f"\x1b]9999;{cols};{rows}\x07".encode()


def split_resize_requests(
    data: bytes,
) -> tuple[bytes, list[tuple[int, int]], bytes]:
    """Pull resize requests out of a host-to-shell byte stream.

    Returns (payload, resizes, held): what the shell should see, the
    (cols, rows) pairs found in order, and a trailing fragment that could
    still grow into a resize sequence and must wait for the next read.
    A lone trailing ESC is not held — it's a real keystroke, and holding
    it would stall Esc in interactive programs.
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
    if start != -1 and b"\x07" not in rest[start:]:
        return bytes(payload + rest[:start]), resizes, bytes(rest[start:])
    return bytes(payload + rest), resizes, b""
JOB_PREFIX = r"Global\sbx-job-"

SHELL_EXECUTABLES = {
    ShellKind.cmd: "cmd.exe",
    ShellKind.powershell: "powershell.exe",
    ShellKind.pwsh: "pwsh.exe",
    ShellKind.git_bash: r"C:\Program Files\Git\bin\bash.exe",
}

def _pipe_names(sandbox_name: str, nonce: str) -> tuple[str, str]:
    """The random nonce keeps the names unguessable, so nothing can
    connect to a pipe before the runner does."""
    return (
        f"{PIPE_PREFIX}{sandbox_name}-{nonce}-in",
        f"{PIPE_PREFIX}{sandbox_name}-{nonce}-out",
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


# The runner starts here so `-m sbx` finds the package without PYTHONPATH.
PACKAGE_ROOT = Path(__file__).resolve().parent.parent


def _runner_cmd(
    sandbox_name: str, sandbox_sid: str, shell_path: str,
    proxy_port: int | None, nonce: str, host_sid: str,
    size: tuple[int, int],
) -> str:
    port = "-" if proxy_port is None else str(proxy_port)
    return (
        f'"{sys.executable}" -m sbx _run {sandbox_name} {sandbox_sid} '
        f'"{shell_path}" {port} {nonce} {host_sid} {size[0]} {size[1]}'
    )


def _current_user_sid() -> str:
    token = winapi.open_process_token(winapi.TOKEN_QUERY)
    try:
        return winapi.token_user_sid(token)
    finally:
        winapi.close_handle(token)


def shell_env(base: dict[str, str], proxy_port: int | None) -> dict[str, str]:
    """The shell's environment: sbx-user's own block (`base`) plus
    HTTPS_PROXY when the sandbox has a proxy. Nothing from the host."""
    env = dict(base)
    env.pop("HTTPS_PROXY", None)
    if proxy_port is not None:
        env["HTTPS_PROXY"] = f"http://127.0.0.1:{proxy_port}"
    return env


@dataclass
class StartHandle:
    runner_process: int
    runner_pid: int
    pipe_in: int
    pipe_out: int
    job_name: str

    def close_input(self) -> None:
        """Signal EOF to the shell's stdin."""
        winapi.close_handle(self.pipe_in)
        self.pipe_in = 0

    def runner_exited(self) -> bool:
        return winapi.wait_for_process(self.runner_process, timeout_ms=0) is not None

    def exit_code(self) -> int:
        """Block until the runner exits; return the shell's exit code."""
        return winapi.wait_for_process(self.runner_process)

    def close(self) -> None:
        for attr in ("runner_process", "pipe_in", "pipe_out"):
            winapi.close_handle(getattr(self, attr))
            setattr(self, attr, 0)


def start_sandbox(
    sandbox_name: str,
    sandbox_sid: str,
    shell: ShellKind | str,
    network_preset: NetworkPreset = NetworkPreset.none,
    proxy_port: int | None = None,
    credentials_path: Path | None = None,
    size: tuple[int, int] = DEFAULT_SIZE,
) -> StartHandle:
    if isinstance(shell, ShellKind):
        shell_path = resolve_shell(shell)
    else:
        shell_path = shell

    username, password = get_credentials(credentials_path)

    import secrets
    nonce = secrets.token_hex(8)
    host_sid = _current_user_sid()
    pipe_in_name, pipe_out_name = _pipe_names(sandbox_name, nonce)
    # Host: full; sbx-user (the runner): read/write; one instance each.
    pipe_sd = winapi.SecurityDescriptor(
        f"D:(A;;GA;;;SY)(A;;GA;;;{host_sid})"
        f"(A;;GRGW;;;{winapi.account_sid(username)})"
    )
    sa = pipe_sd.attributes()
    try:
        pipe_in = winapi.create_named_pipe(
            pipe_in_name, winapi.PIPE_ACCESS_OUTBOUND, sa=sa, max_instances=1,
        )
        pipe_out = winapi.create_named_pipe(
            pipe_out_name, winapi.PIPE_ACCESS_INBOUND, sa=sa, max_instances=1,
        )
    finally:
        pipe_sd.close()

    if network_preset == NetworkPreset.none:
        proxy_port = None
    cmd = _runner_cmd(
        sandbox_name, sandbox_sid, shell_path, proxy_port, nonce, host_sid, size,
    )
    log.info("launching runner: %s", cmd)

    try:
        # No env block: the runner gets sbx-user's profile environment,
        # never the host's (which may hold secrets).
        proc_h, thread_h, pid, _ = winapi.create_process_with_logon(
            username, ".", password, cmd,
            creation_flags=winapi.CREATE_NO_WINDOW,
            cwd=str(PACKAGE_ROOT),
        )
    except OSError as e:
        winapi.close_handle(pipe_in)
        winapi.close_handle(pipe_out)
        import ctypes
        code = getattr(e, "winerror", 0) or (ctypes.get_last_error() if hasattr(ctypes, "get_last_error") else 0)
        if code == 5:
            raise ProcessError(
                f"failed to launch runner as {username}: access denied — "
                f"stale credentials, or {username} can't read {sys.executable}; "
                f"try: python -m sbx install"
            )
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


def sandbox_pids(sandbox_name: str) -> list[int]:
    """PIDs currently in the sandbox's Job Object (empty if it has none)."""
    try:
        job = winapi.open_job_object(_job_name(sandbox_name), winapi.JOB_OBJECT_QUERY)
    except OSError:
        return []
    try:
        return winapi.job_pids(job)
    finally:
        winapi.close_handle(job)


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
    proxy_port: int | None, nonce: str, host_sid: str,
    size: tuple[int, int] = DEFAULT_SIZE,
) -> int:
    """Runner entry point. Returns the shell's exit code."""
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
        return _execute_runner_inner(
            sandbox_name, sandbox_sid, shell_path, proxy_port, nonce, host_sid,
            size, _log,
        )
    except Exception:
        import traceback
        _log(traceback.format_exc())
        raise
    finally:
        if _log_file:
            _log_file.close()


def _relay_output(src: int, dst: int, _log) -> None:
    """Pseudo-console to host. Blocking reads; ends when either pipe
    breaks — the pseudo-console side closes when it is closed after the
    shell exits."""
    while True:
        try:
            data = winapi.read_file(src, RELAY_BUF)
        except OSError as e:
            _log(f"output relay ended: {e}")
            return
        if not data:
            return
        try:
            winapi.write_file(dst, data)
        except OSError as e:
            _log(f"output relay write ended: {e}")
            return


def _relay_input(src: int, dst: int, hpc: int, _log) -> None:
    """Host to pseudo-console, applying resize requests found in the
    stream. A console has no end-of-input, so on host EOF (a script's
    stdin ran out) type `exit` — the word every supported shell exits on."""
    held = b""
    while True:
        try:
            data = winapi.read_file(src, RELAY_BUF)
        except OSError as e:
            _log(f"input relay ended: {e}")
            break
        if not data:
            break
        payload, resizes, held = split_resize_requests(held + data)
        for cols, rows in resizes:
            try:
                winapi.resize_pseudo_console(hpc, cols, rows)
            except OSError as e:
                _log(f"resize failed: {e}")
        if payload:
            try:
                winapi.write_file(dst, payload)
            except OSError as e:
                _log(f"input relay write ended: {e}")
                return
    try:
        winapi.write_file(dst, b"\rexit\r")
    except OSError:
        pass


def _execute_runner_inner(
    sandbox_name: str, sandbox_sid: str, shell_path: str,
    proxy_port: int | None, nonce: str, host_sid: str,
    size: tuple[int, int], _log,
) -> int:
    import threading

    _log(f"runner start: name={sandbox_name} sid={sandbox_sid} "
         f"shell={shell_path} size={size[0]}x{size[1]}")

    pipe_in_name, pipe_out_name = _pipe_names(sandbox_name, nonce)
    job_name_str = _job_name(sandbox_name)

    pipe_in = winapi.open_file(pipe_in_name, winapi.GENERIC_READ)
    pipe_out = winapi.open_file(pipe_out_name, winapi.GENERIC_WRITE)
    _log("pipes opened")

    # Host user (stop, status, proxy lookups) and SYSTEM only; the runner
    # keeps its own handle, sandboxed processes get none.
    job_sd = winapi.SecurityDescriptor(f"D:(A;;GA;;;SY)(A;;GA;;;{host_sid})")
    try:
        job = winapi.create_job_object(job_name_str, sa=job_sd.attributes())
    finally:
        job_sd.close()
    winapi.set_job_kill_on_close(job)

    # The pseudo-console pipe pair. Nothing is inherited; the pseudo-console
    # duplicates what it needs into its own conhost.
    pty_in_read, pty_in_write = winapi.create_pipe(inheritable=False)
    pty_out_read, pty_out_write = winapi.create_pipe(inheritable=False)

    from sbx.tokens import create_sandbox_token, process_sddl
    token = create_sandbox_token(sandbox_sid)
    _log("token created")

    hpc = winapi.create_pseudo_console(size[0], size[1], pty_in_read, pty_out_write)
    # The pseudo-console owns these ends now; holding them here would stop
    # the output pipe ever breaking.
    winapi.close_handle(pty_in_read)
    winapi.close_handle(pty_out_write)
    _log("pseudo-console created")

    # The runner's token is unrestricted sbx-user, and sbx-user is in every
    # sandbox's RestrictedSids — so lock the runner, and the pseudo-console's
    # conhost (another unrestricted sbx-user process, its child), to SYSTEM
    # and the host user before any sandboxed process exists. The lock comes
    # after the restricted token and the pseudo-console: both need to
    # reopen objects the runner creates, which the locked default DACL denies.
    lock = f"D:(A;;GA;;;SY)(A;;GA;;;{host_sid})"
    conhosts = winapi.child_pids(os.getpid())
    winapi.lock_current_process(lock)
    for pid in conhosts:
        winapi.lock_process(pid, lock)
    _log(f"runner and conhost {conhosts} locked to SYSTEM + host user")

    shell_sd = winapi.SecurityDescriptor(
        process_sddl(winapi.token_logon_sid(token), sandbox_sid),
    )
    env_block = winapi.make_env_block(
        shell_env(winapi.user_environment(token), proxy_port),
    )
    from sbx.mounts import SANDBOX_USER_HOME
    workspace = SANDBOX_USER_HOME / sandbox_name
    # Children inherit "ignore Ctrl+C"; clear it so Ctrl+C typed in the
    # sandbox reaches the shell and what it runs.
    winapi.kernel32.SetConsoleCtrlHandler(None, False)
    attr_buf, attr_list = winapi.init_proc_attribute_list(1)
    winapi.update_proc_attribute_console(attr_list, hpc)
    try:
        # NULL std handles, not the runner's: a child that inherits std
        # handles writes to them instead of to its pseudo-console.
        proc_h, thread_h, shell_pid, _ = winapi.create_process_as_user(
            token, shell_path,
            creation_flags=winapi.CREATE_SUSPENDED | winapi.CREATE_UNICODE_ENVIRONMENT,
            env=env_block,
            cwd=str(workspace) if workspace.is_dir() else None,
            attribute_list=attr_list,
            std_handles=winapi.NULL_STD_HANDLES,
            inherit_handles=False,
            process_sa=shell_sd.attributes(),
        )
    except OSError as e:
        _log(f"shell launch failed: {e}")
        winapi.close_pseudo_console(hpc)
        for h in (job, token, pty_in_write, pty_out_read, pipe_in, pipe_out):
            winapi.close_handle(h)
        raise ProcessError(f"failed to launch shell: {e}")
    finally:
        winapi.delete_proc_attribute_list(attr_list)
        shell_sd.close()

    winapi.assign_process_to_job(job, proc_h)
    winapi.resume_thread(thread_h)
    winapi.close_handle(thread_h)
    _log(f"shell running, pid={shell_pid}")

    relay_in = threading.Thread(
        target=_relay_input, args=(pipe_in, pty_in_write, hpc, _log), daemon=True,
    )
    relay_out = threading.Thread(
        target=_relay_output, args=(pty_out_read, pipe_out, _log), daemon=True,
    )
    relay_in.start()
    relay_out.start()

    exit_code = winapi.wait_for_process(proc_h)
    _log(f"shell exited with code {exit_code}")

    # Closing the pseudo-console flushes its last output and breaks its
    # output pipe, which releases the output relay.
    winapi.close_pseudo_console(hpc)
    relay_out.join(timeout=5)

    # Leave pipe_in alone: the input relay may be parked in a blocking read
    # on it, and closing the handle would wait for that read — forever,
    # while the host holds its end open. Process exit closes it. Closing
    # pipe_out is what tells the host the shell is gone.
    winapi.close_handle(proc_h)
    for h in (token, job, pty_out_read, pipe_out):
        winapi.close_handle(h)
    _log("runner cleanup done")
    return exit_code
