from __future__ import annotations

import logging
import os
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


def _runner_cmd(sandbox_name: str, sandbox_sid: str, shell_path: str) -> str:
    python = sys.executable
    return f'"{python}" -m sbx _run {sandbox_name} {sandbox_sid} "{shell_path}"'


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
) -> StartHandle:
    if isinstance(shell, ShellKind):
        shell_path = resolve_shell(shell)
    else:
        shell_path = shell

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

    cmd = _runner_cmd(sandbox_name, sandbox_sid, shell_path)
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
        import ctypes
        code = getattr(e, "winerror", 0) or (ctypes.get_last_error() if hasattr(ctypes, "get_last_error") else 0)
        if code == 5:
            raise ProcessError(
                f"failed to launch runner as {username}: access denied — "
                f"credentials may be stale, try: python -m sbx install"
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


def execute_runner(sandbox_name: str, sandbox_sid: str, shell_path: str) -> None:
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
        _execute_runner_inner(sandbox_name, sandbox_sid, shell_path, _log)
    except Exception:
        import traceback
        _log(traceback.format_exc())
        raise
    finally:
        if _log_file:
            _log_file.close()


def _relay(src: int, dst: int, _log, label: str, stop_event) -> None:
    """Relay data from src pipe to dst pipe until stop_event is set."""
    buf_size = 4096
    while not stop_event.is_set():
        try:
            avail = winapi.peek_pipe(src)
        except OSError:
            break
        if avail > 0:
            try:
                data = winapi.read_file(src, min(avail, buf_size))
                winapi.write_file(dst, data)
            except OSError:
                break
        else:
            stop_event.wait(0.01)


def _execute_runner_inner(
    sandbox_name: str, sandbox_sid: str, shell_path: str,
    _log,
) -> None:
    import threading

    _log(f"runner start: name={sandbox_name} sid={sandbox_sid} shell={shell_path}")

    pipe_in_name, pipe_out_name = _pipe_names(sandbox_name)
    job_name_str = _job_name(sandbox_name)

    _log(f"opening pipes: in={pipe_in_name} out={pipe_out_name}")
    pipe_in = winapi.open_file(pipe_in_name, winapi.GENERIC_READ)
    pipe_out = winapi.open_file(pipe_out_name, winapi.GENERIC_WRITE)
    _log(f"pipes opened: in={pipe_in} out={pipe_out}")

    _log("creating anonymous pipes for shell I/O")
    stdin_read, stdin_write = winapi.create_pipe(inheritable=True)
    stdout_read, stdout_write = winapi.create_pipe(inheritable=True)
    _log(f"shell pipes: stdin_r={stdin_read} stdin_w={stdin_write} "
         f"stdout_r={stdout_read} stdout_w={stdout_write}")

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
    try:
        proc_h, thread_h, shell_pid, _ = winapi.create_process_as_user(
            token, shell_path,
            creation_flags=winapi.CREATE_SUSPENDED,
            std_handles=(stdin_read, stdout_write, stdout_write),
        )
    except OSError as e:
        _log(f"shell launch failed: {e}")
        winapi.close_handle(job)
        winapi.close_handle(token)
        winapi.close_handle(stdin_read)
        winapi.close_handle(stdin_write)
        winapi.close_handle(stdout_read)
        winapi.close_handle(stdout_write)
        winapi.close_handle(pipe_in)
        winapi.close_handle(pipe_out)
        raise ProcessError(f"failed to launch shell: {e}")

    _log(f"shell launched suspended, pid={shell_pid}")
    winapi.close_handle(stdin_read)
    winapi.close_handle(stdout_write)

    winapi.assign_process_to_job(job, proc_h)
    _log("process assigned to job, resuming")
    winapi.resume_thread(thread_h)
    winapi.close_handle(thread_h)

    stop = threading.Event()
    relay_in = threading.Thread(
        target=_relay, args=(pipe_in, stdin_write, _log, "in", stop),
        daemon=True,
    )
    relay_out = threading.Thread(
        target=_relay, args=(stdout_read, pipe_out, _log, "out", stop),
        daemon=True,
    )
    relay_in.start()
    relay_out.start()
    _log("relay threads started")

    _log("waiting for shell to exit")
    exit_code = winapi.wait_for_process(proc_h)
    _log(f"shell exited with code {exit_code}")

    stop.set()
    relay_in.join(timeout=2)
    relay_out.join(timeout=2)

    winapi.close_handle(proc_h)
    winapi.close_handle(token)
    winapi.close_handle(job)
    winapi.close_handle(stdin_write)
    winapi.close_handle(stdout_read)
    winapi.close_handle(pipe_in)
    winapi.close_handle(pipe_out)
    _log("runner cleanup done")
