import os
import time
import uuid
from pathlib import Path

import pytest

from sbx import winapi
from sbx.config import NetworkPreset
from sbx.identity import generate_sid, get_credentials
from sbx.process import (
    StartHandle,
    build_env,
    start_sandbox,
    stop_sandbox,
    _job_name,
)


@pytest.fixture(scope="module")
def credentials_path():
    import sys
    import tempfile

    creds_dir = Path(tempfile.gettempdir()) / "sbx-test"
    creds_dir.mkdir(exist_ok=True)
    creds = creds_dir / "credentials.json"

    python_dir = str(Path(sys.executable).parent)
    project_dir = str(Path(__file__).parent.parent)

    try:
        from sbx.elevation import run_elevated
        from sbx.identity import store_credentials, SANDBOX_USER

        result = run_elevated("setup_test_env", {
            "grant_paths": [python_dir, project_dir],
        })
        store_credentials(SANDBOX_USER, result["password"], creds)
    except Exception:
        pytest.skip("cannot set up test environment (UAC denied)")

    return creds


@pytest.fixture()
def sandbox_name():
    return f"test-{uuid.uuid4().hex[:8]}"


@pytest.fixture()
def sandbox_sid():
    return generate_sid()


def _start(sandbox_name, sandbox_sid, credentials_path, shell="cmd.exe",
           network_preset=NetworkPreset.none, proxy_port=None):
    return start_sandbox(
        sandbox_name, sandbox_sid, shell,
        network_preset=network_preset,
        proxy_port=proxy_port,
        credentials_path=credentials_path,
    )


def _read_output(handle: StartHandle, timeout: float = 5.0) -> bytes:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        avail = winapi.peek_pipe(handle.pipe_out)
        if avail > 0:
            return winapi.read_file(handle.pipe_out, avail)
        time.sleep(0.2)
    return b""


def _send_command(handle: StartHandle, cmd: str) -> None:
    winapi.write_file(handle.pipe_in, (cmd + "\r\n").encode("utf-8"))


@pytest.mark.integration
def test_runner_launches_as_sbx_user(
    sandbox_name, sandbox_sid, credentials_path
):
    handle = _start(sandbox_name, sandbox_sid, credentials_path)
    try:
        _read_output(handle, timeout=5)
        _send_command(handle, "echo %username%")
        output = _read_output(handle, timeout=5)
        assert b"sbx-user" in output.lower()
    finally:
        stop_sandbox(sandbox_name)
        winapi.wait_for_process(handle.runner_process)
        handle.close()


@pytest.mark.integration
def test_named_job_object(sandbox_name, sandbox_sid, credentials_path):
    handle = _start(sandbox_name, sandbox_sid, credentials_path)
    try:
        time.sleep(2)
        job_name = _job_name(sandbox_name)
        job = winapi.open_job_object(
            job_name,
            winapi.JOB_OBJECT_QUERY | winapi.JOB_OBJECT_TERMINATE,
        )
        winapi.close_handle(job)
    finally:
        stop_sandbox(sandbox_name)
        winapi.wait_for_process(handle.runner_process)
        handle.close()


@pytest.mark.integration
def test_shell_inherits_job_object(
    sandbox_name, sandbox_sid, credentials_path
):
    handle = _start(sandbox_name, sandbox_sid, credentials_path)
    try:
        _read_output(handle, timeout=5)
        _send_command(handle, "echo JOB_CHECK_MARKER")
        output = _read_output(handle, timeout=5)
        assert b"JOB_CHECK_MARKER" in output

        job_name = _job_name(sandbox_name)
        job = winapi.open_job_object(
            job_name,
            winapi.JOB_OBJECT_QUERY | winapi.JOB_OBJECT_TERMINATE,
        )
        try:
            pids = _get_job_pids(job)
            assert len(pids) > 0
        finally:
            winapi.close_handle(job)
    finally:
        stop_sandbox(sandbox_name)
        winapi.wait_for_process(handle.runner_process)
        handle.close()


@pytest.mark.integration
def test_child_inherits_job_object(
    sandbox_name, sandbox_sid, credentials_path
):
    handle = _start(sandbox_name, sandbox_sid, credentials_path)
    try:
        _read_output(handle, timeout=5)
        _send_command(handle, "cmd /c echo CHILD_MARKER")
        output = _read_output(handle, timeout=5)
        assert b"CHILD_MARKER" in output

        job_name = _job_name(sandbox_name)
        job = winapi.open_job_object(
            job_name,
            winapi.JOB_OBJECT_QUERY | winapi.JOB_OBJECT_TERMINATE,
        )
        try:
            pids = _get_job_pids(job)
            assert len(pids) >= 1
        finally:
            winapi.close_handle(job)
    finally:
        stop_sandbox(sandbox_name)
        winapi.wait_for_process(handle.runner_process)
        handle.close()


@pytest.mark.integration
def test_echo_roundtrip(sandbox_name, sandbox_sid, credentials_path):
    """Bytes written to the input pipe reach the shell and its output
    comes back on the output pipe."""
    handle = _start(sandbox_name, sandbox_sid, credentials_path)
    try:
        _read_output(handle, timeout=5)
        _send_command(handle, "echo RELAY_TEST_OUTPUT")
        output = _read_output(handle, timeout=5)
        assert b"RELAY_TEST_OUTPUT" in output
    finally:
        stop_sandbox(sandbox_name)
        winapi.wait_for_process(handle.runner_process)
        handle.close()


@pytest.mark.integration
def test_restricted_token_applied(sandbox_name, sandbox_sid, credentials_path):
    """The shell really runs under the fully restricted token, not just
    as sbx-user.

    The sandbox user's own home directory is the observable: its DACL
    grants sbx-user but none of the token's restricted SIDs, and a fully
    restricted token needs both checks to pass — so the account that owns
    the directory cannot write to it.  `whoami /priv` would be the direct
    check but is itself unusable once privileges are stripped.
    """
    handle = _start(sandbox_name, sandbox_sid, credentials_path)
    try:
        _read_output(handle, timeout=10)
        _send_command(
            handle, r"echo probe > C:\Users\sbx-user\sbx-token-probe.txt"
        )
        output = _read_output(handle, timeout=5)
        assert b"denied" in output.lower(), output
    finally:
        stop_sandbox(sandbox_name)
        winapi.wait_for_process(handle.runner_process)
        handle.close()


@pytest.mark.integration
def test_system_paths_still_reachable(
    sandbox_name, sandbox_sid, credentials_path
):
    """The restriction is not blanket: BUILTIN\\Users sits in the token's
    restricted SIDs, so paths whose DACL grants that group stay readable
    and the shell can still run the tools it needs."""
    handle = _start(sandbox_name, sandbox_sid, credentials_path)
    try:
        _read_output(handle, timeout=10)
        _send_command(handle, r"type C:\Windows\System32\drivers\etc\hosts")
        output = _read_output(handle, timeout=5)
        assert b"denied" not in output.lower(), output
    finally:
        stop_sandbox(sandbox_name)
        winapi.wait_for_process(handle.runner_process)
        handle.close()


@pytest.mark.integration
def test_stop_terminates_job(sandbox_name, sandbox_sid, credentials_path):
    handle = _start(sandbox_name, sandbox_sid, credentials_path)
    _read_output(handle, timeout=5)

    stop_sandbox(sandbox_name)
    exit_code = winapi.wait_for_process(handle.runner_process)
    handle.close()

    with pytest.raises(OSError):
        winapi.open_job_object(
            _job_name(sandbox_name), winapi.JOB_OBJECT_QUERY,
        )


@pytest.mark.integration
def test_https_proxy_set(sandbox_name, sandbox_sid, credentials_path):
    handle = _start(
        sandbox_name, sandbox_sid, credentials_path,
        network_preset=NetworkPreset.claude_api_only,
        proxy_port=8080,
    )
    try:
        _read_output(handle, timeout=5)
        _send_command(handle, "echo %HTTPS_PROXY%")
        output = _read_output(handle, timeout=5)
        assert b"http://127.0.0.1:8080" in output
    finally:
        stop_sandbox(sandbox_name)
        winapi.wait_for_process(handle.runner_process)
        handle.close()


@pytest.mark.integration
def test_https_proxy_not_set(sandbox_name, sandbox_sid, credentials_path):
    handle = _start(
        sandbox_name, sandbox_sid, credentials_path,
        network_preset=NetworkPreset.none,
    )
    try:
        _read_output(handle, timeout=5)
        _send_command(handle, "echo [%HTTPS_PROXY%]")
        output = _read_output(handle, timeout=5)
        assert b"[%HTTPS_PROXY%]" in output
    finally:
        stop_sandbox(sandbox_name)
        winapi.wait_for_process(handle.runner_process)
        handle.close()


@pytest.mark.integration
def test_git_bash_under_restricted_token(
    sandbox_name, sandbox_sid, credentials_path
):
    """Test 69: git-bash (default shell) starts under a restricted token.
    Cygwin/MSYS2 shells query their own token and create signal pipes
    during init — both fail if the token DACLs don't include the
    restricted SIDs."""
    git_bash = r"C:\Program Files\Git\bin\bash.exe"
    if not os.path.isfile(git_bash):
        pytest.skip("git-bash not installed")

    handle = _start(sandbox_name, sandbox_sid, credentials_path, shell=git_bash)
    try:
        _read_output(handle, timeout=8)
        _send_command(handle, "echo GIT_BASH_OK")
        output = _read_output(handle, timeout=8)
        assert b"GIT_BASH_OK" in output
    finally:
        stop_sandbox(sandbox_name)
        winapi.wait_for_process(handle.runner_process)
        handle.close()


# Helpers

def _get_job_pids(job: int) -> list[int]:
    import ctypes
    from ctypes import wintypes

    JobObjectBasicProcessIdList = 3

    class JOBOBJECT_BASIC_PROCESS_ID_LIST(ctypes.Structure):
        _fields_ = [
            ("NumberOfAssignedProcesses", wintypes.DWORD),
            ("NumberOfProcessIdsInList", wintypes.DWORD),
            ("ProcessIdList", ctypes.c_size_t * 128),
        ]

    info = JOBOBJECT_BASIC_PROCESS_ID_LIST()
    info.NumberOfAssignedProcesses = 128
    ret_len = wintypes.DWORD()
    ok = winapi.kernel32.QueryInformationJobObject(
        job, JobObjectBasicProcessIdList,
        ctypes.byref(info), ctypes.sizeof(info),
        ctypes.byref(ret_len),
    )
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    return [info.ProcessIdList[i] for i in range(info.NumberOfProcessIdsInList)]
