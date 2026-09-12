# Integration Tests

Engine-level tests that call `start_sandbox` directly and talk through
`StartHandle` pipes. No terminal, no CLI — these verify the engine API
contracts independently of the shell integration.

All tests use the `start_sandbox` / `stop_sandbox` API and communicate
via named pipes on `StartHandle`. Each test gets a unique sandbox name
(UUID-based) and sandbox SID.

## Shell and runner

### Runner launches as the sandbox's account
Verifies: Shell integration mechanism → Runner process
1. `start_sandbox(name, sid, "cmd.exe")`.
2. Wait for initial output (prompt).
3. Send `echo %username%\r\n`.
4. Read output — expect `sbx-<name>`.

### Echo round-trip
Verifies: named pipe relay
1. Start sandbox.
2. Send `echo RELAY_TEST_OUTPUT\r\n`.
3. Read output — expect `RELAY_TEST_OUTPUT`.

### Git-bash starts, with the same isolation as any other shell
Verifies: Shell integration mechanism → Cygwin/MSYS2 shells
1. Start sandbox with `shell=git-bash`.
2. Wait for prompt (longer timeout — 8s+).
3. Send `echo GIT_BASH_OK\n`.
4. Read output — expect `GIT_BASH_OK`.
5. Send `echo $USERNAME` — expect `sbx-<name>`, the same account any other
   shell would get.

The point of this one is that it is no longer a special case. Under the
previous design Cygwin shells could not start at all with restricted SIDs,
and the carve-out that let them start cost them their isolation.

## Job Object

### Named Job Object exists
Verifies: Shell integration mechanism → Runner process (Job Object)
1. Start sandbox.
2. Wait 2s for runner to set up.
3. Open `Global\sbx-job-{name}` via `open_job_object` — expect success.

### Shell inherits Job Object
Verifies: Shell integration mechanism → Runner process (Job Object)
1. Start sandbox, wait for prompt.
2. Send `echo JOB_CHECK_MARKER\r\n`, verify echo.
3. Open Job Object, query PIDs — expect at least one PID.

### Child processes inherit Job Object
Verifies: Shell integration mechanism → Runner process (Job Object)
1. Start sandbox, wait for prompt.
2. Send `cmd /c echo CHILD_MARKER\r\n`, verify echo.
3. Open Job Object, query PIDs — expect at least 1 PID.

### Stop terminates Job Object
Verifies: Sandbox lifecycle → Stop
1. Start sandbox, wait for prompt.
2. `stop_sandbox(name)`.
3. Wait for runner to exit.
4. Try to open Job Object by name — expect `OSError` (object gone).

## Environment

### HTTPS_PROXY set when network preset requires it
Verifies: Network mechanism → Layers (Environment)
1. Start sandbox with `network_preset=claude_api_only`, `proxy_port=8080`.
2. Send `echo %HTTPS_PROXY%\r\n`.
3. Read output — expect `http://127.0.0.1:8080`.

### HTTPS_PROXY not set under preset none
Verifies: Network mechanism → Per preset (none)
1. Start sandbox with `network_preset=none`.
2. Send `echo [%HTTPS_PROXY%]\r\n`.
3. Read output — expect the literal `[%HTTPS_PROXY%]` (unexpanded — variable not set).

## Account and token

`whoami` is the obvious way to inspect a token and is not available here:
`DISABLE_MAX_PRIVILEGE` strips the privileges it needs, so it fails with
"Access is denied" inside the sandbox. These scenarios check what the token
*does* rather than what it reports. That privileges really are stripped is
asserted directly against the handle in `tests/test_tokens.py`, which can
count them.

### Shell runs as the sandbox's own account
Verifies: Filesystem mechanism → User accounts
1. Start sandbox.
2. Send `echo %username%`.
3. Expect `sbx-<name>` — each sandbox has its own account, so this is also
   what distinguishes one sandbox's processes from another's.

### Own home is writable
Verifies: Filesystem mechanism → Mount setup
1. Start sandbox.
2. Send `echo probe > %USERPROFILE%\probe.txt`.
3. Expect success. The mounts live here, so a sandbox that could not write
   its own home would be useless.

### System paths still reachable
Verifies: Filesystem mechanism → Tokens
1. Start sandbox.
2. Send `type C:\Windows\System32\drivers\etc\hosts`.
3. Expect the file contents and no denial — every sandbox account is in
   `BUILTIN\Users`, which system paths already grant.

Cross-sandbox isolation, the other half of what the per-sandbox account buys,
needs two live sandboxes and is covered at the system level:
`tests/test_system.py::test_one_sandbox_cannot_read_anothers_mount`.
