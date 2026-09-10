# Integration Tests

Engine-level tests that call `start_sandbox` directly and talk through
`StartHandle` pipes. No terminal, no CLI — these verify the engine API
contracts independently of the shell integration.

All tests use the `start_sandbox` / `stop_sandbox` API and communicate
via named pipes on `StartHandle`. Each test gets a unique sandbox name
(UUID-based) and sandbox SID.

## Shell and runner

### Runner launches as sbx-user
Verifies: Shell integration mechanism → Runner process
1. `start_sandbox(name, sid, "cmd.exe")`.
2. Wait for initial output (prompt).
3. Send `echo %username%\r\n`.
4. Read output — expect `sbx-user`.

### Echo round-trip
Verifies: named pipe relay
1. Start sandbox.
2. Send `echo RELAY_TEST_OUTPUT\r\n`.
3. Read output — expect `RELAY_TEST_OUTPUT`.

### Git-bash under restricted token
Verifies: Shell integration mechanism → Cygwin/MSYS2 shells
1. Start sandbox with `shell=git-bash`.
2. Wait for prompt (longer timeout — 8s+).
3. Send `echo GIT_BASH_OK\n`.
4. Read output — expect `GIT_BASH_OK`.

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

## Token

### Restricted token applied
Verifies: Filesystem mechanism → Restricted tokens and synthetic SIDs
1. Start sandbox.
2. Send `whoami /priv\r\n`.
3. Read output — expect privileges are absent or disabled.

### Sandbox SID in token
Verifies: Filesystem mechanism → Restricted tokens and synthetic SIDs
1. Start sandbox with a known `sandbox_sid`.
2. Send `whoami /groups\r\n`.
3. Read output — expect the sandbox SID appears in the restricted SIDs list.
