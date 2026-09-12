# System Tests

Full-stack tests driven by a ConPTY harness acting as the terminal emulator.
Each test launches a host shell, types `sbx start`, interacts with the sandbox
shell, and verifies behaviour from the outside.

All tests use `ConPtyShell` (see Integration test infrastructure in spec.md).
Each test gets a unique sandbox name (UUID-based). Timeouts: 10–15s for initial
shell prompt, 5s for command output unless noted otherwise.

Status — everything here except Network isolation is implemented in
`tests/test_system.py`. Network isolation waits on a verified proxy and WFP
rule set. Scenarios corrected against what the implementation found are
marked *Corrected* below; `specs/notes-2.md` has the detail.

Both shells are cmd and their prompts are indistinguishable, so each test
renames the sandbox's prompt to `SBX>` on entry and treats a drive-letter
prompt as the host. Renaming the host's instead does not work — the sandbox
inherits the host environment, `PROMPT` included.

## Filesystem isolation

### Mount read/write
Verifies: Filesystem mechanism → Mount setup
1. Create `host-marker.txt` in the mounted source directory before starting.
2. Start sandbox with the mount pointing at that directory.
3. `type repo\host-marker.txt` — expect the file contents in output.
4. `echo sbx-marker > repo\sbx-created.txt`, exit sandbox.
5. Verify `sbx-created.txt` exists on host at the source path with correct content.

### Mount boundary
Verifies: Filesystem mechanism → User accounts
1. Create a file at a path outside any mount (e.g. `%TEMP%\outside-mount.txt`).
2. Start sandbox.
3. `type %TEMP%\outside-mount.txt` — expect "Access is denied."
4. `echo x > %TEMP%\write-outside.txt` — expect "Access is denied."

### System paths read-only
Verifies: Filesystem mechanism → System paths granted via shared SID
1. Start sandbox.
2. `type C:\Windows\System32\drivers\etc\hosts` — expect success (file contents appear).
3. `echo x > C:\Windows\Temp\sbx-write-test.txt` — expect "Access is denied."

### Cross-sandbox isolation
Verifies: Filesystem mechanism → User accounts
1. Create two sandboxes (A and B) with different mounts.
2. Start sandbox A.
3. From sandbox A, try to read a file in sandbox B's mount path — expect "Access is denied."
4. Stop sandbox A.
5. Start sandbox B, try to read sandbox A's mount path — expect "Access is denied."
6. Stop sandbox B.

### Home directory boundary
Verifies: Filesystem mechanism → Mount setup
1. Start sandbox (name `sbx-alpha`).
2. `echo ok > C:\Users\sbx-alpha\repo\myfile.txt` — expect success (own home).
3. `dir C:\Users\sbx-beta\` — expect "Access is denied" (another sandbox's home).

### Bind link bidirectional
Verifies: Filesystem mechanism → Mount setup
1. Start sandbox.
2. From sandbox, create a file in the mounted path.
3. From the test harness (outside the ConPTY), verify the file exists at the backing path on the host filesystem.
4. From the test harness, modify the file on the host side.
5. From sandbox, `type` the file — expect the modified contents.

## Network isolation

### Preset none — no egress
Verifies: Network mechanism → Per preset (none)
1. Start sandbox with `network: none`.
2. `powershell -c "(New-Object Net.WebClient).DownloadString('https://example.com')"` — expect failure (connection refused or timeout).
3. Timeout: 15s (network timeout can be slow).

### Preset claude-api-only — allowlisted domain
Verifies: Network mechanism → Per preset (claude-api-only)
1. Start sandbox with `network: claude-api-only`, proxy running.
2. `curl -s -o NUL -w "%%{http_code}" https://api.anthropic.com/v1/models` — expect 401 (connection succeeded, auth failed — that's fine, it means the request reached the server).
3. `curl -s https://example.com` — expect failure (proxy rejects).

### Preset all — unrestricted
Verifies: Network mechanism → Per preset (all)
1. Start sandbox with `network: all`, proxy running.
2. `curl -s -o NUL -w "%%{http_code}" https://example.com` — expect 200.

### WFP backstop — direct connection bypassing proxy
Verifies: Network mechanism → Layers (WFP)
1. Start sandbox with `network: none`.
2. Try a raw TCP connection ignoring the proxy: `powershell -c "(New-Object Net.Sockets.TcpClient).Connect('93.184.216.34', 443)"` — expect failure.
3. This verifies WFP blocks egress at the kernel level regardless of whether the process uses the proxy.

### DNS blocked under none
Verifies: Network mechanism → Safe defaults
1. Start sandbox with `network: none`.
2. `nslookup example.com` — expect failure (no DNS egress).

### Proxy crash fallback
Verifies: Network mechanism → Safe defaults (proxy crash or unavailability)
1. Start sandbox with `network: claude-api-only`, proxy running.
2. Verify a request to `api.anthropic.com` succeeds.
3. Kill the proxy process from the test harness.
4. Retry the request — expect failure (WFP blocks everything without the proxy).

## Privilege and token isolation

### Privileges stripped
Verifies: Filesystem mechanism → User accounts
1. Start sandbox.
2. *Corrected*: `whoami` cannot run at all once `DISABLE_MAX_PRIVILEGE` has
   stripped privileges, so it cannot report them. Observe the effect instead:
   writing outside its own mounts is denied, because nothing there grants the
   account but none of the token's restricted SIDs and both checks must pass.

### Cannot kill host processes
Verifies: token isolation
1. Note the PID of a host-side process (e.g. the test harness itself).
2. Start sandbox.
3. `taskkill /F /PID {host_pid}` — expect a failure, and confirm the target
   survives. *Corrected*: the message is "Not enough memory resources are
   available to complete this operation", which is Windows reporting a denial
   misleadingly. Target a throwaway process, never the test runner.

### Cannot create users
Verifies: token isolation
1. Start sandbox.
2. `net user hacker P@ssw0rd123 /add` — expect "Access is denied."

### Registry write blocked
Verifies: token isolation
1. Start sandbox.
2. `reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion` — expect success (read).
3. `reg add HKLM\SOFTWARE\sbx-test /v x /d y /f` — expect "Access is denied."

## Job Object containment

### Child process cleanup on stop
Verifies: Shell integration mechanism → Runner process (Job Object with kill-on-close)
1. Start sandbox.
2. `start /B ping -t 127.0.0.1` — launch a background process.
3. Note the ping PID (via `tasklist | findstr ping` from inside the sandbox).
4. From the test harness, call `stop_sandbox(name)`.
5. Verify the ping process no longer exists (`tasklist /FI "PID eq {pid}"` from outside).

### Deep process tree tracking
Verifies: Shell integration mechanism → Runner process (Job Object)
1. Start sandbox.
2. `cmd /c cmd /c cmd /c echo DEEP` — spawn a chain of child processes.
3. Open the Job Object by name, query PIDs, verify multiple processes are tracked.

## Shell integration

### Shell opens and runs commands
Verifies: Shell integration mechanism (full chain)
1. Launch `cmd.exe` in ConPTY.
2. Wait for host prompt.
3. Type `sbx start --name {name} --shell cmd`.
4. Wait for sandbox prompt.
5. *Corrected*: `echo %username%` — expect the sandbox's account, `sbx-<name>`. `whoami` cannot run once privileges are stripped.
6. `exit`.
7. Wait for host prompt — confirm it returns.

### Ctrl+C passthrough
Verifies: Shell integration mechanism → ConPTY
1. Start sandbox.
2. `ping -t 127.0.0.1`.
3. Wait for first ping reply.
4. Send `\x03` (Ctrl+C).
5. Expect ping stops, prompt reappears.
6. `echo OK` — expect `OK` (shell still alive).

*Does not pass.* Kept as a strict xfail so it fails loudly if it ever
starts working. ConPTY does not turn an `0x03` byte on its input pipe into
a `CTRL_C_EVENT` for the attached client, reproduced with no sandbox in the
picture. Borrowing the console to call `GenerateConsoleCtrlEvent` and
forcing `ENABLE_PROCESSED_INPUT` (already set) were both ruled out too —
see `specs/notes-2.md`. Needs a design decision.

### Interactive program — cursor and colour
Verifies: Shell integration mechanism → ConPTY
1. Start sandbox with `cmd`.
2. `cls`.
3. Using pyte screen: assert cursor near (0, 0).
4. `color 0A`, then `echo COLOURED`.
5. Using pyte screen: assert `COLOURED` text exists with green foreground SGR.

### Terminal resize propagation
Verifies: Shell integration mechanism → Terminal resize
1. Start sandbox (initial size 120x30).
2. Call `resize(80, 24)` on the ConPTY harness.
3. `mode con` — expect output contains `80` columns and `24` lines.

### Exit returns to host shell
Verifies: Shell integration mechanism (session lifecycle)
1. Launch host `cmd` in ConPTY.
2. `echo HOST_BEFORE` — expect `HOST_BEFORE`.
3. `sbx start ...`, wait for sandbox prompt.
4. `exit`, wait for host prompt.
5. `echo HOST_AFTER` — expect `HOST_AFTER`.

### Stop from outside
Verifies: Shell integration mechanism + Sandbox lifecycle → Stop
1. Start sandbox via host shell.
2. Wait for sandbox prompt.
3. From test harness: `stop_sandbox(name)`.
4. Expect host prompt reappears in ConPTY output.

### Git-bash under ConPTY
Verifies: Shell integration mechanism → Cygwin/MSYS2 shells
1. Start sandbox with `--shell git-bash`.
2. Wait for bash prompt.
3. `echo $SHELL` — expect contains `bash`.
4. `ls --color=auto` — expect output (colour escapes flow through).
5. Exit.

## Lifecycle

### Full round-trip
Verifies: Sandbox lifecycle (all steps)
1. `sbx install` (or verify already installed).
2. `sbx create` from a project with config.
3. `sbx start` — wait for the sandbox prompt, run `echo %username%`, exit.
4. `sbx stop`.
5. `sbx destroy` — verify bind links removed, Job Object gone, mount ACLs cleaned up.
6. `sbx create` again (same project) — should succeed (no leftover state).
7. `sbx start` — should work.
8. `sbx stop`, `sbx destroy`.

### Double start
Verifies: Edge cases
1. Start sandbox.
2. From a second ConPTY session, try `sbx start` with the same sandbox name.
3. Expect a clear error naming the sandbox.

Originally failed silently — the second runner connects to the first host's
named pipes, so the second host waits for a connection that never arrives.
`engine.start` now refuses when the sandbox's Job Object already exists.

### Start after stop
Verifies: Sandbox lifecycle → Start, Stop
1. Start sandbox, run a command, stop it.
2. Start the same sandbox again — should work cleanly.
3. Run a command, verify it works.
4. Stop.

### Two sandboxes simultaneously
Verifies: cross-sandbox isolation + per-sandbox network policy
1. Create sandbox A with `network: none` and sandbox B with `network: all`.
2. Start both.
3. From A: attempt `curl https://example.com` — expect failure.
4. From B: attempt `curl https://example.com` — expect success.
5. From A: try to read B's mount — expect "Access is denied."
6. Stop both.
