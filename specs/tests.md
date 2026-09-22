# Tests — Windows Agent Sandbox

Organized by module. Tags: `[elevation]` = needs admin, `[integration]` = needs
Windows APIs (not pure logic), `[system]` = black-box test of the installed tool
(see system).

## system

Goal: prove the isolation guarantees in spec.md hold for what a user actually gets from `sbx install` → `sbx create` → `sbx start` — no mocks, no hand-made grants.

Why: integration tests above check modules in isolation or via shortcuts (`run_elevated` mocked in `create`, `setup_test_env` granting `sbx-user` read on the Python dir and repo). Nothing checks the assembled system against the spec's claims.

Harness:
- Location: `tests/system/`, marker `system`.
- Probe — a shell command run inside a sandbox that prints one line `PROBE <id> OK` or `PROBE <id> DENIED`. Tests assert on probe lines only, never on free-form shell output.
- Session — one `sbx start` subprocess with a probe script piped to stdin, ending with `exit` (needs test 73).
- Probe tools: shell built-ins plus `curl.exe` (ships in `System32`) — nothing that needs the host's Python inside the sandbox.
- Network probes reach `host:443` without TLS — CONNECT through the proxy (or connect directly), then plain HTTP; the server's HTTP 400 proves the connection. System32 curl's TLS (Schannel) fails under restricted tokens (see notes.md).
- Shells: isolation tests parametrized over `git-bash`, `cmd`, `powershell`, `pwsh`; skip a shell not installed, with its name in the message.
- Fixture projects: `sbxsys-a`, `sbxsys-b` under a temp dir, each with `secret.txt` holding a unique token. Host secret: `~\sbxsys-host-secret.txt`, not mounted anywhere.

Rules:
- Skip the whole suite unless `SBX_SYSTEM_TESTS=1` — the value is the acknowledgement; typing it means the runner has read what the suite does. Env var not declared → skip with a message listing the changes below.
- List the changes in the skip message, a session-start banner, and `tests/system/README.md`: creates/deletes the `sbx-user` account, adds/removes firewall rules, creates bind links, edits ACLs on fixture dirs, uninstalls sbx at session end. Say it's meant for a disposable VM.
- Wipe leftover sbx state at session start (`sbx uninstall`, delete `%LOCALAPPDATA%\sbx`) — clean baseline instead of refusing.
- Run fully unattended — no UAC prompt may appear. Mechanism: VM provisioned once with `ConsentPromptBehaviorAdmin=0` (elevate without prompting). `sbx`'s own `runas` elevation then succeeds silently; the admin's split token (admin runs unprivileged until elevated) stays, so `start` still runs unprivileged.
- Provide `tests/system/setup_vm.py` — run once, elevated; sets `ConsentPromptBehaviorAdmin=0`, leaves `EnableLUA=1`. Never change UAC settings from the suite itself.
- Check preconditions at session start and fail fast naming the fix: `EnableLUA=1`, `ConsentPromptBehaviorAdmin=0`, current user in `Administrators`.
- Run the suite unprivileged, so `start` is proven to work without admin. If launched elevated, relaunch pytest unprivileged via a one-shot Task Scheduler task (run level `LIMITED`, as the logged-on user), wait for it, relay its output, exit with its exit code, delete the task. Rely on `schtasks` only; no third-party de-elevation tools.
- Assert inside the suite (after any relaunch) that the process is not elevated — guards against a relaunch that silently stayed elevated.
- Drive every step through the `sbx` CLI as a subprocess; never import `sbx`, mock, or call `setup_test_env`.
- Prefix every sandbox name with `sbxsys-` — makes leftovers identifiable.
- Uninstall in a session-scoped finalizer, even after failures; delete fixture projects and the host secret.
- Time-limit every session to 60 s; on timeout, `sbx stop` and fail.
- Verify owner, elevation and process tree from the host side (`sbx status` PIDs + Win32 queries), not from inside the sandbox — `whoami` is unusable under `DISABLE_MAX_PRIVILEGE` (see notes.md).

### Lifecycle

74. [system] `sbx install` from an unprivileged shell → exit 0; `sbx-user` exists, credentials file exists, firewall rules scoped to `sbx-user` exist.
75. [system] Second `sbx install` → exit 0; same account, no duplicate firewall rules.
76. [system] `sbx init` + `sbx create` → `C:\Users\sbx-user\sbxsys-a\repo` lists the project's files; `sbx list` shows `sbxsys-a` as `created`.
77. [system] `sbx start` (unprivileged) runs a probe session → shell process owned by `sbx-user`, token not elevated, shell PID in the `sbx-sbxsys-a` Job Object.
78. [system] Shell starts a long-running background child, then `sbx stop` → every PID from `sbx status` and the child are gone within 5 s; `sbx list` shows `stopped`.
79. [system] `sbx destroy` → bind links gone, synthetic SID's ACE gone from the project dir, record gone, project files byte-identical to before create.
80. [system] `sbx uninstall` (session end) → `sbx-user` gone along with its profile, no firewall rules scoped to it, credentials file gone, proxy not running, no `sbxsys-` bind links left.

### Filesystem isolation (per shell)

81. [system] Read own mount's `secret.txt` → OK; write `repo\probe.txt` → OK, and the file appears in the host project dir with the written content.
82. [system] Read `C:\Windows\win.ini` → OK — system paths readable.
83. [system] Read host secret by its real path → DENIED.
84. [system] With `sbxsys-a` and `sbxsys-b` both created: from A, read and write under `C:\Users\sbx-user\sbxsys-b\repo` → DENIED; same via B's host backing path → DENIED.
85. [system] Write to `C:\Windows`, `C:\Program Files`, `C:\ProgramData`, `C:\Users\Public` → DENIED — spec says system paths are read-only.
86. [system] Single-file mount (`~\sbxsys-cfg.json` → `config/tool.json`) → readable in the sandbox; a sibling file next to the source in the host home → DENIED.
87. [system] Two sandboxes mounting the same source → both read and write it; destroying one leaves the other's mount working.

### Network isolation (per shell)

88. [system] `none`: `HTTPS_PROXY` unset; direct HTTPS to `example.com` → fails.
89. [system] `none`: HTTPS to `example.com` explicitly via the proxy port (`curl -x`) → rejected.
90. [system] `claude-api-only`: `https://api.anthropic.com` via `HTTPS_PROXY` → any HTTP status (connection made); `https://example.com` → rejected.
91. [system] `claude-api-only`: `curl --noproxy "*" https://api.anthropic.com` → fails — firewall backstop blocks direct egress.
92. [system] `all`: `https://example.com` via `HTTPS_PROXY` → any HTTP status.
93. [system] `sbxsys-a` (`none`) and `sbxsys-b` (`claude-api-only`) running at once → A blocked from `api.anthropic.com`, B allowed.
94. [system] Kill the proxy while B (`claude-api-only`) runs → B's requests fail; no fallback to direct egress.
95. [system] Host process reaches `https://example.com` while sandboxes run and after uninstall — firewall rules hit only `sbx-user`.
96. [system] A sandbox that reaches the proxy's control port (loopback isn't firewalled) can't widen its own policy or stop the proxy — control commands need the secret from the host-only PID file.

### Process isolation (per shell)

98. [system] Host-side env var set on the `sbx start` process → not visible in the shell; writing into `%TEMP%` and `%USERPROFILE%` → OK (they're `sbx-user`'s, not the host's).
99. [system] While a sandbox runs, the runner's process and token DACLs name only SYSTEM and the host user — read host-side.

## config

1. `scaffold_config` creates `.sandbox/config.json` with valid default content (parseable by `load_config`).
2. `scaffold_config` creates the `.sandbox/` directory if it doesn't exist.
3. `scaffold_config` on a directory that already has `.sandbox/config.json` — raises `ConfigError`.
4. Parse a valid config with mounts, shell, and network — returns frozen dataclass with all fields resolved.
5. `.` in mount source resolves to the config file's parent directory.
6. `~` in mount source resolves to the current user's home directory.
7. Omitted `shell` defaults to `git_bash`; omitted `network` defaults to `none`.
8. Duplicate mount targets in the same config — rejected with a message naming the duplicate.
9. Mount source path that doesn't exist on disk — rejected with a message naming the path.
10. Invalid JSON — rejected with a clear parse error (not a Python traceback).
11. Unknown keys are ignored (forward compatibility).

## store

12. Add a record and retrieve it by project path.
13. Retrieve a record by name.
14. Add a record with a name that already exists — rejected.
15. List returns all records, empty store returns empty list.
16. Update individual fields on an existing record.
17. Remove a record — subsequent get returns None.
18. Two concurrent writers — file lock prevents corruption (one wins, other retries or errors).

## identity

19. Generated synthetic SID has authority `{0,0,0,0,0,42}` and 4 sub-authorities.
20. Two consecutive SID generations produce different SIDs.
21. Credential DPAPI round-trip — encrypt then decrypt returns the original password.
22. [elevation, integration] Create `sbx-user` account — account exists afterward; idempotent on second call.
23. [elevation, integration] Delete `sbx-user` account — account gone afterward.

## mounts

24. [elevation, integration] Create bind links for a sandbox — target paths exist and resolve to source content.
25. [elevation, integration] Set ACLs on backing paths — the synthetic SID has read+write access.
26. [elevation, integration] Destroy removes bind links — target paths no longer exist.
27. [elevation, integration] Destroy cleans up ACLs — the synthetic SID's ACE is removed from backing paths.
28. [elevation, integration] Leftover bind link from a previous crash — create detects and cleans it up before proceeding.

## tokens

29. [integration] Created restricted token has `RestrictedSids` containing the per-sandbox SID, `BUILTIN\Users`, `Everyone`, the logon SID and the account SID.
30. [integration] Process under restricted token can read a path ACL'd for the sandbox SID.
31. [integration] Process under restricted token cannot read a path not ACL'd for the sandbox SID — the path grants only a group outside RestrictedSids (Administrators), so normal access alone isn't enough.
32. [integration] `DISABLE_MAX_PRIVILEGE` is set — token has no dangerous privileges.

## elevation

33. [integration] Elevated subprocess executes a trivial operation and returns the result to the caller.
34. [integration] Error in the elevated subprocess propagates as `ElevationError` to the caller.

## process

35. [integration] Runner launches as `sbx-user` via `CreateProcessWithLogonW`.
36. [integration] Runner creates a named Job Object (`sbx-job-<name>`) — Job Object exists and is accessible by the host user.
37. [integration] Shell launched under restricted token inherits Job Object membership.
38. [integration] Child process spawned from the shell also inherits Job Object membership.
39. [integration] ConPTY relays stdin/stdout between the engine CLI and the sandboxed shell — a command typed on the CLI side produces output on the CLI side.
40. [integration] Stop terminates the Job Object — shell and all children exit.
41. [integration] Shell spawned with `HTTPS_PROXY` env var when network preset is `claude_api_only` or `all`.
42. [integration] Shell spawned without `HTTPS_PROXY` env var when network preset is `none`.
69. [integration] Git-bash (Cygwin/MSYS2, the default shell) starts under a restricted token — send a command via pipe, receive output back. Skips if git-bash is not installed.
70. [integration] `start_sandbox` works with the default credentials path — verifies the flow a real user hits via `sbx install` → `sbx start` (all other tests pass an explicit temp path, sidestepping this).
71. [integration] Git-bash via `ShellKind.git_bash` through `start_sandbox` with default shell resolution — the process is assigned to the Job Object before it starts executing (created suspended, assigned, then resumed). Skips if git-bash is not installed.
72. [integration] End-to-end CLI: subprocess calls to `sbx install` → `sbx init` → `sbx create` → `sbx start` (send command, read output) → `sbx stop` → `sbx destroy`. Exercises the same flow a user hits manually.

## proxy

43. Proxy accepts a CONNECT request for an allowed domain and tunnels the connection.
44. Proxy rejects a CONNECT request for a domain not in the allowlist — returns 403.
45. Default policy (no registered sandboxes) denies all connections.
46. Proxy extracts SNI from TLS ClientHello and matches against the domain allowlist.
47. [integration] Proxy looks up source PID via `GetExtendedTcpTable` and resolves to a sandbox via `IsProcessInJob`.
48. Two sandboxes with different policies — each gets its own filtering applied correctly.
49. Proxy self-terminates after 60s with no registered sandboxes.
50. Engine registers a sandbox with the proxy over the control socket — proxy starts applying that sandbox's policy.
51. Engine deregisters a sandbox — proxy stops tracking it.
97. Control command without the proxy's secret — rejected, policy table unchanged.

## network

52. [elevation, integration] Install WFP rules scoped to `sbx-user` — egress blocked for that user.
53. [elevation, integration] WFP rules allow loopback traffic to the proxy port.
54. [elevation, integration] Uninstall removes WFP rules — egress no longer blocked.
55. `ensure_proxy_running` starts proxy when not running, no-ops when already running.
56. `ensure_proxy_running` detects stale PID file (proxy crashed) and starts fresh.

## engine

57. [elevation, integration] Full lifecycle: install → init → create → start → stop → destroy → uninstall — each step transitions state correctly.
58. Init scaffolds config in target directory, create reads it back successfully.
59. Create with an invalid config path — fails before touching system state.
60. Create with a duplicate sandbox name — rejected.
61. Start when configured shell is missing — refused with a message naming the shell.
62. Destroy a running sandbox — stops it first, then destroys.
63. List returns all sandboxes with correct states.
64. Status on a running sandbox includes live PIDs.
65. [integration] Install reports warnings for shells not found on the system (non-fatal).
68. [integration] Engine.start returns a handle that provides an interactive shell — send a command via pipe, receive output back.

## cli

66. Each subcommand (`install`, `init`, `create`, `start`, `stop`, `destroy`, `uninstall`, `list`, `status`) maps to the correct engine method and returns exit code 0 on success.
67. Engine error → non-zero exit code and human-readable message on stderr.
73. [integration] `sbx start` with piped (non-console) stdin — relays stdin to the shell, returns when the shell exits (after `exit` or stdin EOF), exit code = shell's exit code. Prerequisite for system tests.

