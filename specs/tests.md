# Tests — Windows Agent Sandbox

Organized by module. Tags: `[elevation]` = needs admin, `[integration]` = needs
Windows APIs (not pure logic).

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

29. [integration] Created restricted token has `RestrictedSids` containing the per-sandbox SID and `BUILTIN\Users`.
30. [integration] Process under restricted token can read a path ACL'd for the sandbox SID.
31. [integration] Process under restricted token cannot read a path not ACL'd for the sandbox SID.
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
