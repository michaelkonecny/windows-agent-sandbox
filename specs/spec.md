# Windows Agent Sandbox — Spec

Status: draft
Last updated: 2026-09-11

## Goal

Give developers a self-service tool to run AI agents (starting with Claude Code) in isolated Windows environments with controlled filesystem access and network policies.

## Architecture

Two layers:

### Engine (backend)

- Role: manages the full sandbox lifecycle — create, start, stop, destroy — and all underlying Windows primitives.
- Holds: sandbox registry (which sandboxes exist, their state), config parsing, user account management, restricted token creation, synthetic SID management, bind link setup, ACL management, WFP rule management, proxy management.
- Interface: Python library API + CLI.
- Must not depend on: TUI or any specific frontend.

### TUI (frontend)

- Role: fullscreen terminal UI for interactive sandbox management.
- Holds: sandbox list view, status display, start/stop controls, config editing.
- Depends on: engine (as a library).
- Must not depend on: Windows primitives directly — all sandbox operations go through the engine.

## Sandbox lifecycle

1. Install (one-time) — engine creates the shared sandbox user account, sets up system ACLs, configures WFP rules. Requires elevation.
2. Define — user writes a sandbox definition in the JSON config file.
3. Create — engine generates a per-sandbox synthetic SID, sets up bind links and ACLs on mount targets, stores sandbox metadata. Requires elevation.
4. Start — engine creates a restricted token, launches an interactive shell under that token inside a ConPTY. The shell appears embedded in the host terminal with full cursor, colour, and interactive program support. See Shell integration mechanism.
5. Stop — engine terminates sandbox processes.
6. Destroy — engine removes bind links, ACLs, and sandbox metadata. Requires elevation.
7. Uninstall — engine removes shared user account, shared SID ACLs, WFP rules. Requires elevation.

## Configuration

Project-local JSON config file (`.sandbox/config.json` in the project root). Devcontainer-inspired structure.

```json
{
  "mounts": [
    {
      "source": ".",
      "target": "repo"
    },
    {
      "source": "~/.config/some-tool.json",
      "target": "config/some-tool.json"
    }
  ],
  "network": "claude-api-only"
}
```

Mount semantics:
- `source` — absolute path on the host (or `.` for project root, `~` for host user's home).
- `target` — relative path under the sandbox workspace. `"repo"` resolves to `C:\Users\<sandbox-user>\<sandbox-name>\repo`.
- Supports both folders and individual files.

### Network presets

- `none` (default) — all egress blocked. No network access.
- `claude-api-only` — allowlists `api.anthropic.com` and related Anthropic domains.
- `all` — no restrictions.

Preset list is extensible — users will be able to define custom domain allowlists in a later iteration.

## Filesystem isolation

Each sandbox gets its own restricted process token with a unique synthetic SID. The sandbox can only access its own mounts (read+write) and a minimal set of system paths (read-only). Sandbox A cannot read or write sandbox B's files.

All sandboxes share a single local user account — isolation is via restricted tokens, not separate accounts.

See Filesystem mechanism for implementation details.

## Network isolation

Fail-safe by design — three layers all default to "no network":

1. WFP blocks all egress for the sandbox user except loopback to the proxy port.
2. A local proxy enforces per-sandbox domain filtering. Defaults to deny-all.
3. `HTTPS_PROXY` env var set per sandbox process.

If the proxy crashes or the agent ignores the proxy, WFP blocks everything. Multiple sandboxes with different network presets run concurrently — the proxy differentiates by PID.

See Network mechanism for implementation details.

## User-facing behaviour

### CLI (engine)

```
sbx install                 # one-time setup (elevated)
sbx create <name>           # sets up sandbox from config
sbx start <name>            # launches agent inside sandbox
sbx stop <name>             # terminates sandbox processes
sbx destroy <name>          # tears down sandbox
sbx list                    # shows all sandboxes and their state
sbx status <name>           # detailed status of one sandbox
sbx uninstall               # removes all sandbox infrastructure (elevated)
```

The tool runs unprivileged. Operations that need admin (user account creation, bind links, WFP rules, ACLs) request elevation for just that action via UAC prompt. The user never has to launch the whole tool as admin.

### TUI

Fullscreen terminal application showing:
- List of configured sandboxes with status (created/running/stopped).
- Start/stop controls.
- Live output or log tailing from running sandboxes.
- Details to be specced in a later iteration — the engine API is the priority.

## Edge cases

- Source path in a mount doesn't exist → refuse creation, report which mount failed.
- Bind link target already exists (e.g. leftover from a crashed destroy) → clean it up, log a warning.
- Destroying a running sandbox → stop it first, then destroy.
- Multiple sandboxes mounting the same source folder → allowed (different per-sandbox SIDs, independent bind links).
- Shared user account already exists from a previous install → detect and reuse.
- Synthetic SID collision → astronomically unlikely (randomly generated), but check and regenerate if it happens.
- Runner fails to connect to named pipes within 15s → host closes pipes, terminates runner, reports error.
- Shell crashes or exits → runner detects via `WaitForSingleObject`, closes ConPTY, relay threads exit on `ERROR_BROKEN_PIPE`, `sbx start` returns to host prompt.
- Host terminal doesn't support VT input mode → degrade gracefully; VT output still works. Interactive programs that need VT input (mouse, function keys) won't work but basic typing does.
- Ctrl+C in sandbox shell → ConPTY delivers it as `CTRL_C_EVENT` to the shell process. The shell handles it normally (e.g. interrupts `ping`). The host process is not affected.

---

## Technical design

Internal mechanisms — how the engine implements filesystem isolation, network isolation, and shell integration.

### Definitions

- Restricted token — a Windows security token carrying a RestrictedSids list. Every access check must pass twice: once against the token's normal SIDs, and again against the RestrictedSids. If either check fails, access is denied. This is an AND gate — the process can only reach resources explicitly ACL'd for both its user SID and its restricted SID.
- Synthetic SID — a made-up security identifier that doesn't correspond to any real user or group. Placed in a restricted token's RestrictedSids list, it limits access to only those resources where an ACE for that SID has been explicitly added.
- Bind link — a transparent filesystem path redirection provided by the Windows Bindlink API (`bindflt.sys` minifilter). The process sees files at a virtual path; the real files live at a backing path. No file duplication. Requires Windows 11 build 25314+.
- WFP — Windows Filtering Platform. Kernel-level network filtering that can scope rules by user SID.
- SNI — Server Name Indication. A field in the TLS handshake that contains the target domain name. The proxy inspects this to enforce domain allowlists without decrypting traffic.
- ConPTY — Windows Pseudo Console (`CreatePseudoConsole`, available since Windows 10 1809). Provides a real console to a process while exposing its I/O as a VT byte stream on a pipe pair. The process sees a normal console (cursor, colour, mouse, `ReadConsoleInput` all work); the pipe owner reads/writes VT escape sequences. Windows Terminal uses ConPTY internally.

### Filesystem mechanism

Uses a shared sandbox user account + per-sandbox restricted tokens with synthetic SIDs. Inspired by Codex, extended with full read isolation (Codex uses WRITE_RESTRICTED; we use fully restricted tokens).

#### User accounts

A single shared local user account (`sbx-user`) hosts all sandboxes. Individual sandboxes are isolated from each other via restricted tokens, not separate accounts. This avoids managing N accounts.

#### Restricted tokens and synthetic SIDs

Each sandbox gets two synthetic SIDs in its restricted token:

- Per-sandbox SID — unique to this sandbox. ACL'd with read+write on the sandbox's mount targets. Isolates sandbox A from sandbox B's files.
- Shared system SID — common across all sandboxes. ACL'd with read-only on system paths the agent needs to function.

Because the token is fully restricted (not WRITE_RESTRICTED), both reads and writes must pass the restricted SID check. The sandbox process can only access:
- Its own mounts (via the per-sandbox SID)
- System paths (via the shared system SID, read-only)

#### System paths granted via shared SID

Read-only access for all sandboxes:
- `C:\Windows`
- `C:\Program Files` (or specific subdirectories for required tools)
- Python, Node, Git install directories
- Temp directories (`C:\Windows\Temp`, sandbox user's temp)

#### Mount setup

- Mount targets appear as bind links inside the sandbox user's home directory, under a per-sandbox subdirectory (`C:\Users\sbx-user\<sandbox-name>\`).
- Each mount's backing path gets an ACE granting the per-sandbox synthetic SID read+write access.
- The engine manages bind links and ACLs during sandbox create/destroy.

### Network mechanism

Single user, WFP backstop, proxy-based policy. Fail-safe by design — three layers all default to "no network".

#### Layers

1. WFP — static rules scoped to `sbx-user`'s SID block all egress except loopback to the proxy port. Always on, never changes per sandbox. This is the backstop — if the proxy is down or the agent ignores `HTTPS_PROXY`, traffic is blocked.
2. Proxy — a local proxy on loopback that enforces per-sandbox domain filtering via TLS SNI inspection. Defaults to deny-all when no policy is configured.
3. Environment — `HTTPS_PROXY` env var set in the sandbox process, pointing to the proxy.

#### Per preset

- `none` — no `HTTPS_PROXY` set. WFP blocks all direct egress. Even if the agent somehow connects to the proxy port, the proxy's default deny-all policy rejects it.
- `claude-api-only` — proxy configured to allowlist `api.anthropic.com` (and related Anthropic domains). `HTTPS_PROXY` set.
- `all` — proxy configured to forward everything. `HTTPS_PROXY` set.

#### Safe defaults

- Proxy default policy: deny all. Explicit opt-in required per preset.
- No `network` key in config: treated as `none`.
- Proxy crash or unavailability: WFP blocks everything — sandbox falls back to no network automatically.

#### Per-sandbox policy routing

The proxy runs on a single port. All sandboxes share the same `HTTPS_PROXY` address. The proxy differentiates by looking up the source PID of each incoming connection (via `GetExtendedTcpTable`), mapping it to a sandbox (the engine registers which PIDs belong to which sandbox), and applying that sandbox's network policy.

Multiple sandboxes with different network presets run concurrently — the proxy routes per-PID, WFP provides a uniform backstop.

### Shell integration mechanism

The sandbox shell runs embedded in the host terminal via ConPTY. The host process and the shell run under different user accounts (host user vs `sbx-user`), so a cross-user transport bridges them.

#### Architecture

    host terminal ←VT bytes→ named pipe ←VT bytes→ ConPTY ←console API→ shell

Three components:

- Runner process — launched as `sbx-user` via `CreateProcessWithLogonW`. Creates a ConPTY, launches the shell inside it, relays VT bytes between the ConPTY pipe pair and named pipes.
- Named pipes — two named pipes with null DACLs (one per direction) carry VT bytes between the host and runner processes across the user boundary.
- Host relay — the CLI's `_interactive_session` bridges the user's real terminal and the named pipes using VT console modes.

#### Runner process

The engine spawns a runner process as `sbx-user` (`CreateProcessWithLogonW`, `CREATE_NO_WINDOW`). The runner:

1. Connects to the host's named pipes (client side).
2. Creates a pipe pair for ConPTY (`create_pipe`, non-inheritable).
3. Creates a ConPTY: `CreatePseudoConsole(cols, rows, pty_in_read, pty_out_write)`. Closes the ConPTY-side pipe ends — ConPTY owns them.
4. Creates a named Job Object (`Global\sbx-job-{name}`) with kill-on-close and null DACL.
5. Creates a restricted token (`CreateRestrictedToken` with `DISABLE_MAX_PRIVILEGE` and per-sandbox restricted SIDs).
6. Builds a `STARTUPINFOEX` with `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` pointing to the ConPTY handle.
7. Launches the shell via `CreateProcessAsUserW` with the restricted token and attribute list. No `STARTF_USESTDHANDLES` — the ConPTY provides the console.
8. Assigns the shell to the Job Object.
9. Runs two relay threads: `named_pipe_in → pty_in_write` and `pty_out_read → named_pipe_out`. Both use blocking `ReadFile` — no polling.
10. The input relay scans for a resize escape sequence (see Terminal resize), strips it, and calls `ResizePseudoConsole`.
11. Waits for the shell to exit, then closes the ConPTY and all handles.

The initial terminal size (cols, rows) is passed to the runner as command-line arguments.

#### Cygwin/MSYS2 shells

Git-bash and other Cygwin-based shells query their own token and create named pipes during init. Both fail under a restricted token unless the token's default DACL and the token object's DACL include the restricted SIDs. The engine sets null DACLs on both (`SetTokenInformation` for the default DACL, `SetKernelObjectSecurity` for the token object).

#### Host relay

`_interactive_session` in the CLI:

1. Saves the current console input/output modes.
2. Enables `ENABLE_VIRTUAL_TERMINAL_INPUT` on stdin — the console delivers keystrokes as VT sequences.
3. Enables `ENABLE_VIRTUAL_TERMINAL_PROCESSING` on stdout — VT sequences from the sandbox render directly.
4. Output thread: blocking `ReadFile` on the named pipe, `WriteFile` to `CONOUT$`.
5. Input thread: `ReadConsoleInput` loop. Key events forward as raw VT bytes to the named pipe. `WINDOW_BUFFER_SIZE_EVENT` triggers a resize message (see Terminal resize).
6. On shell exit (`ERROR_BROKEN_PIPE`): restores original console modes, returns.

Console mode save/restore is wrapped in a context manager with `finally` — a corrupted console mode persists for the terminal session.

#### Terminal resize

In-band signalling over the input named pipe. The host sends `\x1b]9999;<cols>;<rows>\x07` (a private-use OSC sequence). The runner's input relay recognises and strips it, then calls `ResizePseudoConsole(hpc, cols, rows)`.

Rationale: avoids a third named pipe and its connection handshake. The sequence uses an unregistered OSC number to avoid collision with standard terminal escapes.

#### Named pipes

Two named pipes per sandbox, both with null-DACL security descriptors for cross-user access:

- `\\.\pipe\sbx-{name}-in` — host writes, runner reads (OUTBOUND from host).
- `\\.\pipe\sbx-{name}-out` — runner writes, host reads (INBOUND to host).

The host creates both pipes and waits for the runner to connect (`ConnectNamedPipe`, 15s timeout).

### Assumptions validated

Both PoCs pass on Windows 11 build 22621. Code in `poc/`.

- Bindlink cross-user behaviour — **confirmed**. A bind link created by an admin (via `BfSetupFilter`) is visible and functional for a different local user account. The sandbox user can read and write through the link; writes land in the backing directory.
- Restricted token + bind link interaction — **confirmed**. A fully restricted token (not WRITE_RESTRICTED) with a synthetic SID in `RestrictedSids` can read and write through bind links when the backing path has an ACE for that SID. Access to paths without a matching ACE is correctly denied.

### API findings from PoCs

Discoveries that affect the engine implementation:

- Use `BfSetupFilter`/`BfRemoveMapping` from `bindfltapi.dll` — the lower-level bind filter API available on build 22621+. The higher-level `CreateBindLink`/`RemoveBindLink` (in `KernelBase.dll`) require build 25314+.
- `BfRemoveMapping` takes two parameters `(HANDLE JobHandle, LPCWSTR VirtualizationRootPath)`, matching `BfSetupFilter`. Pass `NULL` for a global (non-job-scoped) mapping.
- Use the Win32 ACL API (`SetEntriesInAcl` + `SetNamedSecurityInfo`) for synthetic SIDs — `icacls` rejects non-account SIDs with `ERROR_NONE_MAPPED` (1332). The `*S-1-...` syntax only works for SIDs that resolve to a known account.
- `CreateRestrictedToken` with `DISABLE_MAX_PRIVILEGE` and a `RestrictedSids` list containing `[per_sandbox_sid, BUILTIN\Users]` produces the correct access behaviour: the per-sandbox SID gates mount access, while `BUILTIN\Users` allows read access to system paths whose DACLs grant the Users group.

### Tech stack

- Python — engine library, CLI, and TUI.
- Textual or similar — TUI framework (decision deferred).
- Windows APIs via ctypes — bind filter (`BfSetupFilter`/`BfRemoveMapping`), user account management (`NetUserAdd`/`NetUserDel`), NTFS ACLs (`SetEntriesInAcl`/`SetNamedSecurityInfo`), restricted tokens (`CreateRestrictedToken`), WFP rules.
- Local proxy — implementation TBD (could be a lightweight Python HTTPS proxy or an existing tool like `mitmproxy` in transparent mode).

### Integration test infrastructure

End-to-end tests drive the full chain programmatically: test harness → host shell → `sbx start` → sandbox shell → commands → exit → host shell.

#### Test driver — `ConPtyShell`

A helper class that wraps a ConPTY session. The test harness acts as the terminal emulator.

```
ConPtyShell
  Role: programmatic terminal for integration tests — launches a process
        inside a ConPTY and provides read/write/expect methods.
  Holds:
    - hpc — PseudoConsole handle
    - pty_in_write, pty_out_read — pipe handles for writing input / reading output
    - proc_handle, pid — the launched process
    - screen — pyte.Screen (optional, for cursor/colour assertions)
  API:
    - __init__(cmd, cols=120, rows=30, env=None) — create ConPTY, launch process
    - write(text) — send raw bytes/string to the process
    - read(timeout=5.0) → bytes — blocking read with timeout
    - expect(pattern, timeout=10.0) → Match — accumulate output until regex matches or timeout
    - expect_prompt(timeout=10.0) — shorthand for expect(prompt_pattern)
    - screen_text() → str — (if pyte enabled) current virtual screen content
    - resize(cols, rows) — call ResizePseudoConsole
    - close() — terminate process, close ConPTY, close handles
    - __enter__ / __exit__ — context manager
```

`expect` reads in a loop, appending to a buffer, testing the regex after each chunk. On timeout it raises with the buffer contents for diagnostics.

#### VT output handling

Two tiers:

- Tier 1 (default) — strip common VT escapes (CSI, OSC) from the accumulated buffer, regex match on plain text. Sufficient for command-output assertions.
- Tier 2 (optional) — feed raw VT bytes into `pyte.Screen` (a pure-Python terminal emulator, test dependency). Query the virtual screen for cursor position, line content, SGR attributes. Use when testing cursor behaviour, colour output, or screen layout.

#### Test scenarios

Each test gets a unique sandbox name (UUID-based).

- Sandbox shell opens and runs commands — launch host `cmd` in ConPTY, type `sbx start`, wait for sandbox prompt, run `whoami` (expect `sbx-user`), `exit`, verify host prompt returns.
- Job Object inheritance — from sandbox shell, spawn `cmd /c echo MARKER`, open Job Object by name, verify PIDs.
- Ctrl+C passthrough — start `ping -t 127.0.0.1`, send `\x03`, verify ping stops and prompt returns, verify shell still alive.
- Interactive program (cursor, colour) — `cls` then `echo COLOURED` with colour set; pyte asserts cursor position and SGR attributes.
- Terminal resize propagation — `resize(80, 24)` on harness, `mode con` in sandbox, expect `80` and `24` in output.
- Exit returns to host shell — type `echo HOST_BEFORE`, enter sandbox, exit, type `echo HOST_AFTER`, expect both markers.
- Stop from outside — while sandbox is running, call `stop_sandbox(name)` from test harness; expect host prompt reappears.
- Git-bash under ConPTY — launch with `--shell git-bash`, `echo $SHELL`, `ls --color=auto`, verify output.

#### Engine-level tests

Direct tests against the `start_sandbox` / `StartHandle` pipe API (no terminal, no CLI). These test the named-pipe contract independently of the CLI relay. Existing tests cover: runner launches as `sbx-user`, named Job Object exists, shell and children inherit Job Object, echo round-trips through pipes, `stop_sandbox` terminates the job, `HTTPS_PROXY` set/unset, git-bash under restricted token.

#### Test requirements

- Elevation: test fixture calls `run_elevated("setup_test_env", ...)` for ACLs.
- ConPTY: Windows 10 1809+ (build 17763). CI must be Win10 1809+ or Win11.
- pyte: test dependency (`pip install pyte`).
- Timeouts: 10–15s for initial shell prompt (especially git-bash under restricted token), 5s for command output.

---

## Follow-ups

- Custom network presets (user-defined domain allowlists in config).
- TUI detailed design and interaction spec.
- Proxy implementation choice.
- Whether the engine should support "hot" config changes (modify mounts/network on a running sandbox) or require stop/recreate.
- Init command that scaffolds a config file.
- Log capture and forwarding from sandbox processes.
- Resize escape sequence format — currently `\x1b]9999;<cols>;<rows>\x07` (private OSC). Any unregistered OSC number works; a dedicated third named pipe is cleaner but adds connection complexity.
- Whether to keep the `StartHandle` pipe API for non-interactive callers (a future API that sends commands programmatically without a terminal). If so, the VT stream over pipes *is* the programmatic API.

## Non-goals

- Cross-platform support — Windows only.
- Replacing or extending idea_sandbox — clean break.
- Running untrusted code from unknown sources — this isolates *agents*, not arbitrary adversarial payloads.
- Hardened security against a determined attacker escaping the sandbox — the threat model is preventing accidental damage and data leakage, not defeating a skilled adversary.
- GUI (non-terminal) frontend.
- Container or VM-based isolation.
- Remote sandbox management — all local.
