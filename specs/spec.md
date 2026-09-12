# Windows Agent Sandbox — Spec

Status: approved
Last updated: 2026-09-11

## Goal

Give developers a self-service tool to run AI agents (starting with Claude Code) in isolated Windows environments with controlled filesystem access and network policies.

## Architecture

Two layers:

### Engine (backend)

- Role: manages the full sandbox lifecycle — create, start, stop, destroy — and all underlying Windows primitives.
- Holds: sandbox registry (which sandboxes exist, their state), config parsing, per-sandbox account management, token creation, bind link setup, ACL management, WFP rule management, proxy management.
- Interface: Python library API + CLI.
- Must not depend on: TUI or any specific frontend.

### TUI (frontend)

- Role: fullscreen terminal UI for interactive sandbox management.
- Holds: sandbox list view, status display, start/stop controls, config editing.
- Depends on: engine (as a library).
- Must not depend on: Windows primitives directly — all sandbox operations go through the engine.

## Sandbox lifecycle

1. Install (one-time) — engine creates the local group that sandbox accounts join, which is what WFP rules are scoped to. Requires elevation. Intended to configure those WFP rules too; it does not yet, so the network backstop described under Network mechanism is not in place (see Follow-ups). No system-path ACLs are needed — see Tokens.
2. Init — `sbx init` scaffolds a `.sandbox/config.json` with defaults. User edits it.
3. Create — engine creates the sandbox's local account, adds it to the sandbox group, hides it from the sign-in screen, sets up bind links and ACLs granting that account on the mounts' backing paths, and stores sandbox metadata. Requires elevation.
4. Start — engine re-invokes itself as the sandbox's own account (via `CreateProcessWithLogonW`), strips privileges from that account's token with `DISABLE_MAX_PRIVILEGE`, and launches an interactive shell under it inside a ConPTY. The shell appears embedded in the host terminal with full cursor, colour, and interactive program support. The user launches agents or other tools from within this shell. Does not require elevation. See Shell integration mechanism.
5. Stop — engine terminates sandbox processes.
6. Destroy — engine removes bind links, ACLs, the sandbox's account and its profile directory, and the sandbox metadata. Requires elevation.
7. Uninstall — engine removes the sandbox group, the WFP rules, and any sandbox accounts and profiles left behind by a failed destroy. Requires elevation.

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
- `target` — relative path under the sandbox workspace. `"repo"` resolves to `C:\ProgramData\sbx\<name>\repo`. The workspace sits outside the account's profile on purpose: creating a directory at `C:\Users\sbx-<name>` before the account's first logon makes Windows put the real profile at `sbx-<name>.<COMPUTERNAME>` instead, and mounts would then not be where the shell expects them.
- Supports both folders and individual files.
- Target names must be unique within a config. Duplicate targets are rejected at parse time.

### Sandbox name

Every sandbox has a name. It becomes the local account (`sbx-<name>`), that account's profile folder, the Job Object and the named pipes, so it is a durable identity rather than a label.

Rules:
- Maximum 12 characters. The account is `sbx-` plus the name, and a Windows account name is capped at 20; the remaining four characters are headroom for a disambiguating suffix.
- Unique across sandboxes, compared case-insensitively — Windows account names are case-insensitive, so `Foo` and `foo` would be the same account.
- Lowercase. Characters a SAM account name forbids (`/ \ : ; | = , + * ? < >`) are replaced with `-`, and runs of `-` are collapsed.

Default, when `--name` is not given: take the project directory name, lowercase and sanitise it, and truncate to 12 characters. Plain truncation, not truncation at a word boundary — `windows-agent-sandbox` becomes `windows-agen`, which is ugly but distinctive, where stopping at a segment boundary would give the generic and misleading `windows`. `sbx create` prints the name it chose, so the default is never a surprise.

On collision, create refuses and asks for another name, with the next free numeric suffix already typed in at the cursor:

```
sandbox name 'windows-agen' is already used by C:\other\project
choose another name: windows-age2█
```

The suggestion is prefilled and editable, not a yes/no question: Enter accepts it, or the user edits it in place first. Prefilling is done by writing the suggestion into the console's input buffer as key events (`WriteConsoleInput`), so the console's own line editing handles the rest — backspace, arrow keys and Enter all behave as the user expects, and the reply is read as an ordinary line.

The base is shortened as needed to keep the suffixed name within 12 characters. Whatever the user submits is validated like any other name, so editing cannot produce an invalid or still-colliding one; a rejected edit asks again.

Without a console to prompt on, create fails with the same message and a non-zero exit rather than accepting its own suggestion — a name is never allocated that the user did not choose, because it becomes an account, a profile and a set of ACLs.

A name beginning with `sbx-` is accepted as given, producing `sbx-sbx-foo`. Deliberate: the prefix is ours to add, and second-guessing the user's name is not worth the special case.

### Shell

Configurable per sandbox via the `"shell"` key. Default: `"git-bash"`.

Options:
- `git-bash` (default) — `C:\Program Files\Git\bin\bash.exe`.
- `cmd` — `cmd.exe`.
- `powershell` — `powershell.exe` (Windows PowerShell 5.1).
- `pwsh` — `pwsh.exe` (PowerShell 7+).

Shell availability is checked at install time. Install reports any missing shells as warnings (since the user may not need all of them). Start refuses to launch if the configured shell is not found.

### Network presets

- `none` (default) — all egress blocked. No network access.
- `claude-api-only` — allowlists `api.anthropic.com` and related Anthropic domains.
- `all` — no restrictions.

Preset list is extensible — users will be able to define custom domain allowlists in a later iteration.

## Filesystem isolation

Each sandbox runs under its own local user account. It can access its own mounts (read+write) and the system paths that `BUILTIN\Users` already grants. Sandbox A cannot read or write sandbox B's files, because B's backing paths are ACL'd for B's account and A's token carries no such identity.

Privileges are stripped with `DISABLE_MAX_PRIVILEGE`. Isolation is by account, not by restricted token — see User accounts for why.

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
sbx init                    # scaffolds .sandbox/config.json in current directory
sbx create [--name alias]   # sets up sandbox from .sandbox/config.json (elevated)
sbx start [name]            # opens interactive shell inside sandbox
sbx stop [name]             # terminates sandbox processes
sbx destroy [name]          # tears down sandbox (elevated)
sbx list                    # shows all sandboxes and their state
sbx status [name]           # detailed status of one sandbox
sbx uninstall               # removes all sandbox infrastructure (elevated)
```

`[path]` — optional project path, defaulting to the current directory. Sandboxes are looked up by project path; the `--name` alias given at create time labels the sandbox but cannot yet be used to address it (see Follow-ups).

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
- Multiple sandboxes mounting the same source folder → allowed. Each sandbox's account gets its own ACE on the backing path and its own bind link, so neither depends on the other.
- A sandbox's account already exists, left behind by a failed destroy → delete it and its profile, then recreate, so the new sandbox cannot inherit stale group membership or ACLs.
- Sandbox name collision → refuse, and propose the next free numeric suffix for the user to confirm. See Sandbox name.
- Starting a sandbox that is already running → refuse with a clear error naming the sandbox. Without the check it fails silently: the second runner connects to the first host's named pipes, and the second host waits for a connection that never arrives.
- Runner fails to connect to named pipes within 15s → host closes pipes, terminates runner, reports error.
- Shell crashes or exits → runner detects via `WaitForSingleObject`, closes ConPTY, relay threads exit on `ERROR_BROKEN_PIPE`, `sbx start` returns to host prompt.
- Host terminal doesn't support VT input mode → degrade gracefully; VT output still works. Interactive programs that need VT input (mouse, function keys) won't work but basic typing does.
- Ctrl+C in sandbox shell → ConPTY delivers it as `CTRL_C_EVENT` to the shell process. The shell handles it normally (e.g. interrupts `ping`). The host process is not affected.

---

## Technical design

Internal mechanisms — how the engine implements filesystem isolation, network isolation, and shell integration.

### Definitions

- Restricted token — a Windows security token carrying a RestrictedSids list. Every access check must pass twice: once against the token's normal SIDs, and again against the RestrictedSids. If either check fails, access is denied. This is an AND gate — the process can only reach resources explicitly ACL'd for both its user SID and its restricted SID.
- Synthetic SID — a made-up security identifier that doesn't correspond to any real user or group. Placed in a restricted token's RestrictedSids list, it limits access to only those resources where an ACE for that SID has been explicitly added. No longer used: isolation is by account. Kept here because the PoC findings below are written in these terms.
- Bind link — a transparent filesystem path redirection provided by the Windows Bindlink API (`bindflt.sys` minifilter). The process sees files at a virtual path; the real files live at a backing path. No file duplication. Requires Windows 11 build 25314+.
- WFP — Windows Filtering Platform. Kernel-level network filtering that can scope rules by user SID.
- SNI — Server Name Indication. A field in the TLS handshake that contains the target domain name. The proxy inspects this to enforce domain allowlists without decrypting traffic.
- ConPTY — Windows Pseudo Console (`CreatePseudoConsole`, available since Windows 10 1809). Provides a real console to a process while exposing its I/O as a VT byte stream on a pipe pair. The process sees a normal console (cursor, colour, mouse, `ReadConsoleInput` all work); the pipe owner reads/writes VT escape sequences. Windows Terminal uses ConPTY internally.
- VT — Virtual Terminal escape sequences. In-band control codes (cursor movement, colour, screen clearing) embedded in a byte stream, the same convention Unix terminals use.

### Filesystem mechanism

One local account per sandbox, each with privileges stripped. The original design — a shared account plus per-sandbox synthetic SIDs in a restricted token, inspired by Codex — is described under User accounts along with the measurements that ruled it out.

#### User accounts

Each sandbox gets its own local user account, `sbx-<id>`. The account *is* the isolation boundary: mount backing paths are ACL'd for that account, so sandbox A's token carries no identity that appears on sandbox B's paths.

Why not one shared account. The original design shared a single `sbx-user` and separated sandboxes with per-sandbox synthetic SIDs in a restricted token, to avoid managing N accounts. That cannot work with Cygwin-based shells, and git-bash is the default:

- A fully restricted token is access-checked twice, and the second pass only grants what `RestrictedSids` names. Cygwin builds POSIX on top of Win32 at startup — signals, a shared process table behind `fork`, cross-process synchronisation — and creating those **named kernel objects** is refused. Measured: creating a named pipe is fine under a restricted token; creating a named mutex, event or section is denied with `ERROR_ACCESS_DENIED`.
- The grants Cygwin needs cannot be given without dissolving the isolation. Backing paths must grant the shared account, or the *first* access check fails and the mount is unreadable. Put that same account in `RestrictedSids` and both checks pass for every sandbox's mount, so the synthetic SID stops gating anything.
- The bind is structural: the first check needs a SID the token holds as a group, the second needs it in `RestrictedSids`, and a synthetic SID can only ever be in the second. Adding the logon session SID, `Authenticated Users` or `INTERACTIVE` does not close it — all measured.

A real account satisfies both checks with one identity, so no synthetic SID is needed and no shell needs a carve-out. See `specs/notes-2.md` for the measurements.

Cost accepted: N accounts to create, hide from the sign-in screen, and delete along with their profiles.

#### Tokens

The sandbox shell runs under the sandbox's own account with `DISABLE_MAX_PRIVILEGE`, which strips every privilege except `SeChangeNotifyPrivilege`. No `RestrictedSids` list: isolation comes from the account, and restricted SIDs are what Cygwin shells cannot survive.

The sandbox process can reach:
- Its own mounts — backing paths are ACL'd for its account
- System paths — via `BUILTIN\Users`, which system paths already grant

Another sandbox's mounts are denied because its account appears on none of them.

That also fixes what system access means: a sandbox inherits exactly what `Users` may do on a path, not a read-only subset. Where `Users` has write, so does the sandbox — `C:\Windows\Temp` is writable today, verified. So system access is not read-only, and any location `Users` can write is a channel between sandboxes. Making it genuinely read-only would need a shared system SID with explicit read-only ACEs, the design these PoC findings replaced; that trade-off is now an open question rather than a settled one.

#### Mount setup

- Mount targets appear as bind links under the sandbox's workspace, `C:\ProgramData\sbx\<name>\`.
- Each mount's backing path gets one ACE, read+write, for the sandbox's own account. Destroy revokes it; nothing is shared, so nothing has to be reference-counted.
- Isolation follows from that ACE: sandbox A's account appears on none of B's backing paths.
- Caveat — a backing path whose DACL grants `BUILTIN\Users` or `Everyone` is reachable from every sandbox, since every sandbox account is in `Users`. Keep project sources out of world-readable locations such as `C:\Users\Public`.
- The engine manages bind links and ACLs during sandbox create/destroy.

### Network mechanism

Single user, WFP backstop, proxy-based policy. Fail-safe by design — three layers all default to "no network".

#### Layers

1. WFP — static rules scoped to the sandbox group's SID block all egress except loopback to the proxy port. Scoped to the group rather than to each account, so the rules are installed once at install time and never change as sandboxes come and go. This is the backstop — if the proxy is down or the agent ignores `HTTPS_PROXY`, traffic is blocked.
2. Proxy — a local proxy on loopback that enforces per-sandbox domain filtering via TLS SNI inspection. Defaults to deny-all when no policy is configured.

   Not what it does yet: the proxy decides on the `CONNECT` host and never inspects the SNI, so a client that connects to an allowed host and then presents a different name in its ClientHello is not caught. `parse_sni` exists and is tested but has no caller in the request path. That matters more while the WFP layer is also missing — see Follow-ups.
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

The proxy runs on a single port. All sandboxes share the same `HTTPS_PROXY` address. The proxy differentiates by looking up the source PID of each incoming connection (via `GetExtendedTcpTable`) and asking which sandbox's Job Object that process belongs to (`IsProcessInJob`); the engine registers a policy per Job Object name at start and removes it at stop. Job membership rather than a registered PID list, so anything the shell spawns is covered too.

Multiple sandboxes with different network presets run concurrently — the proxy routes per-PID, WFP provides a uniform backstop.

### Shell integration mechanism

The sandbox shell runs embedded in the host terminal via ConPTY. The host process and the shell run under different user accounts (the host user vs the sandbox's own account), so a cross-user transport bridges them.

#### Process launch — command runner pattern

Avoids elevation for start/stop.

1. Engine CLI (unprivileged) calls `CreateProcessWithLogonW` to re-invoke itself as the sandbox's account with an internal `_run` subcommand, passing the sandbox name.
2. The re-invoked instance (the "runner") is now running as that account with a full token. It opens its own process token and calls `CreateRestrictedToken` with `DISABLE_MAX_PRIVILEGE` and an empty `RestrictedSids` list, which strips privileges without adding a second access check.
3. The runner calls `CreateProcessAsUser` with that token to spawn the configured shell. This works without special privileges because the token is derived from the runner's own logon session.
4. The runner stays alive to relay VT bytes between the engine CLI and the sandboxed shell, and exits when the shell exits.

Sandbox user credentials are stored DPAPI-encrypted during install, read by the engine at start time.

The ConPTY is created by the runner under its own full token; only the shell child gets the privilege-stripped one. No ConPTY operation therefore depends on a stripped privilege.

#### Architecture

    host terminal ←VT bytes→ named pipe ←VT bytes→ ConPTY ←console API→ shell

Three components:

- Runner process — launched as the sandbox's account via `CreateProcessWithLogonW`. Creates a ConPTY, launches the shell inside it, relays VT bytes between the ConPTY pipe pair and named pipes.
- Named pipes — two named pipes with null DACLs (one per direction) carry VT bytes between the host and runner processes across the user boundary.
- Host relay — the CLI's `_interactive_session` bridges the user's real terminal and the named pipes using VT console modes.

#### Runner process

The runner:

1. Connects to the host's named pipes (client side).
2. Creates a pipe pair for ConPTY (`create_pipe`, non-inheritable).
3. Creates a ConPTY: `CreatePseudoConsole(cols, rows, pty_in_read, pty_out_write)`. Closes the ConPTY-side pipe ends — ConPTY owns them.
4. Creates a named Job Object (`Global\sbx-job-{name}`) with kill-on-close and null DACL.
5. Creates the privilege-stripped token (see Process launch above).
6. Builds a `STARTUPINFOEX` with `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` pointing to the ConPTY handle.
7. Launches the shell via `CreateProcessAsUserW` with that token and the attribute list, passing `STARTF_USESTDHANDLES` with all three std handles NULL. A child that inherits std handles writes to them instead of to its pseudoconsole, so the explicit NULLs are what force it onto the console the ConPTY provides.
8. Assigns the shell to the Job Object.
9. Runs two relay threads: `named_pipe_in → pty_in_write` and `pty_out_read → named_pipe_out`. Both use blocking `ReadFile` — no polling.
10. The input relay scans for a resize escape sequence (see Terminal resize), strips it, and calls `ResizePseudoConsole`.
11. Waits for the shell to exit, then closes the ConPTY and all handles.

The initial terminal size (cols, rows) is passed to the runner as command-line arguments.

#### Cygwin/MSYS2 shells

No special case. Cygwin builds POSIX on top of Win32 at startup — signals, a shared process table, cross-process synchronisation — which means creating named kernel objects. A restricted token refuses that, which is what per-sandbox accounts exist to avoid; see User accounts. Every shell now runs under the same arrangement and gets the same isolation.

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

In-band signalling over the input named pipe. The host sends `\x1b]9999;<cols>;<rows>\x07` (a private-use OSC sequence — Operating System Command, an escape sequence class terminals use for out-of-band requests like setting the window title). The runner's input relay recognises and strips it, then calls `ResizePseudoConsole(hpc, cols, rows)`.

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
- `CreateRestrictedToken` with `DISABLE_MAX_PRIVILEGE` and a `RestrictedSids` list containing `[per_sandbox_sid, BUILTIN\Users]` produces the correct access behaviour: the per-sandbox SID gates mount access, while `BUILTIN\Users` allows read access to system paths whose DACLs grant the Users group. Superseded — restricted SIDs are no longer used at all, because Cygwin shells cannot start under them; see User accounts.

### Tech stack

- Python — engine library, CLI, and TUI.
- Textual or similar — TUI framework (decision deferred).
- Windows APIs via ctypes — bind filter (`BfSetupFilter`/`BfRemoveMapping`), user account and group management (`NetUserAdd`/`NetUserDel`/`NetLocalGroupAddMembers`), NTFS ACLs (`SetEntriesInAcl`/`SetNamedSecurityInfo`), token creation (`CreateRestrictedToken` for privilege stripping), WFP rules.
- Local proxy — implementation TBD (could be a lightweight Python HTTPS proxy or an existing tool like `mitmproxy` in transparent mode).

### Test infrastructure

Two levels of automated tests. Full test plans in `specs/tests/`.

- System tests (`specs/tests/system.md`) — a ConPTY harness drives a host shell, types `sbx start`, interacts with the sandbox, and verifies behaviour from the outside. Full stack including CLI, terminal integration, and OS-level isolation. Uses `ConPtyShell`, a helper that wraps a ConPTY session with `write`/`expect`/`resize` methods and optional `pyte.Screen` for cursor/colour assertions.
- Integration tests (`specs/tests/integration.md`) — call `start_sandbox` directly, talk through `StartHandle` pipes. No terminal, no CLI. Verify engine API contracts: named pipes, Job Object, token, environment.

Test requirements:

- Elevation: test fixture calls `run_elevated("setup_test_env", ...)` for ACLs.
- ConPTY: Windows 10 1809+ (build 17763). CI must be Win10 1809+ or Win11.
- pyte: test dependency for system tests (`pip install pyte`) — a pure-Python VT terminal emulator, used to turn a raw VT byte stream into a screen buffer that tests can assert against.
- Timeouts: 10–15s for initial shell prompt, 5s for command output.

---

## Follow-ups

- Wire WFP rule installation into `sbx install`. Until then layer 1 of the
  network design — the kernel-level backstop — does not exist at runtime, and
  the presets rest on the proxy and `HTTPS_PROXY` alone.
- Address sandboxes by their `--name` alias, not only by project path.
- Custom network presets (user-defined domain allowlists in config).
- TUI detailed design and interaction spec.
- Proxy implementation choice.
- Whether the engine should support "hot" config changes (modify mounts/network on a running sandbox) or require stop/recreate.
- Log capture and forwarding from sandbox processes.
- Resize escape sequence format — currently `\x1b]9999;<cols>;<rows>\x07` (private OSC). Any unregistered OSC number works; a dedicated third named pipe is cleaner but adds connection complexity.
- Whether to keep the `StartHandle` pipe API for non-interactive callers (a future API that sends commands programmatically without a terminal). If so, the VT stream over pipes *is* the programmatic API.
- Restoring synthetic-SID filesystem isolation for Cygwin/MSYS2 shells — currently they trade it away to start at all (see Cygwin/MSYS2 shells).

## Non-goals

- Cross-platform support — Windows only.
- Replacing or extending idea_sandbox — clean break.
- Running untrusted code from unknown sources — this isolates *agents*, not arbitrary adversarial payloads.
- Hardened security against a determined attacker escaping the sandbox — the threat model is preventing accidental damage and data leakage, not defeating a skilled adversary.
- GUI (non-terminal) frontend.
- Container or VM-based isolation.
- Remote sandbox management — all local.
