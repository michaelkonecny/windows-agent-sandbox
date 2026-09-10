# Architecture — Windows Agent Sandbox

Status: draft. Source of truth for structure; the project spec (./spec.md) owns
what the product does.

Terminology:

- engine — the Python library that manages the full sandbox lifecycle; no UI.
- runner — the engine re-invoked as the sandbox user; creates the restricted token and spawns the shell. An internal subprocess, not a separate binary.
- restricted token — a Windows token with a `RestrictedSids` list that gates every access check (see spec, Definitions).
- synthetic SID — a fabricated SID placed in a restricted token to limit access to explicitly ACL'd resources.
- store — persistent JSON file tracking all sandbox metadata across projects.
- elevation helper — a subprocess spawned with UAC (`runas` verb) to perform privileged operations.

## Principles

- Fail-safe — every default denies access. Network: deny-all. Filesystem: restricted token blocks everything not explicitly granted. A missing config key means maximum restriction.
- Least privilege — the engine runs unprivileged. Only bind links, ACLs, WFP rules, and user management elevate, and only for the duration of that operation.
- Single responsibility per module — each module owns one Windows primitive or one domain concept. A likely change (e.g. swapping the proxy implementation, adding a new shell) touches one module.
- No abstraction without a second consumer — the winapi layer wraps ctypes once; everything else calls it directly. No intermediate "platform" layer.
- Process boundaries are trust boundaries — the runner runs as `sbx-user`, the shell runs under a restricted token. Code on each side of that boundary trusts nothing from the other side except the defined contract.

## Runtimes

Two processes at steady state, plus transient helpers:

- Engine CLI — Python, runs as the host user (unprivileged). Entry point for all commands. Single-threaded except for I/O relay during `start`.
- Runner — Python (the engine re-invoked with `_run`), runs as `sbx-user`. Transient: lives only while the sandboxed shell is alive. Creates the restricted token, spawns the shell, relays I/O, exits when the shell exits.
- Elevation helper — Python (the engine re-invoked with an internal elevation subcommand), runs elevated via UAC. Transient: performs one privileged operation and exits. Communicates result back to the unprivileged engine via a temp file.
- Proxy — Python async process on loopback, runs as the host user. Long-lived: started on first sandbox start if not already running, stopped on last sandbox stop or explicitly. Single port, multiplexes per PID.
- Sandboxed shell — the user's configured shell (bash, cmd, etc.), runs under the restricted token. The engine doesn't own this process's internals — it just launches and monitors it.

Constraint forcing this topology: `CreateProcessAsUser` with a derived restricted token works without elevation only when called from the same logon session. That requires the runner to already be running as `sbx-user`.

## Modules

Twelve modules in three layers.

Utility layer (no sandbox domain knowledge):
- winapi

Core layer (sandbox domain, no UI):
- config, store, identity, mounts, tokens, network, process, elevation, proxy

Entry points:
- engine, cli

### winapi

Role: thin ctypes wrapper over every Win32 API the engine needs.

- Holds: DLL bindings, struct definitions, constants, low-level helper functions (SID allocation, handle management). Covers: bind filter, user management, SIDs, ACLs, restricted tokens, process creation, WFP, ConPTY (`CreatePseudoConsole`/`ResizePseudoConsole`/`ClosePseudoConsole`), DPAPI.
- Notes: evolved from `poc/winapi.py`. Pure functions and stateless calls — no sandbox concepts leak in. Adding a new Win32 call means adding it here, nowhere else.
- Depends on: nothing (leaf module).

### config

Role: load, validate, and resolve a project's `.sandbox/config.json`.

- Holds: JSON schema validation, path resolution (`.` → project root, `~` → host home), mount source existence checks, shell executable lookup, network preset resolution.
- Notes: returns a frozen dataclass. All paths are resolved to absolute paths at parse time. Invalid config raises with a clear message naming the offending key.
- Depends on: nothing (reads files, pure logic).

### store

Role: persist and query sandbox metadata across all projects.

- Holds: sandbox records (name, state, synthetic SID string, config path, PIDs, creation time), CRUD operations, state transitions.
- Notes: JSON file in `%LOCALAPPDATA%\sbx\sandboxes.json`. File-locked on write to handle concurrent CLI invocations. Each record is keyed by project path (one sandbox per project). Name is a display alias for easier lookup, defaults to the project directory name.
- Depends on: nothing (reads/writes a JSON file).

### identity

Role: manage the shared sandbox user account, its credentials, and synthetic SIDs.

- Holds: user creation/deletion (`NetUserAdd`/`NetUserDel`), credential generation, DPAPI-encrypted credential storage/retrieval, synthetic SID generation, SID serialization to/from string form.
- Notes: credentials stored in `%LOCALAPPDATA%\sbx\credentials.json` (DPAPI-encrypted, readable only by the host user). Synthetic SIDs are random under authority `{0,0,0,0,0,42}` with 4 sub-authorities — collision probability is negligible but checked on generation.
- Depends on: winapi (user management, SID, DPAPI APIs).

### mounts

Role: set up and tear down filesystem isolation for a sandbox.

- Holds: bind link creation/removal (`BfSetupFilter`/`BfRemoveMapping`), ACL management on backing paths (grant per-sandbox SID via `SetEntriesInAcl` + `SetNamedSecurityInfo`), ACL cleanup on destroy.
- Notes: all operations require elevation — callers must go through the elevation module. Bind link virtual paths live under `C:\Users\sbx-user\<sandbox-name>\`. Leftover bind links from a crashed destroy are detected and cleaned up.
- Depends on: winapi (bind filter, ACL APIs).

### tokens

Role: create restricted tokens for sandbox processes.

- Holds: restricted token creation (`CreateRestrictedToken` with `DISABLE_MAX_PRIVILEGE`), RestrictedSids list assembly (`[per_sandbox_sid, BUILTIN\Users]`).
- Notes: called by the runner (inside the `sbx-user` logon session), not by the engine CLI directly. The token is a primary token suitable for `CreateProcessAsUser`.
- Depends on: winapi (token APIs, SID APIs).

### network

Role: manage WFP rules and the proxy lifecycle.

- Holds: WFP rule installation/removal (scoped to `sbx-user`'s SID, block all egress except loopback to proxy port), proxy start/stop, PID→policy registration/deregistration with the proxy.
- Notes: WFP rules are static — installed once during `install`, removed during `uninstall`. They never change per sandbox. Per-sandbox network policy is purely a proxy concern. The proxy is started lazily on first `start` if not already running.
- Depends on: winapi (WFP APIs), proxy (lifecycle management).

### process

Role: launch and manage sandboxed shell processes via the command runner pattern, with full interactive terminal support via ConPTY.

- Holds: runner launch (`CreateProcessWithLogonW` to re-invoke engine as `sbx-user`), ConPTY pseudo-console creation and management, I/O relay between the CLI terminal and the runner's PTY, PID tracking, process termination.
- Notes: the runner creates a Windows pseudo-console (`CreatePseudoConsole`) and attaches the sandboxed shell to it. This gives the shell proper terminal emulation — ANSI escapes, line editing, tab completion, Ctrl+C handling, window resize. The engine CLI side relays between its own console and the PTY's I/O pipes. On stop, the engine terminates the runner process (which kills the shell child with it).
- Depends on: winapi (process APIs, ConPTY APIs), tokens (called by the runner side), identity (reads credentials for `CreateProcessWithLogonW`), store (registers/deregisters PIDs).

### elevation

Role: run privileged operations via a UAC-elevated subprocess.

- Holds: `ShellExecuteEx` with `runas` verb to re-invoke the engine with an internal elevation subcommand, argument serialization, result communication via temp file, error propagation.
- Notes: each elevation is a separate UAC prompt. The elevated subprocess performs one operation (e.g. "create bind links for sandbox X") and exits. No persistent elevated process.
- Depends on: winapi (`ShellExecuteEx`).

### proxy

Role: enforce per-sandbox network policy via TLS SNI inspection.

- Holds: async TCP server on loopback, CONNECT tunnel handling, TLS ClientHello parsing for SNI extraction, domain allowlist matching, PID→sandbox lookup via `GetExtendedTcpTable`, policy table (PID → allowed domains | "all" | "none").
- Notes: runs as a separate long-lived process. Default policy is deny-all — a connection from an unknown PID or a PID with no registered policy is rejected. The engine registers PID→policy mappings at sandbox start and deregisters at stop. Communication between engine and proxy for policy updates is via a local socket or named pipe (detail TBD in proxy implementation spec).
- Lifecycle: PID file + idle timeout. Proxy writes `%LOCALAPPDATA%\sbx\proxy.pid` (PID + port). On `sbx start`, engine checks if proxy is alive (PID file + process existence), starts it if not, registers sandbox PID. On `sbx stop`, deregisters PID. Proxy self-terminates after 60s with no registered sandboxes. Engine crash → proxy idles out. Proxy crash → WFP blocks everything (fail-safe), next start detects stale PID file and starts fresh.
- Depends on: winapi (`GetExtendedTcpTable`).

### engine

Role: orchestration facade — the single API that CLI and (future) TUI call.

- Holds: lifecycle commands (install, create, start, stop, destroy, uninstall, list, status), sequencing of sub-operations, error handling and rollback on partial failure.
- Notes: stateless between calls — all state lives in the store. Each command is a sequence of calls to core modules. Engine decides which operations need elevation and routes them through the elevation module.
- Depends on: config, store, identity, mounts, network, process, elevation.

### cli

Role: command-line interface — parses args and calls the engine.

- Holds: argument parsing (click or argparse), output formatting, exit codes.
- Notes: thin layer — no business logic. Maps 1:1 to engine commands.
- Depends on: engine.

## Connections

```
                        ┌───────────┐
                        │    cli    │
                        └─────┬─────┘
                              │
                        ┌─────▼─────┐
               ┌────────┤  engine   ├────────┐
               │        └──┬──┬──┬──┘        │
               │           │  │  │           │
        ┌──────▼──┐  ┌─────▼┐ │ ┌▼───────┐ ┌▼─────────┐
        │ identity│  │mounts│ │ │ network │ │ elevation │
        └────┬────┘  └──┬───┘ │ └──┬──────┘ └─────┬────┘
             │          │     │    │               │
             │          │     │    │    ┌───────┐  │
             │          │     │    └────► proxy  │  │
             │          │     │         └───┬───┘  │
             │          │     │             │      │
             │     ┌────▼─────▼──┐          │      │
             │     │   process   │          │      │
             │     └──┬──────┬───┘          │      │
             │        │      │              │      │
             │     ┌──▼───┐  │              │      │
             │     │tokens│  │              │      │
             │     └──┬───┘  │              │      │
             │        │      │              │      │
     ┌───────▼────────▼──────▼──────────────▼──────▼───┐
     │                     winapi                       │
     └──────────────────────────────────────────────────┘

     ┌────────┐  ┌───────┐
     │ config │  │ store │    (leaves — no winapi dependency)
     └────────┘  └───────┘
```

Hub: engine — every user-facing operation flows through it.

Entry points: cli (V1), tui (future).

Universal leaves: winapi (all Win32 calls), config (pure parsing), store (pure persistence).

Internal edges:
- cli → engine : lifecycle commands
- engine → config : parse config for create/start
- engine → store : read/write sandbox metadata
- engine → identity : install/uninstall user; create SIDs
- engine → mounts : create/destroy bind links + ACLs
- engine → network : install/uninstall WFP; start/stop proxy policy
- engine → process : start/stop shell processes
- engine → elevation : delegate privileged operations
- process → tokens : runner creates restricted token
- process → identity : read credentials for `CreateProcessWithLogonW`
- process → store : register/deregister PIDs
- network → proxy : start/stop proxy, register PID→policy
- identity → winapi, mounts → winapi, tokens → winapi, network → winapi, process → winapi, elevation → winapi, proxy → winapi

External edges:
- winapi → Windows kernel (syscalls via ntdll/win32)
- proxy → network (loopback TCP, forwarded TLS tunnels)
- elevation → Windows shell (UAC via `ShellExecuteEx`)

## Contracts

### cli → engine

```python
class Engine:
    def install() -> InstallResult
    def uninstall() -> None
    def create(config_path: Path, name: str | None = None) -> CreateResult
    def destroy(sandbox: str) -> None          # name or project path
    def start(sandbox: str) -> StartHandle     # name or project path
    def stop(sandbox: str) -> None             # name or project path
    def list() -> list[SandboxInfo]
    def status(sandbox: str) -> SandboxStatus  # name or project path
```

`StartHandle` — opaque handle the CLI uses to relay I/O and wait for shell exit. Holds the runner process handle and the relay streams.

`SandboxInfo` / `SandboxStatus` — frozen dataclasses. Status is a superset of info (adds live PID, resource usage).

### engine → config

```python
class SandboxConfig:
    """Frozen. All paths absolute. Validated at construction."""
    name: str
    mounts: list[Mount]        # source (abs), target (relative)
    shell: ShellKind           # enum: git_bash, cmd, powershell, pwsh
    network: NetworkPreset     # enum: none, claude_api_only, all

def load_config(config_path: Path) -> SandboxConfig
```

### engine → store

```python
class SandboxRecord:
    project_path: Path         # primary key — one sandbox per project
    name: str                  # display alias, default = project dir name
    state: SandboxState        # enum: created, running, stopped
    synthetic_sid: str         # S-1-... string form
    config_path: Path          # usually <project>/.sandbox/config.json
    pids: list[int]            # runner + shell PIDs when running
    created_at: datetime

class Store:
    def get(project_path: Path) -> SandboxRecord | None
    def get_by_name(name: str) -> SandboxRecord | None
    def list() -> list[SandboxRecord]
    def add(record: SandboxRecord) -> None
    def update(project_path: Path, **fields) -> None
    def remove(project_path: Path) -> None
```

### engine → elevation

```python
class ElevationHelper:
    def run_elevated(operation: str, args: dict) -> ElevationResult
```

Operations are string-tagged commands (e.g. `"create_bind_links"`, `"set_acls"`, `"install_wfp_rules"`). Args are JSON-serializable. The elevated subprocess deserializes, executes, and writes the result to a temp file. The helper reads the result and raises on error.

### process → tokens (runner-side)

```python
def create_sandbox_token(
    sandbox_sid: str,          # S-1-... string to convert back to SID
) -> int:                      # token HANDLE
```

Called inside the runner (running as `sbx-user`). Opens the runner's own process token, creates a restricted token with `RestrictedSids = [sandbox_sid, BUILTIN\Users]` and `DISABLE_MAX_PRIVILEGE`. Returns the token handle for `CreateProcessAsUser`.

### network → proxy

```python
class ProxyControl:
    def start() -> None
    def stop() -> None
    def register(pid: int, policy: NetworkPolicy) -> None
    def deregister(pid: int) -> None

class NetworkPolicy:
    preset: NetworkPreset
    allowed_domains: list[str] | None   # None = use preset defaults
```

Communication mechanism between engine and proxy process TBD (named pipe or local socket). The proxy is a separate long-lived process; `ProxyControl` is the client stub in the engine.

## Cross-cutting

### Error policy

Raise exceptions for failures. Each module defines its own exception subclass inheriting from `SandboxError`. The engine catches and translates to user-facing messages. No silent fallbacks — if a bind link fails, the create operation fails loudly.

```python
class SandboxError(Exception): ...
class ConfigError(SandboxError): ...
class ElevationError(SandboxError): ...
class MountError(SandboxError): ...
class TokenError(SandboxError): ...
class NetworkError(SandboxError): ...
class ProcessError(SandboxError): ...
class StoreError(SandboxError): ...
class IdentityError(SandboxError): ...
```

### Configuration

Two layers:
- Per-project: `.sandbox/config.json` — sandbox definition (mounts, shell, network).
- Global: `%LOCALAPPDATA%\sbx\` — store, credentials, proxy state. Not user-editable except through the CLI.

### Logging

Python `logging` module. Engine sets up a file handler to `%LOCALAPPDATA%\sbx\sbx.log` and a stderr handler for the CLI. Log level configurable via `--verbose` / `--debug` flags. The proxy logs to the same directory (`proxy.log`).

### Units

All paths are `pathlib.Path` objects internally. SIDs are strings (`S-1-...`) except at the winapi boundary where they're raw pointers. PIDs are `int`. Handles are `int` (raw Windows HANDLE values), always wrapped in a context manager or explicitly closed.

## Open decisions

- Proxy implementation — async Python (asyncio) vs. an existing tool (e.g. mitmproxy). Leans asyncio for full control and fewer dependencies.
- Proxy ↔ engine communication — named pipe vs. local TCP socket for policy registration. Named pipe is more Windows-native; TCP is simpler to implement.
- Store locking — file-level lock (`msvcrt.locking`) vs. a named mutex. File lock is simpler.
- TUI framework — Textual or similar. Deferred per spec.
- `CreateProcessAsUser` vs. `CreateProcessWithTokenW` for spawning the shell from the runner — both should work from the same logon session. Needs a PoC to confirm which plays better with ConPTY.
- ConPTY window resize propagation — the engine CLI needs to detect its own console resize events and forward them to the pseudo-console via `ResizePseudoConsole`. Straightforward but needs testing across shell types.
