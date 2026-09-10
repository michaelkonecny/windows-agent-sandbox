# Architecture — Windows Agent Sandbox

Status: approved. Source of truth for structure; the project spec (./spec.md) owns
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

Five process roles, four alive during a running sandbox:

- Engine CLI — Python, runs as the host user (unprivileged). Entry point for all commands. During `start`, stays alive to relay I/O between the terminal and the runner; exits when the shell exits.
- Runner — Python (the engine re-invoked with `_run`), runs as `sbx-user`. Lives while the sandboxed shell is alive. Creates the restricted token, spawns the shell inside a Job Object, relays I/O, exits when the shell exits.
- Proxy — Python async process on loopback, runs as the host user. Long-lived: started on first sandbox start if not already running, self-terminates after 60s idle. Single port, multiplexes per sandbox via Job Object membership.
- Elevation helper — Python (the engine re-invoked with an internal elevation subcommand), runs elevated via UAC. Transient: performs one privileged operation and exits. Communicates result back to the unprivileged engine via a temp file.
- Sandboxed shell — the user's configured shell (bash, cmd, etc.), runs under the restricted token inside the runner's Job Object. All child processes inherit job membership. The engine doesn't own this process's internals — it just launches and monitors it.

During a running sandbox: Engine CLI + Runner + Proxy + Shell (and its children) = 4+ processes. Between sessions: 0-1 (proxy during idle timeout).

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

- Holds: DLL bindings, struct definitions, constants, low-level helper functions (SID allocation, handle management). Covers: bind filter, user management, SIDs, ACLs, restricted tokens, process creation, Job Objects (`CreateJobObject`/`AssignProcessToJobObject`/`IsProcessInJob`/`TerminateJobObject`), WFP, ConPTY (`CreatePseudoConsole`/`ResizePseudoConsole`/`ClosePseudoConsole`), DPAPI, TCP table (`GetExtendedTcpTable`).
- Notes: evolved from `poc/winapi.py`. Pure functions and stateless calls — no sandbox concepts leak in. Adding a new Win32 call means adding it here, nowhere else.
- Depends on: nothing (leaf module).

### config

Role: load, validate, and resolve a project's `.sandbox/config.json`.

- Holds: JSON schema validation, path resolution (`.` → project root, `~` → host home), mount source existence checks, mount target uniqueness validation, shell executable lookup, network preset resolution.
- Notes: returns a frozen dataclass. All paths are resolved to absolute paths at parse time. Duplicate mount targets are rejected at parse time. Invalid config raises with a clear message naming the offending key.
- Depends on: nothing (reads files, pure logic).

### store

Role: persist and query sandbox metadata across all projects.

- Holds: sandbox records (name, state, synthetic SID string, config path, PIDs, creation time), CRUD operations, state transitions.
- Notes: JSON file in `%LOCALAPPDATA%\sbx\sandboxes.json`. File-locked on write to handle concurrent CLI invocations. Each record is keyed by project path (one sandbox per project). Name is a display alias for easier lookup, defaults to the project directory name. Names must be unique across all sandboxes — `add()` rejects a duplicate name and the user must supply `--name` with a different alias. Uniqueness matters because the name determines the bind link directory (`C:\Users\sbx-user\<name>\`).
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

- Holds: runner launch (`CreateProcessWithLogonW` to re-invoke engine as `sbx-user`), named Job Object creation, ConPTY pseudo-console creation and management, I/O relay between the CLI terminal and the runner's PTY, PID tracking, process termination, re-invocation command line construction.
- Notes: the runner creates a named Job Object (`sbx-job-<sandbox-name>`) with a security descriptor granting the host user read access, then creates a ConPTY and attaches the sandboxed shell to both. The Job Object ensures all child processes (anything the user launches from the shell) inherit membership — this is how the proxy identifies which sandbox a connecting process belongs to. ConPTY gives proper terminal emulation — ANSI escapes, line editing, tab completion, Ctrl+C handling, window resize. The engine CLI side relays between its own console and the PTY's I/O pipes. On stop, the engine terminates the Job Object (which kills the shell and all its children).
- Trust boundary: this module's code runs in two contexts — engine CLI side (host user, unprivileged) handles runner launch and I/O relay; runner side (`sbx-user`) handles token creation, Job Object setup, and shell spawn. Same pattern as the elevation module.
- Depends on: winapi (process APIs, ConPTY APIs, Job Object APIs), tokens (called by the runner side), identity (reads credentials for `CreateProcessWithLogonW`), store (registers/deregisters PIDs).

### elevation

Role: run privileged operations via a UAC-elevated subprocess.

- Holds: `ShellExecuteEx` with `runas` verb to re-invoke the engine with an internal elevation subcommand, argument serialization, result communication via temp file, error propagation.
- Notes: each elevation is a separate UAC prompt. The elevated subprocess performs one operation (e.g. "create bind links for sandbox X") and exits. No persistent elevated process.
- Depends on: winapi (`ShellExecuteEx`).

### proxy

Role: enforce per-sandbox network policy via TLS SNI inspection.

- Holds: async TCP server on loopback, CONNECT tunnel handling, TLS ClientHello parsing for SNI extraction, domain allowlist matching, sandbox identification via Job Object membership, policy table (Job Object → allowed domains | "all" | "none").
- Notes: Python asyncio. Runs as a separate long-lived process. Default policy is deny-all — a connection from an unknown process or one not in any registered Job Object is rejected. Engine communicates policy updates to the proxy over a local TCP socket.
- PID→sandbox resolution: the proxy receives a connection, looks up the source PID via `GetExtendedTcpTable`, then checks which registered Job Object that PID belongs to (via `IsProcessInJob`). This handles the full process tree — the shell, its children (e.g. `claude`), and their children all inherit Job Object membership from the runner.
- Lifecycle: PID file + idle timeout. Proxy writes `%LOCALAPPDATA%\sbx\proxy.pid` (PID + port). On `sbx start`, engine checks if proxy is alive (PID file + process existence), starts it if not, registers the sandbox's Job Object handle. On `sbx stop`, deregisters. Proxy self-terminates after 60s with no registered sandboxes. Engine crash → proxy idles out. Proxy crash → WFP blocks everything (fail-safe), next start detects stale PID file and starts fresh.
- Depends on: winapi (`GetExtendedTcpTable`, `IsProcessInJob`).

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
  ┌────────┐  ┌───────┐  ┌────▼────┐
  │ config ◄──┤ store ◄──┤ engine  ├──────────────────┐
  └────────┘  └───▲───┘  └┬──┬──┬──┘                  │
                  │        │  │  │                     │
                  │ ┌──────▼┐ │ ┌▼───────┐ ┌──────────▼┐
                  │ │ident- │ │ │ network │ │ elevation │
                  │ │ ity   │ │ └──┬──────┘ └───────────┘
                  │ └───┬───┘ │    │
                  │     │     │    │    ┌───────┐
                  │     │     │    └────► proxy  │
                  │     │     │         └───┬───┘
                  │     │     │             │
                  │ ┌───▼─────▼──┐          │
                  └─┤  process   │          │
                    └──┬──────┬──┘          │
                       │      │             │
                    ┌──▼───┐  │             │
                    │tokens│  │             │
                    └──┬───┘  │             │
                       │      │             │
     ┌─────────────────▼──────▼─────────────▼──────────┐
     │                     winapi                       │
     └──────────────────────────────────────────────────┘
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
- process → store : register/deregister sandbox PIDs and Job Object handles
- network → proxy : start/stop proxy, register Job Object→policy
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
class Mount:
    source: Path               # absolute, resolved at parse time
    target: str                # relative path under sandbox workspace

class SandboxConfig:
    """Frozen. All paths absolute. Validated at construction.
    Name is not part of the config — it's assigned at create time."""
    mounts: list[Mount]        # source (abs), target (relative); targets must be unique
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
    job_handle: int | None     # Job Object handle when running
    created_at: datetime

class Store:
    def get(project_path: Path) -> SandboxRecord | None
    def get_by_name(name: str) -> SandboxRecord | None
    def list() -> list[SandboxRecord]
    def add(record: SandboxRecord) -> None
    def update(project_path: Path, **fields) -> None
    def remove(project_path: Path) -> None
```

### engine → identity

```python
class Identity:
    def install_user() -> str
        """Create sbx-user, generate and store DPAPI-encrypted credentials.
        Return the username. No-op if user already exists."""

    def uninstall_user() -> None
        """Delete sbx-user and remove stored credentials."""

    def generate_sid() -> str
        """Create a random synthetic SID. Returns S-1-... string."""

    def get_credentials() -> tuple[str, str]
        """Return (username, password) for sbx-user, decrypted from DPAPI store."""
```

### engine → mounts

```python
class MountSpec:
    source: Path               # absolute backing path
    target: str                # relative path under sandbox workspace
    sandbox_sid: str           # S-1-... SID to grant access

class Mounts:
    def create(sandbox_name: str, specs: list[MountSpec]) -> None
        """Create bind links and set ACLs. Requires elevation."""

    def destroy(sandbox_name: str) -> None
        """Remove bind links and clean up ACLs. Requires elevation."""

    def verify(sandbox_name: str) -> list[str]
        """Check bind links are intact. Returns list of issues (empty = OK)."""
```

### engine → network

```python
class Network:
    def install_wfp_rules() -> None
        """Install static WFP deny rules scoped to sbx-user. Requires elevation."""

    def uninstall_wfp_rules() -> None
        """Remove WFP rules. Requires elevation."""

    def ensure_proxy_running() -> None
        """Start the proxy if not already alive."""

    def register_sandbox(job_handle: int, policy: NetworkPolicy) -> None
        """Register a sandbox's Job Object and its network policy with the proxy."""

    def deregister_sandbox(job_handle: int) -> None
        """Deregister a sandbox from the proxy."""
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
    def register(job_handle: int, policy: NetworkPolicy) -> None
    def deregister(job_handle: int) -> None

class NetworkPolicy:
    preset: NetworkPreset
    allowed_domains: list[str] | None   # None = use preset defaults
```

Engine communicates with the proxy over a local TCP socket on loopback. `ProxyControl` is the client stub in the engine; the proxy exposes a simple command protocol (register/deregister/stop) on a separate control port from the HTTPS proxy port.

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

## Resolved decisions

- Proxy implementation — asyncio. The proxy only needs CONNECT tunneling + SNI peeking; mitmproxy is overkill.
- Proxy ↔ engine communication — local TCP socket. Python asyncio has clean TCP support; Windows named pipes are fiddly in Python.
- Store locking — file-level lock (`msvcrt.locking`).
- Process tree tracking — Job Objects. Runner creates a named Job Object (`sbx-job-<sandbox-name>`), shell and all children inherit membership. Proxy opens the Job Object by name and calls `IsProcessInJob` to identify which sandbox a connecting process belongs to. Security descriptor on the Job Object grants read access to the host user.
- Packaging — develop as a pip-installable package (`python -m sbx`), decide final packaging later. The process module holds the re-invocation command line in a single configurable point so swapping to a PyInstaller exe is a one-line change.

## Open decisions

- TUI framework — Textual or similar. Deferred per spec.
- `CreateProcessAsUser` vs. `CreateProcessWithTokenW` for spawning the shell from the runner — both should work from the same logon session. Needs a PoC to confirm which plays better with ConPTY.
- ConPTY window resize propagation — the engine CLI needs to detect its own console resize events and forward them to the pseudo-console via `ResizePseudoConsole`. Straightforward but needs testing across shell types.
