# Architecture — Windows Agent Sandbox

Status: approved. Source of truth for structure; the project spec (./spec.md) owns
what the product does.

Terminology:

- engine — the Python library that manages the full sandbox lifecycle; no UI.
- runner — the engine re-invoked as the sandbox's own account; strips privileges from its token and spawns the shell. An internal subprocess, not a separate binary.
- sandbox account — the local account `sbx-<name>` a sandbox runs as. One per sandbox, and the thing that isolates sandboxes from each other (see spec, User accounts).
- sandbox group — the local group every sandbox account joins, so WFP rules can be scoped once rather than per account.
- store — persistent JSON file tracking all sandbox metadata across projects.
- elevation helper — a subprocess spawned with UAC (`runas` verb) to perform privileged operations.

## Principles

- Fail-safe — every default denies access. Network: deny-all. Filesystem: a sandbox account is granted nothing beyond its own mounts and what `BUILTIN\Users` already allows. A missing config key means maximum restriction.
- Least privilege — the engine runs unprivileged. Only bind links, ACLs, WFP rules, and user management elevate, and only for the duration of that operation.
- Single responsibility per module — each module owns one Windows primitive or one domain concept. A likely change (e.g. swapping the proxy implementation, adding a new shell) touches one module.
- No abstraction without a second consumer — the winapi layer wraps ctypes once; everything else calls it directly. No intermediate "platform" layer.
- Process boundaries are trust boundaries — the runner runs as the sandbox's own account, the shell runs under a privilege-stripped token from it. Code on each side of that boundary trusts nothing from the other side except the defined contract.

## Runtimes

Five process roles, four alive during a running sandbox:

- Engine CLI — Python, runs as the host user (unprivileged). Entry point for all commands. During `start`, stays alive to relay I/O between the terminal and the runner; exits when the shell exits.
- Runner — Python (the engine re-invoked with `_run`), runs as the sandbox's own account. Lives while the sandboxed shell is alive. Creates the privilege-stripped token, spawns the shell inside a Job Object, relays I/O, exits when the shell exits.
- Proxy — Python async process on loopback, runs as the host user. Long-lived: started on first sandbox start if not already running, self-terminates after 60s idle. Single port, multiplexes per sandbox via Job Object membership.
- Elevation helper — Python (the engine re-invoked with an internal elevation subcommand), runs elevated via UAC. Transient: performs one privileged operation and exits. Communicates result back to the unprivileged engine via a temp file.
- Sandboxed shell — the user's configured shell (bash, cmd, etc.), runs under the privilege-stripped token inside the runner's Job Object. All child processes inherit job membership. The engine doesn't own this process's internals — it just launches and monitors it.

During a running sandbox: Engine CLI + Runner + Proxy + Shell (and its children) = 4+ processes. Between sessions: 0-1 (proxy during idle timeout).

Constraint forcing this topology: `CreateProcessAsUser` with a token derived from another works without elevation only when called from the same logon session. That requires the runner to already be running as the sandbox's account.

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

- Holds: DLL bindings, struct definitions, constants, low-level helper functions (SID allocation, handle management). Covers: bind filter, user and local group management, profile deletion (`DeleteProfileW`), SIDs, ACLs, token creation, process creation, Job Objects (`CreateJobObject`/`AssignProcessToJobObject`/`IsProcessInJob`/`TerminateJobObject`), WFP, ConPTY (`CreatePseudoConsole`/`ResizePseudoConsole`/`ClosePseudoConsole`), DPAPI, TCP table (`GetExtendedTcpTable`).
- Notes: evolved from `poc/winapi.py`. Pure functions and stateless calls — no sandbox concepts leak in. Adding a new Win32 call means adding it here, nowhere else.
- Depends on: nothing (leaf module).

### config

Role: load, validate, and resolve a project's `.sandbox/config.json`.

- Holds: JSON schema validation, path resolution (`.` → project root, `~` → host home), mount source existence checks, mount target uniqueness validation, shell executable lookup, network preset resolution, default config scaffolding.
- Notes: returns a frozen dataclass. All paths are resolved to absolute paths at parse time. Duplicate mount targets are rejected at parse time. Invalid config raises with a clear message naming the offending key. `scaffold_config` writes a `.sandbox/config.json` with commented defaults; refuses if the file already exists.
- Depends on: nothing (reads/writes files, pure logic).

### store

Role: persist and query sandbox metadata across all projects.

- Holds: sandbox records (name, state, account name, config path, PIDs, creation time), CRUD operations, state transitions.
- Notes: JSON file in `%LOCALAPPDATA%\sbx\sandboxes.json`. Locked for both reading and writing, so a read cannot catch a half-written file. Each record is keyed by project path (one sandbox per project). Names must be unique across all sandboxes, compared case-insensitively — the name becomes the account `sbx-<name>`, and Windows account names are case-insensitive. See Sandbox name in the project spec for the rules and the collision prompt.
- Depends on: nothing (reads/writes a JSON file).

### identity

Role: manage per-sandbox accounts and their credentials.

- Holds: account creation/deletion (`NetUserAdd`/`NetUserDel`), sandbox-group membership, hiding accounts from the sign-in screen, profile deletion, name derivation and validation, credential generation, DPAPI-encrypted credential storage/retrieval keyed by sandbox.
- Notes: credentials stored in `%LOCALAPPDATA%\sbx\credentials.json` (DPAPI-encrypted, readable only by the host user). Synthetic SIDs are random under authority `{0,0,0,0,0,42}` with 4 sub-authorities — collision probability is negligible but checked on generation.
- Depends on: winapi (user management, SID, DPAPI APIs).

### mounts

Role: set up and tear down filesystem isolation for a sandbox.

- Holds: bind link creation/removal (`BfSetupFilter`/`BfRemoveMapping`), ACL management on backing paths (grant the sandbox's account via `SetEntriesInAcl` + `SetNamedSecurityInfo`), ACL cleanup on destroy.
- Notes: all operations require elevation — callers must go through the elevation module. Bind link virtual paths live directly in the sandbox account's home, `C:\Users\sbx-<name>\`, which must already exist: create logs the account on once first, or Windows diverts the real profile to `sbx-<name>.<COMPUTERNAME>`. Leftover bind links from a crashed destroy are detected and cleaned up.
- Depends on: winapi (bind filter, ACL APIs).

### tokens

Role: strip privileges from the token a sandbox process runs under.

- Holds: token creation (`CreateRestrictedToken` with `DISABLE_MAX_PRIVILEGE` and an empty RestrictedSids list).
- Notes: called by the runner (inside the sandbox account's logon session), not by the engine CLI directly. The token is a primary token suitable for `CreateProcessAsUser`. No restricted SIDs: isolation comes from the account, and a restricted SID list is precisely what Cygwin shells cannot start under — see User accounts in the project spec. Every shell is treated the same, so there is no per-shell branch here.
- Depends on: winapi (token APIs, SID APIs).

### network

Role: manage WFP rules and the proxy lifecycle.

- Holds: WFP rule installation/removal (scoped to the sandbox group's SID, block all egress except loopback to proxy port), proxy start/stop, Job Object→policy registration/deregistration with the proxy.
- Note: rules go in via PowerShell `New-NetFirewallRule -LocalUser` (an SDDL string), not the ctypes WFP APIs; `netsh` offers no per-user scoping.
- Notes: WFP rules are static — installed once during `install`, removed during `uninstall`. They never change per sandbox. Per-sandbox network policy is purely a proxy concern. The proxy is started lazily on first `start` if not already running.
- Depends on: winapi (WFP APIs), proxy (lifecycle management).

### process

Role: launch and manage sandboxed shell processes via the command runner pattern, with full interactive terminal support via ConPTY.

- Holds: runner launch (`CreateProcessWithLogonW` to re-invoke engine as the sandbox's account), named Job Object creation, ConPTY pseudo-console creation and management, I/O relay between the CLI terminal and the runner's PTY, PID tracking, process termination, re-invocation command line construction.
- Notes: the runner creates a named Job Object (`sbx-job-<sandbox-name>`) with a security descriptor granting the host user read access, then creates a ConPTY and attaches the sandboxed shell to both. The Job Object ensures all child processes (anything the user launches from the shell) inherit membership — this is how the proxy identifies which sandbox a connecting process belongs to. ConPTY gives proper terminal emulation — ANSI escapes, line editing, tab completion, window resize. Ctrl+C is the exception: an `0x03` byte on the pseudoconsole's input pipe does not become a `CTRL_C_EVENT` for the client, so a running command is not interrupted (see `notes-2.md`). Host and runner run under different accounts, so two null-DACL named pipes carry VT bytes between them; the engine CLI side relays between its own console and those pipes, and resize requests travel in band on the input pipe as a private OSC sequence. On stop, the engine terminates the Job Object (which kills the shell and all its children).
- Trust boundary: this module's code runs in two contexts — engine CLI side (host user, unprivileged) handles runner launch and I/O relay; runner side (the sandbox's account) handles token creation, Job Object setup, and shell spawn. Same pattern as the elevation module.
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

- Holds: lifecycle commands (install, init, create, start, stop, destroy, uninstall, list, status), sequencing of sub-operations, error handling and rollback on partial failure.
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
- engine → config : parse config for create/start; scaffold config for init
- engine → store : read/write sandbox metadata
- engine → identity : derive and validate names; create/delete accounts; read credentials
- engine → mounts : create/destroy bind links + ACLs
- engine → network : install/uninstall WFP; start/stop proxy policy
- engine → process : start/stop shell processes
- engine → elevation : delegate privileged operations
- process → tokens : runner strips privileges from its token
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
    def init(project_path: Path) -> Path
        """Scaffold .sandbox/config.json. Returns the created path."""
    def create(config_path: Path, name: str | None = None) -> CreateResult
    def destroy(sandbox: str) -> None          # name or project path
    def start(sandbox: str) -> StartHandle     # name or project path
    def stop(sandbox: str) -> None             # name or project path
    def list() -> list[SandboxInfo]
    def status(sandbox: str) -> SandboxStatus  # name or project path
```

`StartHandle` — opaque handle the CLI uses to relay I/O and wait for shell exit. Holds the runner process handle and the two named-pipe handles carrying VT bytes to and from the runner.

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

def scaffold_config(project_path: Path) -> Path
    """Write .sandbox/config.json with defaults. Raises ConfigError if it already exists.
    Returns the created file path."""
```

### engine → store

```python
class SandboxRecord:
    project_path: Path         # primary key — one sandbox per project
    name: str                  # display alias, default = project dir name
    state: SandboxState        # enum: created, running, stopped
    account: str               # the local account, sbx-<name>
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
    def sandbox_name(project_path: Path, requested: str | None = None) -> str
        """Derive a name from the project directory, or validate one the user
        supplied. Raises on an invalid name. Collisions are the engine's to
        resolve — see Sandbox name in the project spec."""

    def create_account(name: str) -> str
        """Create sbx-<name>, join it to the sandbox group, hide it from the
        sign-in screen, log it on once so Windows creates its profile, and
        store DPAPI-encrypted credentials. Returns the account name.
        Requires elevation."""

    def delete_account(name: str) -> None
        """Delete the account, its profile and its stored credentials.
        DeleteProfileW removes the profile directory and its registry entry
        together. Requires elevation."""

    def get_credentials(name: str) -> tuple[str, str]
        """Return (account, password) for one sandbox, from the DPAPI store."""

    def create_sandbox_group() -> None
        """Create the local group every sandbox account joins, which the WFP
        rules are scoped to. Install-time, idempotent. Requires elevation."""
```

### engine → mounts

```python
class MountSpec:
    source: Path               # absolute backing path
    target: str                # relative path under the sandbox's home
    account: str               # the account to grant on the backing path

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
        """Install static WFP deny rules scoped to the sandbox group. Requires elevation."""

    def uninstall_wfp_rules() -> None
        """Remove WFP rules. Requires elevation."""

    def ensure_proxy_running() -> None
        """Start the proxy if not already alive."""

    def register_sandbox(job_name: str, policy: NetworkPolicy) -> None
        """Register a sandbox's Job Object name and its network policy with the
        proxy. The proxy resolves a connection's PID to a sandbox by asking
        which job it belongs to, so both sides key on this exact string."""

    def deregister_sandbox(job_name: str) -> None
        """Deregister a sandbox from the proxy, under the name it registered."""
```

### engine → elevation

```python
class ElevationHelper:
    def run_elevated(operation: str, args: dict) -> ElevationResult
```

Operations are string-tagged commands (e.g. `"create_account"`, `"delete_account"`, `"create_bind_links"`, `"install_wfp_rules"`). Args are JSON-serializable. The elevated subprocess deserializes, executes, and writes the result to a temp file. The helper reads the result and raises on error.

### process → tokens (runner-side)

```python
def create_sandbox_token() -> int:     # token HANDLE
```

Called inside the runner (running as the sandbox's account). Opens the runner's own process token and derives one with `DISABLE_MAX_PRIVILEGE` and an empty `RestrictedSids` list. Returns the token handle for `CreateProcessAsUser`. No per-shell variants.

### network → proxy

```python
class ProxyControl:
    def start() -> None
    def stop() -> None
    def register(job_name: str, policy: NetworkPolicy) -> None
    def deregister(job_name: str) -> None

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
- `CreateProcessAsUser` for spawning the shell from the runner — works from the same logon session and with ConPTY, covered by the integration and system tests.
- ConPTY resize propagation — the CLI reads `WINDOW_BUFFER_SIZE_EVENT` from its console input and sends `\x1b]9999;<cols>;<rows>\x07` on the input pipe; the runner strips it and calls `ResizePseudoConsole`.
- Packaging — develop as a pip-installable package (`python -m sbx`), decide final packaging later. The process module holds the re-invocation command line in a single configurable point so swapping to a PyInstaller exe is a one-line change.

## Open decisions

- TUI framework — Textual or similar. Deferred per spec.
- Whether the sandbox shell should inherit the host process's environment. It currently does, so host state such as `PROMPT` leaks in.
- How Ctrl+C should reach the sandbox shell, given ConPTY will not deliver it (see `notes-2.md`).
- Whether `sbx install` should refuse to proceed on a machine where local account creation is blocked by policy, rather than failing later at the first `create`.
