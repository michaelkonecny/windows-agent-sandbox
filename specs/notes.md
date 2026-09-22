# Implementation Notes — Windows Agent Sandbox

Deviations from `plan.md` and follow-ups noticed during implementation.

## Deviations

- ConPTY replaced with pipe-redirected I/O — ConPTY produced zero output under
  restricted tokens on Windows 11 22621 (ctypes marshalling issue). Switched to
  `STARTF_USESTDHANDLES` with anonymous inheritable pipes. Relay threads bridge
  named pipes (engine↔runner IPC) and anonymous pipes (runner↔shell I/O).

- Shell launched without `CREATE_NO_WINDOW` — restricted tokens cannot create a
  new console subsystem. The shell inherits the runner's hidden console instead.
  `SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX)` suppresses
  error dialogs in the runner.

- `whoami` unusable under `DISABLE_MAX_PRIVILEGE` — returns "Access is denied".
  Tests use `echo %username%` with explicit `USERNAME` env var instead.

- `RestrictedSids` includes `Everyone` — added alongside per-sandbox SID and
  `BUILTIN\Users` to prevent `STATUS_DLL_INIT_FAILED` during process
  initialization.

- WFP rules via PowerShell instead of ctypes WFP APIs — plan specified
  `FwpmEngineOpen0`, `FwpmFilterAdd0`, etc. First attempt used `netsh
  advfirewall firewall`, but netsh doesn't support per-user rule scoping.
  Switched to PowerShell `New-NetFirewallRule` with `-LocalUser` SDDL
  parameter for proper per-user scoping. Simpler than ctypes WFP bindings,
  same security effect.

- `GetExtendedTcpTable` byte order — the plan didn't mention this, but
  `dwLocalAddr` in `MIB_TCPROW_OWNER_PID` stores IP addresses in network byte
  order read as native (little-endian) DWORDs. Must use `struct.unpack("<I",
  ...)` not `"!I"`.

- Restricted SIDs skipped for Cygwin/MSYS2 shells — restricted SIDs add a
  second access check against every secured kernel object.  Cygwin/MSYS2
  shells (git-bash) touch session-local kernel objects during init
  (CreateFileMapping for shared memory, named pipes for signal handling)
  whose DACLs don't include the restricted SIDs.  No combination of token
  DACL fixes (NULL default DACL, NULL object DACL, adding the logon SID)
  resolved it — the problem is architectural: Cygwin's runtime accesses
  objects whose security descriptors are outside our control.  For
  Cygwin-based shells, `create_sandbox_token` uses `DISABLE_MAX_PRIVILEGE`
  only (strips all privileges except `SeChangeNotifyPrivilege`) without
  adding restricted SIDs.  Security for Cygwin shells still comes from:
  separate user account, filesystem ACLs via synthetic SID, Job Object
  containment, WFP network rules, and privilege stripping.  Native shells
  (cmd, powershell, pwsh) keep the full restricted-SID token.  Detection
  is by checking for `msys-2.0.dll` or `cygwin1.dll` near the shell binary.

- Token DACL hardening for non-Cygwin shells — after creating the restricted
  token, `set_kernel_object_null_dacl` sets a NULL DACL on the token object
  itself (so the process can query its own token via NtQueryInformationToken),
  and `set_token_null_default_dacl` sets the token's default DACL to NULL (so
  objects created by the process are accessible).  Requires `WRITE_DAC` access
  on the token handle, obtained by adding it to `open_process_token`'s access
  mask.

- Token and shell DACLs no longer NULL — the earlier NULL token DACL and
  NULL default DACL let any process, including another sandbox's shell,
  open a sandbox's processes with full access. Replaced by explicit DACLs
  (see spec, Process launch mechanism). Integration tests 29-42 and 69-71
  still pass with them.

- Shell no longer inherits the runner's pipe ends — `create_pipe` made
  both ends inheritable, so the shell held its own stdin write end and
  never saw EOF. Needed for scriptable `sbx start` (test 73).

## Follow-ups

- TUI — deferred per spec, not implemented.
- Custom network presets — deferred per spec.
- Log capture and forwarding — deferred per spec.
- ConPTY revisit — may work on newer Windows builds or with different ctypes
  approach. Current pipe-based I/O is functional but lacks terminal emulation
  features (colours, cursor positioning).
- Console resize propagation — not implemented (irrelevant without ConPTY).
