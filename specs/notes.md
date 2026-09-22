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

- Restricted SIDs no longer skipped for Cygwin/MSYS2 — earlier, git-bash
  ran with privilege stripping only, which gave it no filesystem isolation
  between sandboxes (found by system test 84 once mounts became readable).
  Root causes: `user32` init needs the logon SID (desktop DACL), and
  Cygwin's signal pipe DACL names only the account SID. Both SIDs are now
  in every shell's RestrictedSids; mounts grant the `sbx-users` group
  instead of the account (see spec, Mount setup).

- Token and shell DACLs no longer NULL — the earlier NULL token DACL and
  NULL default DACL let any process, including another sandbox's shell,
  open a sandbox's processes with full access. Replaced by explicit DACLs
  (see spec, Process launch mechanism). Integration tests 29-42 and 69-71
  still pass with them.

- Shell no longer inherits the runner's pipe ends — `create_pipe` made
  both ends inheritable, so the shell held its own stdin write end and
  never saw EOF. Needed for scriptable `sbx start` (test 73).

## Follow-ups

- Cygwin objects name the account SID — processes and shared memory a
  git-bash sandbox creates grant `sbx-user`, which every sandbox's token
  passes. One git-bash sandbox can signal another's processes. Filesystem
  isolation is unaffected.
- Shared account profile — HOME/TEMP of `sbx-user` is shared by all
  sandboxes.
- Other world-writable system dirs (`C:\Windows\Temp`, subfolders of
  `C:\Users\Public`) stay writable; only the two roots are locked.
- Mount sources with an OWNER RIGHTS ACE (e.g. dirs from Python 3.13+
  `tempfile.mkdtemp`) — files the sandbox creates there are owned by
  `sbx-user` and unreadable to the host.
- Schannel fails under the restricted token — `AcquireCredentialsHandle`
  returns `SEC_E_NO_CREDENTIALS` for any token with RestrictedSids (tried
  adding every normal group SID; only dropping RestrictedSids fixes it).
  So Windows-native TLS clients (System32 curl, PowerShell
  `Invoke-WebRequest`, .NET, WinHTTP) can't do HTTPS inside a sandbox.
  OpenSSL-based ones (Node, so Claude Code; Git's curl) are unaffected.
  System tests probe connectivity with CONNECT + plain HTTP instead.
- Runner DACLs — Windows' defaults granted `sbx-user` full access to the
  runner process (unrestricted token) and read to its logon SID, both in
  every sandbox's RestrictedSids. The runner now locks its process, thread,
  token and default DACL to SYSTEM + host user (test 99, host-side DACL
  read). Worth an independent security review of the whole runner/shell
  boundary anyway.

- TUI — deferred per spec, not implemented.
- Custom network presets — deferred per spec.
- Log capture and forwarding — deferred per spec.
- ConPTY revisit — may work on newer Windows builds or with different ctypes
  approach. Current pipe-based I/O is functional but lacks terminal emulation
  features (colours, cursor positioning).
- Console resize propagation — not implemented (irrelevant without ConPTY).
