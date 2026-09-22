# AFK log — 2026-09-22, 8 h window

Decisions taken while you were away. Branch: `afk/hardening`.

- Work on hardening follow-ups from notes.md rather than new features — they're gaps in shipped behaviour.
- Found: the sandbox shell inherits the host's whole environment. Host env vars (possibly secrets) leak in, and TEMP/USERPROFILE/APPDATA point at the host profile, which the sandbox can't write — tools needing a temp dir or home break. Fix: shell env = sbx-user's own environment block (`CreateEnvironmentBlock`) + `HTTPS_PROXY`; runner gets the sbx package path and proxy port on its command line, not via env. New system test 98.
- Runner DACLs: read host-side, the runner's default process DACL granted sbx-user full access. Applied the defensive fix (runner locks its process/thread/token/default DACL to SYSTEM + host user once the shell token is built); test 99 checks the DACLs host-side. I did not build in-sandbox tooling to try reaching the runner — an independent security review of that boundary is still worth doing.
- Job Object and engine-runner pipes: replaced NULL DACLs with explicit ones (host user + SYSTEM; pipes also sbx-user read/write), single-instance pipes with a random name suffix. Covered by existing tests (stop, status, proxy lookups, session I/O); no in-sandbox probe written for it.
- Locked `C:\Windows\Temp` like ProgramData/Public (Users could create files there); added to test 85.
- Stopped here — the remaining follow-ups need your call, not mine:
  - Schannel under restricted tokens (structural; affects PowerShell/.NET HTTPS inside sandboxes).
  - Cygwin cross-sandbox signalling and the shared sbx-user profile (both inherent to one shared account).
  - `architecture.md` is marked approved but predates today's token/mount/env/DACL changes; spec.md and notes.md are current. Didn't rewrite an approved doc unasked.
- State: all suites green on `afk/hardening` (system 57 passed / 16 pwsh skips; unit+integration 76 passed / 2 skipped). Not merged into main.
- Removed unused NULL-DACL helpers from winapi (set_kernel_object_null_dacl, set_token_null_default_dacl) — dead since the explicit-DACL change, and the pattern behind today's bugs. Kept ConPTY helpers (notes list a ConPTY revisit).
- Nothing safe left to do autonomously; going idle after a final check-in.
