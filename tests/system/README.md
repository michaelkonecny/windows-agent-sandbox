# System tests

Black-box tests of what a user gets from `sbx install` → `sbx create` → `sbx start`: every step runs through the `sbx` CLI as a subprocess, with no mocks and no hand-made grants.

Meant for a disposable VM. The suite:

- creates and deletes the local account `sbx-user` (via `sbx install` / `sbx uninstall`)
- adds and removes Windows Firewall rules scoped to `sbx-user`
- creates bind links under `C:\Users\sbx-user`
- edits ACLs on fixture directories under `%TEMP%` and your home directory
- wipes any existing sbx state at session start (`sbx uninstall`, deletes `%LOCALAPPDATA%\sbx`)
- uninstalls sbx at session end

## Run

1. Once per VM, elevated: `python tests/system/setup_vm.py`. This sets `ConsentPromptBehaviorAdmin=0`, so admins elevate without a prompt.
2. `set SBX_SYSTEM_TESTS=1`. Setting it acknowledges the list above; without it, every test skips.
3. `python -m pytest tests/system -v`

Run it from an unprivileged shell. If it is launched elevated, it relaunches itself unprivileged via a one-shot scheduled task (`schtasks`, run level `LIMITED`), relays that run's output and exits with its exit code.

Preconditions, checked at session start: `EnableLUA=1`, `ConsentPromptBehaviorAdmin=0`, current user in `Administrators`.

## Layout

- `probes.py` — per-shell probe snippets. Each prints one line, `PROBE <id> OK|DENIED`, and tests assert only on those lines.
- `hostwin.py` — host-side Win32 queries (process owner, elevation, Job Object PIDs, firewall rules, ACLs).
- `syshelp.py` — `sbx` CLI driver, one-shot and live sessions (60 s limit each).
- `conftest.py` — opt-in gate, de-elevation, preconditions, fixture projects, session-end uninstall.
- `test_sys_*.py` — tests 74-95. They run in number order, with 80 (uninstall) last.
