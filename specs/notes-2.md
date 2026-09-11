# Implementation notes — iteration 01-conpty

Deviations from `specs/plan.md` and things found along the way.
Earlier iterations' notes are in `notes-1.md`.

## Why ConPTY works now

`notes-1.md` records ConPTY being abandoned after it produced zero output,
with "suspected ctypes marshalling" as the guess. Two real bugs, both
isolated by A/B test:

1. `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` takes the `HPCON` **by value** as
   `lpValue`, not a pointer to it. It is the odd one out among process
   attributes; the [documented sample][conpty-doc] passes `hpc`, not
   `&hpc`. We passed `byref()`, so Windows read the pointer as the console
   handle. Every call still returned success — `CreatePseudoConsole`,
   `UpdateProcThreadAttribute` and `CreateProcess` all reported OK, conhost
   spawned with the right `--width`/`--height`, and the child silently
   inherited the parent's console instead.
2. A child that inherits the parent's std handles writes to them rather
   than to its pseudoconsole. With the parent's stdio redirected to a pipe
   or file — pytest, or any CI runner — output bypassed the ConPTY and only
   its initial frame was ever emitted. Launching with
   `STARTF_USESTDHANDLES` and NULL std handles forces the child onto its
   own console.

Bug 1 broke ConPTY everywhere; bug 2 broke it only under redirected
stdio, which is why it first looked environment-dependent. `pywinpty`'s
ConPTY backend reproduces the same failure on this build, so it was never
specific to our code path — worth knowing before anyone blames the OS
again.

Diagnosis that generalises: when an attribute list looks correct, dump the
48 bytes and check `Count`, `Attribute`, `cbSize` and whether `lpValue`
*is* the value or points at it.

[conpty-doc]: https://learn.microsoft.com/en-us/windows/console/creating-a-pseudoconsole-session

## Deviations from the plan

- Launch the shell with `STARTF_USESTDHANDLES` and NULL std handles. The
  plan and the spec's Runner process both say to pass no std handles at
  all. Reality needs the explicit NULLs — see bug 2 above. The spec's
  Runner process step 7 has been corrected.
- Do not close a handle another thread is blocking on. Hit twice: the
  runner closing `pipe_in` under the input relay's `ReadFile`, and the CLI
  closing `CONIN$` under the input pump's `ReadConsoleInput`. `CloseHandle`
  waits for the pending synchronous read, so both deadlocked and neither
  process exited. Both now leave the handle to process exit and keep the
  thread a daemon. `pipe_out` is still closed explicitly — `ERROR_BROKEN_PIPE`
  on it is how the host learns the shell is gone.
- Read console input records rather than bytes in the CLI. The plan
  offered either; resize events exist only in the `INPUT_RECORD` stream, so
  `ReadConsoleInput` is the only option that covers both jobs.
- Replace integration.md's two whoami-based token scenarios. `whoami` is
  itself unusable once `DISABLE_MAX_PRIVILEGE` strips privileges
  (`notes-1.md` records this). Substituted observable effects: writing to
  the sandbox user's own home is denied, while a system path granting
  `BUILTIN\Users` stays readable.
- Add winapi helpers the plan did not list: `terminate_process`,
  `process_is_running`, a bounded `wait_for_process`, `read_console_input`,
  `NULL_STD_HANDLES`, and an explicit `inherit_handles` argument. The
  harness and the relays need them.
- Extract `encode_console_records` and `split_resize_requests` as pure
  functions. Both hold the fiddly logic and are untestable through a live
  console otherwise.

## Verified behaviour that contradicts the spec

Both are strict xfails in `tests/test_system.py`, so they fail loudly the
day they start working.

### Ctrl+C does not interrupt a running command

- Symptom: `ping -t` keeps running after the host sends `0x03`.
- Cause: writing `0x03` to a pseudoconsole's input pipe does not become a
  `CTRL_C_EVENT` for the attached client. Reproduced with no sandbox
  involved — a bare `ConPtyShell` writing `0x03` leaves `ping -t` running —
  so this is ConPTY, not the relay.
- The spec's Ctrl+C edge case ("ConPTY delivers it as `CTRL_C_EVENT` to the
  shell process") is wrong as written. Left unchanged pending a decision.
- Option, not implemented because it is new design: have the runner watch
  its input stream for `0x03` and call `GenerateConsoleCtrlEvent` on the
  shell's process group.

### A mount is not readable from inside its own sandbox — fixed

Left here for the record; the fix is described under AFK decisions below.

- Symptom: `type <mount>\work\from_host.txt` gives "Access is denied."
- Cause: `mounts.create` granted only the per-sandbox synthetic SID on the
  backing path, never `sbx-user`. A fully restricted token must pass the
  user check *and* the restricted-SID check. The synthetic SID satisfies
  only the second, so any backing path that does not already grant
  `sbx-user` — anything under the host user's profile, `%TEMP%` included —
  failed the first.

## Also worth knowing

- The sandbox shell inherits the host process's environment. `PROMPT` set
  in the host terminal shows up in the sandbox, which cost real debugging
  time: both shells rendered the same prompt and the tests looked like
  `sbx start` was hanging. Whether the sandbox should get a scrubbed
  environment is a spec question.
- Resize is ambiguous on one byte. `split_resize_requests` holds back a
  trailing fragment so a sequence split across two pipe reads still
  parses, but deliberately does not hold a lone trailing `\x1b`: that is a
  real keystroke, and waiting to see whether a resize follows would stall
  Esc in interactive programs. A resize split at exactly that byte reaches
  the shell as a stray escape and is not applied. The spec already lists a
  dedicated third pipe as the clean fix.
- pyte reports ConPTY's colour as a truecolor hex value (`00ff00`), not a
  palette name — assert on both spellings.
- `mode con` prints Lines before Columns.
- System tests need credentials at the default path, which is what
  `sbx install` writes. The fixture writes them only when absent, so it
  cannot desynchronise an existing install's password.
- The elevated helper inherits the caller's working directory. Run
  anything that calls `run_elevated` from the repo root, or `python -m sbx`
  fails inside the helper and the only symptom is "elevated subprocess
  produced no output".

## AFK decisions

Decided without sign-off during an 8h `/afk` window. Each is one commit,
so each is revertible on its own.

### Grant `sbx-user` on mount backing paths — done

- Rationale: mounts were unusable, which is the product's core feature,
  and the spec's own description of the mechanism could not work without
  it. Isolation still comes from the synthetic SID, which another
  sandbox's token does not carry — now covered by
  `test_one_sandbox_cannot_read_anothers_mount`.
- Destroy revokes the `sbx-user` ACE only once no other sandbox still
  mounts that backing path; the ACE is shared, unlike the synthetic SID.
- Uncovered while testing: a backing path whose DACL grants
  `BUILTIN\Users` or `Everyone` is reachable from *every* sandbox, because
  those SIDs sit in every restricted token — that is what makes system
  paths readable. A project under `C:\Users\Public` therefore gets no
  cross-sandbox isolation. Recorded in the spec as a caveat.
- Sharper consequence, and the reason to read this one carefully:
  Cygwin/MSYS2 shells run with an empty RestrictedSids list, so the
  `sbx-user` ACE is all the check they face. A git-bash sandbox can now
  read and write *every* other sandbox's mounts. git-bash is the default
  shell. Before this change it could reach nothing, so the hole was
  masked by the feature being broken. Options, none taken: change the
  default shell to `cmd` or `pwsh`; refuse to mount when the shell is
  Cygwin; or solve the Cygwin carve-out properly.

### Leave the host environment inherited — no change

- The sandbox shell keeps inheriting the host process's environment.
  Scrubbing it is the tidier answer but risks removing `PATH` entries the
  agent needs, and "which variables survive" is a product question with
  no obviously right default. Reversible either way; not worth guessing
  while away.

## Follow-ups

- Decide how Ctrl+C should reach the sandbox shell.
- Decide what to do about git-bash sandboxes sharing mount access (see
  AFK decisions above) — this is the one with security consequences.
- Decide whether the sandbox shell should inherit the host environment.
- Implement the network system tests once the proxy and WFP rules are
  verified; scenarios are listed in `specs/tests/system.md`.
- Implement the remaining privilege scenarios (taskkill against a host
  PID, `net user /add`, registry writes) and deep process-tree tracking.
- Consider a dedicated pipe for resize, removing the lone-ESC ambiguity.
