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

Three mechanisms tried and eliminated, so nobody repeats them:

1. Write `0x03` to the pseudoconsole's input pipe. Ignored — the byte
   reaches the shell as data, `ping -t` keeps running.
2. Borrow the console from a short-lived helper: `FreeConsole`,
   `AttachConsole(shell_pid)`, `GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0)`.
   `AttachConsole` succeeds and `GenerateConsoleCtrlEvent` reports success,
   yet the command keeps running.
3. Suspect `ENABLE_PROCESSED_INPUT` was off on the pseudoconsole's input
   buffer, since that is the flag that turns `0x03` into a control event.
   Read from inside the console it is already set — mode `0x01e7` — so
   this was never the cause.

What is left is the ConPTY signal pipe, the channel conhost is started
with (visible as `--signal 0x...` on its command line) and which
`ResizePseudoConsole` uses. Its protocol is undocumented and exposes no
Ctrl+C packet through the public API, so any fix here is either a private
protocol or a different design.

### A mount is not readable from inside its own sandbox — fixed

Left here for the record; the fix is described under AFK decisions below.

- Symptom: `type <mount>\work\from_host.txt` gives "Access is denied."
- Cause: `mounts.create` granted only the per-sandbox synthetic SID on the
  backing path, never `sbx-user`. A fully restricted token must pass the
  user check *and* the restricted-SID check. The synthetic SID satisfies
  only the second, so any backing path that does not already grant
  `sbx-user` — anything under the host user's profile, `%TEMP%` included —
  failed the first.

### System paths are not read-only — found, not fixed

- Symptom: `echo nope> C:\Windows\Temp\sbx-probe.txt` succeeds from inside
  a sandbox. Kept as a strict xfail asserting the spec's intent.
- Cause: system access comes from `BUILTIN\Users` being in every
  restricted token, so a sandbox inherits exactly what that group may do.
  `Users` has write on `C:\Windows\Temp` by default.
- Two consequences. The spec's "system paths read-only" is intent, not
  something enforced. And any location `Users` can write — `C:\Windows\Temp`,
  `C:\Users\Public` — is a channel between sandboxes, which undercuts the
  isolation the synthetic SID provides on mounts.
- Not fixed because the fix is the design the PoCs explicitly replaced: a
  shared system SID with explicit read-only ACEs on each system path.
  Reinstating it is a real decision about the filesystem mechanism, and a
  sandbox does need *somewhere* writable for temp files.

## Review pass

A read-only review of the branch turned up bugs no test had reached,
mostly around ctypes and handle lifetimes. Each is fixed with a test.

- `read_file` dropped every byte above 0x7f. Its buffer was `c_byte`,
  which is signed, so `bytes()` rejected the negative ints — `ValueError`,
  not `OSError`, which none of the three relays catch. Any accented
  character would have killed the relay thread and left the terminal
  silent with the shell still running. Nothing hit it because ConPTY's
  escapes and cmd's banner are pure ASCII.
- Console output stayed on the OEM codepage (437 here) while the
  pseudoconsole emits UTF-8, so non-ASCII would have rendered as
  mojibake even after the above.
- Holding a partial escape sequence was unbounded on both sides. In the
  runner this was reachable and silent: anything starting `ESC ]` was
  held until a terminator arrived, so Alt+] left every later keystroke
  accumulating and the sandbox keyboard dead. Now only a fragment that
  could still become a resize request is held.
- The start timeout path left the runner alive. It owns the kill-on-close
  Job Object, so the sandbox looked running forever and the new
  already-running guard then refused every start — a trap the guard
  itself created.
- `StartHandle.close` was not idempotent, `mounts.destroy` could abort
  mid-teardown on a missing account, backing paths were compared as raw
  strings despite Windows path case-insensitivity, and three relays
  closed handles a blocked thread still held.
- `process_is_running` compared the exit code against `STILL_ACTIVE`,
  which is just 259 — a process genuinely exiting with 259 looked alive.
- Auto-repeat was dropped: the console coalesces a held key into one
  record with a count, and only one character was sent.

Checked and found clean: every new ctypes prototype and struct layout
against the SDK, the dangling-pointer class that caused the original
ConPTY bug, and handle cleanup on the main ConPTY paths.

## Spec-versus-code cross-check

A second pass compared every concrete claim in `spec.md` against the
implementation. Most matched — named pipes, Job Object naming, the resize
sequence, the runner's eleven steps, the Cygwin carve-out, mount ACLs, the
config keys and defaults, and the edge cases all check out. What did not:

Fixed in code, because the spec was right and the code was missing it:

- Network policy leaked in the proxy. `start` registered it under the Job
  Object name, `stop` deregistered under the sandbox name, so the entry
  never went away. The sharp edge: `start` only registers when the preset
  is not `none`, and a Job Object name repeats for a sandbox of the same
  name — so a stale `all` policy could outlive its sandbox and still match
  a later one deliberately configured with no network.
- `sbx create` required a config path while the spec (and every sibling
  command) says it defaults. It now defaults to `.sandbox/config.json`.
- A leftover bind link was cleared silently; the spec asks for a warning,
  which is what tells you a previous destroy failed.
- Synthetic SID collisions were never checked for, though the spec says to
  check and regenerate. Two sandboxes sharing a SID would silently share
  filesystem access — the one thing the SID exists to prevent.

Fixed in the spec, because the code was right:

- `RestrictedSids` was described as two SIDs in two places and three in a
  third; the code uses three (`Everyone` included, to avoid
  `STATUS_DLL_INIT_FAILED`).
- The proxy was described as mapping registered PIDs to sandboxes. It
  actually asks which Job Object a PID belongs to, which is better — it
  covers anything the shell spawns, where a PID list would not.
- `[name]` was documented as an alias that could address a sandbox. Only
  project paths work; `--name` labels a sandbox but cannot address it.

### `sbx install` does not install the WFP rules

Worth its own heading. The spec presents WFP as layer 1 of a three-layer
fail-safe — "always on", the backstop that blocks everything if the proxy
dies or an agent ignores `HTTPS_PROXY`. `Engine.install` only creates the
user account; `network.install_wfp_rules` has no caller outside its tests.
`uninstall` removes rules nobody installed.

So the network isolation currently rests on the proxy and the environment
variable alone, and a sandbox that ignores `HTTPS_PROXY` has unrestricted
egress. Not fixed here: wiring it up means installing machine-wide
firewall rules, which is not something to switch on unattended. It is the
one gap that makes a spec guarantee untrue rather than merely unbuilt.

### Not contradictions, just unbuilt

The TUI, custom domain allowlists, and mounting an individual file — the
spec allows a file mount, but `mounts.create` always creates the virtual
path as a directory and no test covers it. All three are in Follow-ups.

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
  masked by the feature being broken.

### Warn loudly on Cygwin shells; leave the default shell alone — done

- Tested whether the carve-out is still needed now that the shell gets a
  real console: it is. Under a full restricted token git-bash still dies
  during init with `couldn't create signal pipe, Win32 error 5`
  (access denied), with ConPTY in place and running as `sbx-user`. So
  "solve the carve-out properly" is not available cheaply — Cygwin creates
  that pipe before we get any say.
- Taken: `start_sandbox` logs a warning naming the shell whenever the
  isolation is being traded away. Purely additive, changes no behaviour,
  and the CLI logs at WARNING by default so it reaches the user.
- Not taken: changing the default shell away from `git-bash`, or refusing
  to mount for Cygwin shells. Both change documented product behaviour on
  a security-sensitive axis, which is yours to call, not mine while
  you're away. My recommendation is to default to `pwsh` and keep
  git-bash opt-in.

### Refuse a double start — done

- `specs/tests/system.md` expects a clear error; reality was a silent
  failure. The second runner connects to the *first* host's named pipes,
  so the second host waits 15s for a connection that never comes and the
  user gets nothing back.
- `engine.start` now refuses when the sandbox's Job Object already exists
  — the job is created with kill-on-close, so it exists exactly while the
  sandbox is up. `sbx start` reports it as a CLI error rather than a
  traceback. `test_start_after_stop` still passes, so the check does not
  block legitimate restarts.

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
- Decide whether system paths should be genuinely read-only, and where a
  sandbox is then allowed to write temp files.
- Implement the network system tests once the proxy and WFP rules are
  verified; scenarios are listed in `specs/tests/system.md`.
- Implement the remaining privilege scenarios (taskkill against a host
  PID, `net user /add`, registry writes) and deep process-tree tracking.
- Consider a dedicated pipe for resize, removing the lone-ESC ambiguity.
