# ConPTY Shell Integration — Spec

Status: draft
Last updated: 2026-09-10

## Goal

Replace the raw byte-pipe shell relay with a ConPTY-based terminal that gives the sandboxed shell a real console — cursor, colours, interactive programs, mouse — while keeping it embedded in the host terminal.

## Context

The current implementation (`process.py`, `cli.py`) uses a four-hop polling relay:

    host terminal → named pipe → runner → anonymous pipe → shell

The shell has no console (`CREATE_NO_WINDOW` on the runner, no ConPTY). Interactive programs that use console APIs (cursor positioning, colours, `cls`, `ReadConsoleInput`) break silently. All relay loops poll `PeekNamedPipe` every 10–20 ms. The ConPTY wrapper functions exist in `winapi.py` but are never called.

### Alternative considered — separate window

Launching the shell with `CREATE_NEW_CONSOLE` would be far simpler but gives a detached window. The embedded approach is preferred: the sandbox shell should feel like part of the host terminal, and programmatic I/O control is needed for testing.

## Architecture

Two-hop relay over ConPTY:

    host terminal ←VT bytes→ named pipe ←VT bytes→ ConPTY ←console API→ shell

### Components

#### ConPTY (runner side)

- Role: provide a real pseudo-console to the shell process, translating between console API calls and VT sequences on a pipe pair.
- Creates: `CreatePseudoConsole` with a pipe pair owned by the runner.
- Attaches: shell launched via `CreateProcessAsUserW` + `STARTUPINFOEX` with `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE`.
- No anonymous pipes — ConPTY's own pipe pair replaces them.
- Relay: two threads shuttle VT bytes between the ConPTY pipe pair and the named pipes (same as today, but no anonymous-pipe intermediary).
- Resize: `ResizePseudoConsole` called when the host sends a resize message.

#### Named pipes (cross-user transport)

- Role: carry VT byte stream between the host process and the runner process running as `sbx-user`.
- Unchanged from current design — two named pipes with null DACL, one in each direction.
- New: a third control pipe (or in-band escape sequence) for resize events.

#### Host terminal relay (CLI side)

- Role: bridge the user's real terminal and the named pipes.
- Enable `ENABLE_VIRTUAL_TERMINAL_INPUT` on the host console input handle — the console delivers keystrokes as VT sequences instead of `INPUT_RECORD` structs.
- Enable `ENABLE_VIRTUAL_TERMINAL_PROCESSING` on the host console output handle — VT sequences from the sandbox shell render directly.
- Read loop: `ReadConsoleInput` or `ReadFile` on `CONIN$`, forward raw bytes to the named pipe.
- Write loop: `ReadFile` on the named pipe, `WriteFile` to `CONOUT$`.
- Resize detection: monitor `WINDOW_BUFFER_SIZE_EVENT` from `ReadConsoleInput`, send new dimensions to runner via control channel.

### Resize signalling

Use in-band signalling over the existing named pipes rather than a third pipe. The host sends a short escape sequence (a private-use OSC or DCS — e.g. `\x1b]9999;<cols>;<rows>\x07`) on the input pipe. The runner's input relay thread recognises and strips it before forwarding to the ConPTY, then calls `ResizePseudoConsole`.

Rationale: avoids a third named pipe and its connection handshake. The sequence is chosen to not collide with any standard terminal escape.

### What gets removed

- Anonymous pipes in `_execute_runner_inner` — replaced by ConPTY pipe pair.
- `STARTF_USESTDHANDLES` path in the runner — replaced by `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE`.
- `msvcrt.kbhit()` / `msvcrt.getwch()` polling loop in `cli.py` — replaced by `ReadConsoleInput` / `ReadFile` with VT input mode.
- `PeekNamedPipe` polling in relay threads — replaced by blocking `ReadFile` on dedicated threads.

### What stays

- Named pipes with null DACL for cross-user transport.
- Runner process launched via `CreateProcessWithLogonW` under `sbx-user`.
- Restricted token creation in the runner (`create_sandbox_token`).
- Job Object with kill-on-close.
- Null-DACL workarounds for Cygwin/MSYS2 shells.

## Detailed changes

### `process.py` — `_execute_runner_inner`

Current flow → new flow:

1. Open named pipes from client side — unchanged.
2. ~~Create anonymous pipes~~ → Create a pipe pair for ConPTY (`create_pipe` with `inheritable=False`).
3. Create ConPTY: `create_pseudo_console(cols, rows, pty_in_read, pty_out_write)`.
4. Close the ConPTY-side pipe ends (`pty_in_read`, `pty_out_write`) — ConPTY owns them now.
5. Create Job Object — unchanged.
6. Create restricted token — unchanged.
7. Build attribute list: `init_proc_attribute_list(1)` → `update_proc_attribute_console(attr_list, hpc)`.
8. Launch shell: `create_process_as_user(token, shell_path, attribute_list=attr_list_addr)` — no `std_handles`, no `creation_flags`.
9. `delete_proc_attribute_list` after launch.
10. Assign to Job Object — unchanged.
11. Two relay threads: `named_pipe_in → pty_in_write` and `pty_out_read → named_pipe_out`.
12. Input relay thread: scan for resize escape sequence, strip it, call `resize_pseudo_console`.
13. Wait for shell exit — unchanged.
14. Cleanup: `close_pseudo_console(hpc)` + close remaining handles.

Relay threads use blocking `ReadFile` instead of `PeekNamedPipe` polling — the thread blocks until data arrives, writes it, loops. Stop signal: when the shell exits, close the pipe handles from the main thread; the blocking `ReadFile` fails with `ERROR_BROKEN_PIPE`, the thread exits.

#### Initial terminal size

The runner needs to know the initial terminal size for `CreatePseudoConsole`. Two options:

- Option A — pass dimensions as extra argv to the runner command line (`python -m sbx _run {name} {sid} {shell} {cols} {rows}`).
- Option B — host sends a resize escape on the input pipe immediately after connect; runner starts ConPTY at a default size (120x30), resizes on first message.

Option A is simpler and avoids a race. Use it.

### `process.py` — `start_sandbox`

- Accept `cols` and `rows` parameters (default to host terminal size).
- Pass them through to the runner command line.
- `StartHandle` — remove `pipe_in` / `pipe_out` naming ambiguity; keep as-is since the semantics (bytes in, bytes out) don't change.

### `cli.py` — `_interactive_session`

Replace the `msvcrt` polling loop:

1. Get console handles: `GetStdHandle(STD_INPUT_HANDLE)`, `GetStdHandle(STD_OUTPUT_HANDLE)`.
2. Save current console modes. Set `ENABLE_VIRTUAL_TERMINAL_INPUT` on input, `ENABLE_VIRTUAL_TERMINAL_PROCESSING` on output.
3. Read thread: `ReadFile` on named pipe out → `WriteFile` to `CONOUT$`. Blocking.
4. Input thread: `ReadConsoleInput` in a loop. For `KEY_EVENT` records, the console provides VT sequences (with VT input mode enabled). Forward raw bytes to named pipe in. For `WINDOW_BUFFER_SIZE_EVENT`, format the resize escape and send it on the input pipe.
5. On shell exit (read thread gets `ERROR_BROKEN_PIPE`): restore console modes, return.

#### Console mode management

Wrap mode save/restore in a context manager. If the process crashes or the user hits Ctrl+C, the `finally` block must restore the original modes — a corrupted console mode persists for the terminal session and is disorienting.

### `winapi.py`

New wrappers needed:

- `get_std_handle(which: int) → int`
- `get_console_mode(handle: int) → int`
- `set_console_mode(handle: int, mode: int) → None`
- `read_console_input(handle: int) → list[INPUT_RECORD]` — or simplified to return key events and resize events only.
- Constants: `ENABLE_VIRTUAL_TERMINAL_INPUT`, `ENABLE_VIRTUAL_TERMINAL_PROCESSING`, `STD_INPUT_HANDLE`, `STD_OUTPUT_HANDLE`, `WINDOW_BUFFER_SIZE_EVENT`.

The ConPTY wrappers already exist and are correct. No changes needed.

### `__main__.py`

Update `_run` dispatch to pass `cols` and `rows` (argv[5], argv[6]) to `execute_runner`.

## Integration test infrastructure

### Approach

Use ConPTY from the test harness to drive the entire flow programmatically. The test creates a pseudo-console, launches a host shell inside it, types commands, reads VT output, and asserts on results. The test harness acts as the terminal emulator.

### Test driver — `ConPtyShell`

A helper class (in `tests/conpty_harness.py` or similar) that wraps a ConPTY session:

```
ConPtyShell
  Role: programmatic terminal for integration tests — launches a process
        inside a ConPTY and provides read/write/expect methods.
  Holds:
    - hpc — PseudoConsole handle
    - pty_in_write, pty_out_read — pipe handles for writing input / reading output
    - proc_handle, pid — the launched process
    - screen — pyte.Screen (optional, for cursor/colour assertions)
  API:
    - __init__(cmd, cols=120, rows=30, env=None) — create ConPTY, launch process
    - write(text) — send raw bytes/string to the process
    - read(timeout=5.0) → bytes — blocking read with timeout, returns available output
    - expect(pattern, timeout=10.0) → Match — accumulate output until regex matches or timeout
    - expect_prompt(timeout=10.0) — shorthand for expect(prompt_pattern)
    - screen_text() → str — (if pyte enabled) return the current virtual screen content
    - resize(cols, rows) — call ResizePseudoConsole
    - close() — terminate process, close ConPTY, close handles
    - __enter__ / __exit__ — context manager
```

`expect` is the key primitive — it reads in a loop, appending to a buffer, testing the regex after each read. On timeout it raises with the buffer contents for diagnostics.

### VT output handling

Two tiers:

- Tier 1 (default) — raw text matching. Strip common VT escapes (CSI sequences, OSC) from the accumulated buffer, then regex match on the plain text. Sufficient for "did `whoami` output `sbx-user`?" style tests.
- Tier 2 (optional) — `pyte.Screen`. Feed raw VT bytes into a pyte terminal emulator. Query the virtual screen for cursor position, character at (row, col), text content of a line, SGR attributes. Use when testing cursor behaviour, colour output, or screen layout.

`pyte` is a pure-Python terminal emulator (~1k LOC) with no native dependencies. Add as a test dependency.

### Test scenarios

Tests that exercise the full chain: test harness (ConPTY) → host shell → `sbx start` → sandbox shell → commands → exit → host shell. Each test gets a unique sandbox name (UUID-based, same as current fixtures).

#### Test: sandbox shell opens and runs commands

1. Launch `cmd.exe` in ConPTY.
2. Wait for `cmd` prompt.
3. Type `sbx start --name {name} --shell cmd`.
4. Wait for sandbox prompt to appear.
5. Type `whoami`, expect `sbx-user`.
6. Type `echo %COMPUTERNAME%`, expect the machine name (sanity check — not isolated).
7. Type `exit`.
8. Wait for host `cmd` prompt to reappear.
9. Assert the host prompt is back (not stuck).

#### Test: sandbox shell inherits Job Object

1. Launch sandbox shell as above.
2. From sandbox shell, type `cmd /c echo CHILD_MARKER`.
3. Expect `CHILD_MARKER` in output.
4. Open Job Object by name, query PIDs, assert at least 2 (runner + shell or shell + child).
5. Exit sandbox shell.

#### Test: Ctrl+C in sandbox shell

1. Launch sandbox shell.
2. Type `ping -t 127.0.0.1` (infinite ping).
3. Wait for first ping reply.
4. Send Ctrl+C (`\x03`).
5. Expect ping stops, prompt reappears.
6. Sandbox shell is still alive (type `echo OK`, expect `OK`).

#### Test: interactive program (cursor, colour)

1. Launch sandbox shell with `cmd`.
2. Type `cls`.
3. Using pyte screen: assert cursor is at (0, 0) or (1, 0) after cls.
4. Type `color 0A` (green on black), then `echo COLOURED`.
5. Using pyte screen: assert text `COLOURED` exists and has SGR attribute for green foreground.

#### Test: terminal resize propagates

1. Launch sandbox shell (initial size 120x30).
2. Call `resize(80, 24)` on the ConPTY harness.
3. In the sandbox shell, type `mode con` (cmd) or `tput cols; tput lines` (bash).
4. Expect output contains `80` and `24`.

#### Test: exit returns to host shell

1. Launch host `cmd` in ConPTY.
2. Type `echo HOST_BEFORE`.
3. Type `sbx start ...`.
4. Wait for sandbox prompt.
5. Type `exit`.
6. Wait for host prompt.
7. Type `echo HOST_AFTER`.
8. Expect `HOST_AFTER` in output — confirms host shell resumed, not terminated.

#### Test: stop from outside kills sandbox

1. Launch sandbox shell via host shell.
2. Wait for sandbox prompt.
3. From the test harness (not through the ConPTY): call `stop_sandbox(name)`.
4. In the ConPTY output, expect the host prompt to reappear (sandbox process terminated, `sbx start` returned).

#### Test: git-bash under ConPTY

1. Launch sandbox shell with `--shell git-bash`.
2. Wait for bash prompt.
3. Type `echo $SHELL`, expect contains `bash`.
4. Type `ls --color=auto`, verify output appears (colour escapes flow through).
5. Exit.

### Existing tests — migration

The current 9 tests in `test_process.py` test the pipe-relay mechanism directly (call `start_sandbox`, talk through `StartHandle` pipes). These should:

- Keep working — they test the engine API, not the CLI. `start_sandbox` still returns a `StartHandle` with named pipes carrying VT bytes. The test helpers (`_send_command`, `_read_output`) still work.
- Rename `test_conpty_relay` to `test_pipe_relay` or `test_echo_roundtrip` — it was always misnamed.
- Add a note that these are engine-level tests (no real terminal), vs the new ConPTY harness tests which are end-to-end.

### Test execution requirements

- Elevation: the fixture calls `run_elevated("setup_test_env", ...)` for ACLs — same as today.
- ConPTY: available on Windows 10 1809+ (build 17763). Not available on Windows Server 2016 or older. The CI environment must be Windows 10 1809+ or Windows 11.
- pyte: add to test dependencies (`pip install pyte`).
- Timeouts: all `expect` calls use explicit timeouts. Shell startup under a restricted token can be slow (especially git-bash) — use 10–15s for initial prompt, 5s for command output.

## Sequencing

1. Add `winapi.py` console-mode wrappers and constants.
2. Rework `_execute_runner_inner` to use ConPTY.
3. Rework `cli.py` `_interactive_session` to use VT input/output mode.
4. Build `ConPtyShell` test harness.
5. Write engine-level tests (update existing).
6. Write end-to-end ConPTY harness tests.

Steps 1–3 are the functional change. Steps 4–6 are the test infrastructure. The engine-level tests (step 5) should pass after step 2 since the named-pipe API doesn't change. The end-to-end tests (step 6) need steps 3–4 complete.

## Open decisions

- Resize escape sequence format — the spec proposes `\x1b]9999;<cols>;<rows>\x07` (private OSC). Any private-use sequence works; this just needs to not collide with real terminal traffic. An alternative is a dedicated third named pipe, which is cleaner but adds connection complexity.
- pyte as test dependency — it's small and stable, but it's a new dependency. The alternative is hand-rolled VT stripping, which is simpler but can't assert on cursor/colour.
- Whether to support the legacy `StartHandle` pipe API for non-interactive callers (e.g. a future API that wants to send commands programmatically without a terminal). If so, `start_sandbox` stays pipe-based; if not, the VT stream over pipes *is* the programmatic API.

## Out of scope

- Mouse passthrough — works automatically with ConPTY if the inner application requests mouse mode. No special handling needed.
- 256-colour / true-colour — works automatically via VT sequences.
- Unicode/emoji — works if the host terminal font supports it. ConPTY passes UTF-8/UTF-16 through.
- Detached-window mode (`CREATE_NEW_CONSOLE`) — deferred as an alternative UX, not needed now.
- TUI integration — the TUI (see main spec) will embed the VT stream differently (into a Textual widget or similar). That's a separate concern.
