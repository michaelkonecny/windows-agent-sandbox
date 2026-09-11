"""ConPtyShell — a programmatic terminal for system tests.

Wraps a process in a ConPTY (Windows pseudoconsole) so tests can type at
it and assert on what it renders, the way a user at a terminal would.
The process sees a real console; this side sees a VT byte stream —
in-band escape sequences for cursor movement, colour and so on.

Two views of that stream are available:

- `expect` matches against the text with escape sequences stripped, which
  is enough for "did this command print X".
- `screen_text` replays the stream through pyte, a pure-Python terminal
  emulator, giving the rendered screen — needed when a test cares where
  text landed or what colour it is.
"""

from __future__ import annotations

import codecs
import re
import threading

from sbx import winapi

# CSI (cursor, colour, erase — including private `?` params ConPTY emits
# for cursor visibility), OSC (title and other host commands, terminated
# by BEL or ST), charset selection, and the bare single-character escapes.
VT_SEQUENCE = re.compile(
    r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"
    r"|\x1b\[[0-9;:?<>!]*[ -/]*[@-~]"
    r"|\x1b[()][0-9A-Za-z]"
    r"|\x1b[=>78MDEHc]"
)

READ_CHUNK = 4096
DEFAULT_TIMEOUT = 10.0

# Longest tail held back waiting for an escape sequence to finish. Real
# sequences are far shorter; the cap is what stops an unrecognised one
# (DCS, APC, a sixel image) swallowing the rest of the stream forever.
MAX_HELD = 64

# cmd and powershell prompts end in ">", bash in "$".
DEFAULT_PROMPT = r"[>$]\s*$"


class ConPtyShell:
    """A process attached to a pseudoconsole, driven programmatically."""

    def __init__(
        self,
        command: str,
        cols: int = 120,
        rows: int = 30,
        capture_screen: bool = False,
        prompt: str = DEFAULT_PROMPT,
        cwd: str | None = None,
    ) -> None:
        self.command = command
        self.cwd = cwd
        self.cols = cols
        self.rows = rows
        self.prompt = prompt
        self.capture_screen = capture_screen

        self._raw = bytearray()
        self._text = ""  # same stream, escape sequences stripped
        self._pos = 0  # how far `expect` has consumed of _text
        self._decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        self._held = ""  # trailing bytes that may be an unfinished sequence
        self._lock = threading.Lock()
        self._data = threading.Event()
        self._reader: threading.Thread | None = None
        self._closed = False

        self._hpc = 0
        self._pty_in_write = 0
        self._pty_out_read = 0
        self._process = 0
        self.pid = 0

    # ── lifecycle ────────────────────────────────────────────

    def start(self) -> None:
        # Handles stay non-inheritable: the ConPTY passes the console to
        # the child itself, so nothing needs to be inherited.
        pty_in_read, self._pty_in_write = winapi.create_pipe(inheritable=False)
        self._pty_out_read, pty_out_write = winapi.create_pipe(inheritable=False)

        self._hpc = winapi.create_pseudo_console(
            self.cols, self.rows, pty_in_read, pty_out_write
        )
        # The ConPTY owns its ends now; holding them open here would keep
        # the output pipe from ever reporting end-of-stream.
        winapi.close_handle(pty_in_read)
        winapi.close_handle(pty_out_write)

        attr_buf, attr_addr = winapi.init_proc_attribute_list(1)
        winapi.update_proc_attribute_console(attr_addr, self._hpc)
        try:
            self._process, thread_h, self.pid, _ = winapi.create_process(
                self.command,
                cwd=self.cwd,
                attribute_list=attr_addr,
                std_handles=winapi.NULL_STD_HANDLES,
                inherit_handles=False,
            )
        finally:
            winapi.delete_proc_attribute_list(attr_addr)
            del attr_buf
        winapi.close_handle(thread_h)

        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True

        if self._process and winapi.process_is_running(self._process):
            winapi.terminate_process(self._process)

        # Closing the ConPTY breaks the output pipe, which is what lets
        # the reader thread's blocking ReadFile return.
        winapi.close_pseudo_console(self._hpc)
        self._hpc = 0

        if self._reader:
            self._reader.join(timeout=5)

        for handle in (self._pty_in_write, self._pty_out_read, self._process):
            winapi.close_handle(handle)
        self._pty_in_write = self._pty_out_read = self._process = 0

    def __enter__(self) -> ConPtyShell:
        self.start()
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    # ── I/O ──────────────────────────────────────────────────

    def _read_loop(self) -> None:
        while True:
            try:
                chunk = winapi.read_file(self._pty_out_read, READ_CHUNK)
            except OSError:
                break  # ERROR_BROKEN_PIPE once the ConPTY is closed
            if not chunk:
                break
            with self._lock:
                self._raw.extend(chunk)
                self._feed(chunk)
            self._data.set()

    def _feed(self, chunk: bytes) -> None:
        """Strip escape sequences incrementally, holding back a partial tail.

        Stripping per chunk keeps `_text` offsets exact, which is what lets
        `expect` consume precisely up to a match.  A chunk can end in the
        middle of an escape sequence, a multi-byte character, or a CRLF
        pair, so anything that might still grow is held for the next read.
        """
        text = self._held + self._decoder.decode(chunk)

        escape = text.rfind("\x1b")
        if (
            escape != -1
            and not VT_SEQUENCE.match(text, escape)
            and len(text) - escape < MAX_HELD
        ):
            text, self._held = text[:escape], text[escape:]
        elif text.endswith("\r"):
            text, self._held = text[:-1], "\r"
        else:
            self._held = ""

        stripped = VT_SEQUENCE.sub("", text)
        self._text += stripped.replace("\r\n", "\n").replace("\r", "\n")

    def write(self, text: str) -> None:
        winapi.write_file(self._pty_in_write, text.encode("utf-8"))

    def send_line(self, text: str) -> None:
        self.write(text + "\r\n")

    def read_all(self) -> str:
        """Everything received so far, escape sequences stripped."""
        with self._lock:
            return self._text

    def raw(self) -> bytes:
        with self._lock:
            return bytes(self._raw)

    def expect(
        self, pattern: str, timeout: float = DEFAULT_TIMEOUT
    ) -> re.Match[str]:
        """Wait for `pattern` in the output, consuming up to the match.

        Matching is on the escape-stripped text, so patterns describe what
        a user would read.  Consuming means successive `expect` calls scan
        forward rather than re-matching earlier output.
        """
        regex = re.compile(pattern, re.MULTILINE)
        deadline = threading.Event()
        timer = threading.Timer(timeout, deadline.set)
        timer.start()
        try:
            while True:
                with self._lock:
                    match = regex.search(self._text, self._pos)
                    if match:
                        self._pos = match.end()
                        return match
                    buffered = self._text
                self._data.clear()
                if deadline.is_set():
                    raise TimeoutError(
                        f"timed out after {timeout}s waiting for {pattern!r}; "
                        f"buffer so far:\n{buffered}"
                    )
                self._data.wait(0.05)
        finally:
            timer.cancel()

    def expect_prompt(self, timeout: float = DEFAULT_TIMEOUT) -> re.Match[str]:
        return self.expect(self.prompt, timeout=timeout)

    # ── console state ────────────────────────────────────────

    def resize(self, cols: int, rows: int) -> None:
        winapi.resize_pseudo_console(self._hpc, cols, rows)
        self.cols, self.rows = cols, rows

    def screen_text(self) -> str:
        """The rendered screen, via pyte.

        Replays the whole stream each call — the emulator is cheap and a
        fresh screen avoids carrying state between assertions.
        """
        if not self.capture_screen:
            raise RuntimeError("construct ConPtyShell with capture_screen=True")
        import pyte

        screen = pyte.Screen(self.cols, self.rows)
        stream = pyte.Stream(screen)
        stream.feed(self.raw().decode("utf-8", errors="replace"))
        return "\n".join(screen.display)

    def screen(self):
        """The pyte Screen itself, for cursor and attribute assertions."""
        if not self.capture_screen:
            raise RuntimeError("construct ConPtyShell with capture_screen=True")
        import pyte

        screen = pyte.Screen(self.cols, self.rows)
        stream = pyte.Stream(screen)
        stream.feed(self.raw().decode("utf-8", errors="replace"))
        return screen

    def wait(self, timeout: float = DEFAULT_TIMEOUT) -> int:
        return winapi.wait_for_process(self._process, int(timeout * 1000))
