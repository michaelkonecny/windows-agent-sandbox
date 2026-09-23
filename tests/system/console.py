"""A cmd window the test can type into: cmd.exe hosted in a ConPTY.

ctypes only — never imports sbx. The hosted cmd sees a real console, so
`sbx start` typed into it takes the console (terminal) path, exactly as
when a person types it.
"""
from __future__ import annotations

import codecs
import ctypes
import re
import threading
import time
from ctypes import wintypes

from hostwin import kernel32

# CSI, OSC, charset selection, single-character escapes.
VT = re.compile(
    r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"
    r"|\x1b\[[0-?]*[ -/]*[@-~]"
    r"|\x1b[()][0-9A-Za-z]"
    r"|\x1b[=>78MDEHc]"
)
CURSOR_MOVE = re.compile(r"\x1b\[[0-9;]*[Hf]")

EXTENDED_STARTUPINFO_PRESENT = 0x00080000
STARTF_USESTDHANDLES = 0x00000100
PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE = 0x00020016
JobObjectExtendedLimitInformation = 9
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000

# Keys as a VT terminal sends them.
ENTER = "\r"
BACKSPACE = "\x7f"
UP = "\x1b[A"
TAB = "\t"
CTRL_C = "\x03"


class COORD(ctypes.Structure):
    _fields_ = [("X", wintypes.SHORT), ("Y", wintypes.SHORT)]


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR), ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD), ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.c_void_p), ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE), ("hStdError", wintypes.HANDLE),
    ]


class STARTUPINFOEXW(ctypes.Structure):
    _fields_ = [("StartupInfo", STARTUPINFOW), ("lpAttributeList", ctypes.c_void_p)]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD),
    ]


class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
        ("IoCounters", ctypes.c_uint64 * 6),
        ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


kernel32.CreatePipe.argtypes = [
    ctypes.POINTER(wintypes.HANDLE), ctypes.POINTER(wintypes.HANDLE), ctypes.c_void_p, wintypes.DWORD,
]
kernel32.CreatePseudoConsole.argtypes = [
    COORD, wintypes.HANDLE, wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p),
]
kernel32.CreatePseudoConsole.restype = ctypes.c_long
kernel32.ResizePseudoConsole.argtypes = [ctypes.c_void_p, COORD]
kernel32.ResizePseudoConsole.restype = ctypes.c_long
kernel32.ClosePseudoConsole.argtypes = [ctypes.c_void_p]
kernel32.InitializeProcThreadAttributeList.argtypes = [
    ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(ctypes.c_size_t),
]
kernel32.UpdateProcThreadAttribute.argtypes = [
    ctypes.c_void_p, wintypes.DWORD, ctypes.c_size_t, ctypes.c_void_p,
    ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p,
]
kernel32.DeleteProcThreadAttributeList.argtypes = [ctypes.c_void_p]
kernel32.CreateProcessW.argtypes = [
    wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p, ctypes.c_void_p, wintypes.BOOL,
    wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR, ctypes.c_void_p,
    ctypes.POINTER(PROCESS_INFORMATION),
]
kernel32.ReadFile.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p,
]
kernel32.WriteFile.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p,
]
kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
kernel32.CreateJobObjectW.restype = wintypes.HANDLE
kernel32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]

CREATE_SUSPENDED = 0x4


def _check(ok) -> None:
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())


def _pipe() -> tuple[int, int]:
    r, w = wintypes.HANDLE(), wintypes.HANDLE()
    _check(kernel32.CreatePipe(ctypes.byref(r), ctypes.byref(w), None, 0))
    return r.value, w.value


class ConsoleSession:
    """cmd.exe in a pseudo-console, typed at like a person would."""

    def __init__(self, cwd: str, cols: int = 400, rows: int = 50,
                 command: str = "cmd.exe /q /k prompt HOST$G") -> None:
        self.cols, self.rows = cols, rows
        self._raw = bytearray()
        self._text = ""
        self._pos = 0
        self._held = ""
        self._decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        self._lock = threading.Lock()
        self._data = threading.Event()

        pty_in_r, self._in_w = _pipe()
        self._out_r, pty_out_w = _pipe()
        hpc = ctypes.c_void_p()
        hr = kernel32.CreatePseudoConsole(COORD(cols, rows), pty_in_r, pty_out_w, 0, ctypes.byref(hpc))
        if hr < 0:
            raise OSError(f"CreatePseudoConsole failed: 0x{hr & 0xFFFFFFFF:08X}")
        self._hpc = hpc.value
        kernel32.CloseHandle(pty_in_r)
        kernel32.CloseHandle(pty_out_w)

        size = ctypes.c_size_t()
        kernel32.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(size))
        attrs = (ctypes.c_byte * size.value)()
        _check(kernel32.InitializeProcThreadAttributeList(attrs, 1, 0, ctypes.byref(size)))
        # The HPCON itself, not a pointer to it.
        _check(kernel32.UpdateProcThreadAttribute(
            attrs, 0, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, self._hpc,
            ctypes.sizeof(ctypes.c_void_p), None, None,
        ))
        si = STARTUPINFOEXW()
        si.StartupInfo.cb = ctypes.sizeof(si)
        si.StartupInfo.dwFlags = STARTF_USESTDHANDLES  # NULL std handles
        si.lpAttributeList = ctypes.addressof(attrs)
        pi = PROCESS_INFORMATION()
        # Children inherit "ignore Ctrl+C"; whatever launched the tests may
        # have set it, and then Ctrl+C typed into the session does nothing.
        kernel32.SetConsoleCtrlHandler(None, False)
        try:
            _check(kernel32.CreateProcessW(
                None, ctypes.create_unicode_buffer(command), None, None, False,
                EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED, None, cwd,
                ctypes.byref(si), ctypes.byref(pi),
            ))
        finally:
            kernel32.DeleteProcThreadAttributeList(attrs)

        # A job so closing the session takes cmd and everything it started.
        self._job = kernel32.CreateJobObjectW(None, None)
        info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        kernel32.SetInformationJobObject(
            self._job, JobObjectExtendedLimitInformation, ctypes.byref(info), ctypes.sizeof(info),
        )
        kernel32.AssignProcessToJobObject(self._job, pi.hProcess)
        kernel32.ResumeThread(pi.hThread)
        kernel32.CloseHandle(pi.hThread)
        self._process = pi.hProcess
        self._closed = False
        threading.Thread(target=self._read, daemon=True).start()

    # ── I/O ──

    def _read(self) -> None:
        buf = ctypes.create_string_buffer(4096)
        n = wintypes.DWORD()
        while kernel32.ReadFile(self._out_r, buf, 4096, ctypes.byref(n), None) and n.value:
            chunk = buf.raw[:n.value]
            with self._lock:
                self._raw += chunk
                self._feed(chunk)
            self._data.set()

    def _feed(self, chunk: bytes) -> None:
        """Strip VT incrementally, holding back a tail that may be an
        unfinished sequence. Cursor positioning starts a new line."""
        text = self._held + self._decoder.decode(chunk)
        esc = text.rfind("\x1b")
        if esc != -1 and not VT.match(text, esc):
            text, self._held = text[:esc], text[esc:]
        else:
            self._held = ""
        text = CURSOR_MOVE.sub("\n", text)
        self._text += VT.sub("", text).replace("\r\n", "\n").replace("\r", "\n")

    def type(self, keys: str) -> None:
        data = keys.encode("utf-8")
        n = wintypes.DWORD()
        _check(kernel32.WriteFile(self._in_w, data, len(data), ctypes.byref(n), None))

    def line(self, text: str) -> None:
        self.type(text + ENTER)

    def text(self) -> str:
        """Everything shown so far, VT stripped."""
        with self._lock:
            return self._text

    def raw(self) -> bytes:
        with self._lock:
            return bytes(self._raw)

    def expect(self, pattern: str, timeout: float = 30) -> re.Match:
        """Wait for regex `pattern` on screen (VT stripped, MULTILINE),
        consuming output up to the match so later waits scan forward."""
        regex = re.compile(pattern, re.MULTILINE)
        deadline = time.monotonic() + timeout
        while True:
            with self._lock:
                m = regex.search(self._text, self._pos)
                if m:
                    self._pos = m.end()
                    return m
                seen = self._text[self._pos:]
            if time.monotonic() > deadline:
                raise TimeoutError(
                    f"no {pattern!r} within {timeout}s; unconsumed screen text:\n{seen[-3000:]}"
                )
            self._data.clear()
            self._data.wait(0.05)

    def resize(self, cols: int, rows: int) -> None:
        hr = kernel32.ResizePseudoConsole(self._hpc, COORD(cols, rows))
        if hr < 0:
            raise OSError(f"ResizePseudoConsole failed: 0x{hr & 0xFFFFFFFF:08X}")
        self.cols, self.rows = cols, rows

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        kernel32.CloseHandle(self._job)  # kills cmd and its descendants
        kernel32.ClosePseudoConsole(self._hpc)
        for h in (self._in_w, self._out_r, self._process):
            kernel32.CloseHandle(h)

    def __enter__(self) -> ConsoleSession:
        return self

    def __exit__(self, *exc) -> None:
        self.close()
