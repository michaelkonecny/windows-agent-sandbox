from __future__ import annotations

import logging
import sys
from contextlib import contextmanager
from pathlib import Path

import click

from sbx.engine import Engine
from sbx.errors import SandboxError

log = logging.getLogger(__name__)


class PipedNewlines:
    """Translate script line endings for a pseudo-console, where Enter is
    CR: LF and CRLF both become one CR, even with CRLF split across reads."""

    def __init__(self) -> None:
        self._after_cr = False

    def feed(self, data: bytes) -> bytes:
        if self._after_cr and data.startswith(b"\n"):
            data = data[1:]
        self._after_cr = data.endswith(b"\r")
        return data.replace(b"\r\n", b"\r").replace(b"\n", b"\r")


def encode_console_records(records, terminal_size) -> bytes:
    """Console input events to bytes for the sandbox shell.

    In VT input mode the console has already turned keys into escape
    sequences: each key-down record carries one character. Key-ups and
    bare modifiers carry none. `terminal_size` is consulted only on a
    resize event and may return None when the size is unavailable.
    """
    from sbx import winapi
    from sbx.process import resize_request

    payload = bytearray()
    for record in records:
        if record.EventType == winapi.KEY_EVENT:
            key = record.Event.KeyEvent
            if key.bKeyDown and key.UnicodeChar != "\x00":
                payload += key.UnicodeChar.encode("utf-8")
        elif record.EventType == winapi.WINDOW_BUFFER_SIZE_EVENT:
            size = terminal_size()
            if size is not None:
                payload += resize_request(*size)
    return bytes(payload)


def _open_console() -> tuple[int, int] | None:
    """CONIN$/CONOUT$ if this process has a console and stdin is it."""
    import msvcrt

    from sbx import winapi

    if not winapi.is_console(msvcrt.get_osfhandle(sys.stdin.fileno())):
        return None
    access = winapi.GENERIC_READ | winapi.GENERIC_WRITE
    conin = winapi.open_file("CONIN$", access, share=3)
    try:
        conout = winapi.open_file("CONOUT$", access, share=3)
    except OSError:
        winapi.close_handle(conin)
        return None
    return conin, conout


@contextmanager
def _vt_modes(conin: int, conout: int):
    """VT input and output for the duration of a session, restored after —
    a console left in VT input mode stays broken for the rest of the
    terminal session. A console that refuses VT input still gets VT
    output: basic typing works, keys needing escapes may not."""
    from sbx import winapi

    in_mode = winapi.get_console_mode(conin)
    out_mode = winapi.get_console_mode(conout)
    try:
        # No ENABLE_PROCESSED_INPUT: Ctrl+C must reach the sandbox as a
        # byte, not raise a control event in this process.
        try:
            winapi.set_console_mode(
                conin, winapi.ENABLE_VIRTUAL_TERMINAL_INPUT | winapi.ENABLE_WINDOW_INPUT,
            )
        except OSError as e:
            log.warning("terminal does not support VT input: %s", e)
        winapi.set_console_mode(
            conout, out_mode | winapi.ENABLE_VIRTUAL_TERMINAL_PROCESSING,
        )
        yield
    finally:
        winapi.set_console_mode(conin, in_mode)
        winapi.set_console_mode(conout, out_mode)


def _pump_output(pipe_out: int, write) -> None:
    """Sandbox to host until the runner closes its end."""
    from sbx import winapi

    while True:
        try:
            data = winapi.read_file(pipe_out, 4096)
        except OSError:
            return
        if not data:
            return
        write(data)


def _pump_console_input(handle, conin: int, conout: int) -> None:
    """Keystrokes (as VT bytes) and resize requests to the sandbox."""
    from sbx import winapi

    def size():
        try:
            return winapi.console_window_size(conout)
        except OSError:
            return None

    while True:
        try:
            records = winapi.read_console_input(conin)
        except OSError:
            return
        payload = encode_console_records(records, size)
        if payload:
            try:
                winapi.write_file(handle.pipe_in, payload)
            except OSError:
                return


def _pump_piped_input(handle) -> None:
    """Relay non-console stdin; signal EOF when it ends."""
    from sbx import winapi

    stdin = sys.stdin.buffer.raw
    newlines = PipedNewlines()
    while True:
        data = stdin.read(4096)
        if not data:
            break
        try:
            winapi.write_file(handle.pipe_in, newlines.feed(data))
        except OSError:
            return
    handle.close_input()


def _write_stdout(data: bytes) -> None:
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()


def _session(handle, console: tuple[int, int] | None) -> int:
    """Relay I/O between this process and the sandboxed shell until the
    shell exits. Returns the shell's exit code. The output pump runs on
    this thread: its end means the shell is gone. Input is a daemon
    thread, abandoned then."""
    import threading

    from sbx import winapi

    if console is None:
        threading.Thread(target=_pump_piped_input, args=(handle,), daemon=True).start()
        _pump_output(handle.pipe_out, _write_stdout)
    else:
        conin, conout = console
        with _vt_modes(conin, conout):
            threading.Thread(
                target=_pump_console_input, args=(handle, conin, conout), daemon=True,
            ).start()
            _pump_output(handle.pipe_out, lambda data: winapi.write_file(conout, data))
    return handle.exit_code()


def _setup_logging(verbose: bool = False, debug: bool = False) -> None:
    level = logging.DEBUG if debug else (logging.INFO if verbose else logging.WARNING)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=[logging.StreamHandler(sys.stderr)],
    )


class _Group(click.Group):
    """Turns engine errors into one line on stderr and exit code 1."""

    def invoke(self, ctx: click.Context):
        try:
            return super().invoke(ctx)
        except SandboxError as e:
            click.echo(f"error: {e}", err=True)
            ctx.exit(1)


@click.group(cls=_Group)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output.")
@click.option("--debug", is_flag=True, help="Enable debug output.")
@click.pass_context
def main(ctx: click.Context, verbose: bool, debug: bool) -> None:
    _setup_logging(verbose, debug)
    ctx.ensure_object(dict)
    ctx.obj["engine"] = Engine()


def _engine(ctx: click.Context) -> Engine:
    return ctx.obj["engine"]


@main.command()
@click.pass_context
def install(ctx: click.Context) -> None:
    result = _engine(ctx).install()
    click.echo("sbx installed.")
    for w in result.get("warnings", []):
        click.echo(f"  warning: {w}", err=True)


@main.command()
@click.argument("project_path", default=".")
@click.pass_context
def init(ctx: click.Context, project_path: str) -> None:
    path = _engine(ctx).init(project_path)
    click.echo(f"config created: {path}")


@main.command()
@click.argument("config_path")
@click.option("--name", "-n", default=None, help="Sandbox name.")
@click.pass_context
def create(ctx: click.Context, config_path: str, name: str | None) -> None:
    record = _engine(ctx).create(config_path, name)
    click.echo(f"sandbox created: {record.name} (SID {record.synthetic_sid})")


@main.command()
@click.argument("sandbox", default=".")
@click.pass_context
def start(ctx: click.Context, sandbox: str) -> None:
    from sbx import winapi
    from sbx.process import DEFAULT_SIZE

    engine = _engine(ctx)
    console = _open_console()
    size = DEFAULT_SIZE
    if console is not None:
        try:
            size = winapi.console_window_size(console[1])
        except OSError:
            pass
    handle = engine.start(sandbox, size=size)
    try:
        code = _session(handle, console)
    finally:
        handle.close()
        # Console handles are left to process exit: the input thread may be
        # parked in ReadConsoleInput on CONIN$, and closing it would wait
        # for that read — forever.
        engine.session_ended(sandbox)
    sys.exit(code)


@main.command()
@click.argument("sandbox", default=".")
@click.pass_context
def stop(ctx: click.Context, sandbox: str) -> None:
    _engine(ctx).stop(sandbox)
    click.echo("sandbox stopped.")


@main.command()
@click.argument("sandbox", default=".")
@click.pass_context
def destroy(ctx: click.Context, sandbox: str) -> None:
    _engine(ctx).destroy(sandbox)
    click.echo("sandbox destroyed.")


@main.command()
@click.pass_context
def uninstall(ctx: click.Context) -> None:
    _engine(ctx).uninstall()
    click.echo("sbx uninstalled.")


@main.command("list")
@click.pass_context
def list_cmd(ctx: click.Context) -> None:
    records = _engine(ctx).list()
    if not records:
        click.echo("no sandboxes.")
        return
    for r in records:
        click.echo(f"  {r.name}  {r.state.value}  {r.project_path}")


@main.command()
@click.argument("sandbox", default=".")
@click.pass_context
def status(ctx: click.Context, sandbox: str) -> None:
    info = _engine(ctx).status(sandbox)
    for k, v in info.items():
        click.echo(f"  {k}: {v}")
