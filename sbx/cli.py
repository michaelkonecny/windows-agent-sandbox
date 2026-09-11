from __future__ import annotations

import logging
import sys
from contextlib import contextmanager
from pathlib import Path

import click

from sbx.engine import Engine
from sbx.errors import SandboxError

log = logging.getLogger(__name__)


RELAY_BUF = 4096


def _terminal_size() -> tuple[int, int]:
    """The user's terminal size, measured from CONOUT$ so that redirected
    stdout does not hide it."""
    from sbx import winapi
    from sbx.process import DEFAULT_SIZE

    try:
        conout = winapi.open_file("CONOUT$", winapi.GENERIC_READ, share=3)
    except OSError:
        return DEFAULT_SIZE
    try:
        return winapi.get_console_screen_buffer_info(conout)
    except OSError:
        return DEFAULT_SIZE
    finally:
        winapi.close_handle(conout)


def _restore(action) -> None:
    """Undo one piece of console state, without masking the others."""
    try:
        action()
    except OSError as e:
        log.warning("failed to restore console state: %s", e)


@contextmanager
def _vt_console():
    """Put the real console into VT mode for the duration of a session.

    Opens CONIN$/CONOUT$ rather than the std handles, so the relay still
    works when stdio is redirected.  Restoring both modes is not optional:
    a console left in VT input mode stays broken for the rest of the
    terminal session, long after this process is gone.

    A terminal that refuses VT input still gets VT output — basic typing
    works, keys that need escape sequences do not.
    """
    from sbx import winapi

    access = winapi.GENERIC_READ | winapi.GENERIC_WRITE
    conin = winapi.open_file("CONIN$", access, share=3)
    try:
        conout = winapi.open_file("CONOUT$", access, share=3)
    except OSError:
        winapi.close_handle(conin)
        raise

    try:
        in_mode = winapi.get_console_mode(conin)
        out_mode = winapi.get_console_mode(conout)
        original_cp = winapi.get_console_output_cp()
    except OSError:
        winapi.close_handle(conin)
        winapi.close_handle(conout)
        raise

    try:
        # The sandbox's output is UTF-8; a console left on its default
        # OEM codepage would render every non-ASCII byte as mojibake.
        winapi.set_console_output_cp(winapi.CP_UTF8)
        # No ENABLE_PROCESSED_INPUT: Ctrl+C must reach the sandbox as a
        # byte rather than raising a control event in this process.
        try:
            winapi.set_console_mode(
                conin,
                winapi.ENABLE_VIRTUAL_TERMINAL_INPUT
                | winapi.ENABLE_WINDOW_INPUT,
            )
        except OSError as e:
            log.warning("terminal does not support VT input: %s", e)
        winapi.set_console_mode(
            conout, out_mode | winapi.ENABLE_VIRTUAL_TERMINAL_PROCESSING
        )
        yield conin, conout
    finally:
        # Undo each piece independently — one failure must not leave the
        # rest of the terminal half-configured.  conin is left open on
        # purpose: the input pump is parked in a blocking
        # ReadConsoleInput on it, and CloseHandle waits for that pending
        # read to finish, which hangs the session instead of ending it.
        # Process exit releases the handle.
        _restore(lambda: winapi.set_console_mode(conin, in_mode))
        _restore(lambda: winapi.set_console_mode(conout, out_mode))
        _restore(lambda: winapi.set_console_output_cp(original_cp))
        winapi.close_handle(conout)


def encode_console_records(records, terminal_size) -> bytes:
    """Translate console input events into bytes for the sandbox shell.

    terminal_size is a callable, consulted only when a resize event
    arrives: the event itself reports the screen buffer, whereas the
    shell needs the visible window size.
    """
    from sbx import winapi
    from sbx.process import resize_request

    payload = bytearray()
    for record in records:
        if record.EventType == winapi.KEY_EVENT:
            key = record.Event.KeyEvent
            # With VT input mode the console hands us the escape sequence
            # itself, one character per key-down record.  Key-up records
            # and pure modifiers carry no character.
            if key.bKeyDown and key.UnicodeChar != "\x00":
                payload += key.UnicodeChar.encode("utf-8")
        elif record.EventType == winapi.WINDOW_BUFFER_SIZE_EVENT:
            size = terminal_size()
            if size is not None:
                payload += resize_request(*size)
    return bytes(payload)


def _pump_input(conin: int, conout: int, pipe_in: int) -> None:
    """Terminal to sandbox: keystrokes as VT bytes, plus resize requests."""
    from sbx import winapi

    def size():
        try:
            return winapi.get_console_screen_buffer_info(conout)
        except OSError:
            return None

    while True:
        try:
            records = winapi.read_console_input(conin)
        except OSError:
            return
        payload = encode_console_records(records, size)
        if not payload:
            continue
        try:
            winapi.write_file(pipe_in, payload)
        except OSError:
            return


def _pump_output(pipe_out: int, conout: int) -> None:
    """Sandbox to terminal.  Returns once the shell is gone."""
    from sbx import winapi

    while True:
        try:
            data = winapi.read_file(pipe_out, RELAY_BUF)
        except OSError:
            return  # ERROR_BROKEN_PIPE once the runner closes its end
        if not data:
            return
        try:
            winapi.write_file(conout, data)
        except OSError:
            return


def _interactive_session(handle) -> None:
    """Bridge the user's terminal and the sandboxed shell.

    The output pump runs on this thread: its end means the shell exited,
    which is exactly when the session should finish.  Input is a daemon
    thread parked in a blocking console read, abandoned at that point.
    """
    import threading

    try:
        with _vt_console() as (conin, conout):
            threading.Thread(
                target=_pump_input,
                args=(conin, conout, handle.pipe_in),
                daemon=True,
            ).start()
            _pump_output(handle.pipe_out, conout)
    finally:
        handle.close()


def _setup_logging(verbose: bool = False, debug: bool = False) -> None:
    level = logging.DEBUG if debug else (logging.INFO if verbose else logging.WARNING)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=[logging.StreamHandler(sys.stderr)],
    )


@click.group()
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
@click.argument("project_path", default=".")
@click.pass_context
def start(ctx: click.Context, project_path: str) -> None:
    cols, rows = _terminal_size()
    try:
        handle = _engine(ctx).start(project_path, cols=cols, rows=rows)
    except SandboxError as e:
        # A traceback in the middle of a terminal session is no way to
        # report "already running".
        raise click.ClickException(str(e))
    _interactive_session(handle)


@main.command()
@click.argument("project_path", default=".")
@click.pass_context
def stop(ctx: click.Context, project_path: str) -> None:
    _engine(ctx).stop(project_path)
    click.echo("sandbox stopped.")


@main.command()
@click.argument("project_path", default=".")
@click.pass_context
def destroy(ctx: click.Context, project_path: str) -> None:
    _engine(ctx).destroy(project_path)
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
@click.argument("project_path", default=".")
@click.pass_context
def status(ctx: click.Context, project_path: str) -> None:
    info = _engine(ctx).status(project_path)
    for k, v in info.items():
        click.echo(f"  {k}: {v}")
