from __future__ import annotations

import logging
import sys
import threading
import time
from pathlib import Path

import click

from sbx.engine import Engine
from sbx.errors import SandboxError

log = logging.getLogger(__name__)


def _pump_output(handle) -> None:
    """Copy the shell's output to stdout until the runner exits and the
    pipe is drained, or the pipe breaks."""
    from sbx import winapi

    while True:
        try:
            avail = winapi.peek_pipe(handle.pipe_out)
        except OSError:
            return
        if avail > 0:
            try:
                data = winapi.read_file(handle.pipe_out, min(avail, 4096))
            except OSError:
                return
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()
        elif handle.runner_exited():
            return
        else:
            time.sleep(0.02)


def _pump_piped_input(handle) -> None:
    """Relay non-console stdin to the shell; signal EOF when it ends."""
    from sbx import winapi

    stdin = sys.stdin.buffer.raw
    while True:
        data = stdin.read(4096)
        if not data:
            break
        try:
            winapi.write_file(handle.pipe_in, data)
        except OSError:
            return
    handle.close_input()


def _pump_console_input(handle) -> None:
    """Relay console keystrokes to the shell until the runner exits."""
    import msvcrt

    from sbx import winapi

    while not handle.runner_exited():
        if not msvcrt.kbhit():
            time.sleep(0.02)
            continue
        ch = msvcrt.getwch()
        if ch == "\r":
            ch = "\r\n"
        try:
            winapi.write_file(handle.pipe_in, ch.encode("utf-8"))
        except OSError:
            return


def _session(handle) -> int:
    """Relay I/O between this process and the sandboxed shell until the
    shell exits. Returns the shell's exit code."""
    import msvcrt

    from sbx import winapi

    output =threading.Thread(target=_pump_output, args=(handle,), daemon=True)
    output.start()
    try:
        if winapi.is_console(msvcrt.get_osfhandle(sys.stdin.fileno())):
            _pump_console_input(handle)
        else:
            threading.Thread(
                target=_pump_piped_input, args=(handle,), daemon=True,
            ).start()
        code = handle.exit_code()
    except KeyboardInterrupt:
        code = 130
    output.join(timeout=5)
    return code


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
    engine = _engine(ctx)
    handle = engine.start(project_path)
    try:
        code = _session(handle)
    finally:
        handle.close()
        engine.session_ended(project_path)
    sys.exit(code)


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
