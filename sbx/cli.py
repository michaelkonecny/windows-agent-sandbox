from __future__ import annotations

import logging
import sys
from pathlib import Path

import click

from sbx.engine import Engine
from sbx.errors import SandboxError

log = logging.getLogger(__name__)


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
    _engine(ctx).start(project_path)
    click.echo("sandbox started.")


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
