"""Click entry point; command operations live in src.commands."""

from pathlib import Path

import click

from src import commands


@click.group()
def main() -> None:
    """Reproduce the eMudhra CA key compromise."""


@main.command()
@click.argument("domain_name")
@click.option("--all", "all_cas", is_flag=True, help="Use all six TLS intermediates.")
@click.option("--ca", help="CA name (default: em-dv-tls-ca-g3b).")
@click.option(
    "--output",
    type=click.Path(path_type=Path, file_okay=False),
    default=Path("certificates"),
    show_default=True,
)
def generate(domain_name: str, all_cas: bool, ca: str | None, output: Path) -> None:
    """Sign a DNS certificate."""
    try:
        targets = commands.generate(domain_name, ca=ca, all_cas=all_cas, output=output)
    except (ValueError, OSError) as error:
        raise click.UsageError(str(error)) from None
    for target in targets:
        click.echo(target)


@main.command("end_to_end")
@click.argument("domain_name")
@click.option(
    "--ca", default=commands.DEFAULT_CA, show_default=True, help="TLS CA name."
)
def end_to_end(domain_name: str, ca: str) -> None:
    """Serve HTTPS locally until interrupted; restore DNS on exit."""
    try:
        commands.end_to_end(domain_name, ca=ca)
    except (ValueError, OSError) as error:
        raise click.UsageError(str(error)) from None


if __name__ == "__main__":
    main()
