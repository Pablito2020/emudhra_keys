"""Click entry point; command operations live in src.commands."""

from pathlib import Path

import click
from click.core import ParameterSource

from src import commands
from src.emudhra.certificates import EmudhraCertificates

DEFAULT_CA = "em-dv-tls-ca-g3b"
DEFAULT_OUTPUT_PATH = Path("certificates")
TLS_CA = click.Choice([ca.name for ca in EmudhraCertificates() if ca.supports_tls])


@click.group()
def main() -> None:
    """Reproduce the eMudhra CA key compromise."""


@main.command()
@click.argument("domain_name")
@click.option(
    "--all",
    "all_cas",
    is_flag=True,
    default=False,
    help="Use all six TLS intermediates.",
)
@click.option(
    "--ca", type=TLS_CA, default=DEFAULT_CA, show_default=True, help="TLS CA name."
)
@click.option(
    "--output",
    type=click.Path(path_type=Path, file_okay=False),
    default=DEFAULT_OUTPUT_PATH,
    show_default=True,
    help="Certificate output directory.",
)
@click.pass_context
def generate(
    ctx: click.Context, domain_name: str, all_cas: bool, ca: str | None, output: Path
) -> None:
    if all_cas and ctx.get_parameter_source("ca") == ParameterSource.DEFAULT:
        ca = None
    try:
        commands.generate(domain_name, ca=ca, all_cas=all_cas, output=output)
    except (ValueError, OSError) as error:
        raise click.UsageError(str(error)) from None


@main.command("end_to_end")
@click.argument("domain_name")
@click.option(
    "--ca", type=TLS_CA, default=DEFAULT_CA, show_default=True, help="TLS CA name."
)
@click.option(
    "--output",
    type=click.Path(path_type=Path, file_okay=False),
    default=DEFAULT_OUTPUT_PATH,
    show_default=True,
    help="Certificate output directory; cleared before each run.",
)
def end_to_end(domain_name: str, ca: str, output: Path) -> None:
    try:
        commands.end_to_end(domain_name, ca=ca, output=output)
    except (ValueError, OSError) as error:
        raise click.UsageError(str(error)) from None


if __name__ == "__main__":
    main()
