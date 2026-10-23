"""Small argparse entry point."""

import argparse
from pathlib import Path

from . import commands


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Classroom X.509 signing demonstration"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    generate = subparsers.add_parser("generate", help="sign a DNS certificate")
    generate.add_argument("domain_name")
    selection = generate.add_mutually_exclusive_group()
    selection.add_argument("--all", action="store_true", help="use every configured CA")
    selection.add_argument("--ca", help="configured CA name (default: first CA)")
    generate.add_argument(
        "--demo", action="store_true", help="use local, untrusted classroom CAs"
    )
    generate.add_argument("--output", type=Path, default=Path("certificates"))
    end_to_end = subparsers.add_parser(
        "end_to_end", help="reserved for DNS and nginx integration"
    )
    end_to_end.add_argument("domain_name")
    args = parser.parse_args(argv)
    try:
        if args.command == "generate":
            targets = commands.generate(
                args.domain_name,
                ca=args.ca,
                all_cas=args.all,
                demo=args.demo,
                output=args.output,
            )
            if args.demo:
                print(
                    "Local demo certificates; not issued by eMudhra. "
                    "They are not publicly trusted."
                )
            for target in targets:
                print(target)
        else:
            commands.end_to_end(args.domain_name)
    except (ValueError, OSError, NotImplementedError) as error:
        parser.exit(2, f"error: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
