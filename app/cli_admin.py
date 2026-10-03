"""Admin CLI commands (owned by the admin agent).

Contract: `register(subparsers)` adds sub-commands to the `python -m app.cli` parser.
Each sub-parser must `set_defaults(func=handler)` where `handler(args) -> int` returns
the process exit code.
"""


def register(subparsers) -> None:
    return None
