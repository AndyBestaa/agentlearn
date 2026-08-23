"""Console entrypoints that preserve the full AsterCode command surface."""

from __future__ import annotations

import sys

from . import cli
from .terminal import configure_utf8_output


def _invoke(*, default_chat: bool) -> None:
    configure_utf8_output()
    if default_chat and len(sys.argv) == 1:
        sys.argv.append("chat")
    previous = cli._STRICT_SHORTCUT
    cli._STRICT_SHORTCUT = True
    try:
        cli.app()
    finally:
        cli._STRICT_SHORTCUT = previous


def main() -> None:
    """Enter interactive chat only when ``aster`` receives no arguments."""

    _invoke(default_chat=True)


def astercode_main() -> None:
    """Keep the compatibility command surface while enforcing strict roots."""

    _invoke(default_chat=False)


__all__ = ["astercode_main", "main"]
