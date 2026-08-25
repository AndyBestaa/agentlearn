"""Terminal compatibility helpers for public CLI entrypoints."""

from __future__ import annotations

import signal
import sys
from typing import TextIO


def _normalize_output_stream(stream: TextIO) -> None:
    """Use UTF-8 when Python inherited a legacy Windows output code page."""

    encoding = getattr(stream, "encoding", None)
    if isinstance(encoding, str) and encoding.replace("-", "").lower() == "utf8":
        return
    reconfigure = getattr(stream, "reconfigure", None)
    if not callable(reconfigure):
        return
    try:
        reconfigure(encoding="utf-8", errors="backslashreplace")
    except (AttributeError, LookupError, OSError, TypeError, ValueError):
        # Embedded hosts may expose a text-like stream whose reconfigure method
        # is unavailable or intentionally restricted. Rich can still use it.
        return


def configure_utf8_output() -> None:
    """Prevent localized CLI text from crashing on legacy Windows runners."""

    _normalize_output_stream(sys.stdout)
    _normalize_output_stream(sys.stderr)


def configure_console_signals() -> None:
    """Route Windows Ctrl-Break through the normal KeyboardInterrupt path."""

    sigbreak = getattr(signal, "SIGBREAK", None)
    if sigbreak is not None:
        signal.signal(sigbreak, signal.default_int_handler)


__all__ = ["configure_console_signals", "configure_utf8_output"]
