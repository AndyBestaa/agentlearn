from __future__ import annotations

import io
import sys

from astercode import entrypoint
from astercode.terminal import configure_utf8_output


def test_utf8_output_replaces_legacy_windows_code_pages(monkeypatch) -> None:
    stdout_bytes = io.BytesIO()
    stderr_bytes = io.BytesIO()
    stdout = io.TextIOWrapper(stdout_bytes, encoding="cp1252")
    stderr = io.TextIOWrapper(stderr_bytes, encoding="cp1252")
    monkeypatch.setattr(sys, "stdout", stdout)
    monkeypatch.setattr(sys, "stderr", stderr)

    configure_utf8_output()
    stdout.write("AsterCode 对话模式")
    stderr.write("工作区")
    stdout.flush()
    stderr.flush()

    assert stdout.encoding == "utf-8"
    assert stderr.encoding == "utf-8"
    assert stdout_bytes.getvalue().decode("utf-8") == "AsterCode 对话模式"
    assert stderr_bytes.getvalue().decode("utf-8") == "工作区"


def test_aster_without_arguments_forwards_chat(monkeypatch) -> None:
    observed: list[tuple[list[str], bool]] = []
    monkeypatch.setattr(sys, "argv", ["aster"])
    monkeypatch.setattr(
        entrypoint.cli,
        "app",
        lambda: observed.append(
            (sys.argv.copy(), entrypoint.cli._STRICT_SHORTCUT)
        ),
    )

    entrypoint.main()

    assert observed == [(["aster", "chat"], True)]
    assert entrypoint.cli._STRICT_SHORTCUT is False


def test_aster_with_arguments_forwards_them_unchanged(monkeypatch) -> None:
    argv = ["aster", "run", "inspect README.md", "--root", "."]
    observed: list[tuple[list[str], bool]] = []
    monkeypatch.setattr(sys, "argv", argv)
    monkeypatch.setattr(
        entrypoint.cli,
        "app",
        lambda: observed.append(
            (sys.argv.copy(), entrypoint.cli._STRICT_SHORTCUT)
        ),
    )

    entrypoint.main()

    assert sys.argv is argv
    assert observed == [(argv, True)]
    assert entrypoint.cli._STRICT_SHORTCUT is False


def test_astercode_compatibility_entrypoint_is_strict_without_injecting_chat(
    monkeypatch,
) -> None:
    observed: list[tuple[list[str], bool]] = []
    monkeypatch.setattr(sys, "argv", ["astercode"])
    monkeypatch.setattr(
        entrypoint.cli,
        "app",
        lambda: observed.append(
            (sys.argv.copy(), entrypoint.cli._STRICT_SHORTCUT)
        ),
    )

    entrypoint.astercode_main()

    assert observed == [(["astercode"], True)]
    assert entrypoint.cli._STRICT_SHORTCUT is False
