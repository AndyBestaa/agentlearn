from __future__ import annotations

import sys

from astercode import entrypoint


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
