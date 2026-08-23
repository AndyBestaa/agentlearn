from __future__ import annotations

from pathlib import Path

import pytest

from astercode.extensions import (
    BlockedSubprocessRunner,
    DeterministicFakeExtensionRunner,
    ExtensionBlockedError,
    ExtensionKind,
    ExtensionManifest,
    ExtensionPin,
    ExtensionRegistry,
    ExtensionToolManifest,
    classify_extension_invocation,
)
from astercode.models import RiskLevel


def _manifest(kind: ExtensionKind = ExtensionKind.MCP) -> ExtensionManifest:
    return ExtensionManifest(
        extension_id="example.reader",
        kind=kind,
        source="https://packages.example.com/example-reader",
        version="1.2.3",
        sha256="a" * 64,
        capabilities=frozenset({"workspace.read"}),
        tools=(
            ExtensionToolManifest(
                name="files.read",
                capability="workspace.read",
                input_schema={
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"],
                    "additionalProperties": False,
                },
                declared_read_only=True,
                declared_risk=RiskLevel.P0,
            ),
        ),
    )


def _pin() -> ExtensionPin:
    return ExtensionPin(
        extension_id="example.reader",
        source="https://packages.example.com/example-reader",
        version="1.2.3",
        sha256="a" * 64,
        capabilities=frozenset({"workspace.read"}),
    )


def test_extension_requires_exact_source_version_hash_and_capabilities(tmp_path: Path) -> None:
    registry = ExtensionRegistry(
        ExtensionKind.MCP,
        [_pin()],
        authorized_roots=[tmp_path],
        enabled=True,
    )
    changed = _manifest().model_copy(update={"version": "1.2.4"})

    with pytest.raises(ExtensionBlockedError, match="differ"):
        registry.register(changed)


def test_manifest_read_only_claim_cannot_lower_concrete_delete_risk() -> None:
    assert (
        classify_extension_invocation(
            "files.read",
            {"operation": "delete", "path": "old.txt"},
        )
        is RiskLevel.P4
    )


@pytest.mark.parametrize(
    ("arguments", "validator"),
    [
        ({}, "required"),
        ({"path": 42}, "type"),
        ({"path": "source.txt", "unexpected": True}, "additionalProperties"),
    ],
)
def test_extension_arguments_must_match_pinned_json_schema(
    arguments: dict[str, object],
    validator: str,
    tmp_path: Path,
) -> None:
    registry = ExtensionRegistry(
        ExtensionKind.MCP,
        [_pin()],
        authorized_roots=[tmp_path],
        enabled=True,
    )
    registry.register(_manifest())

    with pytest.raises(ExtensionBlockedError, match=rf"JSON Schema.*{validator}"):
        registry.prepare("example.reader", "files.read", arguments)


@pytest.mark.parametrize(
    "schema",
    [
        {"type": "definitely-not-a-json-type"},
        {"$ref": "https://attacker.example/schema.json"},
        {"$dynamicRef": "file:///outside/schema.json"},
    ],
)
def test_extension_manifest_rejects_invalid_or_remote_json_schema(schema: dict[str, object]) -> None:
    payload = _manifest().model_dump(mode="python")
    payload["tools"][0]["input_schema"] = schema

    with pytest.raises(ValueError, match="input schema"):
        ExtensionManifest.model_validate(payload)


def test_default_extension_runner_is_fail_closed(tmp_path: Path) -> None:
    registry = ExtensionRegistry(
        ExtensionKind.MCP,
        [_pin()],
        authorized_roots=[tmp_path],
        runner=BlockedSubprocessRunner(),
        enabled=True,
    )
    registry.register(_manifest())
    target = tmp_path / "source.txt"
    target.write_text("safe", encoding="utf-8")
    prepared = registry.prepare("example.reader", "files.read", {"path": str(target)})

    with pytest.raises(ExtensionBlockedError, match="LIVE EXTENSION NOT VERIFIED"):
        registry.invoke(prepared)


def test_deterministic_fake_extension_is_offline(tmp_path: Path) -> None:
    runner = DeterministicFakeExtensionRunner(
        {("example.reader", "files.read"): {"stdout": "fixture contents"}}
    )
    registry = ExtensionRegistry(
        ExtensionKind.MCP,
        [_pin()],
        authorized_roots=[tmp_path],
        runner=runner,
        enabled=True,
    )
    registry.register(_manifest())
    target = tmp_path / "source.txt"
    target.write_text("safe", encoding="utf-8")

    prepared = registry.prepare("example.reader", "files.read", {"path": str(target)})
    result = registry.invoke(prepared)

    assert prepared.risk is RiskLevel.P0
    assert result["stdout"] == "fixture contents"
    assert runner.calls[0]["network_used"] is False
    assert runner.isolation_verified is False
