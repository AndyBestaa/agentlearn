"""Allowlisted MCP/plugin manifests and fail-closed runner abstractions.

Manifests are untrusted declarations: their read-only/risk labels never lower
the classification derived from the concrete invocation arguments.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .models import RiskLevel
from .security import (
    action_hash,
    canonicalize_authorized_path,
    contains_probable_secret,
    normalize_action,
)
from .tools.base import ToolResult, ToolSpec, new_action_id, timed_result


class ExtensionBlockedError(RuntimeError):
    """An extension is disabled, unpinned, unisolated, or otherwise unsafe."""


class ExtensionKind(str, Enum):
    MCP = "mcp"
    PLUGIN = "plugin"


class ManifestModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
_VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+){1,3}(?:[-+][0-9A-Za-z.-]+)?$")
_TOOL = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$")

_MAX_SCHEMA_DEPTH = 32
_MAX_SCHEMA_NODES = 4_096


def _check_local_json_schema(schema: Mapping[str, Any]) -> None:
    """Validate a bounded Draft 2020-12 schema without remote retrieval.

    Extension manifests are untrusted data.  ``jsonschema`` can resolve remote
    references when asked to validate one, which would turn manifest loading
    into an implicit network/file read.  Only in-document references are
    accepted, and a simple structural budget prevents pathological manifests
    from consuming unbounded validation work before a tool is invoked.
    """

    nodes = 0
    stack: list[tuple[Any, int]] = [(schema, 0)]
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > _MAX_SCHEMA_NODES or depth > _MAX_SCHEMA_DEPTH:
            raise ValueError("extension tool input schema exceeds the structural limit")
        if isinstance(value, Mapping):
            for key, item in value.items():
                if key in {"$ref", "$dynamicRef"}:
                    if not isinstance(item, str) or not item.startswith("#"):
                        raise ValueError("extension tool input schema may use only local references")
                stack.append((item, depth + 1))
        elif isinstance(value, (list, tuple)):
            stack.extend((item, depth + 1) for item in value)
    try:
        Draft202012Validator.check_schema(dict(schema))
    except SchemaError as exc:
        raise ValueError("extension tool input schema is not valid Draft 2020-12 JSON Schema") from exc


def _schema_error_location(error: Any) -> str:
    location = "$"
    for item in error.absolute_path:
        location += f"[{item}]" if isinstance(item, int) else f".{item}"
    return location


def _validate_extension_arguments(schema: Mapping[str, Any], arguments: Mapping[str, Any]) -> None:
    """Reject arguments that do not match the pinned tool declaration.

    Error text intentionally omits the offending value: tool arguments can
    contain user data even though probable secrets are rejected separately.
    """

    errors = sorted(
        Draft202012Validator(dict(schema)).iter_errors(dict(arguments)),
        key=lambda item: (
            tuple(str(part) for part in item.absolute_path),
            tuple(str(part) for part in item.absolute_schema_path),
        ),
    )
    if errors:
        error = errors[0]
        raise ExtensionBlockedError(
            "extension arguments violate the pinned JSON Schema "
            f"at {_schema_error_location(error)} ({error.validator})"
        )


class ExtensionToolManifest(ManifestModel):
    name: str
    capability: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=1_024)
    input_schema: dict[str, Any] = Field(
        default_factory=lambda: {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        }
    )
    declared_read_only: bool = False
    declared_risk: RiskLevel = RiskLevel.P2

    @field_validator("name")
    @classmethod
    def validate_tool_name(cls, value: str) -> str:
        if not _TOOL.fullmatch(value):
            raise ValueError("extension tool must use namespace.action syntax")
        return value


class ExtensionManifest(ManifestModel):
    extension_id: str
    kind: ExtensionKind
    source: str = Field(min_length=1, max_length=2_048)
    version: str
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    capabilities: frozenset[str] = Field(min_length=1)
    tools: tuple[ExtensionToolManifest, ...] = Field(min_length=1)

    @field_validator("extension_id")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if not _IDENTIFIER.fullmatch(value):
            raise ValueError("invalid extension identifier")
        return value

    @field_validator("source")
    @classmethod
    def normalize_source(cls, value: str) -> str:
        if any(char in value for char in ("\n", "\r", "\x00")):
            raise ValueError("extension source contains control characters")
        return value.rstrip("/")

    @field_validator("version")
    @classmethod
    def require_exact_version(cls, value: str) -> str:
        if not _VERSION.fullmatch(value):
            raise ValueError("extension version must be exact; ranges and tags are forbidden")
        return value

    @model_validator(mode="after")
    def validate_tools_and_capabilities(self) -> ExtensionManifest:
        names = [tool.name for tool in self.tools]
        if len(names) != len(set(names)):
            raise ValueError("extension tool names must be unique")
        for tool in self.tools:
            if tool.capability not in self.capabilities:
                raise ValueError(f"tool capability is absent from manifest: {tool.capability}")
            _check_local_json_schema(tool.input_schema)
        return self


class ExtensionPin(ManifestModel):
    extension_id: str
    source: str
    version: str
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    capabilities: frozenset[str]

    @field_validator("extension_id")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if not _IDENTIFIER.fullmatch(value):
            raise ValueError("invalid extension pin identifier")
        return value

    @field_validator("source")
    @classmethod
    def normalize_source(cls, value: str) -> str:
        return value.rstrip("/")

    @field_validator("version")
    @classmethod
    def require_exact_version(cls, value: str) -> str:
        if not _VERSION.fullmatch(value):
            raise ValueError("extension pin version must be exact")
        return value


class ExtensionRunner(Protocol):
    """Interface for an independently isolated extension process."""

    isolation_verified: bool

    def invoke(
        self,
        manifest: ExtensionManifest,
        tool: ExtensionToolManifest,
        arguments: Mapping[str, Any],
    ) -> Mapping[str, Any]: ...

    def close(self) -> None: ...


class BlockedSubprocessRunner:
    """Production default: never spawn an unverified plugin/MCP process."""

    isolation_verified = False

    def invoke(
        self,
        manifest: ExtensionManifest,
        tool: ExtensionToolManifest,
        arguments: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        del manifest, tool, arguments
        raise ExtensionBlockedError(
            "LIVE EXTENSION NOT VERIFIED: isolated subprocess and network policy are unavailable"
        )

    def close(self) -> None:
        return None


class DeterministicFakeExtensionRunner:
    """Explicit test adapter. It evaluates fixture callables in-process only."""

    # It is a deterministic in-process fixture, not a production isolation
    # boundary.  Keeping this false prevents test evidence being mistaken for
    # a verified subprocess sandbox.
    isolation_verified = False
    is_test_adapter = True

    def __init__(self, responses: Mapping[tuple[str, str], Mapping[str, Any]]) -> None:
        self._responses = {key: dict(value) for key, value in responses.items()}
        self.calls: list[dict[str, Any]] = []
        self.closed = False

    def invoke(
        self,
        manifest: ExtensionManifest,
        tool: ExtensionToolManifest,
        arguments: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        if self.closed:
            raise ExtensionBlockedError("fake extension runner is closed")
        key = (manifest.extension_id, tool.name)
        if key not in self._responses:
            raise ExtensionBlockedError("deterministic extension fixture is absent")
        self.calls.append(
            {
                "extension_id": manifest.extension_id,
                "tool": tool.name,
                "arguments": dict(arguments),
                "network_used": False,
            }
        )
        return dict(self._responses[key])

    def close(self) -> None:
        self.closed = True


@dataclass(frozen=True, slots=True)
class PreparedExtensionInvocation:
    extension_id: str
    kind: ExtensionKind
    tool: str
    arguments: dict[str, Any]
    risk: RiskLevel
    action_hash: str


_P4_WORDS = re.compile(
    r"(?:^|[._-])(?:drop|truncate|delete|remove|delete_recursive|force_push|reset_hard|clean|reboot|shutdown|"
    r"firewall|iam|credential|disable_security)(?:$|[._-])",
    re.IGNORECASE,
)
_P3_WORDS = re.compile(
    r"(?:^|[._-])(?:push|publish|deploy|submit|send|remote_write|service_start|service_stop|sudo)(?:$|[._-])",
    re.IGNORECASE,
)
_P1_WORDS = re.compile(
    r"(?:^|[._-])(?:write|create|update|patch|mkdir|move)(?:$|[._-])",
    re.IGNORECASE,
)
_P0_WORDS = re.compile(
    r"(?:^|[._-])(?:read|get|list|show|status|diff|log|search|stat)(?:$|[._-])",
    re.IGNORECASE,
)
_P4_COMMANDS = (
    re.compile(r"\brm(?:\.exe)?(?:\s|$)", re.IGNORECASE),
    re.compile(r"\bremove-item\b", re.IGNORECASE),
    re.compile(r"\b(?:del|erase|rmdir)(?:\.exe)?(?:\s|$)", re.IGNORECASE),
    re.compile(r"\bgit\s+(?:reset\s+--hard|clean\s+-[^\r\n]*f|push\b[^\r\n]*--force)", re.IGNORECASE),
    re.compile(r"\b(?:drop|truncate)\s+(?:database|schema|table)\b", re.IGNORECASE),
    re.compile(r"\b(?:shutdown|reboot|diskpart)(?:\.exe)?\b", re.IGNORECASE),
    re.compile(r"\bformat(?:\.com)?\s+[a-z]:", re.IGNORECASE),
    re.compile(r"\bset-executionpolicy\s+(?:bypass|unrestricted)\b", re.IGNORECASE),
    re.compile(r"(?:^|\s)-(?:encodedcommand|enc)(?:\s|$)", re.IGNORECASE),
)
_P3_COMMANDS = (
    re.compile(r"\b(?:sudo|runas)(?:\.exe)?\b", re.IGNORECASE),
    re.compile(r"\bstart-process\b[^\r\n]*\s-verb\s+runas\b", re.IGNORECASE),
    re.compile(r"\b(?:ssh|scp|sftp|netcat|nc)(?:\.exe)?\b", re.IGNORECASE),
    re.compile(
        r"\bcurl(?:\.exe)?\b[^\r\n]*(?:--data(?:-[a-z-]+)?|(?-i:-d)(?:\s|$)|--form|(?-i:-F)(?:\s|$)|"
        r"--upload-file|(?-i:-T)(?:\s|$)|(?-i:-X)\s*(?:post|put|patch|delete)\b)",
        re.IGNORECASE,
    ),
    re.compile(r"\bwget(?:\.exe)?\b[^\r\n]*(?:--post-(?:data|file)|--method\s*=\s*(?:post|put|patch|delete))", re.IGNORECASE),
    re.compile(
        r"\binvoke-(?:webrequest|restmethod)\b[^\r\n]*(?:-method\s+(?:post|put|patch|delete)|-body\b|-infile\b)",
        re.IGNORECASE,
    ),
    re.compile(r"\brequests\.(?:post|put|patch|delete)\s*\(", re.IGNORECASE),
)
_COMMAND_KEYS = frozenset(
    {
        "argv",
        "bash",
        "cmd",
        "command",
        "executable",
        "powershell",
        "program",
        "script",
        "shell",
    }
)
_EXTERNAL_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _flatten_strings(value: Any) -> list[str]:
    result: list[str] = []
    if isinstance(value, str):
        result.append(value)
    elif isinstance(value, Mapping):
        for key, item in value.items():
            result.append(str(key))
            result.extend(_flatten_strings(item))
    elif isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            result.extend(_flatten_strings(item))
    return result


def _walk_items(value: Any) -> list[tuple[str, Any]]:
    result: list[tuple[str, Any]] = []
    if isinstance(value, Mapping):
        for raw_key, item in value.items():
            key = str(raw_key).strip().casefold().replace("-", "_")
            result.append((key, item))
            result.extend(_walk_items(item))
    elif isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            result.extend(_walk_items(item))
    return result


def _contains_command_field(items: Sequence[tuple[str, Any]]) -> bool:
    return any(key in _COMMAND_KEYS or key.endswith("_command") or key.endswith("_script") for key, _ in items)


def _contains_external_write(items: Sequence[tuple[str, Any]]) -> bool:
    for key, value in items:
        if key in {"method", "http_method"} and str(value).strip().upper() in _EXTERNAL_WRITE_METHODS:
            return True
        if (
            key in {"upload", "publish", "submit", "send", "external_write"}
            and value is not False
            and value is not None
            and value != ""
        ):
            return True
    return False


def classify_extension_invocation(tool: str, arguments: Mapping[str, Any]) -> RiskLevel:
    """Classify concrete action text; ignore manifest-supplied risk labels."""

    strings = (tool, *_flatten_strings(arguments))
    raw_text = "\n".join(strings)
    searchable = " ".join(strings).replace(" ", "_")
    items = _walk_items(arguments)
    if (
        any(key in {"recursive", "force"} and value is True for key, value in items)
        or _P4_WORDS.search(searchable)
        or any(pattern.search(raw_text) for pattern in _P4_COMMANDS)
    ):
        return RiskLevel.P4
    if (
        _P3_WORDS.search(searchable)
        or any(pattern.search(raw_text) for pattern in _P3_COMMANDS)
        or _contains_external_write(items)
        # An opaque command/script surface cannot inherit a manifest's
        # read-only claim.  Unknown code execution is conservatively P3.
        or _contains_command_field(items)
    ):
        return RiskLevel.P3
    if _P1_WORDS.search(searchable):
        return RiskLevel.P1
    if _P0_WORDS.search(searchable):
        return RiskLevel.P0
    return RiskLevel.P2


class ExtensionRegistry:
    """Registry that accepts only exact source/version/hash/capability pins."""

    def __init__(
        self,
        kind: ExtensionKind,
        pins: Sequence[ExtensionPin | Mapping[str, Any]],
        *,
        authorized_roots: Sequence[str | Path],
        runner: ExtensionRunner | None = None,
        enabled: bool = False,
    ) -> None:
        self.kind = kind
        self.enabled = enabled
        self._pins = {
            pin.extension_id: pin
            for raw in pins
            for pin in [raw if isinstance(raw, ExtensionPin) else ExtensionPin.model_validate(raw)]
        }
        if len(self._pins) != len(pins):
            raise ValueError("duplicate extension allowlist pin")
        self._authorized_roots = tuple(Path(root) for root in authorized_roots)
        self.runner: ExtensionRunner = runner or BlockedSubprocessRunner()
        self._manifests: dict[str, ExtensionManifest] = {}

    def register(self, manifest: ExtensionManifest | Mapping[str, Any]) -> ExtensionManifest:
        item = manifest if isinstance(manifest, ExtensionManifest) else ExtensionManifest.model_validate(manifest)
        if not self.enabled:
            raise ExtensionBlockedError(f"{self.kind.value} extensions are disabled")
        if item.kind is not self.kind:
            raise ExtensionBlockedError("extension kind does not match registry")
        pin = self._pins.get(item.extension_id)
        if pin is None:
            raise ExtensionBlockedError("extension source is not allowlisted")
        if (
            pin.source != item.source
            or pin.version != item.version
            or pin.sha256 != item.sha256
            or not item.capabilities.issubset(pin.capabilities)
        ):
            raise ExtensionBlockedError("extension source/version/hash/capabilities differ from the exact pin")
        if item.extension_id in self._manifests:
            raise ExtensionBlockedError("extension is already registered")
        self._manifests[item.extension_id] = item
        return item

    def prepare(
        self,
        extension_id: str,
        tool: str,
        arguments: Mapping[str, Any],
    ) -> PreparedExtensionInvocation:
        if not self.enabled:
            raise ExtensionBlockedError(f"{self.kind.value} extensions are disabled")
        manifest = self._manifests.get(extension_id)
        if manifest is None:
            raise ExtensionBlockedError("extension is not registered")
        declaration = next((item for item in manifest.tools if item.name == tool), None)
        if declaration is None:
            raise ExtensionBlockedError("extension tool is not allowlisted by its pinned manifest")
        if contains_probable_secret(arguments):
            raise ExtensionBlockedError("secret-looking extension arguments are forbidden")
        normalized_arguments = self._validate_paths(arguments)
        _validate_extension_arguments(declaration.input_schema, normalized_arguments)
        risk = classify_extension_invocation(tool, normalized_arguments)
        action = normalize_action(
            {
                "kind": self.kind.value,
                "extension_id": extension_id,
                "source": manifest.source,
                "version": manifest.version,
                "sha256": manifest.sha256,
                "tool": tool,
                "arguments": normalized_arguments,
            }
        )
        return PreparedExtensionInvocation(
            extension_id=extension_id,
            kind=self.kind,
            tool=tool,
            arguments=normalized_arguments,
            risk=risk,
            action_hash=action_hash(action),
        )

    def invoke(self, prepared: PreparedExtensionInvocation) -> Mapping[str, Any]:
        if prepared.kind is not self.kind:
            raise ExtensionBlockedError("prepared invocation belongs to a different registry")
        manifest = self._manifests.get(prepared.extension_id)
        if manifest is None:
            raise ExtensionBlockedError("extension is no longer registered")
        declaration = next((item for item in manifest.tools if item.name == prepared.tool), None)
        if declaration is None:
            raise ExtensionBlockedError("extension tool is no longer registered")
        repeated = self.prepare(prepared.extension_id, prepared.tool, prepared.arguments)
        if repeated.action_hash != prepared.action_hash or repeated.risk is not prepared.risk:
            raise ExtensionBlockedError("prepared extension invocation changed")
        return self.runner.invoke(manifest, declaration, prepared.arguments)

    def _validate_paths(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        normalized = dict(arguments)
        for key in ("path", "source", "destination", "cwd"):
            value = normalized.get(key)
            if isinstance(value, str):
                checked = canonicalize_authorized_path(
                    value,
                    self._authorized_roots,
                    must_exist=key in {"source", "cwd"},
                )
                normalized[key] = str(checked.resolved)
        return normalize_action(normalized)

    def close(self) -> None:
        self.runner.close()


class _ExtensionTools:
    namespace: str

    def __init__(self, registry: ExtensionRegistry) -> None:
        self.registry = registry

    def invoke(self, extension_id: str, tool: str, arguments: Mapping[str, Any]) -> ToolResult:
        call_arguments = {"extension_id": extension_id, "tool": tool, "arguments": dict(arguments)}
        name = f"{self.namespace}.invoke"
        result = timed_result(name, new_action_id(name, call_arguments))
        try:
            prepared = self.registry.prepare(extension_id, tool, arguments)
            payload = self.registry.invoke(prepared)
            result.stdout = str(payload.get("stdout", ""))
            result.stderr = str(payload.get("stderr", ""))
            result.metadata.update(
                {
                    "extension_id": extension_id,
                    "extension_tool": tool,
                    "effective_risk": prepared.risk.value,
                    "action_hash": prepared.action_hash,
                    "isolated_runner_verified": self.registry.runner.isolation_verified,
                    "test_adapter": isinstance(self.registry.runner, DeterministicFakeExtensionRunner),
                    "network_used": False if isinstance(self.registry.runner, DeterministicFakeExtensionRunner) else None,
                }
            )
            return result.finish()
        except ExtensionBlockedError as exc:
            result.status = "failed"
            result.error = str(exc)
            result.metadata.update({"blocked": True, "isolated_runner_verified": self.registry.runner.isolation_verified})
            return result.finish()


_INVOKE_SCHEMA = {
    "type": "object",
    "properties": {
        "extension_id": {"type": "string"},
        "tool": {"type": "string"},
        "arguments": {"type": "object"},
    },
    "required": ["extension_id", "tool", "arguments"],
    "additionalProperties": False,
}


class MCPTools(_ExtensionTools):
    namespace = "mcp"
    specs = (
        ToolSpec(
            "mcp.invoke",
            "Invoke an exact-version allowlisted MCP tool through an isolated runner.",
            "extension.mcp",
            ("extension_defined",),
            "P2",
            idempotent=False,
            schema=_INVOKE_SCHEMA,
        ),
    )


class PluginTools(_ExtensionTools):
    namespace = "plugin"
    specs = (
        ToolSpec(
            "plugin.invoke",
            "Invoke an exact-version allowlisted plugin through an isolated runner.",
            "extension.plugin",
            ("extension_defined",),
            "P2",
            idempotent=False,
            schema=_INVOKE_SCHEMA,
        ),
    )


__all__ = [
    "BlockedSubprocessRunner",
    "DeterministicFakeExtensionRunner",
    "ExtensionBlockedError",
    "ExtensionKind",
    "ExtensionManifest",
    "ExtensionPin",
    "ExtensionRegistry",
    "ExtensionRunner",
    "ExtensionToolManifest",
    "MCPTools",
    "PluginTools",
    "PreparedExtensionInvocation",
    "classify_extension_invocation",
]
