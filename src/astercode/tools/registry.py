"""Strict registry: model-facing names resolve only to registered callables."""

from __future__ import annotations

import inspect
from collections.abc import Callable, Mapping
from typing import Any

from .base import ToolResult, ToolSpec


class ToolRegistry:
    def __init__(self) -> None:
        self._specs: dict[str, ToolSpec] = {}
        self._handlers: dict[str, Callable[..., ToolResult]] = {}

    def register(self, spec: ToolSpec, handler: Callable[..., ToolResult]) -> None:
        if spec.name in self._specs:
            raise ValueError(f"duplicate tool: {spec.name}")
        if not callable(handler):
            raise TypeError("handler must be callable")
        self._specs[spec.name] = spec
        self._handlers[spec.name] = handler

    def register_provider(self, provider: Any) -> None:
        for spec in getattr(provider, "specs", ()):
            # Providers may expose Pydantic ToolSpec objects. Normalize only
            # the fields needed by the local registry.
            if not isinstance(spec, ToolSpec):
                spec = ToolSpec(
                    name=spec.name,
                    description=getattr(spec, "description", ""),
                    capability=getattr(spec, "capability", "unknown"),
                    side_effects=tuple(getattr(spec, "side_effects", ())),
                    risk=str(getattr(spec, "risk", "P0")),
                    timeout_seconds=float(getattr(spec, "timeout", 30.0)),
                    max_output=int(getattr(spec, "max_output", 32_000)),
                    idempotent=bool(getattr(spec, "idempotent", False)),
                    schema=getattr(spec, "input_schema", getattr(spec, "schema", {})),
                )
            method_name = spec.name.split(".", 1)[1]
            handler = getattr(provider, method_name, None)
            if handler is None:
                raise AttributeError(f"provider {type(provider).__name__} lacks {method_name}")
            self.register(spec, handler)

    def get(self, name: str) -> tuple[ToolSpec, Callable[..., ToolResult]]:
        try:
            return self._specs[name], self._handlers[name]
        except KeyError as exc:
            raise KeyError(f"unregistered tool: {name}") from exc

    def validate_arguments(self, name: str, arguments: Mapping[str, Any]) -> None:
        spec, _ = self.get(name)
        schema = getattr(spec, "schema", None) or getattr(spec, "input_schema", None) or {}
        if not schema:
            return
        try:
            from jsonschema import Draft202012Validator
        except ImportError as exc:  # pragma: no cover - dependency is locked
            raise RuntimeError("jsonschema is required for tool argument validation") from exc
        errors = sorted(Draft202012Validator(schema).iter_errors(dict(arguments)), key=lambda item: list(item.path))
        if errors:
            location = ".".join(str(item) for item in errors[0].path) or "$"
            raise ValueError(f"invalid arguments for {name} at {location}: {errors[0].message}")

    def specs(self) -> list[ToolSpec]:
        return list(self._specs.values())

    def providers(self) -> list[Any]:
        """Return unique bound executor instances for host-wide cancellation."""
        result: list[Any] = []
        seen: set[int] = set()
        for handler in self._handlers.values():
            owner = getattr(handler, "__self__", None)
            if owner is not None and id(owner) not in seen:
                seen.add(id(owner))
                result.append(owner)
        return result

    def describe(self) -> list[dict[str, Any]]:
        descriptions: list[dict[str, Any]] = []
        for spec in self._specs.values():
            if hasattr(spec, "as_dict"):
                descriptions.append(spec.as_dict())
            else:
                dump = getattr(spec, "model_dump", None)
                descriptions.append(dump(mode="json") if callable(dump) else {"name": spec.name})
        return descriptions

    def invoke(self, name: str, arguments: Mapping[str, Any]) -> ToolResult:
        _, handler = self.get(name)
        if not isinstance(arguments, Mapping):
            raise TypeError("tool arguments must be an object")
        self.validate_arguments(name, arguments)
        result = handler(**dict(arguments))
        if inspect.isawaitable(result):
            raise TypeError("async tool handlers must be awaited by the orchestrator")
        if not isinstance(result, ToolResult):
            raise TypeError(f"tool {name} returned {type(result).__name__}, expected ToolResult")
        return result
