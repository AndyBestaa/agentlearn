"""Typed configuration with secure, local-first defaults."""

from __future__ import annotations

import os
import platform
import re
import tempfile
import tomllib
from enum import Enum
from pathlib import Path
from typing import Any, Literal, Mapping
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

DEEPSEEK_CHAT_MODEL_IDS = frozenset({"deepseek-v4-flash", "deepseek-v4-pro"})
CURRENT_CONFIG_VERSION: Literal[1] = 1


class ConfigError(ValueError):
    """Raised when configuration is missing, malformed, or unsafe."""


def validate_strict_workspace_root(value: str | Path) -> Path:
    """Resolve a convenience-shell workspace without touching broad/remote roots.

    ``aster`` is intended to be launched from one concrete local project.  Its
    current directory is therefore an authority boundary, not merely a default.
    Reject network/device paths before resolution so an untrusted argument cannot
    cause an implicit UNC access while we are still deciding whether it is safe.
    """

    raw = os.fspath(value)
    expanded = os.path.expanduser(raw)
    windows_spelling = expanded.replace("/", "\\")
    if windows_spelling.startswith("\\\\"):
        raise ConfigError("strict workspace cannot be a UNC or device path")
    lexical = Path(os.path.abspath(Path(expanded)))
    for component in (*reversed(lexical.parents), lexical):
        is_junction = bool(getattr(component, "is_junction", lambda: False)())
        if component.is_symlink() or is_junction:
            raise ConfigError(
                f"strict workspace cannot traverse a link or junction: {component}"
            )
    try:
        resolved = lexical.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ConfigError(f"strict workspace must be an existing local directory: {value}") from exc
    if not resolved.is_dir():
        raise ConfigError(f"strict workspace is not a directory: {resolved}")
    if str(resolved.drive).startswith("\\\\"):
        raise ConfigError("strict workspace cannot be a UNC path")

    broad_roots = {
        Path.home().resolve(),
        Path.home().resolve().parent,
        Path(tempfile.gettempdir()).resolve(),
    }
    if resolved.anchor:
        broad_roots.add(Path(resolved.anchor).resolve())
    protected_trees = {
        Path(item).expanduser().resolve(strict=False)
        for item in (
            os.environ.get("SystemRoot"),
            os.environ.get("ProgramFiles"),
            os.environ.get("ProgramFiles(x86)"),
        )
        if item
    }
    if os.name == "nt" and resolved.drive:
        drive = Path(f"{resolved.drive}\\")
        broad_roots.add(drive / "Users")
        protected_trees.update(
            {
                drive / "Program Files",
                drive / "Program Files (x86)",
                drive / "ProgramData",
                drive / "Windows",
            }
        )
    if os.name != "nt":
        protected_trees.update(
            Path(item).resolve(strict=False)
            for item in (
                "/boot",
                "/dev",
                "/etc",
                "/proc",
                "/run",
                "/sys",
                "/usr",
                "/var",
            )
        )
    if resolved in broad_roots or any(
        resolved == protected or protected in resolved.parents
        for protected in protected_trees
    ):
        raise ConfigError(
            "refusing a broad/system workspace; enter a specific project directory"
        )
    return resolved


def validate_strict_project_file(value: str | Path, root: str | Path) -> Path:
    """Resolve one existing project file without crossing a strict workspace."""

    workspace = validate_strict_workspace_root(root)
    candidate = Path(value).expanduser()
    spelling = os.fspath(candidate).replace("/", "\\")
    if spelling.startswith("\\\\"):
        raise ConfigError("project file cannot be a UNC or device path")
    if not candidate.is_absolute():
        candidate = workspace / candidate
    candidate = Path(os.path.abspath(candidate))
    is_junction = bool(getattr(candidate, "is_junction", lambda: False)())
    if candidate.is_symlink() or is_junction:
        raise ConfigError(f"project file cannot be a link or junction: {candidate}")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise ConfigError(f"project file does not exist: {candidate}") from exc
    try:
        resolved.relative_to(workspace)
    except ValueError as exc:
        raise ConfigError(f"project file escapes the strict workspace: {resolved}") from exc
    if not resolved.is_file():
        raise ConfigError(f"project path is not a file: {resolved}")
    if resolved.stat(follow_symlinks=False).st_nlink > 1:
        raise ConfigError(f"project file cannot be hard-linked: {resolved}")
    return resolved


class ConfigModel(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class TargetOS(str, Enum):
    WINDOWS = "windows"
    LINUX = "linux"


class NetworkMode(str, Enum):
    DENY_BY_DEFAULT = "deny_by_default"
    ALLOWLIST = "allowlist"


class ExecutionMode(str, Enum):
    INSPECT_THEN_IMPLEMENT = "inspect_then_implement"
    READ_ONLY = "read_only"


class SandboxBackend(str, Enum):
    NONE = "none"
    WINDOWS_SANDBOX = "windows_sandbox"
    APPCONTAINER = "appcontainer"
    CONTAINER = "container"
    POSIX_NAMESPACE = "posix_namespace"


class ModelConfig(ConfigModel):
    provider: Literal["fake", "openai", "deepseek"] = "openai"
    model_id: str | None = None
    api_key_env: str = "OPENAI_API_KEY"
    base_url: str | None = None
    reasoning: str | None = None
    verbosity: str | None = None
    timeout_seconds: float = Field(default=120.0, gt=0, le=3_600)
    max_retries: int = Field(default=2, ge=0, le=8)
    decision_max_tokens: int = Field(default=8_192, ge=512, le=131_072)
    tracing_enabled: bool = False

    @model_validator(mode="before")
    @classmethod
    def normalise_provider_defaults(cls, value: Any) -> Any:
        data = dict(value or {})
        aliases = {
            "openai": "openai",
            "openai_responses": "openai",
            "openai_responses_agents": "openai",
            "fake": "fake",
            "deterministic_fake": "fake",
            "deepseek": "deepseek",
            "deepseek_chat": "deepseek",
            "deepseek_openai": "deepseek",
            "deepseek_openai_chat": "deepseek",
        }
        raw_provider = str(data.get("provider", "openai")).strip().lower()
        provider = aliases.get(raw_provider)
        if provider is None:
            raise ValueError(f"unsupported model provider: {raw_provider or '<blank>'}")
        data["provider"] = provider
        if "api_key_env" not in data:
            data["api_key_env"] = (
                "DEEPSEEK_API_KEY" if provider == "deepseek" else "OPENAI_API_KEY"
            )
        if provider == "deepseek" and "base_url" not in data:
            data["base_url"] = "https://api.deepseek.com"
        return data

    @field_validator("api_key_env")
    @classmethod
    def validate_secret_reference(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value):
            raise ValueError("api_key_env must be an environment variable name")
        return value

    @field_validator("model_id")
    @classmethod
    def validate_model_id(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("model_id cannot be blank")
        return value.strip() if value is not None else None

    @field_validator("base_url")
    @classmethod
    def validate_base_url_shape(cls, value: str | None) -> str | None:
        if value is None:
            return None
        candidate = value.strip()
        if not candidate or len(candidate) > 2_048 or any(char.isspace() for char in candidate):
            raise ValueError("base_url must be a bounded URL without whitespace")
        return candidate

    @field_validator("reasoning")
    @classmethod
    def validate_reasoning(cls, value: str | None) -> str | None:
        if value is None:
            return None
        candidate = value.strip().lower()
        if candidate not in {"none", "minimal", "low", "medium", "high", "max"}:
            raise ValueError("reasoning must be none, minimal, low, medium, high, or max")
        return candidate

    @field_validator("verbosity")
    @classmethod
    def validate_verbosity(cls, value: str | None) -> str | None:
        if value is None:
            return None
        candidate = value.strip().lower()
        if candidate not in {"low", "medium", "high"}:
            raise ValueError("verbosity must be low, medium, or high")
        return candidate

    @model_validator(mode="after")
    def reject_unsupported_endpoint_combinations(self) -> ModelConfig:
        if self.provider == "deepseek":
            if self.model_id is not None and self.model_id not in DEEPSEEK_CHAT_MODEL_IDS:
                raise ValueError(
                    "DeepSeek model_id must be deepseek-v4-flash or deepseek-v4-pro"
                )
            if self.reasoning not in {None, "none", "low", "high", "max"}:
                raise ValueError(
                    "DeepSeek reasoning must be none, low, high, or max"
                )
            if self.base_url is None:
                raise ValueError("DeepSeek requires the official base_url")
            try:
                parsed = urlsplit(self.base_url)
                port = parsed.port
            except ValueError as exc:
                raise ValueError("DeepSeek base_url is malformed") from exc
            if (
                parsed.scheme.lower() != "https"
                or (parsed.hostname or "").lower() != "api.deepseek.com"
                or parsed.username is not None
                or parsed.password is not None
                or port not in {None, 443}
                or parsed.path.rstrip("/")
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError("DeepSeek base_url must be exactly https://api.deepseek.com")
        elif self.base_url is not None:
            raise ValueError("model.base_url is currently supported only for DeepSeek")
        return self


class BudgetConfig(ConfigModel):
    max_rounds: int = Field(default=40, ge=1, le=1_000)
    max_tool_calls: int = Field(default=100, ge=1, le=10_000)
    max_tokens: int | None = Field(default=120_000, ge=1)
    max_input_tokens: int | None = Field(default=100_000, ge=1)
    max_output_tokens: int | None = Field(default=20_000, ge=1)
    max_cost_usd: float | None = Field(default=None, gt=0)
    max_elapsed_seconds: float = Field(default=3_600.0, gt=0, le=604_800)
    max_concurrency: int = Field(default=1, ge=1, le=32)


class FeatureConfig(ConfigModel):
    browser_automation: bool = True
    native_desktop_gui: bool = False
    multi_agent: bool = False


class SSHHostConfig(ConfigModel):
    host_id: str = Field(min_length=1, max_length=128)
    hostname: str = Field(min_length=1, max_length=253)
    port: int = Field(default=22, ge=1, le=65_535)
    user: str = Field(min_length=1, max_length=256)
    host_key_fingerprint: str = Field(min_length=16, max_length=512)
    known_hosts: Path | None = None

    @field_validator("hostname")
    @classmethod
    def reject_ambiguous_hostname(cls, value: str) -> str:
        candidate = value.strip().lower()
        if candidate in {"localhost", "localhost.localdomain"}:
            raise ValueError("loopback SSH hosts are not accepted as remote allowlist entries")
        if (
            not candidate
            or candidate.startswith("-")
            or any(char.isspace() or ord(char) < 32 for char in candidate)
            or any(char in candidate for char in ("@", "/", "\\"))
        ):
            raise ValueError("SSH hostname contains ambiguous or option-like text")
        return candidate

    @field_validator("user")
    @classmethod
    def reject_ambiguous_user(cls, value: str) -> str:
        candidate = value.strip()
        if (
            not candidate
            or candidate.startswith("-")
            or any(char.isspace() or ord(char) < 32 for char in candidate)
            or "@" in candidate
        ):
            raise ValueError("SSH user contains ambiguous or option-like text")
        return candidate


class SSHSecurityConfig(ConfigModel):
    """Live transport intent; runtime attestation is independently required."""

    enabled: bool = False
    backend: Literal["openssh"] = "openssh"
    connect_timeout_seconds: float = Field(default=15.0, gt=0, le=300)


class ProcessSecurityConfig(ConfigModel):
    # The convenience CLI asks for a verified container boundary by default.
    # Hosts without Docker or the configured local image still fail closed.
    sandbox_backend: SandboxBackend = SandboxBackend.CONTAINER
    allow_unsandboxed_process: bool = False
    clean_path: list[Path] = Field(default_factory=list)
    container_image: str = (
        "mirror.gcr.io/library/python@"
        "sha256:2c941e860699f878900b0edc2403613c234d4b32eda3cc9fa7036991a2a63c4a"
    )
    container_cpus: float = Field(default=1.0, gt=0, le=64)
    container_tmpfs_bytes: int = Field(
        default=67_108_864, ge=1_048_576, le=4_294_967_296
    )
    container_workspace_bytes: int = Field(
        default=536_870_912, ge=16_777_216, le=17_179_869_184
    )
    container_user: str = "65534:65534"
    max_output_bytes: int = Field(default=1_048_576, ge=1_024, le=1_073_741_824)
    default_timeout_seconds: float = Field(default=120.0, gt=0, le=86_400)
    max_timeout_seconds: float = Field(default=3_600.0, gt=0, le=604_800)
    max_processes: int = Field(default=32, ge=1, le=1_024)
    max_memory_bytes: int | None = Field(
        default=2_147_483_648, ge=16_777_216, le=274_877_906_944
    )
    max_cpu_time_seconds: float | None = Field(
        default=600.0, ge=0.01, le=604_800
    )

    @field_validator("container_image")
    @classmethod
    def validate_container_image(cls, value: str) -> str:
        candidate = value.strip()
        if (
            not candidate
            or len(candidate) > 512
            or candidate.startswith("-")
            or any(char.isspace() or ord(char) < 32 for char in candidate)
        ):
            raise ValueError("container_image must be a bounded image reference")
        return candidate

    @field_validator("container_user")
    @classmethod
    def validate_container_user(cls, value: str) -> str:
        candidate = value.strip()
        if not re.fullmatch(r"[0-9]{1,10}:[0-9]{1,10}", candidate):
            raise ValueError("container_user must be a numeric uid:gid pair")
        return candidate

    @property
    def has_enforced_sandbox(self) -> bool:
        # Backend names are configuration intent, not runtime proof.  The
        # Docker adapter separately resolves an immutable image digest and
        # runs active filesystem/network probes before reporting attestation.
        return False


class BrowserSecurityConfig(ConfigModel):
    """Browser policy; a non-empty allowlist is necessary but not a live proof."""

    enabled: bool = True
    engine: Literal["disabled", "playwright_edge"] = "disabled"
    allowed_domains: list[str] = Field(default_factory=list)
    download_dir: Path | None = None
    max_redirects: int = Field(default=8, ge=0, le=32)
    max_download_bytes: int = Field(default=33_554_432, ge=1_024, le=1_073_741_824)
    isolated_profile_required: bool = True

    @field_validator("allowed_domains")
    @classmethod
    def normalize_domains(cls, values: list[str]) -> list[str]:
        domains: set[str] = set()
        for value in values:
            item = value.strip().lower().rstrip(".")
            if not item or "://" in item or "/" in item or "@" in item:
                raise ValueError("browser allowlist entries must be bare domains")
            if item == "localhost" or item.endswith(".localhost"):
                raise ValueError("browser allowlist cannot include localhost")
            domains.add(item.encode("idna").decode("ascii"))
        return sorted(domains)

    @model_validator(mode="after")
    def require_isolated_profile(self) -> BrowserSecurityConfig:
        if not self.isolated_profile_required:
            raise ValueError("reuse of a user's main browser profile is unsupported")
        return self


class ExtensionPinConfig(ConfigModel):
    extension_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")
    source: str = Field(min_length=1, max_length=2_048)
    version: str = Field(pattern=r"^[0-9]+(?:\.[0-9]+){1,3}(?:[-+][0-9A-Za-z.-]+)?$")
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    capabilities: frozenset[str] = Field(min_length=1)

    @field_validator("source")
    @classmethod
    def normalize_source(cls, value: str) -> str:
        if any(char in value for char in ("\n", "\r", "\x00")):
            raise ValueError("extension source contains control characters")
        return value.rstrip("/")


class ExtensionSecurityConfig(ConfigModel):
    mcp_enabled: bool = False
    plugins_enabled: bool = False
    mcp_pins: list[ExtensionPinConfig] = Field(default_factory=list)
    plugin_pins: list[ExtensionPinConfig] = Field(default_factory=list)

    @model_validator(mode="after")
    def require_unique_pins(self) -> ExtensionSecurityConfig:
        for name, values in (("mcp", self.mcp_pins), ("plugin", self.plugin_pins)):
            ids = [item.extension_id for item in values]
            if len(ids) != len(set(ids)):
                raise ValueError(f"duplicate {name} extension pin")
        return self


class SubagentSecurityConfig(ConfigModel):
    enabled: bool = False
    read_only: bool = True
    max_depth: int = Field(default=1, ge=0, le=16)
    max_concurrency: int = Field(default=1, ge=1, le=32)
    max_tool_calls: int = Field(default=12, ge=1, le=1_000)
    max_tokens: int = Field(default=8_000, ge=1, le=10_000_000)
    max_elapsed_seconds: float = Field(default=300.0, gt=0, le=86_400)

    @model_validator(mode="after")
    def require_read_only(self) -> SubagentSecurityConfig:
        if not self.read_only:
            raise ValueError("M6 subagents must be read-only")
        return self


class SecurityConfig(ConfigModel):
    authorized_roots: list[Path] = Field(min_length=1)
    authorized_ssh_hosts: list[SSHHostConfig] = Field(default_factory=list)
    network_mode: NetworkMode = NetworkMode.DENY_BY_DEFAULT
    network_allowlist: list[str] = Field(default_factory=list)
    ssh: SSHSecurityConfig = Field(default_factory=SSHSecurityConfig)
    process: ProcessSecurityConfig = Field(default_factory=ProcessSecurityConfig)
    browser: BrowserSecurityConfig = Field(default_factory=BrowserSecurityConfig)
    extensions: ExtensionSecurityConfig = Field(default_factory=ExtensionSecurityConfig)
    subagents: SubagentSecurityConfig = Field(default_factory=SubagentSecurityConfig)
    reject_unc_paths: bool = True
    approval_ttl_seconds: int = Field(default=600, ge=30, le=86_400)
    artifact_max_bytes: int = Field(default=67_108_864, ge=1_024)
    telemetry_enabled: bool = False

    @field_validator("authorized_roots")
    @classmethod
    def canonicalize_roots(cls, roots: list[Path]) -> list[Path]:
        canonical: list[Path] = []
        seen: set[str] = set()
        for root in roots:
            resolved = root.expanduser().resolve(strict=True)
            if not resolved.is_dir():
                raise ValueError(f"authorized root is not a directory: {resolved}")
            key = os.path.normcase(str(resolved))
            if key not in seen:
                seen.add(key)
                canonical.append(resolved)
        if not canonical:
            raise ValueError("at least one authorized root is required")
        return canonical

    @field_validator("network_allowlist")
    @classmethod
    def normalize_network_allowlist(cls, values: list[str]) -> list[str]:
        result: list[str] = []
        for value in values:
            entry = value.strip().lower().rstrip(".")
            if not entry or "://" in entry or "/" in entry or "@" in entry:
                raise ValueError("network allowlist entries must be bare hostnames")
            result.append(entry)
        return sorted(set(result))

    @model_validator(mode="after")
    def validate_network_mode(self) -> SecurityConfig:
        if self.network_mode is NetworkMode.DENY_BY_DEFAULT and self.network_allowlist:
            raise ValueError("deny_by_default mode cannot contain network allowlist entries")
        host_ids = [host.host_id for host in self.authorized_ssh_hosts]
        if len(host_ids) != len(set(host_ids)):
            raise ValueError("SSH host_id values must be unique")
        return self


class StorageConfig(ConfigModel):
    database_path: Path
    audit_jsonl_path: Path
    artifacts_dir: Path
    busy_timeout_ms: int = Field(default=5_000, ge=100, le=120_000)
    wal_autocheckpoint_pages: int = Field(default=1_000, ge=1, le=1_000_000)


class AppConfig(ConfigModel):
    config_version: Literal[1] = CURRENT_CONFIG_VERSION
    product_name: str = "AsterCode"
    project_root: Path = Field(default_factory=Path.cwd)
    target_os: TargetOS = Field(
        default_factory=lambda: (
            TargetOS.WINDOWS if platform.system() == "Windows" else TargetOS.LINUX
        )
    )
    execution_mode: ExecutionMode = ExecutionMode.INSPECT_THEN_IMPLEMENT
    model: ModelConfig = Field(default_factory=ModelConfig)
    budget: BudgetConfig = Field(default_factory=BudgetConfig)
    features: FeatureConfig = Field(default_factory=FeatureConfig)
    security: SecurityConfig
    storage: StorageConfig

    @model_validator(mode="before")
    @classmethod
    def populate_project_scoped_defaults(cls, value: Any) -> Any:
        data = dict(value or {})
        root = Path(data.get("project_root", Path.cwd())).expanduser().resolve(strict=True)
        data["project_root"] = root

        security = dict(data.get("security") or {})
        security.setdefault("authorized_roots", [root])
        security["authorized_roots"] = [
            (root / Path(item)) if not Path(item).expanduser().is_absolute() else item
            for item in security.get("authorized_roots", [root])
        ]
        data["security"] = security

        state_dir = root / ".astercode"
        storage = dict(data.get("storage") or {})
        storage.setdefault("database_path", state_dir / "astercode.db")
        storage.setdefault("audit_jsonl_path", state_dir / "audit.jsonl")
        storage.setdefault("artifacts_dir", state_dir / "artifacts")
        data["storage"] = storage
        return data

    @field_validator("project_root")
    @classmethod
    def validate_project_root(cls, value: Path) -> Path:
        resolved = value.expanduser().resolve(strict=True)
        if not resolved.is_dir():
            raise ValueError("project_root must be an existing directory")
        return resolved

    @model_validator(mode="after")
    def resolve_storage_paths(self) -> AppConfig:
        for field_name in ("database_path", "audit_jsonl_path", "artifacts_dir"):
            path = getattr(self.storage, field_name).expanduser()
            if not path.is_absolute():
                path = self.project_root / path
            resolved = path.resolve(strict=False)
            try:
                resolved.relative_to(self.project_root)
            except ValueError as exc:
                raise ValueError(f"{field_name} must remain under project_root") from exc
            setattr(self.storage, field_name, resolved)
        download_dir = self.security.browser.download_dir or Path(".astercode") / "downloads"
        if not download_dir.is_absolute():
            download_dir = self.project_root / download_dir
        resolved_download = download_dir.expanduser().resolve(strict=False)
        if not any(
            resolved_download == root or root in resolved_download.parents
            for root in self.security.authorized_roots
        ):
            raise ValueError("browser.download_dir must remain under an authorized root")
        self.security.browser.download_dir = resolved_download
        return self

    @property
    def live_provider_ready(self) -> bool:
        return bool(
            self.model.provider != "fake"
            and self.model.model_id
            and os.getenv(self.model.api_key_env)
        )

    @property
    def live_provider_requested(self) -> bool:
        """Return true when a partial live configuration must fail closed."""

        return bool(
            self.model.provider != "fake"
            and (self.model.model_id or os.getenv(self.model.api_key_env))
        )


AsterCodeConfig = AppConfig


def _deep_merge(base: dict[str, Any], overlay: Mapping[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in overlay.items():
        if isinstance(value, Mapping) and isinstance(merged.get(key), Mapping):
            merged[key] = _deep_merge(dict(merged[key]), value)
        else:
            merged[key] = value
    return merged


def _environment_overlay(
    environ: Mapping[str, str],
    *,
    configured_provider: str | None = None,
) -> dict[str, Any]:
    """Read non-secret runtime settings; secret *values* remain outside config."""

    overlay: dict[str, Any] = {}
    model_overlay: dict[str, Any] = {}
    provider = environ.get("ASTERCODE_MODEL_PROVIDER")
    provider_hint = (provider or configured_provider or "").strip().lower()
    deepseek_selected = provider_hint in {
        "deepseek",
        "deepseek_chat",
        "deepseek_openai",
        "deepseek_openai_chat",
    }
    if provider:
        model_overlay["provider"] = provider
        model_overlay["api_key_env"] = environ.get("ASTERCODE_API_KEY_ENV") or (
            "DEEPSEEK_API_KEY" if deepseek_selected else "OPENAI_API_KEY"
        )
        model_overlay["base_url"] = (
            environ.get("ASTERCODE_MODEL_BASE_URL")
            or environ.get("DEEPSEEK_BASE_URL")
            or "https://api.deepseek.com"
            if deepseek_selected
            else None
        )
    elif api_key_env := environ.get("ASTERCODE_API_KEY_ENV"):
        model_overlay["api_key_env"] = api_key_env
    model_id = environ.get("ASTERCODE_MODEL_ID") or (
        environ.get("DEEPSEEK_MODEL") if deepseek_selected else environ.get("OPENAI_MODEL")
    )
    if model_id:
        model_overlay["model_id"] = model_id
    if not provider and (
        base_url := environ.get("ASTERCODE_MODEL_BASE_URL")
        or (environ.get("DEEPSEEK_BASE_URL") if deepseek_selected else None)
    ):
        model_overlay["base_url"] = base_url
    if reasoning := environ.get("ASTERCODE_REASONING_EFFORT"):
        model_overlay["reasoning"] = reasoning
    if model_overlay:
        overlay["model"] = model_overlay
    if root := environ.get("ASTERCODE_PROJECT_ROOT"):
        overlay["project_root"] = root
    return overlay


def load_config(
    path: str | Path | None = None,
    *,
    project_root: str | Path | None = None,
    environ: Mapping[str, str] | None = None,
    strict_workspace: bool = False,
) -> AppConfig:
    """Load TOML plus a narrow environment overlay.

    This function intentionally does not load ``.env`` files.  Credentials are
    obtained by the provider from the configured environment reference.
    """

    strict_root: Path | None = None
    if strict_workspace:
        if project_root is None:
            raise ConfigError("strict_workspace requires an explicit project_root")
        strict_root = validate_strict_workspace_root(project_root)

    effective_environ = os.environ if environ is None else environ
    data: dict[str, Any] = {}
    if path is not None:
        config_path = (
            validate_strict_project_file(path, strict_root)
            if strict_root is not None
            else Path(path).expanduser().resolve(strict=True)
        )
        try:
            if config_path.stat().st_size > 1_048_576:
                raise ConfigError(f"config exceeds 1 MiB: {config_path}")
            with config_path.open("rb") as handle:
                parsed = tomllib.load(handle)
        except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
            raise ConfigError(f"cannot load config {config_path}: {exc}") from exc
        data = dict(parsed)
    try:
        data = _normalise_legacy_config(data)
    except (OSError, TypeError, ValueError) as exc:
        raise ConfigError(f"cannot normalize config: {exc}") from exc
    if project_root is not None:
        data["project_root"] = str(project_root)
    model_data = data.get("model")
    configured_provider = (
        str(model_data.get("provider"))
        if isinstance(model_data, Mapping) and model_data.get("provider") is not None
        else None
    )
    data = _deep_merge(
        data,
        _environment_overlay(
            effective_environ,
            configured_provider=configured_provider,
        ),
    )
    raw_model_boundary = data.get("model") or {}
    if not isinstance(raw_model_boundary, Mapping):
        raise ConfigError("model must be a TOML table")
    model_boundary = dict(raw_model_boundary)
    provider_boundary = str(model_boundary.get("provider", "openai")).strip().lower()
    if provider_boundary in {
        "deepseek",
        "deepseek_chat",
        "deepseek_openai",
        "deepseek_openai_chat",
    }:
        model_boundary["api_key_env"] = "DEEPSEEK_API_KEY"
    elif provider_boundary != "fake":
        model_boundary["api_key_env"] = "OPENAI_API_KEY"
    data["model"] = model_boundary
    if strict_root is not None:
        root = strict_root
        data["project_root"] = str(root)
        # A repository is untrusted input.  Under the convenience shortcut it
        # cannot grant itself network, SSH, process, browser, extension, GUI or
        # subagent capabilities.  Every public CLI entrypoint uses this same
        # boundary; project files are data, not host-authority grants.
        data["security"] = SecurityConfig(
            authorized_roots=[root],
            browser=BrowserSecurityConfig(
                download_dir=root / ".astercode" / "downloads"
            ),
        ).model_dump(mode="python")
        data["features"] = FeatureConfig().model_dump(mode="python")
        data["budget"] = BudgetConfig().model_dump(mode="python")
        data["storage"] = StorageConfig(
            database_path=root / ".astercode" / "astercode.db",
            audit_jsonl_path=root / ".astercode" / "audit.jsonl",
            artifacts_dir=root / ".astercode" / "artifacts",
        ).model_dump(mode="python")
        strict_environ = effective_environ
        provider = str(strict_environ.get("ASTERCODE_MODEL_PROVIDER", "")).strip()
        if not provider:
            data["model"] = {"provider": "fake"}
        else:
            model = dict(
                _environment_overlay(
                    strict_environ,
                    configured_provider=None,
                ).get("model", {})
            )
            model["provider"] = provider
            deepseek = provider.strip().lower() in {
                "deepseek",
                "deepseek_chat",
                "deepseek_openai",
                "deepseek_openai_chat",
            }
            model["api_key_env"] = (
                "DEEPSEEK_API_KEY" if deepseek else "OPENAI_API_KEY"
            )
            model["base_url"] = "https://api.deepseek.com" if deepseek else None
            data["model"] = model
    try:
        return AppConfig.model_validate(data)
    except (OSError, ValueError) as exc:
        raise ConfigError(str(exc)) from exc


def _normalise_legacy_config(data: Mapping[str, Any]) -> dict[str, Any]:
    """Accept the human-facing example schema while keeping one typed model.

    Early AsterCode drafts used ``[product]``/``[budgets]`` and flatter
    security/storage keys.  Normalising here keeps old local config files
    readable without weakening the strict Pydantic model or accepting unknown
    keys silently.
    """
    value = dict(data)
    raw_version = value.pop("config_version", None)
    if raw_version is not None:
        if isinstance(raw_version, bool) or not isinstance(raw_version, int):
            raise ValueError("config_version must be an integer")
        if raw_version > CURRENT_CONFIG_VERSION:
            raise ValueError(
                f"config version {raw_version} is newer than supported version {CURRENT_CONFIG_VERSION}"
            )
        if raw_version < 1:
            raise ValueError("config_version must be at least 1")

    legacy_sections = {"product", "budgets", "approval"}
    if raw_version == CURRENT_CONFIG_VERSION and legacy_sections.intersection(value):
        names = ", ".join(sorted(legacy_sections.intersection(value)))
        raise ValueError(
            f"config_version={CURRENT_CONFIG_VERSION} cannot contain legacy sections: {names}"
        )

    def legacy_section(name: str) -> dict[str, Any] | None:
        if name not in value:
            return None
        candidate = value.pop(name)
        if not isinstance(candidate, Mapping):
            raise ValueError(f"legacy section {name} must be a TOML table")
        return dict(candidate)

    def canonical_section(name: str) -> dict[str, Any]:
        candidate = value.get(name)
        if candidate is None:
            return {}
        if not isinstance(candidate, Mapping):
            raise ValueError(f"section {name} must be a TOML table")
        return dict(candidate)

    def merge_legacy(
        target: dict[str, Any], key: str, item: Any, source: str
    ) -> None:
        if key in target and target[key] != item:
            raise ValueError(
                f"legacy field {source} conflicts with canonical field {key}"
            )
        target.setdefault(key, item)

    product = legacy_section("product")
    if product is not None:
        if "name" in product:
            merge_legacy(value, "product_name", product["name"], "product.name")
        for key in ("project_root", "execution_mode"):
            if key in product:
                merge_legacy(value, key, product[key], f"product.{key}")
        unknown = set(product).difference({"name", "project_root", "execution_mode"})
        if unknown:
            raise ValueError(f"unknown legacy product fields: {', '.join(sorted(unknown))}")

    budgets = legacy_section("budgets")
    budget = canonical_section("budget")
    if budgets is not None:
        aliases = {
            "max_turns": "max_rounds",
            "max_wall_time_seconds": "max_elapsed_seconds",
        }
        for key, item in budgets.items():
            canonical_key = aliases.get(key, key)
            merge_legacy(budget, canonical_key, item, f"budgets.{key}")
    if budget or "budget" in value:
        value["budget"] = budget

    security = canonical_section("security")
    security_aliases = {
        "max_output_bytes": ("process", "max_output_bytes"),
        "default_command_timeout_seconds": ("process", "default_timeout_seconds"),
    }
    for old, (section_name, new) in security_aliases.items():
        if old in security:
            nested_value = security.get(section_name)
            if nested_value is not None and not isinstance(nested_value, Mapping):
                raise ValueError(f"security.{section_name} must be a TOML table")
            nested = dict(nested_value or {})
            merge_legacy(
                nested,
                new,
                security.pop(old),
                f"security.{old}",
            )
            security[section_name] = nested
    for old in (
        "enable_browser_automation",
        "enable_native_desktop_gui",
        "enable_multi_agent",
        "allow_workspace_writes",
    ):
        if old in security:
            features = canonical_section("features")
            mapping = {
                "enable_browser_automation": "browser_automation",
                "enable_native_desktop_gui": "native_desktop_gui",
                "enable_multi_agent": "multi_agent",
            }
            if old in mapping:
                merge_legacy(
                    features,
                    mapping[old],
                    security[old],
                    f"security.{old}",
                )
                value["features"] = features
            if old == "allow_workspace_writes":
                if not isinstance(security[old], bool):
                    raise ValueError("security.allow_workspace_writes must be boolean")
                merge_legacy(
                    value,
                    "execution_mode",
                    (
                        "inspect_then_implement"
                        if security[old]
                        else "read_only"
                    ),
                    "security.allow_workspace_writes",
                )
            security.pop(old)
    value["security"] = security

    storage = canonical_section("storage")
    if "artifact_dir" in storage and "artifacts_dir" not in storage:
        storage["artifacts_dir"] = storage.pop("artifact_dir")
    elif "artifact_dir" in storage:
        legacy = storage.pop("artifact_dir")
        if storage["artifacts_dir"] != legacy:
            raise ValueError(
                "legacy field storage.artifact_dir conflicts with canonical field artifacts_dir"
            )
    if "audit_log_path" in storage and "audit_jsonl_path" not in storage:
        storage["audit_jsonl_path"] = storage.pop("audit_log_path")
    elif "audit_log_path" in storage:
        legacy = storage.pop("audit_log_path")
        if storage["audit_jsonl_path"] != legacy:
            raise ValueError(
                "legacy field storage.audit_log_path conflicts with canonical field audit_jsonl_path"
            )
    if "wal" in storage:
        if storage["wal"] is not True:
            raise ValueError("storage.wal=false is not supported")
        storage.pop("wal")
    value["storage"] = storage

    approval = legacy_section("approval")
    if approval is not None:
        if "default_expiry_seconds" in approval:
            merge_legacy(
                security,
                "approval_ttl_seconds",
                approval["default_expiry_seconds"],
                "approval.default_expiry_seconds",
            )
        # Persist/one-shot are invariant runtime guarantees in this release;
        # reject attempts to disable them instead of silently accepting them.
        if approval.get("single_use") is False:
            raise ValueError("approval.single_use=false is not supported")
        if approval.get("persist_requests") is False:
            raise ValueError("approval.persist_requests=false is not supported")
        unknown = set(approval).difference(
            {"default_expiry_seconds", "single_use", "persist_requests"}
        )
        if unknown:
            raise ValueError(f"unknown legacy approval fields: {', '.join(sorted(unknown))}")
    value["security"] = security

    model = canonical_section("model")
    for key in ("model_id", "reasoning", "verbosity"):
        if model.get(key) == "":
            model.pop(key)
    value["model"] = model
    value["config_version"] = CURRENT_CONFIG_VERSION
    return value


__all__ = [
    "AppConfig",
    "AsterCodeConfig",
    "BrowserSecurityConfig",
    "BudgetConfig",
    "CURRENT_CONFIG_VERSION",
    "ConfigError",
    "ExecutionMode",
    "ExtensionPinConfig",
    "ExtensionSecurityConfig",
    "FeatureConfig",
    "ModelConfig",
    "NetworkMode",
    "ProcessSecurityConfig",
    "SSHHostConfig",
    "SSHSecurityConfig",
    "SandboxBackend",
    "SecurityConfig",
    "StorageConfig",
    "SubagentSecurityConfig",
    "TargetOS",
    "load_config",
    "validate_strict_project_file",
    "validate_strict_workspace_root",
]
