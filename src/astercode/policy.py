"""Independent, runtime-enforced policy and approval engine."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Mapping

from .config import AppConfig
from .extensions import classify_extension_invocation
from .models import ApprovalDecision, ApprovalRequest, ApprovalStatus, RiskLevel, ToolSpec, new_id, utc_now
from .security import (
    action_hash,
    canonicalize_authorized_path,
    contains_probable_secret,
    generate_nonce,
    normalize_action,
    protected_path_reason,
    redact_secrets,
    secure_equal,
    sha256_hex,
)

_DEDICATED_OR_NETWORK_EXECUTABLES = frozenset(
    {
        "aws",
        "az",
        "curl",
        "docker",
        "ftp",
        "gcloud",
        "git",
        "helm",
        "kubectl",
        "mysql",
        "nc",
        "ncat",
        "netcat",
        "podman",
        "pscp",
        "psql",
        "rsync",
        "scp",
        "sftp",
        "sqlcmd",
        "ssh",
        "telnet",
        "wget",
    }
)
_DESTRUCTIVE_EXECUTABLES = frozenset(
    {
        "bcdedit",
        "cipher",
        "del",
        "diskpart",
        "erase",
        "format",
        "firewall-cmd",
        "halt",
        "iptables",
        "kill",
        "killall",
        "launchctl",
        "mkfs",
        "net",
        "netsh",
        "nft",
        "pkill",
        "poweroff",
        "rd",
        "reboot",
        "reg",
        "rmdir",
        "rm",
        "shutdown",
        "shred",
        "sc",
        "service",
        "systemctl",
        "taskkill",
        "ufw",
    }
)
_INLINE_INTERPRETERS = frozenset(
    {"bash", "cmd", "node", "perl", "powershell", "pwsh", "python", "python3", "ruby", "sh", "zsh"}
)
_COMMAND_WRAPPERS = frozenset(
    {
        "conda",
        "env",
        "nice",
        "nohup",
        "npx",
        "pipx",
        "poetry",
        "runas",
        "setsid",
        "start",
        "sudo",
        "timeout",
        "uv",
        "xargs",
    }
)
_INLINE_CODE_FLAGS = frozenset(
    {"-c", "/c", "-e", "--eval", "-command", "-encodedcommand", "-enc"}
)
_SHELL_DEDICATED_PATTERN = re.compile(
    r"(?i)(?:^|[\s;&|()\"'/\\])(?:"
    r"aws|az|curl|docker|ftp|gcloud|git|helm|invoke-restmethod|invoke-webrequest|irm|iwr|"
    r"kubectl|mysql|nc|ncat|netcat|podman|pscp|psql|rsync|scp|sftp|sqlcmd|ssh|"
    r"start-bitstransfer|telnet|wget"
    r")(?:\.exe|\.cmd|\.bat|\.com|\.ps1)?(?:$|[\s;&|()\"'])"
)
_SHELL_DESTRUCTIVE_PATTERN = re.compile(
    r"(?i)(?:^|[\s;&|()\"'/\\])(?:"
    r"bcdedit|cipher|del|diskpart|erase|firewall-cmd|format|format-volume|halt|iptables|kill|"
    r"killall|launchctl|mkfs(?:\.[a-z0-9_-]+)?|net|netsh|nft|pkill|poweroff|rd|reboot|reg|"
    r"remove-item|rmdir|rm|sc|service|shutdown|shred|systemctl|taskkill|ufw"
    r")(?:\.exe|\.cmd|\.bat|\.com|\.ps1)?(?:$|[\s;&|()\"'])"
)


@dataclass(frozen=True)
class PolicyDecision:
    decision: str  # allow | approval_required | deny
    risk: RiskLevel
    reason: str
    normalized_action: dict[str, Any]
    action_hash: str
    approval: ApprovalRequest | None = None


@dataclass(frozen=True)
class RuntimePolicyCapabilities:
    """Host-attested boundaries used for concrete policy decisions."""

    process_sandbox_enforced: bool = False
    process_network_policy_enforced: bool = False
    browser_profile_isolated: bool = False
    browser_network_policy_enforced: bool = False


class PolicyEngine:
    def __init__(
        self,
        config: AppConfig,
        storage: Any | None = None,
        runtime_capabilities: RuntimePolicyCapabilities | None = None,
    ) -> None:
        self.config = config
        self.storage = storage
        self.runtime_capabilities = runtime_capabilities or RuntimePolicyCapabilities()

    @staticmethod
    def _program_name(value: Any) -> str:
        if not isinstance(value, str) or not value.strip():
            return ""
        name = value.strip().strip('"').replace("\\", "/").rsplit("/", 1)[-1].lower()
        for suffix in (".exe", ".cmd", ".bat", ".com", ".ps1"):
            if name.endswith(suffix):
                name = name[: -len(suffix)]
                break
        return name

    @classmethod
    def _process_command_policy(
        cls, tool: str, arguments: Mapping[str, Any]
    ) -> tuple[RiskLevel, str | None]:
        """Reclassify the concrete command instead of trusting the tool name.

        General process tools must not be an alternate route around the Git,
        SSH, browser/network, filesystem-delete, service or machine-control
        adapters.  Shell text cannot be parsed with complete fidelity, so it
        starts at P3 and obvious boundary bypasses fail closed at P4.
        """

        if tool == "shell.exec":
            script = arguments.get("script")
            if not isinstance(script, str):
                return RiskLevel.P4, "shell script must be a string"
            if _SHELL_DESTRUCTIVE_PATTERN.search(script):
                return RiskLevel.P4, "destructive shell commands must use a dedicated constrained tool"
            if _SHELL_DEDICATED_PATTERN.search(script):
                return RiskLevel.P4, "Git, SSH, network and external-service commands cannot use shell.exec"
            return RiskLevel.P3, None

        argv = arguments.get("argv")
        if not isinstance(argv, (list, tuple)) or not argv:
            return RiskLevel.P4, "process launch requires a non-empty structured argv"
        program = cls._program_name(argv[0])
        if program in _DESTRUCTIVE_EXECUTABLES:
            return RiskLevel.P4, "destructive commands must use a dedicated constrained tool"
        if program in _DEDICATED_OR_NETWORK_EXECUTABLES:
            return RiskLevel.P4, "Git, SSH, network and external-service commands cannot use general process tools"
        if program in _INLINE_INTERPRETERS:
            script = " ".join(str(item) for item in argv[1:])
            if _SHELL_DESTRUCTIVE_PATTERN.search(script) or _SHELL_DEDICATED_PATTERN.search(script):
                return RiskLevel.P4, "inline shell commands cannot bypass dedicated constrained tools"
            if any(str(item).strip().lower() in _INLINE_CODE_FLAGS for item in argv[1:]):
                return RiskLevel.P4, "inline interpreter code must use a separately reviewed constrained workflow"
            return RiskLevel.P3, None
        if program in _COMMAND_WRAPPERS:
            wrapped = " ".join(str(item) for item in argv[1:])
            if _SHELL_DESTRUCTIVE_PATTERN.search(wrapped) or _SHELL_DEDICATED_PATTERN.search(wrapped):
                return RiskLevel.P4, "command wrappers cannot bypass dedicated constrained tools"
            return RiskLevel.P3, None
        return RiskLevel.P2, None

    def classify(self, tool: str, arguments: Mapping[str, Any], declared: ToolSpec | Any | None = None) -> RiskLevel:
        name = tool.lower()
        if name in {"fs.list", "fs.stat", "fs.read", "fs.search", "git.status", "git.diff", "git.log", "git.show", "git.branch"}:
            return RiskLevel.P0
        if name in {"fs.apply_patch", "fs.mkdir", "fs.move"}:
            return RiskLevel.P1
        if name in {"process.exec", "shell.exec", "process.start"}:
            return self._process_command_policy(name, arguments)[0]
        if name in {"process.send_input", "process.stop"}:
            return RiskLevel.P2
        if name == "fs.delete":
            return RiskLevel.P4 if arguments.get("recursive") else RiskLevel.P2
        if name in {"git.commit", "git.push", "browser.submit"}:
            return RiskLevel.P3
        if name.startswith("ssh.") and self._is_offline_ssh(declared):
            return RiskLevel.P0 if name in {"ssh.test_connection", "ssh.poll", "ssh.stat", "ssh.close"} else RiskLevel.P1
        if name in {"ssh.exec", "ssh.start", "ssh.stop", "ssh.upload", "ssh.download"}:
            return RiskLevel.P3
        if name in {"mcp.invoke", "plugin.invoke"}:
            nested = arguments.get("arguments")
            concrete = nested if isinstance(nested, Mapping) else {}
            return classify_extension_invocation(str(arguments.get("tool", "")), concrete)
        if name in {"browser.open", "browser.snapshot"}:
            return RiskLevel.P0 if self._is_offline_browser(declared) else RiskLevel.P2
        if name == "browser.download":
            return RiskLevel.P1 if self._is_offline_browser(declared) else RiskLevel.P2
        if name.startswith("ssh.") or name.startswith("desktop."):
            return RiskLevel.P3
        declared_risk = getattr(declared, "risk", RiskLevel.P2)
        try: return declared_risk if isinstance(declared_risk, RiskLevel) else RiskLevel(str(declared_risk))
        except ValueError: return RiskLevel.P4

    @staticmethod
    def _is_offline_browser(declared: ToolSpec | Any | None) -> bool:
        return getattr(declared, "capability", None) == "browser.fake.offline"

    @staticmethod
    def _is_offline_ssh(declared: ToolSpec | Any | None) -> bool:
        return getattr(declared, "capability", None) == "ssh.fake.offline"

    def _ssh_target_binding(self, arguments: Mapping[str, Any]) -> dict[str, Any] | None:
        """Resolve immutable SSH target evidence for approval/action hashing.

        The model supplies only ``host_id``.  Hostname, port, username and
        trust material come from the authenticated configuration, and the
        known_hosts bytes are hashed on every policy evaluation.  The execute
        phase therefore invalidates an earlier approval if either the target
        configuration or trust file changes in the meantime.
        """

        host_id = arguments.get("host_id")
        if not isinstance(host_id, str):
            return None
        configured = next(
            (
                item
                for item in self.config.security.authorized_ssh_hosts
                if item.host_id == host_id
            ),
            None,
        )
        if configured is None:
            return None
        if configured.known_hosts is None:
            raise ValueError("strict known_hosts file is required")
        known_hosts = configured.known_hosts.expanduser()
        if not known_hosts.is_absolute():
            known_hosts = self.config.security.authorized_roots[0] / known_hosts
        if known_hosts.is_symlink():
            raise ValueError("strict known_hosts cannot be a symbolic link")
        known_hosts = known_hosts.resolve(strict=True)
        if not known_hosts.is_file():
            raise ValueError("strict known_hosts file is required")
        trust_bytes = known_hosts.read_bytes()
        fingerprint = configured.host_key_fingerprint.strip()
        if fingerprint.lower().startswith("sha256:"):
            fingerprint = "sha256:" + fingerprint[7:].rstrip("=")
        hostname = configured.hostname
        destination_host = f"[{hostname}]" if ":" in hostname else hostname
        return {
            "host_id": configured.host_id,
            "hostname": hostname,
            "port": configured.port,
            "user": configured.user,
            "configured_fingerprint": fingerprint,
            "known_hosts_path": str(known_hosts),
            "known_hosts_sha256": sha256_hex(trust_bytes),
            "network_destination": f"ssh://{destination_host}:{configured.port}",
        }

    def normalize(self, tool: str, arguments: Mapping[str, Any], *, host: str = "local", cwd: str | None = None) -> dict[str, Any]:
        data: dict[str, Any] = {"tool": tool, "arguments": redact_secrets(dict(arguments)), "host": host, "cwd": cwd}
        if cwd is not None:
            checked_cwd = canonicalize_authorized_path(cwd, self.config.security.authorized_roots, must_exist=True, reject_unc=self.config.security.reject_unc_paths)
            data["cwd"] = str(checked_cwd.resolved)
        # Bind concrete paths to canonical authorized roots in the action hash.
        path_keys = {"path", "source", "destination"}
        paths: list[str] = []
        for key in path_keys:
            value = arguments.get(key)
            if isinstance(value, str):
                checked = canonicalize_authorized_path(value, self.config.security.authorized_roots, cwd=cwd, must_exist=(key in {"path", "source"} and tool not in {"fs.mkdir", "fs.apply_patch", "fs.delete"}), reject_unc=self.config.security.reject_unc_paths)
                data["arguments"][key] = str(checked.resolved)
                paths.append(str(checked.resolved))
        if tool in {"mcp.invoke", "plugin.invoke"} and isinstance(arguments.get("arguments"), Mapping):
            nested = dict(arguments["arguments"])
            for key in path_keys | {"cwd"}:
                value = nested.get(key)
                if isinstance(value, str):
                    checked = canonicalize_authorized_path(
                        value,
                        self.config.security.authorized_roots,
                        cwd=cwd,
                        must_exist=key in {"source", "cwd"},
                        reject_unc=self.config.security.reject_unc_paths,
                    )
                    nested[key] = str(checked.resolved)
                    paths.append(str(checked.resolved))
            data["arguments"]["arguments"] = nested
        if tool == "browser.download":
            name = arguments.get("name")
            if not isinstance(name, str) or not name or name != Path(name).name:
                raise ValueError("browser download name must be one plain filename")
            download_dir = self.config.security.browser.download_dir
            if download_dir is None:
                raise ValueError("browser download directory is not configured")
            checked = canonicalize_authorized_path(
                download_dir / name,
                self.config.security.authorized_roots,
                must_exist=False,
                reject_unc=self.config.security.reject_unc_paths,
            )
            data["arguments"]["destination"] = str(checked.resolved)
            paths.append(str(checked.resolved))
        if tool == "fs.apply_patch" and isinstance(arguments.get("patch"), str):
            # Bind every concrete patch target into the approval hash.  The
            # patch text is model-controlled data, so malformed/escaping
            # targets fail closed here rather than being trusted by the
            # executor later.
            patch_paths: list[str] = []
            for line in str(arguments["patch"]).splitlines():
                match = re.match(r"^\*\*\*\s+(?:Update|Add|Delete) File:\s*(.+?)\s*$", line)
                if match is None:
                    continue
                checked = canonicalize_authorized_path(
                    match.group(1),
                    self.config.security.authorized_roots,
                    cwd=cwd,
                    must_exist=False,
                    reject_unc=self.config.security.reject_unc_paths,
                )
                patch_paths.append(str(checked.resolved))
            if patch_paths:
                data["patch_paths"] = patch_paths
                paths.extend(patch_paths)
        if paths: data["real_paths"] = paths
        if tool.startswith("ssh."):
            ssh_target = self._ssh_target_binding(arguments)
            if ssh_target is not None:
                data["ssh_target"] = ssh_target
        return normalize_action(data)

    def evaluate(self, tool: str, arguments: Mapping[str, Any], *, host: str = "local", cwd: str | None = None, declared: ToolSpec | Any | None = None, purpose: str | None = None) -> PolicyDecision:
        normalized = self.normalize(tool, arguments, host=host, cwd=cwd)
        digest = action_hash(normalized); risk = self.classify(tool, arguments, declared)
        if contains_probable_secret(arguments):
            return PolicyDecision("deny", RiskLevel.P4, "secret-looking material must use a secret reference", normalized, digest)
        if tool.startswith("fs."):
            for path in normalized.get("real_paths", []):
                reason = protected_path_reason(path, self.config.security.authorized_roots)
                if reason:
                    return PolicyDecision("deny", RiskLevel.P4, reason, normalized, digest)
        if self.storage is not None and self.storage.kill_switch_engaged():
            return PolicyDecision("deny", RiskLevel.P4, "global kill switch is engaged", normalized, digest)
        local_tools = tool.startswith(("fs.", "git.", "process.")) or tool == "shell.exec"
        if local_tools and host != "local":
            return PolicyDecision("deny", RiskLevel.P4, "local executor tools must use host=local", normalized, digest)
        if tool.startswith("ssh."):
            requested_host = arguments.get("host_id")
            if host == "local" or requested_host != host:
                return PolicyDecision("deny", RiskLevel.P4, "SSH tool host and host_id must bind exactly", normalized, digest)
        if host != "local":
            allowed = {item.host_id for item in self.config.security.authorized_ssh_hosts}
            if host not in allowed:
                return PolicyDecision("deny", RiskLevel.P4, "SSH host is not in the explicit allowlist", normalized, digest)
        if tool.startswith("ssh.") and not self.config.security.authorized_ssh_hosts:
            return PolicyDecision("deny", RiskLevel.P4, "real SSH is disabled because AUTHORIZED_SSH_HOSTS is empty", normalized, digest)
        if tool.startswith("desktop."):
            reason = (
                "native desktop GUI is disabled"
                if not self.config.features.native_desktop_gui
                else "native desktop isolation and emergency stop are not verified"
            )
            return PolicyDecision("deny", max(risk, RiskLevel.P3, key=lambda item: item.rank), reason, normalized, digest)
        if tool.startswith("browser."):
            if not self.config.features.browser_automation or not self.config.security.browser.enabled:
                return PolicyDecision("deny", max(risk, RiskLevel.P2, key=lambda item: item.rank), "browser automation is disabled", normalized, digest)
            if not self._is_offline_browser(declared) and not (
                self.runtime_capabilities.browser_profile_isolated
                and self.runtime_capabilities.browser_network_policy_enforced
            ):
                return PolicyDecision(
                    "deny",
                    max(risk, RiskLevel.P2, key=lambda item: item.rank),
                    "live browser network/profile isolation is not verified",
                    normalized,
                    digest,
                )
            if not self.config.security.browser.allowed_domains:
                return PolicyDecision("deny", RiskLevel.P2, "browser domain allowlist is empty", normalized, digest)
            if tool == "browser.open":
                from .tools.browser import BrowserSecurityError, BrowserURLPolicy

                try:
                    BrowserURLPolicy(
                        self.config.security.browser.allowed_domains,
                        max_redirects=self.config.security.browser.max_redirects,
                    ).validate(str(arguments.get("url", "")))
                except BrowserSecurityError as exc:
                    return PolicyDecision("deny", RiskLevel.P4, str(exc), normalized, digest)
        if tool in {"mcp.invoke", "plugin.invoke"}:
            settings = self.config.security.extensions
            enabled = settings.mcp_enabled if tool == "mcp.invoke" else settings.plugins_enabled
            pins = settings.mcp_pins if tool == "mcp.invoke" else settings.plugin_pins
            if not enabled:
                return PolicyDecision("deny", RiskLevel.P2, f"{tool.split('.')[0]} extensions are disabled", normalized, digest)
            extension_id = arguments.get("extension_id")
            if not isinstance(extension_id, str) or extension_id not in {pin.extension_id for pin in pins}:
                return PolicyDecision("deny", RiskLevel.P4, "extension is absent from the exact allowlist", normalized, digest)
        if tool == "git.push" or (tool.startswith("ssh.") and not self._is_offline_ssh(declared)):
            return PolicyDecision(
                "deny",
                max(risk, RiskLevel.P3, key=lambda item: item.rank),
                "network egress is not backed by a verified allowlist adapter",
                normalized,
                digest,
            )
        if tool in {"process.exec", "shell.exec", "process.start"}:
            risk, process_denial = self._process_command_policy(tool, arguments)
            if process_denial is not None:
                return PolicyDecision("deny", RiskLevel.P4, process_denial, normalized, digest)
            if not self.runtime_capabilities.process_sandbox_enforced:
                return PolicyDecision(
                    "deny",
                    max(risk, RiskLevel.P2, key=lambda item: item.rank),
                    "no runtime-attested process sandbox is available; approval cannot replace the boundary",
                    normalized,
                    digest,
                )
            if not self.runtime_capabilities.process_network_policy_enforced:
                return PolicyDecision(
                    "deny",
                    max(risk, RiskLevel.P2, key=lambda item: item.rank),
                    "the configured process network policy is not runtime-attested; approval cannot grant host networking",
                    normalized,
                    digest,
                )
        if self.config.execution_mode.value == "read_only" and risk is not RiskLevel.P0:
            return PolicyDecision("deny", max(risk, RiskLevel.P1, key=lambda item: item.rank), "execution_mode=read_only blocks side effects", normalized, digest)
        if risk is RiskLevel.P4:
            return PolicyDecision("deny", risk, "P4 actions are denied by default", normalized, digest)
        if risk is RiskLevel.P0:
            return PolicyDecision("allow", risk, "local read-only operation", normalized, digest)
        approval = self._approval_request(tool, arguments, normalized, digest, risk, host, cwd, purpose, declared)
        return PolicyDecision("approval_required", risk, "side effect or boundary crossing requires exact approval", normalized, digest, approval)

    def _approval_request(
        self,
        tool: str,
        arguments: Mapping[str, Any],
        normalized: dict[str, Any],
        digest: str,
        risk: RiskLevel,
        host: str,
        cwd: str | None,
        purpose: str | None,
        declared: ToolSpec | Any | None,
    ) -> ApprovalRequest:
        del arguments
        now = utc_now(); ttl = timedelta(seconds=self.config.security.approval_ttl_seconds)
        declared_effects = getattr(declared, "side_effects", ())
        canonical_cwd = normalized.get("cwd") if isinstance(normalized.get("cwd"), str) else cwd
        normalized_arguments = normalized.get("arguments")
        ssh_target = normalized.get("ssh_target")
        if not isinstance(ssh_target, Mapping):
            ssh_target = {}
        diff_hash = (
            sha256_hex(str(normalized_arguments.get("patch")))
            if tool == "fs.apply_patch" and isinstance(normalized_arguments, Mapping) and "patch" in normalized_arguments
            else None
        )
        return ApprovalRequest(
            action_id=new_id("action"),
            tool=tool,
            risk=risk,
            purpose=purpose or f"execute {tool}",
            normalized_action=normalized,
            action_hash=digest,
            nonce=generate_nonce(),
            host=host,
            port=(
                int(ssh_target["port"])
                if isinstance(ssh_target.get("port"), int)
                else None
            ),
            user=(
                str(ssh_target["user"])
                if isinstance(ssh_target.get("user"), str)
                else None
            ),
            host_fingerprint=(
                str(ssh_target["configured_fingerprint"])
                if isinstance(ssh_target.get("configured_fingerprint"), str)
                else None
            ),
            cwd=canonical_cwd,
            real_paths=list(normalized.get("real_paths", [])),
            diff_hash=diff_hash,
            network_destination=(
                str(ssh_target["network_destination"])
                if isinstance(ssh_target.get("network_destination"), str)
                else None
            ),
            side_effects=list(declared_effects),
            validation="runtime result and diff",
            backup="not automatic; preserve the pre-action hash and diff before applying",
            rollback="user-controlled workspace backup where applicable",
            expires_at=now + ttl,
        )

    def persist_request(self, request: ApprovalRequest) -> ApprovalRequest:
        if self.storage is not None: self.storage.save_approval(request)
        return request

    def verify_decision(self, request: ApprovalRequest, decision: ApprovalDecision | Mapping[str, Any]) -> bool:
        item = decision if isinstance(decision, ApprovalDecision) else ApprovalDecision.model_validate(decision)
        if item.approval_id != request.approval_id or item.action_id != request.action_id or not secure_equal(item.action_hash, request.action_hash) or not secure_equal(item.nonce, request.nonce): return False
        if datetime.now(UTC) >= request.expires_at: return False
        if self.storage is not None:
            try: current = self.storage.get_approval(request.approval_id)
            except KeyError: return False
            if current.get("status") not in {ApprovalStatus.PENDING.value, ApprovalStatus.APPROVED.value}: return False
        # Binding validity is independent from the user's yes/no choice.  A
        # valid denial must still be persisted as DENIED so it cannot be
        # silently retried as a pending approval.
        return True

    def approve(self, request: ApprovalRequest, *, actor: str = "authenticated_user") -> ApprovalDecision:
        decision = ApprovalDecision(approval_id=request.approval_id, action_id=request.action_id, action_hash=request.action_hash, nonce=request.nonce, approved=True, actor=actor)
        if self.storage is not None: self.storage.update_approval_status(request.approval_id, ApprovalStatus.APPROVED)
        return decision

    def consume(self, request: ApprovalRequest) -> None:
        if self.storage is not None: self.storage.update_approval_status(request.approval_id, ApprovalStatus.CONSUMED)


__all__ = ["PolicyDecision", "PolicyEngine"]
