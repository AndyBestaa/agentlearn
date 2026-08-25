from __future__ import annotations

import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from typer.testing import CliRunner

from astercode import cli
from astercode.supply_chain import (
    CommandEvidence,
    SupplyChainClaims,
    ToolSnapshot,
    _configured_image_from_file,
    _database_evidence,
    _discover_supply_config,
    _parse_spdx_report,
    _parse_syft_report,
    _parse_trivy_report,
    _run_logged,
    _tool_environment,
    generate_supply_chain_evidence,
)


def test_tool_environment_drops_credentials_proxies_and_tool_overrides(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    for key, value in {
        "OPENAI_API_KEY": "secret",
        "DEEPSEEK_API_KEY": "secret",
        "HTTP_PROXY": "http://attacker.invalid",
        "DOCKER_HOST": "tcp://attacker.invalid:2375",
        "TRIVY_DB_REPOSITORY": "attacker.invalid/db",
        "SYFT_CONFIG": str(tmp_path / "attacker.yaml"),
        "SystemRoot": str(tmp_path / "attacker-system-root"),
    }.items():
        monkeypatch.setenv(key, value)

    environment = _tool_environment(tmp_path / "control")

    for key in (
        "OPENAI_API_KEY",
        "DEEPSEEK_API_KEY",
        "HTTP_PROXY",
        "DOCKER_HOST",
        "TRIVY_DB_REPOSITORY",
        "SYFT_CONFIG",
    ):
        assert key not in environment
    assert environment["PATH"] == ""
    assert environment["SYFT_CHECK_FOR_APP_UPDATE"] == "false"
    assert Path(environment["TEMP"]).parent == tmp_path / "control"
    assert Path(environment["TMP"]) == Path(environment["TEMP"])
    if sys.platform == "win32":
        assert environment.get("SystemRoot") != str(tmp_path / "attacker-system-root")


def test_logged_command_preserves_argv_and_separates_streams(tmp_path: Path) -> None:
    run_directory = tmp_path / "run"
    run_directory.mkdir()
    control = run_directory / "control"
    environment = _tool_environment(control)
    marker = "value;$(must-not-execute)"

    evidence = _run_logged(
        run_directory,
        "argv-smoke",
        [
            sys.executable,
            "-c",
            "import sys; print(sys.argv[1]); print('err', file=sys.stderr)",
            marker,
        ],
        environment=environment,
        cwd=run_directory,
        timeout=10,
    )

    assert evidence.exit_code == 0
    assert marker in (run_directory / evidence.stdout_log).read_text(encoding="utf-8")
    assert (run_directory / evidence.stderr_log).read_text(encoding="utf-8").strip() == "err"


def test_logged_command_timeout_is_bounded(tmp_path: Path) -> None:
    run_directory = tmp_path / "run"
    run_directory.mkdir()
    environment = _tool_environment(run_directory / "control")
    evidence = _run_logged(
        run_directory,
        "timeout-smoke",
        [sys.executable, "-c", "import time; time.sleep(10)"],
        environment=environment,
        cwd=run_directory,
        timeout=0.05,
    )
    assert evidence.exit_code is not None
    assert evidence.error and "exceeded" in evidence.error


def test_syft_report_requires_exact_digest_binding() -> None:
    digest = "sha256:" + "a" * 64
    payload = {"artifacts": [{"name": "python"}], "source": {"type": "image", "version": digest}}

    assert _parse_syft_report(payload, digest) == (1, True)
    with pytest.raises(ValueError, match="expected image digest"):
        _parse_syft_report(payload, "sha256:" + "b" * 64)
    with pytest.raises(ValueError, match="expected image digest"):
        _parse_syft_report(
            {
                "artifacts": [{"name": "python"}],
                "source": {
                    "type": "image",
                    "version": "not-the-digest",
                    "metadata": {"note": digest},
                },
            },
            digest,
        )


def test_trivy_report_counts_policy_severities_and_requires_image_binding() -> None:
    digest = "sha256:" + "a" * 64
    image_id = "sha256:" + "b" * 64
    payload = {
        "SchemaVersion": 2,
        "ArtifactType": "container_image",
        "ArtifactName": f"example.invalid/python@{digest}",
        "ArtifactID": image_id,
        "Metadata": {
            "ImageID": image_id,
            "RepoDigests": [f"example.invalid/python@{digest}"],
            "OS": {"EOSL": False},
        },
        "Results": [
            {
                "Vulnerabilities": [
                    {"Severity": "HIGH"},
                    {"Severity": "medium"},
                    {"Severity": "UNKNOWN"},
                ]
            }
        ],
    }

    counts, os_eol, bound = _parse_trivy_report(
        payload,
        expected_digest=digest,
        expected_image_id=image_id,
    )

    assert counts == {"UNKNOWN": 1, "LOW": 0, "MEDIUM": 1, "HIGH": 1, "CRITICAL": 0}
    assert os_eol is False
    assert bound is True
    with pytest.raises(ValueError, match="expected image digest"):
        _parse_trivy_report(
            payload,
            expected_digest="sha256:" + "c" * 64,
            expected_image_id="sha256:" + "d" * 64,
        )
    with pytest.raises(ValueError, match="malformed entry"):
        _parse_trivy_report(
            {**payload, "Results": ["malformed"]},
            expected_digest=digest,
            expected_image_id=image_id,
        )
    with pytest.raises(ValueError, match="unknown vulnerability severity"):
        _parse_trivy_report(
            {
                **payload,
                "Results": [{"Vulnerabilities": [{"Severity": "unexpected"}]}],
            },
            expected_digest=digest,
            expected_image_id=image_id,
        )
    with pytest.raises(ValueError, match="missing or invalid"):
        _parse_trivy_report(
            payload,
            expected_digest=digest,
            expected_image_id="",
        )


def test_trivy_report_does_not_use_an_empty_id_or_substring_binding() -> None:
    digest = "sha256:" + "a" * 64
    payload = {
        "SchemaVersion": 2,
        "ArtifactType": "container_image",
        "ArtifactName": f"example.invalid/python@{digest}",
        "Metadata": {
            "ImageID": "sha256:" + "b" * 64,
            "RepoDigests": [f"example.invalid/python@{digest}"],
        },
        "Results": [{"Vulnerabilities": [{"Severity": "LOW"}]}],
    }
    with pytest.raises(ValueError, match="missing or invalid"):
        _parse_trivy_report(
            payload,
            expected_digest=digest,
            expected_image_id="",
        )
    with pytest.raises(ValueError, match="expected image digest"):
        _parse_trivy_report(
            {**payload, "ArtifactName": f"example.invalid/python@{digest}x"},
            expected_digest=digest,
            expected_image_id="sha256:" + "b" * 64,
        )


def test_supply_config_extracts_only_image_and_binds_default_discovery_to_root(
    tmp_path: Path,
) -> None:
    digest = "sha256:" + "e" * 64
    image = f"registry.example/python@{digest}"
    config = tmp_path / "astercode.toml"
    config.write_text(
        "\n".join(
            (
                "config_version=1",
                "product_name='AsterCode'",
                "[model]",
                "provider='fake'",
                "[security]",
                "network_mode='allowlist'",
                "authorized_roots=['C:/outside']",
                "[security.process]",
                f"container_image='{image}'",
            )
        ),
        encoding="utf-8",
    )
    assert _discover_supply_config(tmp_path) == config.resolve()
    assert _configured_image_from_file(config.resolve()) == image


def test_trivy_database_evidence_enforces_freshness(tmp_path: Path) -> None:
    metadata = tmp_path / "db" / "metadata.json"
    metadata.parent.mkdir()
    (metadata.parent / "trivy.db").write_bytes(b"deterministic trivy db")
    metadata.write_text(
        json.dumps(
            {
                "Version": 2,
                "UpdatedAt": (datetime.now(UTC) - timedelta(hours=1)).isoformat(),
                "DownloadedAt": (datetime.now(UTC) - timedelta(minutes=30)).isoformat(),
                "NextUpdate": (datetime.now(UTC) + timedelta(hours=12)).isoformat(),
            }
        ),
        encoding="utf-8",
    )

    fresh = _database_evidence(tmp_path, max_age_hours=48, update_command=None)
    assert fresh.status == "passed"
    assert fresh.age_hours is not None and fresh.age_hours < 2
    assert fresh.metadata_sha256 and fresh.database_sha256
    assert fresh.provenance_verified is False

    metadata.write_text(
        json.dumps(
            {
                "Version": 2,
                "UpdatedAt": (datetime.now(UTC) - timedelta(hours=72)).isoformat(),
                "DownloadedAt": (datetime.now(UTC) - timedelta(hours=71)).isoformat(),
                "NextUpdate": (datetime.now(UTC) + timedelta(hours=12)).isoformat(),
            }
        ),
        encoding="utf-8",
    )
    stale = _database_evidence(tmp_path, max_age_hours=48, update_command=None)
    assert stale.status == "blocked"
    assert "stale" in stale.reason


def test_trivy_database_optional_type_accepts_only_integer_one(tmp_path: Path) -> None:
    metadata = tmp_path / "db" / "metadata.json"
    metadata.parent.mkdir()
    (metadata.parent / "trivy.db").write_bytes(b"deterministic trivy db")
    base = {
        "Version": 2,
        "UpdatedAt": datetime.now(UTC).isoformat(),
        "DownloadedAt": datetime.now(UTC).isoformat(),
        "NextUpdate": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
    }

    for type_key, type_value, expected_status in (
        ("Type", 1, "passed"),
        ("type", 1, "passed"),
        ("Type", 2, "blocked"),
        ("Type", True, "blocked"),
    ):
        payload = dict(base)
        payload[type_key] = type_value
        metadata.write_text(json.dumps(payload), encoding="utf-8")
        evidence = _database_evidence(tmp_path, max_age_hours=48, update_command=None)
        assert evidence.status == expected_status
        if expected_status == "blocked":
            assert "Type=1" in evidence.reason


def test_trivy_database_requires_real_db_and_supported_metadata(tmp_path: Path) -> None:
    metadata = tmp_path / "db" / "metadata.json"
    metadata.parent.mkdir()
    metadata.write_text(
        json.dumps(
            {
                "Version": 1,
                "Type": 1,
                "UpdatedAt": datetime.now(UTC).isoformat(),
                "DownloadedAt": datetime.now(UTC).isoformat(),
                "NextUpdate": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
            }
        ),
        encoding="utf-8",
    )
    blocked = _database_evidence(tmp_path, max_age_hours=48, update_command=None)
    assert blocked.status == "blocked"
    assert "trivy.db" in blocked.reason


def test_spdx_report_requires_exact_reference_binding() -> None:
    digest = "sha256:" + "a" * 64
    reference = f"example.invalid/python@{digest}"
    payload = {"spdxVersion": "SPDX-2.3", "name": reference}
    assert _parse_spdx_report(
        payload, expected_digest=digest, expected_reference=reference
    ) is True
    with pytest.raises(ValueError, match="image reference"):
        _parse_spdx_report(
            {"spdxVersion": "SPDX-2.3", "name": "example.invalid/python"},
            expected_digest=digest,
            expected_reference=reference,
        )


def test_supply_chain_claims_remain_independent() -> None:
    claims = SupplyChainClaims(
        content_pinned=True,
        sbom_generated=True,
        vulnerability_policy_passed=True,
    )

    assert claims.content_pinned is True
    assert claims.sbom_generated is True
    assert claims.vulnerability_policy_passed is True
    assert claims.signature_verified is False


def test_supply_chain_cli_keeps_partial_evidence_nonzero(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """The public command must expose a blocked claim instead of hiding it."""

    calls: dict[str, Any] = {}

    def fake_generate(root: Path, **kwargs: Any) -> Any:
        calls["root"] = root
        calls["kwargs"] = kwargs
        return SimpleNamespace(
            manifest=SimpleNamespace(
                overall_status="blocked",
                target_commit="a" * 40,
                working_tree_clean=False,
                claims=SimpleNamespace(
                    model_dump=lambda mode="json": {
                        "content_pinned": True,
                        "sbom_generated": True,
                        "vulnerability_policy_passed": False,
                        "signature_verified": False,
                    }
                ),
            ),
            manifest_path=tmp_path / "manifest.json",
            checksums_path=tmp_path / "SHA256SUMS",
            exit_code=2,
        )

    monkeypatch.setattr("astercode.supply_chain.generate_supply_chain_evidence", fake_generate)
    result = CliRunner().invoke(
        cli.app,
        [
            "supply-chain",
            "verify",
            "--root",
            str(tmp_path),
            "--allow-dirty",
            "--allow-unverified-signature",
        ],
    )

    assert result.exit_code == 2, result.output
    assert calls["root"] == tmp_path.resolve()
    assert calls["kwargs"]["allow_dirty"] is True
    assert calls["kwargs"]["allow_unverified_signature"] is True
    assert '"overall_status": "blocked"' in result.output
    assert "NOT VERIFIED" in result.output


def test_generate_evidence_requires_clean_target_unless_development_override(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr("astercode.supply_chain._git_facts", lambda _root: ("c" * 40, False))

    with pytest.raises(RuntimeError, match="working tree is dirty"):
        generate_supply_chain_evidence(tmp_path)


def test_generate_evidence_keeps_signature_unverified_and_hashes_artifacts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    commit = "c" * 40
    digest = "sha256:2c941e860699f878900b0edc2403613c234d4b32eda3cc9fa7036991a2a63c4a"
    image = f"mirror.gcr.io/library/python@{digest}"
    image_id = "sha256:" + "b" * 64
    metadata = tmp_path / ".astercode" / "cache" / "trivy" / "db" / "metadata.json"
    metadata.parent.mkdir(parents=True)
    (metadata.parent / "trivy.db").write_bytes(b"fake trivy db")
    metadata.write_text(
        json.dumps(
            {
                "Version": 2,
                "UpdatedAt": datetime.now(UTC).isoformat(),
                "DownloadedAt": datetime.now(UTC).isoformat(),
                "NextUpdate": (datetime.now(UTC) + timedelta(hours=12)).isoformat(),
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr("astercode.supply_chain._git_facts", lambda _root: (commit, True))
    monkeypatch.setattr("astercode.supply_chain.discover_trusted_docker", lambda: Path("docker"))
    monkeypatch.setattr("astercode.supply_chain._resolve_local_image", lambda _docker, _image: (image, image_id))

    def fake_snapshot(
        _run_directory: Path,
        name: str,
        **_kwargs: Any,
    ) -> ToolSnapshot:
        return ToolSnapshot(
            detected=True,
            executable=name,
            binary_sha256="d" * 64,
            version=f"{name} test",
        )

    def fake_run(
        run_directory: Path,
        label: str,
        argv: list[str],
        **_kwargs: Any,
    ) -> CommandEvidence:
        logs = run_directory / "logs"
        logs.mkdir(exist_ok=True)
        stdout = logs / f"{label}.stdout.txt"
        stderr = logs / f"{label}.stderr.txt"
        stdout.write_text("", encoding="utf-8")
        stderr.write_text("", encoding="utf-8")
        if label == "syft-sbom":
            outputs = [
                Path(value.split("=", 1)[1])
                for value in argv
                if value.startswith(("syft-json=", "spdx-json="))
            ]
            outputs[0].write_text(
                json.dumps(
                    {
                        "artifacts": [{"name": "python"}],
                        "source": {"type": "image", "version": digest},
                    }
                ),
                encoding="utf-8",
            )
            outputs[1].write_text(
                json.dumps({"spdxVersion": "SPDX-2.3", "name": image}),
                encoding="utf-8",
            )
        elif label == "trivy-scan":
            output = Path(argv[argv.index("--output") + 1])
            output.write_text(
                json.dumps(
                    {
                        "SchemaVersion": 2,
                        "ArtifactType": "container_image",
                        "ArtifactName": image,
                        "ArtifactID": image_id,
                        "Metadata": {
                            "ImageID": image_id,
                            "RepoDigests": [image],
                            "OS": {"EOSL": False},
                        },
                        "Results": [{"Vulnerabilities": []}],
                    }
                ),
                encoding="utf-8",
            )
        return CommandEvidence(
            argv=argv,
            exit_code=0,
            elapsed_seconds=0.01,
            stdout_log=stdout.relative_to(run_directory).as_posix(),
            stderr_log=stderr.relative_to(run_directory).as_posix(),
        )

    monkeypatch.setattr("astercode.supply_chain._snapshot_tool", fake_snapshot)
    monkeypatch.setattr("astercode.supply_chain._run_logged", fake_run)

    result = generate_supply_chain_evidence(tmp_path)

    assert result.exit_code == 2
    assert result.manifest.overall_status == "blocked"
    assert result.manifest.claims.content_pinned is True
    assert result.manifest.claims.sbom_generated is True
    assert result.manifest.claims.vulnerability_policy_passed is False
    assert result.manifest.claims.signature_verified is False
    assert result.manifest_path.is_file()
    checksums = result.checksums_path.read_text(encoding="utf-8")
    assert "manifest.json" in checksums
    assert "sbom.spdx.json" in checksums
    assert "trivy.json" in checksums
