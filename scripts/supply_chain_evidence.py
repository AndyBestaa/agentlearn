"""Generate commit-bound SBOM and vulnerability evidence for AsterCode's image.

The default mode is offline: it uses only the local Docker daemon and an
already-present Trivy database.  ``--update-trivy-db`` is the sole networked
phase; this helper never signs, publishes, pulls the target image, or guesses a
Cosign trust identity.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from astercode.config import validate_strict_workspace_root
from astercode.supply_chain import generate_supply_chain_evidence


def _inside_root(root: Path, value: Path | None) -> Path | None:
    if value is None or value.is_absolute():
        return value
    return root / value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--config", type=Path, help="Explicit AsterCode TOML inside the project root")
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Directory below .astercode/artifacts (default: .astercode/artifacts/supply-chain)",
    )
    parser.add_argument(
        "--update-trivy-db",
        action="store_true",
        help="Explicitly allow Trivy to download/update its vulnerability DB before the offline scan",
    )
    parser.add_argument("--max-db-age-hours", type=float, default=48.0)
    parser.add_argument("--timeout-seconds", type=float, default=600.0)
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="Development-only: generate evidence while recording working_tree_clean=false",
    )
    parser.add_argument(
        "--allow-unverified-signature",
        action="store_true",
        help="Development-only: permit partial evidence without Cosign trust verification",
    )
    args = parser.parse_args()
    if args.max_db_age_hours <= 0 or args.max_db_age_hours > 720:
        parser.error("--max-db-age-hours must be within (0, 720]")
    if args.timeout_seconds <= 0 or args.timeout_seconds > 3_600:
        parser.error("--timeout-seconds must be within (0, 3600]")

    try:
        root = validate_strict_workspace_root(args.root)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    config = _inside_root(root, args.config)
    output = _inside_root(root, args.output_dir)
    if args.update_trivy_db:
        print(
            "Trivy DB update explicitly enabled; target image remains local and no signing/publishing is performed.",
            flush=True,
        )
    try:
        result = generate_supply_chain_evidence(
            root,
            config_file=config,
            output_directory=output,
            update_trivy_db=args.update_trivy_db,
            max_db_age_hours=args.max_db_age_hours,
            timeout_seconds=args.timeout_seconds,
            allow_dirty=args.allow_dirty,
            allow_unverified_signature=args.allow_unverified_signature,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"AsterCode supply-chain evidence: BLOCKED ({exc})", file=sys.stderr)
        return 2

    summary = {
        "overall_status": result.manifest.overall_status,
        "target_commit": result.manifest.target_commit,
        "working_tree_clean": result.manifest.working_tree_clean,
        "claims": result.manifest.claims.model_dump(mode="json"),
        "manifest": str(result.manifest_path),
        "checksums": str(result.checksums_path),
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2), flush=True)
    if not result.manifest.claims.signature_verified:
        print("Cosign signature: NOT VERIFIED (no approved trust policy was supplied)", flush=True)
    return result.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
