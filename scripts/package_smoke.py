"""Install the built wheel offline and smoke-test only packaged artifacts.

The regular ``uv sync`` CI step has already populated uv's platform-specific
cache.  This script creates a genuinely fresh virtual environment, materializes
the locked runtime dependencies there from ``uv.lock`` without installing the
source project, and then installs the local wheel without dependency resolution.
Every install step is offline.  It never contacts a model provider or SSH host.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def _run(
    argv: list[str],
    *,
    env: dict[str, str] | None = None,
    cwd: Path | None = None,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    print("+", subprocess.list2cmdline(argv), flush=True)
    return subprocess.run(
        argv,
        check=True,
        env=env,
        cwd=cwd,
        input=input_text,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def _run_offline_with_windows_retry(
    argv: list[str], *, env: dict[str, str]
) -> None:
    """Retry one replay-safe offline operation only for a Windows file lock."""

    transient_markers = (
        "access is denied",
        "sharing violation",
        "os error -2147024891",
        "os error -2147024864",
        "拒绝访问",
    )
    for attempt in range(2):
        print("+", subprocess.list2cmdline(argv), flush=True)
        completed = subprocess.run(
            argv,
            check=False,
            env=env,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
        )
        if completed.stdout:
            sys.stdout.write(completed.stdout)
        if completed.stderr:
            sys.stderr.write(completed.stderr)
        if completed.returncode == 0:
            return
        combined = f"{completed.stdout}\n{completed.stderr}".lower()
        transient = os.name == "nt" and any(
            marker in combined for marker in transient_markers
        )
        if attempt == 0 and transient:
            print("transient Windows cache/file lock; retrying offline operation once", flush=True)
            time.sleep(0.5)
            continue
        raise subprocess.CalledProcessError(
            completed.returncode,
            argv,
            output=completed.stdout,
            stderr=completed.stderr,
        )


def _sync_locked_runtime_dependencies(
    uv: str,
    *,
    root: Path,
    venv: Path,
    env: dict[str, str],
) -> None:
    """Populate a fresh environment from the lock without installing AsterCode."""

    sync_env = dict(env)
    sync_env["VIRTUAL_ENV"] = str(venv)
    _run_offline_with_windows_retry(
        [
            uv,
            "sync",
            "--directory",
            str(root),
            "--active",
            "--offline",
            "--frozen",
            "--no-dev",
            "--no-install-project",
        ],
        env=sync_env,
    )


def _clean_environment() -> dict[str, str]:
    env = dict(os.environ)
    for key in tuple(env):
        if key.startswith("ASTERCODE_") or key in {
            "DEEPSEEK_API_KEY",
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "ANTHROPIC_AUTH_TOKEN",
        }:
            env.pop(key, None)
    # Copying is slower than linking but avoids intermittent cache hard-link
    # access failures on Windows hosts with real-time file scanning enabled.
    env["UV_LINK_MODE"] = "copy"
    return env


def _wheel(root: Path) -> Path:
    wheels = sorted((root / "dist").glob("astercode-*.whl"))
    if len(wheels) != 1:
        raise RuntimeError(f"expected exactly one AsterCode wheel in dist, found {len(wheels)}")
    return wheels[0].resolve()


def _entrypoint(venv: Path, name: str) -> Path:
    candidate = venv / (f"Scripts/{name}.exe" if os.name == "nt" else f"bin/{name}")
    if not candidate.is_file():
        raise RuntimeError(f"wheel did not install the {name} entrypoint: {candidate}")
    return candidate


def _python(venv: Path) -> Path:
    return venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def _write_fake_config(project: Path) -> Path:
    root = project.resolve().as_posix()
    config = project / "config.toml"
    config.write_text(
        "\n".join(
            (
                "config_version = 1",
                'product_name = "AsterCode CI package smoke"',
                f'project_root = "{root}"',
                "",
                "[model]",
                'provider = "fake"',
                "",
                "[security]",
                'network_mode = "deny_by_default"',
                f'authorized_roots = ["{root}"]',
                "",
            )
        ),
        encoding="utf-8",
        newline="\n",
    )
    return config


def _verify_packaged_prompt(python: Path, source_prompt: Path, env: dict[str, str]) -> None:
    expected_hash = hashlib.sha256(source_prompt.read_bytes()).hexdigest()
    check = (
        "import hashlib, pathlib, sys; "
        "import astercode; "
        "from astercode.provider import OpenAIAgentsProvider; "
        "package_dir=pathlib.Path(astercode.__file__).resolve().parent; "
        "prompt=OpenAIAgentsProvider._default_prompt_path().resolve(); "
        "assert prompt.parent == package_dir, (prompt, package_dir); "
        "actual=hashlib.sha256(prompt.read_bytes()).hexdigest(); "
        "assert actual == sys.argv[1], (actual, sys.argv[1]); "
        "print(f'packaged prompt exact: {actual}')"
    )
    _run([str(python), "-c", check, expected_hash], env=env)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    root = args.root.resolve()
    wheel = _wheel(root)
    uv = shutil.which("uv")
    if uv is None:
        raise RuntimeError("uv is required for the package smoke")
    clean_env = _clean_environment()

    with tempfile.TemporaryDirectory(prefix="astercode-package-smoke-") as temporary:
        workspace = Path(temporary)
        venv = workspace / "venv"
        project = workspace / "project"
        project.mkdir()

        _run([uv, "venv", "--python", "3.12", "--clear", str(venv)], env=clean_env)
        python = _python(venv)
        _sync_locked_runtime_dependencies(
            uv,
            root=root,
            venv=venv,
            env=clean_env,
        )
        _run_offline_with_windows_retry(
            [
                uv,
                "pip",
                "install",
                "--python",
                str(python),
                "--offline",
                "--no-deps",
                str(wheel),
            ],
            env=clean_env,
        )
        _run([uv, "pip", "check", "--python", str(python)], env=clean_env)

        astercode = _entrypoint(venv, "astercode")
        aster = _entrypoint(venv, "aster")
        _run([str(astercode), "--help"], env=clean_env)
        _run([str(aster), "--help"], env=clean_env)
        config = _write_fake_config(project)
        _run(
            [
                str(astercode),
                "config",
                "validate",
                "--root",
                str(project),
                "--file",
                str(config),
            ],
            env=clean_env,
        )
        (project / ".astercode").mkdir()
        _run([str(aster)], env=clean_env, cwd=project, input_text="/exit\n")
        _verify_packaged_prompt(
            python,
            root / "prompts" / "coding_agent.md",
            clean_env,
        )

    print(f"package smoke passed: {wheel.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
