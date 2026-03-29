#!/usr/bin/env python3
"""Daily orchestrator for opencode-ai safety investigation.

Checks for new opencode-ai releases, runs the Docker investigation,
generates an SBOM and safety report, and saves versioned results.

Usage:
    uv run python orchestrator.py            # only runs if new version found
    uv run python orchestrator.py --force    # always run
    uv run python orchestrator.py --update-baseline  # promote latest sbom to baseline
"""

import asyncio
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import httpx

PROJECT_ROOT = Path(__file__).parent.resolve()
STATE_DIR = PROJECT_ROOT / "state"
OUTPUT_DIR = PROJECT_ROOT / "output"
API_ENV = PROJECT_ROOT / "api.env"
PERSISTENT_BASELINE = OUTPUT_DIR / "sbom_baseline.json"


# ── Version tracking ──────────────────────────────────────────────────────────


async def get_latest_version() -> str:
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get("https://registry.npmjs.org/opencode-ai/latest")
        resp.raise_for_status()
        return resp.json()["version"]


def load_last_version() -> str | None:
    path = STATE_DIR / "last_version.txt"
    if path.exists():
        v = path.read_text().strip()
        return v or None
    return None


def save_last_version(version: str) -> None:
    STATE_DIR.mkdir(exist_ok=True)
    (STATE_DIR / "last_version.txt").write_text(version + "\n")


# ── Credentials ───────────────────────────────────────────────────────────────


def load_api_env() -> dict[str, str]:
    """Parse api.env key=value file into a dict."""
    env: dict[str, str] = {}
    if not API_ENV.exists():
        return env
    for line in API_ENV.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            env[key.strip()] = value.strip().strip('"').strip("'")
    return env


# ── Docker ────────────────────────────────────────────────────────────────────


def docker_available() -> bool:
    result = subprocess.run(
        ["docker", "info"], capture_output=True, timeout=10
    )
    return result.returncode == 0


def docker_build(api_env: dict[str, str]) -> None:
    print("[orchestrator] Building Docker image...")
    cmd = [
        "docker", "build",
        "--build-arg", f"MY_LLM_BASE_URL={api_env.get('MY_LLM_BASE_URL', '')}",
        "--build-arg", f"MY_LLM_API_KEY={api_env.get('MY_LLM_API_KEY', '')}",
        "--build-arg", f"MY_LLM_MODEL_NAME={api_env.get('MY_LLM_MODEL_NAME', '')}",
        "-t", "opencode-investigation",
        str(PROJECT_ROOT),
    ]
    subprocess.run(cmd, check=True, cwd=PROJECT_ROOT)


def docker_run(run_output_dir: Path) -> None:
    print(f"[orchestrator] Running investigation container (output → {run_output_dir})...")
    run_output_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{run_output_dir}:/output",
        "opencode-investigation",
    ]
    subprocess.run(cmd, check=True)


# ── Analysis ──────────────────────────────────────────────────────────────────


def run_sbom(run_output_dir: Path) -> int:
    """Run SBOM generator on host against the versioned output dir.

    Uses the persistent cross-version baseline for comparison.
    Returns the exit code (1 = ALERT findings present).
    """
    print("[orchestrator] Running SBOM analysis (host-side, persistent baseline)...")
    env = os.environ.copy()
    env["URL_LOG_FILE"] = str(run_output_dir / "urls.log")
    env["SBOM_OUTPUT"] = str(run_output_dir / "sbom.json")
    env["SBOM_BASELINE"] = str(PERSISTENT_BASELINE)

    result = subprocess.run(
        ["uv", "run", "python", "sbom_generator.py"],
        env=env,
        cwd=PROJECT_ROOT,
    )
    return result.returncode


def run_report_generator(version: str, run_output_dir: Path) -> Path:
    """Generate the markdown safety report. Returns the report path."""
    report_path = run_output_dir / "report.md"
    print(f"[orchestrator] Generating safety report → {report_path}")
    env = os.environ.copy()
    env["OPENCODE_VERSION"] = version
    env["RUN_OUTPUT_DIR"] = str(run_output_dir)
    env["REPORT_OUTPUT"] = str(report_path)

    subprocess.run(
        ["uv", "run", "python", "report_generator.py"],
        env=env,
        cwd=PROJECT_ROOT,
        check=True,
    )
    return report_path


# ── Baseline management ───────────────────────────────────────────────────────


def update_baseline(run_output_dir: Path) -> None:
    sbom_path = run_output_dir / "sbom.json"
    if not sbom_path.exists():
        print("[orchestrator] No sbom.json found to promote.")
        return
    shutil.copy2(sbom_path, PERSISTENT_BASELINE)
    print(f"[orchestrator] Baseline updated: {PERSISTENT_BASELINE}")


# ── Main ──────────────────────────────────────────────────────────────────────


async def main() -> None:
    force = "--force" in sys.argv
    update_bl = "--update-baseline" in sys.argv

    # Handle --update-baseline: promote the most recent versioned sbom to baseline
    if update_bl:
        last = load_last_version()
        if not last:
            print("[orchestrator] No previous version in state. Run an investigation first.")
            sys.exit(1)
        update_baseline(OUTPUT_DIR / f"v{last}")
        return

    print("[orchestrator] Checking latest opencode-ai version on npm...")
    try:
        latest_version = await get_latest_version()
    except Exception as e:
        print(f"[orchestrator] ERROR: Could not fetch version from npm: {e}")
        sys.exit(1)

    last_version = load_last_version()
    print(f"[orchestrator] Latest: v{latest_version} | Last investigated: {last_version or 'none'}")

    if not force and latest_version == last_version:
        print("[orchestrator] No new release. Nothing to do. (Use --force to re-run.)")
        return

    # Validate credentials
    api_env = load_api_env()
    if not api_env.get("MY_LLM_API_KEY"):
        print("[orchestrator] ERROR: api.env missing or MY_LLM_API_KEY not set.")
        sys.exit(1)

    # Check Docker
    if not docker_available():
        print("[orchestrator] ERROR: Docker is not running or not installed.")
        sys.exit(1)

    run_output_dir = OUTPUT_DIR / f"v{latest_version}"
    print(f"\n[orchestrator] === Investigating opencode-ai v{latest_version} ===\n")

    # 1. Docker investigation
    docker_build(api_env)
    docker_run(run_output_dir)

    # 2. SBOM (host-side, persistent baseline)
    sbom_exit = run_sbom(run_output_dir)

    # 3. Safety report
    report_path = run_report_generator(latest_version, run_output_dir)

    # 4. Save "latest" symlink for convenience
    latest_link = OUTPUT_DIR / "latest"
    if latest_link.is_symlink() or latest_link.exists():
        latest_link.unlink()
    latest_link.symlink_to(run_output_dir.name)

    # 5. Persist state
    save_last_version(latest_version)

    # 6. Print final summary
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    verdict = "ALERTS DETECTED — review required" if sbom_exit != 0 else "CLEAN"
    print(f"""
{'=' * 56}
  opencode-ai v{latest_version} — Safety Investigation Complete
  {timestamp}
  Verdict: {verdict}
{'=' * 56}
  Report:  {report_path}
  SBOM:    {run_output_dir / 'sbom.json'}
  URLs:    {run_output_dir / 'urls.log'}
  Latest:  {OUTPUT_DIR / 'latest'}
{'=' * 56}
""")

    if PERSISTENT_BASELINE.exists() and sbom_exit == 0:
        print("  Tip: run with --update-baseline to advance the SBOM baseline to this version.")
    elif not PERSISTENT_BASELINE.exists():
        print("  Baseline created from this run. Subsequent runs will diff against it.")

    if sbom_exit != 0:
        sys.exit(1)


def main_sync() -> None:
    asyncio.run(main())


if __name__ == "__main__":
    main_sync()
