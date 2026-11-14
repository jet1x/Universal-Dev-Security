"""Build and verify a UDS release locally. Never publishes or pushes.

Steps:
1. run the full test suite (aborts on failure);
2. scan the repository with UDS itself (aborts on secret findings);
3. build sdist + wheel into dist/<version>/;
4. write SHA256SUMS;
5. install the wheel into a fresh virtual environment and smoke-test the CLI.

Usage:  python scripts/release.py [--skip-tests] [--skip-self-scan]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from universal_dev_security import __version__  # noqa: E402


def run(args: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
    print("$ " + " ".join(args), flush=True)
    return subprocess.run(args, cwd=ROOT, text=True, check=False, **kwargs)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-tests", action="store_true")
    parser.add_argument("--skip-self-scan", action="store_true")
    args = parser.parse_args()
    out = ROOT / "dist" / __version__

    if not args.skip_tests and run([sys.executable, "-m", "pytest", "-q"]).returncode != 0:
        print("Tests failed; release aborted.")
        return 1

    if not args.skip_self_scan:
        report_dir = Path(tempfile.mkdtemp(prefix="uds-selfscan-"))
        scan = run([sys.executable, "-m", "universal_dev_security", "scan", ".", "--tool", "gitleaks", "--no-history",
                    "--json", "--report-dir", str(report_dir), "--fail-on", "low"], capture_output=True)
        if scan.returncode != 0:
            print(scan.stdout[-2000:])
            print("Self-scan found potential secrets or could not run; release aborted.")
            return 1
        shutil.rmtree(report_dir, ignore_errors=True)

    if out.exists():
        shutil.rmtree(out)
    if run([sys.executable, "-m", "build", "--sdist", "--wheel", "--outdir", str(out)]).returncode != 0:
        print("Build failed.")
        return 1

    artifacts = sorted(p for p in out.iterdir() if p.suffix in (".whl", ".gz"))
    sums = "".join(f"{sha256(p)}  {p.name}\n" for p in artifacts)
    (out / "SHA256SUMS").write_text(sums, encoding="utf-8", newline="\n")
    print(sums)

    wheel = next(p for p in artifacts if p.suffix == ".whl")
    with tempfile.TemporaryDirectory(prefix="uds-verify-") as temp:
        env_dir = Path(temp) / "venv"
        venv.create(env_dir, with_pip=True)
        python = env_dir / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        if run([str(python), "-m", "pip", "install", "-q", "--no-deps", str(wheel)]).returncode != 0:
            print("Wheel installation failed.")
            return 1
        version = run([str(python), "-m", "universal_dev_security", "--version"], capture_output=True)
        doctor = run([str(python), "-m", "universal_dev_security", "doctor", str(ROOT), "--json"], capture_output=True)
        if version.returncode != 0 or __version__ not in version.stdout or doctor.returncode != 0:
            print("Installed wheel smoke test failed.")
            return 1
        json.loads(doctor.stdout)
    manifest = {"version": __version__, "artifacts": [{"file": p.name, "sha256": sha256(p)} for p in artifacts],
                "verified": ["tests", "self-scan" if not args.skip_self_scan else "self-scan skipped",
                             "wheel install + CLI smoke test"]}
    (out / "release-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"Release candidate {__version__} built and verified in {out}. Nothing was published.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
