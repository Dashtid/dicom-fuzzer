#!/usr/bin/env python3
"""Reliable coverage measurement with pytest-xdist.

This script ensures consistent coverage results by:
1. Cleaning old coverage data before each run
2. Running tests with parallel workers
3. Explicitly combining coverage data from all workers
4. Generating reports with consistent settings

Usage:
    uv run python tools/scripts/run_coverage.py [--threshold N] [--html] [--xml]

Options:
    --threshold N   Fail if coverage is below N% (default: 0, no threshold)
    --html          Generate HTML report in artifacts/reports/coverage/htmlcov
    --xml           Generate XML report in artifacts/reports/coverage/coverage.xml
    --serial        Run tests serially (slower but most accurate)
    --quick         Run only fast tests (skip performance/stress tests)
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def clean_coverage_files(project_root: Path) -> int:
    """Remove old coverage data files."""
    count = 0
    for pattern in [".coverage", ".coverage.*"]:
        for f in project_root.glob(pattern):
            f.unlink()
            count += 1
    return count


def run_tests(
    project_root: Path,
    serial: bool = False,
    quick: bool = False,
) -> subprocess.CompletedProcess:
    """Run pytest with coverage collection."""
    cmd = [
        sys.executable,
        "-m",
        "pytest",
        "tests/",
        "--cov=dicom_fuzzer",
        "--cov-report=",  # Suppress report during run (we'll generate after combine)
        "-q",
        "--tb=short",
    ]

    if serial:
        cmd.extend(["-n", "0"])  # Disable xdist
    else:
        cmd.extend(["-n", "auto", "--dist=worksteal"])

    if quick:
        cmd.extend(["-m", "not slow and not performance"])

    return subprocess.run(cmd, cwd=project_root)


def combine_coverage(project_root: Path) -> subprocess.CompletedProcess:
    """Combine coverage data from all parallel workers."""
    return subprocess.run(
        [sys.executable, "-m", "coverage", "combine", "--keep"],
        cwd=project_root,
        capture_output=True,
    )


def generate_report(
    project_root: Path,
    html: bool = False,
    xml: bool = False,
) -> tuple[subprocess.CompletedProcess, float]:
    """Generate coverage report and return coverage percentage."""
    # Text report to stdout
    result = subprocess.run(
        [sys.executable, "-m", "coverage", "report", "--show-missing"],
        cwd=project_root,
        capture_output=True,
        text=True,
    )

    # Parse coverage percentage from output
    coverage_pct = 0.0
    for line in result.stdout.splitlines():
        if line.startswith("TOTAL"):
            parts = line.split()
            for part in parts:
                if part.endswith("%"):
                    coverage_pct = float(part.rstrip("%"))
                    break

    # Print the report
    print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)

    # Generate HTML report if requested
    if html:
        html_dir = project_root / "artifacts" / "reports" / "coverage" / "htmlcov"
        html_dir.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            [sys.executable, "-m", "coverage", "html", "-d", str(html_dir)],
            cwd=project_root,
        )
        print(f"\n[i] HTML report: {html_dir}/index.html")

    # Generate XML report if requested
    if xml:
        xml_file = project_root / "artifacts" / "reports" / "coverage" / "coverage.xml"
        xml_file.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            [sys.executable, "-m", "coverage", "xml", "-o", str(xml_file)],
            cwd=project_root,
        )
        print(f"[i] XML report: {xml_file}")

    return result, coverage_pct


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Reliable coverage measurement with pytest-xdist"
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0,
        help="Fail if coverage is below this percentage",
    )
    parser.add_argument(
        "--html",
        action="store_true",
        help="Generate HTML report",
    )
    parser.add_argument(
        "--xml",
        action="store_true",
        help="Generate XML report",
    )
    parser.add_argument(
        "--serial",
        action="store_true",
        help="Run tests serially (slower but most accurate)",
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Skip slow/performance tests",
    )
    args = parser.parse_args()

    # Determine project root (script is in tools/scripts/)
    project_root = Path(__file__).resolve().parent.parent.parent

    print("[i] Cleaning old coverage data...")
    cleaned = clean_coverage_files(project_root)
    if cleaned:
        print(f"    Removed {cleaned} old coverage file(s)")

    print("\n[i] Running tests with coverage...")
    test_result = run_tests(
        project_root,
        serial=args.serial,
        quick=args.quick,
    )

    print("\n[i] Combining coverage data from workers...")
    combine_result = combine_coverage(project_root)
    if combine_result.returncode != 0:
        print("    Warning: coverage combine had issues")
        if combine_result.stderr:
            print(f"    {combine_result.stderr.decode()}")

    print("\n[i] Coverage Report:")
    print("=" * 80)
    _, coverage_pct = generate_report(
        project_root,
        html=args.html,
        xml=args.xml,
    )
    print("=" * 80)
    print(f"\n[+] Total coverage: {coverage_pct:.1f}%")

    # Check threshold
    if args.threshold > 0 and coverage_pct < args.threshold:
        print(
            f"[-] FAIL: Coverage {coverage_pct:.1f}% is below threshold {args.threshold}%"
        )
        return 1

    if test_result.returncode != 0:
        print(f"[-] Tests failed with exit code {test_result.returncode}")
        return test_result.returncode

    print("[+] OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
