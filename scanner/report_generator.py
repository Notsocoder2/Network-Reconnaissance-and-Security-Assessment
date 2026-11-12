"""Combine the individual scan results into one assessment report."""

from __future__ import annotations

import sys
from pathlib import Path

from scanner import common

REPORT_FILE = "network_assessment_report.txt"

SECTIONS = (
    ("1. HOST DISCOVERY", "host_discovery.txt"),
    ("2. PING SWEEP", "ping_sweep.txt"),
    ("3. SERVICE DETECTION", "service_detection.txt"),
    ("4. OS DETECTION", "os_detection.txt"),
    ("5. RISK ANALYSIS", "risk_analysis.txt"),
)


def read_file(output_dir: str, filename: str) -> str:
    path = Path(output_dir) / filename
    if not path.exists():
        return f"{filename} not found (step was skipped or failed).\n"
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        return f"{filename} could not be read: {exc}\n"


def generate_report(output_dir: str = common.DEFAULT_OUTPUT_DIR) -> str:
    report = "=" * 70 + "\n"
    report += "NETWORK RECONNAISSANCE AND SECURITY ASSESSMENT REPORT\n"
    report += "=" * 70 + "\n"
    report += f"Report generated: {common.timestamp()}\n\n"

    for title, filename in SECTIONS:
        report += f"{title}\n" + "-" * 70 + "\n"
        report += read_file(output_dir, filename).rstrip() + "\n\n"
    return report


def run(output_dir: str = common.DEFAULT_OUTPUT_DIR) -> str:
    report = generate_report(output_dir)
    print("\n" + "=" * 70)
    print("FINAL NETWORK ASSESSMENT REPORT")
    print("=" * 70)
    print(report)
    path = common.write_text(output_dir, REPORT_FILE, report)
    print(f"Report saved to: {path}")
    return report


def main() -> int:
    """Standalone entry point: python3 -m scanner.report_generator"""
    return common.run_cli(lambda: run(common.DEFAULT_OUTPUT_DIR))


if __name__ == "__main__":
    sys.exit(main())
