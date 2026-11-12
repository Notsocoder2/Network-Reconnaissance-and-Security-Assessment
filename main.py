#!/usr/bin/env python3
"""Network Reconnaissance and Security Assessment - command line entry point.

Runs host discovery, ping sweep, service detection, OS detection, risk analysis
and report generation against systems you are explicitly authorized to test.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional, Sequence, Tuple

from scanner import (
    __version__,
    common,
    host_discovery,
    os_detection,
    ping_sweep,
    report_generator,
    risk_analysis,
    service_detection,
)

SCAN_STEPS = ("host-discovery", "ping-sweep", "service-detection", "os-detection")

OUTPUT_FILES = (
    host_discovery.TXT_FILE,
    host_discovery.JSON_FILE,
    ping_sweep.TXT_FILE,
    ping_sweep.JSON_FILE,
    service_detection.TXT_FILE,
    service_detection.JSON_FILE,
    os_detection.TXT_FILE,
    os_detection.JSON_FILE,
    risk_analysis.TXT_FILE,
    risk_analysis.JSON_FILE,
    report_generator.REPORT_FILE,
)


@dataclass
class Scope:
    subnet: Optional[object] = None
    target: Optional[object] = None
    ports: Optional[Tuple[int, int]] = None

    def describe(self) -> str:
        parts = []
        if self.subnet is not None:
            parts.append(f"subnet {self.subnet}")
        if self.target is not None:
            parts.append(f"target {self.target}")
        if self.ports is not None:
            parts.append(f"ports {service_detection.format_port_spec(*self.ports)}")
        return ", ".join(parts) or "no scan steps selected"


def _positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"'{value}' is not an integer")
    if number < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="Network reconnaissance and security assessment for systems "
        "you are authorized to test.",
        epilog="Host discovery and OS detection need root (run with sudo). "
        "Missing --subnet/--target values are requested interactively.",
    )
    parser.add_argument("--subnet", help="subnet for host discovery and ping sweep, e.g. 192.168.1.0/24")
    parser.add_argument("--target", help="single IPv4 address for service and OS detection")
    parser.add_argument("--ports", help="port or range for service detection, e.g. 22 or 1-1024 (default 1-1024)")
    parser.add_argument("--skip", action="append", choices=SCAN_STEPS, default=[], metavar="STEP",
                        help="skip a scan step (repeatable): " + ", ".join(SCAN_STEPS))
    parser.add_argument("--output-dir", default=common.DEFAULT_OUTPUT_DIR,
                        help="directory for results and the audit log (default: results)")
    parser.add_argument("--timeout", type=_positive_int, default=common.DEFAULT_TIMEOUT,
                        help="per-step command timeout in seconds (default: %(default)s)")
    parser.add_argument("--max-hosts", type=_positive_int, default=common.DEFAULT_MAX_HOSTS,
                        help="largest subnet (in addresses) that may be scanned (default: %(default)s)")
    parser.add_argument("--allow-public", action="store_true",
                        help="allow non-private address space (requires written authorization)")
    parser.add_argument("--authorized", action="store_true",
                        help="confirm you are authorized to scan, skipping the interactive prompt")
    parser.add_argument("-v", "--verbose", action="store_true", help="show informational log messages")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def resolve_scope(args: argparse.Namespace) -> Scope:
    """Validate command-line scope, prompting for anything missing."""
    skipped = set(args.skip)
    scope = Scope()

    if {"host-discovery", "ping-sweep"} - skipped:
        scope.subnet = (
            common.validate_network(args.subnet, args.allow_public, args.max_hosts)
            if args.subnet
            else common.prompt_network(args.allow_public, args.max_hosts)
        )
    if {"service-detection", "os-detection"} - skipped:
        scope.target = (
            common.validate_target(args.target, args.allow_public)
            if args.target
            else common.prompt_target(args.allow_public)
        )
    if "service-detection" not in skipped:
        if args.ports:
            scope.ports = common.parse_port_range(args.ports)
        elif sys.stdin.isatty():
            scope.ports = common.prompt_ports()
        else:
            scope.ports = common.parse_port_range(common.DEFAULT_PORTS)
    return scope


def clear_previous_results(output_dir: str) -> None:
    """Remove this tool's own output files so stale data never enters a new report."""
    for name in OUTPUT_FILES:
        path = Path(output_dir) / name
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            common.LOGGER.warning("Could not remove old result %s: %s", path, exc)


def build_steps(scope: Scope, args: argparse.Namespace) -> List[Tuple[str, Callable[[], object]]]:
    out, timeout, skipped = args.output_dir, args.timeout, set(args.skip)
    steps: List[Tuple[str, Callable[[], object]]] = []
    if "host-discovery" not in skipped:
        steps.append(("Host Discovery", lambda: host_discovery.run(scope.subnet, out, timeout)))
    if "ping-sweep" not in skipped:
        steps.append(("Ping Sweep", lambda: ping_sweep.run(scope.subnet, out, timeout)))
    if "service-detection" not in skipped:
        steps.append(("Service Detection", lambda: service_detection.run(scope.target, scope.ports, out, timeout)))
    if "os-detection" not in skipped:
        steps.append(("OS Detection", lambda: os_detection.run(scope.target, out, timeout)))
    steps.append(("Risk Analysis", lambda: risk_analysis.run(out)))
    steps.append(("Final Report", lambda: report_generator.run(out)))
    return steps


def run_pipeline(args: argparse.Namespace) -> int:
    common.setup_logging(args.output_dir, args.verbose)
    try:
        scope = resolve_scope(args)
        common.confirm_authorization(scope.describe(), args.authorized)
    except (common.ScopeError, common.ScanError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    common.LOGGER.info("Assessment started; scope: %s", scope.describe())
    try:
        common.ensure_output_dir(args.output_dir)
    except common.ScanError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    clear_previous_results(args.output_dir)

    print("=" * 70)
    print("NETWORK RECONNAISSANCE AND SECURITY ASSESSMENT")
    print("=" * 70)

    steps = build_steps(scope, args)
    outcomes: List[Tuple[str, str, str]] = []
    try:
        for index, (name, action) in enumerate(steps, start=1):
            print(f"\n[{index}/{len(steps)}] {name}...")
            try:
                action()
                outcomes.append((name, "OK", ""))
            except common.ScanError as exc:
                common.LOGGER.error("%s failed: %s", name, exc)
                print(f"  {name} FAILED: {exc}")
                outcomes.append((name, "FAILED", str(exc)))
    except KeyboardInterrupt:
        print("\nInterrupted by user.", file=sys.stderr)
        return 130

    failed = [name for name, status, _ in outcomes if status == "FAILED"]
    print("\n" + "=" * 70)
    print("ASSESSMENT FINISHED" + (" WITH ERRORS" if failed else " SUCCESSFULLY"))
    print("=" * 70)
    for name, status, detail in outcomes:
        print(f"  [{status:<6}] {name}" + (f" - {detail}" if detail else ""))

    produced = [n for n in OUTPUT_FILES if (Path(args.output_dir) / n).exists()]
    print(f"\nFiles written to {args.output_dir}/:")
    for name in produced:
        print(f"  - {name}")
    common.LOGGER.info("Assessment finished; failed steps: %s", failed or "none")
    return 1 if failed else 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    return run_pipeline(build_parser().parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
