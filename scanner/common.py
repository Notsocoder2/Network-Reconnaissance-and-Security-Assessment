"""Shared helpers for the reconnaissance toolkit.

Provides scope validation, the authorization gate, safe subprocess execution,
output-file helpers and small formatting utilities used by every scanner module.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Optional, Sequence, Tuple, TypeVar

LOGGER = logging.getLogger("scanner")

DEFAULT_OUTPUT_DIR = "results"
DEFAULT_MAX_HOSTS = 1024
DEFAULT_TIMEOUT = 300
DEFAULT_PORTS = "1-1024"
MAX_PORT = 65535
LOG_FILENAME = "assessment.log"

# Address space considered "lab / internal". Anything else is treated as public
# and is refused unless the operator explicitly passes --allow-public.
_PRIVATE_RANGES = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "169.254.0.0/16",
        "127.0.0.0/8",
    )
)

T = TypeVar("T")


class ScanError(Exception):
    """A scan step could not be completed (missing tool, privileges, failure)."""


class ScopeError(ValueError):
    """Input is invalid or outside the permitted scan scope."""


@dataclass
class CommandResult:
    """Captured result of an external command."""

    stdout: str
    stderr: str
    returncode: int


# --------------------------------------------------------------------------
# Output directory and logging
# --------------------------------------------------------------------------

def ensure_output_dir(output_dir: str = DEFAULT_OUTPUT_DIR) -> Path:
    """Create the (owner-only) output directory if needed and return it."""
    path = Path(output_dir)
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as exc:
        raise ScanError(f"Cannot create output directory '{path}': {exc}") from exc
    return path


def setup_logging(output_dir: str = DEFAULT_OUTPUT_DIR, verbose: bool = False) -> None:
    """Log warnings to stderr and a full audit trail to <output_dir>/assessment.log."""
    LOGGER.setLevel(logging.DEBUG)
    LOGGER.propagate = False
    if LOGGER.handlers:
        return

    console = logging.StreamHandler(sys.stderr)
    console.setLevel(logging.INFO if verbose else logging.WARNING)
    console.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    LOGGER.addHandler(console)

    try:
        log_path = ensure_output_dir(output_dir) / LOG_FILENAME
        file_handler = logging.FileHandler(log_path, encoding="utf-8")
    except (OSError, ScanError) as exc:
        LOGGER.warning("Could not open the audit log (%s); continuing without it.", exc)
        return
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    )
    LOGGER.addHandler(file_handler)


# --------------------------------------------------------------------------
# Input validation and scope control
# --------------------------------------------------------------------------

def _is_private(network: ipaddress.IPv4Network) -> bool:
    return any(network.subnet_of(private) for private in _PRIVATE_RANGES)


def validate_target(value: str, allow_public: bool = False) -> ipaddress.IPv4Address:
    """Validate a single IPv4 scan target."""
    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError as exc:
        raise ScopeError(f"'{value}' is not a valid IP address.") from exc
    if address.version != 4:
        raise ScopeError("Only IPv4 targets are supported.")
    if address.is_unspecified or address.is_multicast or address.is_reserved:
        raise ScopeError(f"{address} is not a valid scan target.")
    if not allow_public and not _is_private(ipaddress.ip_network(f"{address}/32")):
        raise ScopeError(
            f"{address} is not a private/lab address. Scanning public hosts "
            "requires --allow-public and written authorization."
        )
    return address


def validate_network(
    value: str,
    allow_public: bool = False,
    max_hosts: int = DEFAULT_MAX_HOSTS,
) -> ipaddress.IPv4Network:
    """Validate a subnet and enforce the size and address-space limits."""
    try:
        network = ipaddress.ip_network(str(value).strip(), strict=False)
    except ValueError as exc:
        raise ScopeError(
            f"'{value}' is not a valid subnet (example: 192.168.1.0/24)."
        ) from exc
    if network.version != 4:
        raise ScopeError("Only IPv4 subnets are supported.")
    if network.is_multicast or network.is_reserved or network.is_unspecified:
        raise ScopeError(f"{network} is not a valid scan range.")
    if network.num_addresses > max_hosts:
        raise ScopeError(
            f"{network} covers {network.num_addresses} addresses, above the limit "
            f"of {max_hosts}. Narrow the range, or raise --max-hosts if you are "
            "authorized to scan it."
        )
    if not allow_public and not _is_private(network):
        raise ScopeError(
            f"{network} is not entirely private/lab address space. Scanning public "
            "ranges requires --allow-public and written authorization."
        )
    return network


def parse_port_range(value: str) -> Tuple[int, int]:
    """Parse '22' or '1-1024' into an inclusive (start, end) tuple."""
    text = str(value).strip()
    try:
        if "-" in text:
            start_text, end_text = text.split("-", 1)
            start, end = int(start_text), int(end_text)
        else:
            start = end = int(text)
    except ValueError as exc:
        raise ScopeError("Ports must be integers, e.g. '22' or '1-1024'.") from exc
    if not 1 <= start <= end <= MAX_PORT:
        raise ScopeError(f"Port range must satisfy 1 <= start <= end <= {MAX_PORT}.")
    return start, end


def confirm_authorization(scope: str, assume_yes: bool = False) -> None:
    """Require explicit confirmation that the operator may scan this scope."""
    if assume_yes:
        LOGGER.info("Authorization asserted with --authorized for scope: %s", scope)
        return

    print("\n" + "!" * 70)
    print("AUTHORIZED USE ONLY")
    print(f"Scope: {scope}")
    print("Only scan systems you own or have explicit written permission to test.")
    print("!" * 70)
    try:
        answer = input("Type 'yes' to confirm you are authorized to scan this scope: ")
    except EOFError:
        answer = ""
    if answer.strip().lower() != "yes":
        raise ScopeError("Authorization not confirmed; nothing was scanned.")
    LOGGER.info("Authorization confirmed interactively for scope: %s", scope)


# --------------------------------------------------------------------------
# Safe command execution
# --------------------------------------------------------------------------

def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def run_command(
    args: Sequence[str],
    timeout: int = DEFAULT_TIMEOUT,
    needs_root: bool = False,
) -> CommandResult:
    """Run an external tool without a shell and return its captured output.

    Raises ScanError if the tool is missing, privileges are insufficient, the
    command times out, or it exits with a non-zero status.
    """
    tool = args[0]
    if shutil.which(tool) is None:
        raise ScanError(f"'{tool}' is not installed or not on PATH.")
    if needs_root and not is_root():
        raise ScanError(
            f"'{tool}' requires root privileges. Re-run with sudo "
            "(for example: sudo python3 main.py ...) or skip this step."
        )

    LOGGER.info("Running: %s", shlex.join(args))
    try:
        completed = subprocess.run(
            list(args),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ScanError(f"'{tool}' timed out after {timeout} seconds.") from exc
    except OSError as exc:
        raise ScanError(f"Could not execute '{tool}': {exc}") from exc

    if completed.returncode != 0:
        detail = (completed.stderr.strip() or completed.stdout.strip())[:500]
        raise ScanError(f"'{tool}' exited with status {completed.returncode}: {detail}")
    if completed.stderr.strip():
        LOGGER.debug("%s stderr: %s", tool, completed.stderr.strip()[:500])
    return CommandResult(completed.stdout, completed.stderr, completed.returncode)


# --------------------------------------------------------------------------
# Output helpers
# --------------------------------------------------------------------------

def timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def build_header(title: str, details: Optional[dict] = None, width: int = 60) -> str:
    """Standard report header with generation time and optional key/value details."""
    lines = [title, "=" * width, f"Generated: {timestamp()}"]
    for key, value in (details or {}).items():
        lines.append(f"{key}: {value}")
    return "\n".join(lines) + "\n\n"


def format_table(headers: Sequence[str], rows: Iterable[Sequence[object]]) -> str:
    """Render a left-aligned plain-text table."""
    table = [[str(cell) for cell in headers]]
    table.extend([str(cell) for cell in row] for row in rows)
    widths = [max(len(row[i]) for row in table) for i in range(len(headers))]

    def fmt(row: Sequence[str]) -> str:
        return "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)).rstrip()

    lines = [fmt(table[0]), "  ".join("-" * width for width in widths)]
    lines.extend(fmt(row) for row in table[1:])
    return "\n".join(lines)


def write_text(output_dir: str, filename: str, content: str) -> Path:
    path = ensure_output_dir(output_dir) / filename
    try:
        path.write_text(content, encoding="utf-8")
    except OSError as exc:
        raise ScanError(f"Could not write {path}: {exc}") from exc
    return path


def write_json(output_dir: str, filename: str, data: object) -> Path:
    return write_text(output_dir, filename, json.dumps(data, indent=2) + "\n")


def read_json(output_dir: str, filename: str) -> Optional[dict]:
    """Return parsed JSON, or None if the file does not exist."""
    path = Path(output_dir) / filename
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ScanError(f"Could not read {path}: {exc}") from exc


# --------------------------------------------------------------------------
# Interactive prompts (shared by every module and main.py)
# --------------------------------------------------------------------------

def _prompt(prompt: str, validator: Callable[[str], T]) -> T:
    while True:
        try:
            raw = input(prompt)
        except EOFError as exc:
            raise ScopeError(
                "No input available; supply the value with a command-line option."
            ) from exc
        try:
            return validator(raw)
        except ScopeError as exc:
            print(f"  {exc}")


def prompt_network(
    allow_public: bool = False, max_hosts: int = DEFAULT_MAX_HOSTS
) -> ipaddress.IPv4Network:
    return _prompt(
        "Enter subnet (example: 192.168.1.0/24): ",
        lambda raw: validate_network(raw, allow_public, max_hosts),
    )


def prompt_target(allow_public: bool = False) -> ipaddress.IPv4Address:
    return _prompt(
        "Enter target IP address: ", lambda raw: validate_target(raw, allow_public)
    )


def prompt_ports(default: str = DEFAULT_PORTS) -> Tuple[int, int]:
    return _prompt(
        f"Enter port or range, e.g. 22 or 1-1024 [{default}]: ",
        lambda raw: parse_port_range(raw.strip() or default),
    )


def run_cli(action: Callable[[], object], output_dir: str = DEFAULT_OUTPUT_DIR) -> int:
    """Run a standalone module entry point with uniform error handling."""
    setup_logging(output_dir)
    try:
        action()
    except KeyboardInterrupt:
        print("\nInterrupted by user.", file=sys.stderr)
        return 130
    except (ScopeError, ScanError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0
