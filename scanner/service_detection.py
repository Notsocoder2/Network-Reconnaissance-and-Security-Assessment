"""Service and version detection using Nmap."""

from __future__ import annotations

import re
import sys
from typing import Dict, List, Tuple

from scanner import common

TXT_FILE = "service_detection.txt"
JSON_FILE = "service_detection.json"

# e.g. "22/tcp   open  ssh   OpenSSH 8.9p1 Ubuntu"
_SERVICE_LINE = re.compile(
    r"^(?P<port>\d{1,5}/(?:tcp|udp))\s+(?P<state>\S+)\s+(?P<service>\S+)"
    r"(?:\s+(?P<version>.*\S))?\s*$"
)


def format_port_spec(start_port: int, end_port: int) -> str:
    """Nmap port specification: '22' for one port, '1-1024' for a range."""
    return str(start_port) if start_port == end_port else f"{start_port}-{end_port}"


def build_command(target, start_port: int, end_port: int) -> List[str]:
    return ["nmap", "-sV", "-p", format_port_spec(start_port, end_port), str(target)]


def run_service_detection(
    target, start_port: int, end_port: int, timeout: int = common.DEFAULT_TIMEOUT
) -> str:
    result = common.run_command(
        build_command(target, start_port, end_port), timeout=timeout
    )
    return result.stdout


def extract_services(output: str) -> List[Dict[str, str]]:
    """Parse the nmap port table into service records."""
    services: List[Dict[str, str]] = []
    for line in output.splitlines():
        match = _SERVICE_LINE.match(line.strip())
        if match:
            services.append(
                {
                    "Port": match.group("port"),
                    "State": match.group("state"),
                    "Service": match.group("service"),
                    "Version": match.group("version") or "Unknown",
                }
            )
    return services


def host_is_up(output: str) -> bool:
    return "Host seems down" not in output


def render_results(
    target, ports: Tuple[int, int], services: List[Dict[str, str]], host_up: bool
) -> str:
    text = common.build_header(
        "SERVICE DETECTION RESULTS",
        {"Target": target, "Ports": format_port_spec(*ports)},
    )
    if not host_up:
        text += (
            "WARNING: nmap reported the host as down; verify the target address "
            "(results may be incomplete).\n\n"
        )
    if services:
        rows = [(s["Port"], s["State"], s["Service"], s["Version"]) for s in services]
        text += common.format_table(("Port", "State", "Service", "Version"), rows)
        text += f"\n\nTotal Ports Listed: {len(services)}\n"
    else:
        text += "No services detected.\n"
    return text


def run(
    target,
    ports: Tuple[int, int],
    output_dir: str = common.DEFAULT_OUTPUT_DIR,
    timeout: int = common.DEFAULT_TIMEOUT,
) -> List[Dict[str, str]]:
    start_port, end_port = ports
    print(f"Running service detection on {target} (ports {format_port_spec(*ports)})...\n")
    output = run_service_detection(target, start_port, end_port, timeout)
    services = extract_services(output)
    host_up = host_is_up(output)
    if not host_up:
        common.LOGGER.warning("nmap reports that %s appears to be down.", target)

    text = render_results(target, ports, services, host_up)
    print(text)
    path = common.write_text(output_dir, TXT_FILE, text)
    common.write_json(
        output_dir,
        JSON_FILE,
        {
            "target": str(target),
            "ports": format_port_spec(*ports),
            "timestamp": common.timestamp(),
            "host_up": host_up,
            "services": services,
        },
    )
    print(f"Results saved to {path}")
    return services


def main() -> int:
    """Interactive entry point: python3 -m scanner.service_detection"""

    def interactive() -> None:
        target = common.prompt_target()
        ports = common.prompt_ports()
        common.confirm_authorization(
            f"target {target}, ports {format_port_spec(*ports)}"
        )
        run(target, ports)

    return common.run_cli(interactive)


if __name__ == "__main__":
    sys.exit(main())
