"""Ping sweep (live host detection) using Nmap."""

from __future__ import annotations

import re
import sys
from typing import Dict, List

from scanner import common

TXT_FILE = "ping_sweep.txt"
JSON_FILE = "ping_sweep.json"

_IP = r"\d{1,3}(?:\.\d{1,3}){3}"
# "Nmap scan report for router.lan (192.168.1.1)"  or  "Nmap scan report for 192.168.1.5"
_REPORT_LINE = re.compile(
    rf"^Nmap scan report for (?:(?P<host>\S+) \((?P<ip>{_IP})\)|(?P<bare>{_IP}))$"
)


def run_pingsweep(subnet, timeout: int = common.DEFAULT_TIMEOUT) -> str:
    if not common.is_root():
        common.LOGGER.warning(
            "Running without root: nmap uses TCP probes instead of ARP, so hosts on "
            "the local network may be missed."
        )
    result = common.run_command(["nmap", "-sn", str(subnet)], timeout=timeout)
    return result.stdout


def extract_hosts(output: str) -> List[Dict[str, str]]:
    """Parse ``nmap -sn`` output into live-host records."""
    hosts: List[Dict[str, str]] = []
    current = None
    for line in output.splitlines():
        line = line.strip()
        match = _REPORT_LINE.match(line)
        if match:
            current = {
                "IP": match.group("ip") or match.group("bare"),
                "Hostname": match.group("host") or "N/A",
            }
        elif line.startswith("Host is up") and current is not None:
            current["Status"] = "Up"
            hosts.append(current)
            current = None
    return hosts


def render_results(subnet, hosts: List[Dict[str, str]]) -> str:
    text = common.build_header("PING SWEEP RESULTS", {"Subnet": subnet})
    if hosts:
        rows = [(h["IP"], h["Hostname"], h["Status"]) for h in hosts]
        text += common.format_table(("IP Address", "Hostname", "Status"), rows) + "\n\n"
        text += f"Total Live Hosts: {len(hosts)}\n"
    else:
        text += "No live hosts found.\n"
    return text


def run(
    subnet,
    output_dir: str = common.DEFAULT_OUTPUT_DIR,
    timeout: int = common.DEFAULT_TIMEOUT,
) -> List[Dict[str, str]]:
    print(f"Running ping sweep on {subnet}...\n")
    hosts = extract_hosts(run_pingsweep(subnet, timeout))
    text = render_results(subnet, hosts)
    print(text)
    path = common.write_text(output_dir, TXT_FILE, text)
    common.write_json(
        output_dir,
        JSON_FILE,
        {"subnet": str(subnet), "timestamp": common.timestamp(), "hosts": hosts},
    )
    print(f"Results saved to {path}")
    return hosts


def main() -> int:
    """Interactive entry point: python3 -m scanner.ping_sweep"""

    def interactive() -> None:
        subnet = common.prompt_network()
        common.confirm_authorization(f"subnet {subnet}")
        run(subnet)

    return common.run_cli(interactive)


if __name__ == "__main__":
    sys.exit(main())
