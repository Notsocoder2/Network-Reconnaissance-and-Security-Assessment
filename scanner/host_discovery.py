"""Host discovery on the local network segment using Netdiscover (ARP)."""

from __future__ import annotations

import ipaddress
import re
import sys
from typing import Dict, List

from scanner import common

TXT_FILE = "host_discovery.txt"
JSON_FILE = "host_discovery.json"

_HOST_PATTERN = re.compile(
    r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\b",
    re.MULTILINE,
)


def run_netdiscover(subnet, timeout: int = common.DEFAULT_TIMEOUT) -> str:
    """Run a one-shot active ARP scan.

    ``-P`` prints parseable output and exits after the scan (without it
    Netdiscover starts an interactive UI and never returns), ``-N`` drops the header.
    """
    result = common.run_command(
        ["netdiscover", "-P", "-N", "-r", str(subnet)],
        timeout=timeout,
        needs_root=True,
    )
    return result.stdout


def extract_hosts(output: str) -> List[Dict[str, str]]:
    """Parse Netdiscover output into unique, IP-sorted host records."""
    hosts: Dict[str, Dict[str, str]] = {}
    for ip, mac in _HOST_PATTERN.findall(output):
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        hosts.setdefault(ip, {"IP": ip, "MAC": mac})
    return sorted(hosts.values(), key=lambda host: ipaddress.ip_address(host["IP"]))


def render_results(subnet, hosts: List[Dict[str, str]]) -> str:
    text = common.build_header("HOST DISCOVERY RESULTS", {"Subnet": subnet})
    if hosts:
        rows = [(host["IP"], host["MAC"]) for host in hosts]
        text += common.format_table(("IP Address", "MAC Address"), rows) + "\n\n"
        text += f"Total Hosts Found: {len(hosts)}\n"
    else:
        text += "No hosts found.\n"
    return text


def run(
    subnet,
    output_dir: str = common.DEFAULT_OUTPUT_DIR,
    timeout: int = common.DEFAULT_TIMEOUT,
) -> List[Dict[str, str]]:
    print(f"Running Netdiscover on {subnet}...\n")
    hosts = extract_hosts(run_netdiscover(subnet, timeout))
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
    """Interactive entry point: python3 -m scanner.host_discovery"""

    def interactive() -> None:
        subnet = common.prompt_network()
        common.confirm_authorization(f"subnet {subnet}")
        run(subnet)

    return common.run_cli(interactive)


if __name__ == "__main__":
    sys.exit(main())
