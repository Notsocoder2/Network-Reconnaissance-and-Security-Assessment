"""Operating system fingerprinting using Nmap."""

from __future__ import annotations

import re
import sys
from typing import Dict

from scanner import common

TXT_FILE = "os_detection.txt"
JSON_FILE = "os_detection.json"

# nmap prints "Running: ..." (or "Running (JUST GUESSING): ...") with a capital R,
# so matching is case-insensitive. Fields may have several fallbacks.
_PATTERNS = {
    "Running": (r"^Running(?: \(JUST GUESSING\))?:\s*(.+)$",),
    "OS Details": (r"^OS details:\s*(.+)$", r"^Aggressive OS guesses:\s*(.+)$"),
    "Device Type": (r"^Device type:\s*(.+)$",),
    "Network Distance": (r"^Network Distance:\s*(.+)$",),
}


def run_os_detection(target, timeout: int = common.DEFAULT_TIMEOUT) -> str:
    result = common.run_command(
        ["nmap", "-O", str(target)], timeout=timeout, needs_root=True
    )
    return result.stdout


def extract_os_info(output: str) -> Dict[str, str]:
    info: Dict[str, str] = {}
    for field, patterns in _PATTERNS.items():
        info[field] = "Unknown"
        for pattern in patterns:
            match = re.search(pattern, output, re.MULTILINE | re.IGNORECASE)
            if match:
                info[field] = match.group(1).strip()
                break
    return info


def render_results(target, os_info: Dict[str, str]) -> str:
    text = common.build_header("OS DETECTION RESULTS", {"Target": target})
    for field in _PATTERNS:
        text += f"{field}: {os_info[field]}\n"
    return text


def run(
    target,
    output_dir: str = common.DEFAULT_OUTPUT_DIR,
    timeout: int = common.DEFAULT_TIMEOUT,
) -> Dict[str, str]:
    print(f"Running Nmap OS detection on {target}...\n")
    output = run_os_detection(target, timeout)
    os_info = extract_os_info(output)
    if "Host seems down" in output:
        common.LOGGER.warning("nmap reports that %s appears to be down.", target)

    text = render_results(target, os_info)
    print(text)
    path = common.write_text(output_dir, TXT_FILE, text)
    common.write_json(
        output_dir,
        JSON_FILE,
        {"target": str(target), "timestamp": common.timestamp(), "os_info": os_info},
    )
    print(f"Results saved to {path}")
    return os_info


def main() -> int:
    """Interactive entry point: python3 -m scanner.os_detection"""

    def interactive() -> None:
        target = common.prompt_target()
        common.confirm_authorization(f"target {target}")
        run(target)

    return common.run_cli(interactive)


if __name__ == "__main__":
    sys.exit(main())
