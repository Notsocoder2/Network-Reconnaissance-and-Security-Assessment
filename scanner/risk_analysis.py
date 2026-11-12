"""Rule-based risk analysis of detected services and operating system."""

from __future__ import annotations

import sys
from collections import Counter
from typing import Dict, List, Optional, Tuple

from scanner import common, os_detection, service_detection

TXT_FILE = "risk_analysis.txt"
JSON_FILE = "risk_analysis.json"

LEVEL_ORDER = ("High", "Medium", "Low", "Unknown")

DISCLAIMER = (
    "Note: findings are rule-based and derived from detected service and OS names. "
    "They indicate areas to review and do not confirm that a vulnerability exists."
)

RISK_DATABASE = {

    "ftp": {
        "level": "High",
        "risk": "FTP transmits usernames and passwords in plain text.",
        "recommendation": "Use SFTP or FTPS instead of FTP."
    },

    "telnet": {
        "level": "High",
        "risk": "Telnet communication is unencrypted and vulnerable to interception.",
        "recommendation": "Disable Telnet and use SSH."
    },

    "ssh": {
        "level": "Low",
        "risk": "SSH is generally secure but weak passwords or outdated versions increase risk.",
        "recommendation": "Use strong passwords or SSH keys and keep OpenSSH updated."
    },

    "http": {
        "level": "Medium",
        "risk": "HTTP traffic is transmitted without encryption.",
        "recommendation": "Use HTTPS instead of HTTP."
    },

    "https": {
        "level": "Low",
        "risk": "HTTPS is secure but requires valid certificates and regular updates.",
        "recommendation": "Keep SSL/TLS certificates updated."
    },

    "smtp": {
        "level": "Medium",
        "risk": "SMTP servers may be abused for spam if improperly configured.",
        "recommendation": "Disable open relay and enable authentication."
    },

    "dns": {
        "level": "Medium",
        "risk": "DNS servers may be vulnerable to cache poisoning or amplification attacks.",
        "recommendation": "Restrict recursive queries and keep DNS software updated."
    },

    "smb": {
        "level": "High",
        "risk": "SMB services may expose shared files and are often targeted by attackers.",
        "recommendation": "Disable SMBv1 and restrict file sharing."
    },

    "mysql": {
        "level": "High",
        "risk": "Exposed MySQL services may allow unauthorized database access.",
        "recommendation": "Restrict database access and use strong authentication."
    },

    "postgresql": {
        "level": "High",
        "risk": "Exposed PostgreSQL databases may be vulnerable to unauthorized access.",
        "recommendation": "Limit remote access and enforce strong passwords."
    },

    "mongodb": {
        "level": "High",
        "risk": "MongoDB instances without authentication are easily compromised.",
        "recommendation": "Enable authentication and restrict external access."
    },

    "redis": {
        "level": "High",
        "risk": "Redis services exposed to the internet may allow unauthorized access.",
        "recommendation": "Bind Redis to localhost or trusted hosts and enable authentication."
    },

    "rdp": {
        "level": "High",
        "risk": "Remote Desktop services are common targets for brute-force attacks.",
        "recommendation": "Use strong passwords, MFA, and restrict access."
    },

    "snmp": {
        "level": "Medium",
        "risk": "Default SNMP community strings may expose sensitive information.",
        "recommendation": "Change default community strings and restrict access."
    },

    "vnc": {
        "level": "Medium",
        "risk": "VNC services may allow remote access with weak authentication.",
        "recommendation": "Use strong passwords and restrict remote access."
    }

}

# Nmap reports some services under different names than the keys above.
SERVICE_ALIASES = {
    "microsoft-ds": "smb",
    "netbios-ssn": "smb",
    "ms-wbt-server": "rdp",
    "domain": "dns",
    "mongod": "mongodb",
    "ssl/http": "https",
    "vnc-http": "vnc",
}


def normalize_service_name(name: str) -> str:
    """Lower-case an nmap service name, drop the '?' guess marker, apply aliases."""
    cleaned = name.strip().lower().rstrip("?")
    return SERVICE_ALIASES.get(cleaned, cleaned)


def load_service_results(output_dir: str) -> Tuple[List[Dict[str, str]], Optional[str]]:
    data = common.read_json(output_dir, service_detection.JSON_FILE)
    if data is None:
        common.LOGGER.warning("Service detection results not found; skipping services.")
        return [], None
    return data.get("services", []), data.get("target")


def load_os_results(output_dir: str) -> Dict[str, str]:
    data = common.read_json(output_dir, os_detection.JSON_FILE)
    if data is None:
        common.LOGGER.warning("OS detection results not found.")
        return {}
    return data.get("os_info", {})


def analyze_services(services: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """Map open services to known risks. Closed/filtered ports are ignored."""
    findings = []
    for service in services:
        if service.get("State", "").lower() != "open":
            continue
        name = normalize_service_name(service.get("Service", ""))
        entry = RISK_DATABASE.get(name)
        if entry is None:
            continue
        findings.append(
            {
                "Type": "Service",
                "Name": name,
                "Port": service.get("Port", "unknown"),
                "Level": entry["level"],
                "Risk": entry["risk"],
                "Recommendation": entry["recommendation"],
            }
        )
    return findings


def analyze_os(os_info: Dict[str, str]) -> List[Dict[str, str]]:
    running = (os_info or {}).get("Running", "Unknown")
    lowered = running.lower()

    if "windows" in lowered:
        finding = {
            "Type": "Operating System",
            "Name": running,
            "Level": "Medium",
            "Risk": "Windows systems must be regularly updated to prevent exploitation of known vulnerabilities.",
            "Recommendation": "Enable automatic updates, keep Windows Defender active, and install security patches regularly.",
        }
    elif "linux" in lowered:
        finding = {
            "Type": "Operating System",
            "Name": running,
            "Level": "Low",
            "Risk": "Outdated Linux packages and unnecessary services may introduce security vulnerabilities.",
            "Recommendation": "Keep packages updated and disable unnecessary services.",
        }
    else:
        finding = {
            "Type": "Operating System",
            "Name": "Unknown",
            "Level": "Unknown",
            "Risk": "Operating system could not be identified (detection missing or inconclusive).",
            "Recommendation": "Perform additional scanning or verify firewall settings.",
        }
    return [finding]


def analyze(services, os_info) -> List[Dict[str, str]]:
    """Combine service and OS findings, most severe first."""
    findings = analyze_services(services) + analyze_os(os_info)
    findings.sort(
        key=lambda f: LEVEL_ORDER.index(f["Level"]) if f["Level"] in LEVEL_ORDER else len(LEVEL_ORDER)
    )
    return findings


def summarize(findings: List[Dict[str, str]]) -> str:
    counts = Counter(f["Level"] for f in findings)
    return ", ".join(f"{level}: {counts[level]}" for level in LEVEL_ORDER if counts[level])


def render_results(findings: List[Dict[str, str]], target: Optional[str]) -> str:
    text = common.build_header("RISK ANALYSIS RESULTS", {"Target": target or "unknown"})
    if not findings:
        return text + "No risks identified.\n"

    for count, finding in enumerate(findings, start=1):
        text += f"Risk {count}\n" + "-" * 60 + "\n"
        text += f"Type: {finding['Type']}\n"
        text += f"Name: {finding['Name']}\n"
        if "Port" in finding:
            text += f"Port: {finding['Port']}\n"
        text += f"Risk Level: {finding['Level']}\n"
        text += f"Risk: {finding['Risk']}\n"
        text += f"Recommendation: {finding['Recommendation']}\n\n"

    text += "=" * 60 + "\n"
    text += f"Total Risks Identified: {len(findings)} ({summarize(findings)})\n\n"
    text += DISCLAIMER + "\n"
    return text


def run(output_dir: str = common.DEFAULT_OUTPUT_DIR) -> List[Dict[str, str]]:
    services, target = load_service_results(output_dir)
    os_info = load_os_results(output_dir)
    findings = analyze(services, os_info)

    text = render_results(findings, target)
    print(text)
    path = common.write_text(output_dir, TXT_FILE, text)
    common.write_json(
        output_dir,
        JSON_FILE,
        {"target": target, "timestamp": common.timestamp(), "findings": findings},
    )
    print(f"Results saved to {path}")
    return findings


def main() -> int:
    """Standalone entry point: python3 -m scanner.risk_analysis"""
    return common.run_cli(lambda: run(common.DEFAULT_OUTPUT_DIR))


if __name__ == "__main__":
    sys.exit(main())
