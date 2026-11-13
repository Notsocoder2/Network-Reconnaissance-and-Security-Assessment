# Network Reconnaissance and Security Assessment

A Python tool that automates a basic network reconnaissance workflow on a lab network: host discovery, ping sweep, service/version detection, OS fingerprinting, rule-based risk analysis and a combined text report. It orchestrates **Nmap** and **Netdiscover** and was built as a cybersecurity minor project.

> **Authorized use only.** Run this tool only against systems and networks you own or have explicit written permission to test. Unauthorized scanning may be illegal. The tool asks you to confirm authorization before every run, refuses public address space by default, and caps the size of the subnet it will scan.

---

## Features

- **Host discovery** (ARP) with Netdiscover
- **Ping sweep** of live hosts with Nmap
- **Service and version detection** (`nmap -sV`) for a port or port range
- **OS fingerprinting** (`nmap -O`)
- **Risk analysis** that maps open services and the detected OS to known risks with recommendations, sorted by severity
- **Combined report** (`network_assessment_report.txt`) plus machine-readable JSON per step
- **Safety controls**: authorization confirmation, private/lab address space by default, subnet size limit, strict input validation, no shell execution, audit log
- **Honest status reporting**: a failed step (missing tool, no root, timeout) is reported as failed instead of "no results"

## Requirements

- Linux (developed on Kali Linux)
- Python 3.8 or newer (standard library only; no `pip` packages are required)
- [Nmap](https://nmap.org/) and [Netdiscover](https://github.com/netdiscover-scanner/netdiscover)
- Root privileges for host discovery and OS detection (`sudo`)

```bash
sudo apt install nmap netdiscover
```

Wireshark is not used by the scripts. It can still be used separately to capture traffic while a scan runs.

## Installation

```bash
git clone https://github.com/Notsocoder2/Network-Reconnaissance-and-Security-Assessment.git
cd Network-Reconnaissance-and-Security-Assessment
```

`pip install -r requirements.txt` is safe to run but installs nothing; the file documents the external tools.

## Usage

Run the full assessment (host discovery and OS detection need root):

```bash
sudo python3 main.py --subnet 192.168.56.0/24 --target 192.168.56.101 --ports 1-1024
```

Missing `--subnet` / `--target` values are requested interactively, and you are asked to type `yes` to confirm authorization. Use `--authorized` to skip that prompt in scripts (only if you really are authorized).

Other examples:

```bash
# Scan one host only, without root (skips steps that need it)
python3 main.py --target 192.168.56.101 --ports 22 \
    --skip host-discovery --skip ping-sweep --skip os-detection --authorized

# Larger lab network (default limit is 1024 addresses)
sudo python3 main.py --subnet 10.10.0.0/20 --max-hosts 4096 --target 10.10.0.5

# Run a single module interactively
python3 -m scanner.ping_sweep
```

### Options

| Option | Description |
| --- | --- |
| `--subnet CIDR` | Subnet for host discovery and ping sweep, e.g. `192.168.1.0/24` |
| `--target IP` | Single IPv4 address for service and OS detection |
| `--ports SPEC` | Port or range, e.g. `22` or `1-1024` (default `1-1024`) |
| `--skip STEP` | Skip `host-discovery`, `ping-sweep`, `service-detection` or `os-detection` (repeatable) |
| `--output-dir DIR` | Where results and the log are written (default `results/`) |
| `--timeout SECONDS` | Per-step command timeout (default 300) |
| `--max-hosts N` | Largest subnet, in addresses, that may be scanned (default 1024) |
| `--allow-public` | Permit non-private address space (requires written authorization) |
| `--authorized` | Confirm authorization without the interactive prompt |
| `-v`, `--verbose` | Show informational log messages |

The exit code is `0` on success, `1` if any step failed, and `2` if the scope was rejected or authorization was not confirmed.

## Output

Files are written to `results/` (created with owner-only permissions and ignored by git, because scan data can be sensitive):

```text
host_discovery.txt / .json
ping_sweep.txt / .json
service_detection.txt / .json
os_detection.txt / .json
risk_analysis.txt / .json
network_assessment_report.txt
assessment.log            # audit trail: scope, authorization, commands run
```

Each full run first removes the previous output files of this tool, so an old scan never leaks into a new report. If you run with `sudo`, the directory is owned by root; use `sudo chown -R "$USER" results` to read it as a normal user.

## Project Structure

```text
.
├── main.py                    # CLI: validation, authorization, orchestration
├── requirements.txt           # documents external tools (no pip packages)
├── scanner/
│   ├── common.py              # scope validation, safe command runner, output helpers
│   ├── host_discovery.py      # Netdiscover ARP discovery
│   ├── ping_sweep.py          # Nmap ping sweep
│   ├── service_detection.py   # Nmap service/version detection
│   ├── os_detection.py        # Nmap OS fingerprinting
│   ├── risk_analysis.py       # rule-based risk database and analysis
│   └── report_generator.py    # combined report
└── tests/test_scanner.py      # offline unit tests (no network traffic)
```

## Risk Analysis

Open services are matched by name against a built-in table (FTP, Telnet, SSH, HTTP/HTTPS, SMTP, DNS, SMB, MySQL, PostgreSQL, MongoDB, Redis, RDP, SNMP, VNC), including Nmap's alternate names such as `microsoft-ds` (SMB) and `ms-wbt-server` (RDP). Closed and filtered ports are ignored. The detected OS family adds a general hardening note.

Findings are **indicators to review, not confirmed vulnerabilities**: the analysis does not check software versions or look up CVEs.

## Running the Tests

```bash
python3 -m unittest discover -v
```

The tests use canned Nmap/Netdiscover output and never touch the network.

## Limitations

- IPv4 only.
- Netdiscover (ARP) only sees hosts on the local layer-2 segment.
- Nmap's human-readable output is parsed; unusual Nmap versions or output formats may need parser updates.
- Service detection scans TCP only. OS detection gives Nmap's best guess and needs root.
- Risk analysis is name-based; there is no CVE or version matching yet.
- Steps run sequentially and are not multi-threaded.
- Not a substitute for a professional penetration test or vulnerability scanner.

## Future Improvements

- Automatic network topology generation
- CVE lookup for detected service versions
- HTML and PDF report export
- Parallel scanning
- GUI

