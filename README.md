# Network Reconnaissance and Security Assessment

A Python-based Network Reconnaissance and Security Assessment tool developed as a cybersecurity minor project.

The project performs host discovery, service enumeration, operating system fingerprinting, and risk analysis on a laboratory network using industry-standard tools such as **Nmap**, **Netdiscover**, and **Wireshark**.

---

## Objective

Assess the security posture of a laboratory network by identifying active hosts, enumerating exposed services, detecting operating systems, and generating security recommendations.

---

## Features

- Host Discovery using Netdiscover
- Live Host Detection (Ping Sweep)
- Service Detection using Nmap
- Operating System Fingerprinting
- Identification of Exposed Services
- Risk Analysis
- Security Recommendations
- Automatic Report Generation

---

## Technologies Used

- Python 3
- Kali Linux
- Nmap
- Netdiscover
- Wireshark

---

## Project Structure

```text
Network-Reconnaissance-and-Security-Assessment/

├── main.py
├── scanner/
├── results/
├── captures/
├── screenshots/
├── topology/
└── report/
```

---

## Modules

### Host Discovery

Discovers active devices in the local network using Netdiscover.

Output:

```
results/host_discovery.txt
```

---

### Ping Sweep

Checks which discovered hosts are reachable.

Output:

```
results/ping_sweep.txt
```

---

### Service Detection

Performs TCP SYN scanning and service/version detection using Nmap.

Output:

```
results/service_detection.txt
```

---

### OS Detection

Uses Nmap OS fingerprinting to identify the operating system.

Output:

```
results/os_detection.txt
```

---

### Risk Analysis

Analyzes detected services and operating systems to identify potential security risks and provides recommendations.

Output:

```
results/risk_analysis.txt
```

---

### Report Generator

Combines all scan results into a single assessment report.

Output:

```
results/network_assessment_report.txt
```

---

## Installation

Clone the repository

```bash
git clone <repository-url>
```

Move into the project directory

```bash
cd Network-Reconnaissance-and-Security-Assessment
```

Install dependencies

```bash
pip install -r requirements.txt
```

---

## Usage

Run the complete assessment

```bash
python3 main.py
```

---

## Expected Output

After execution the following files are generated:

```
results/

host_discovery.txt
ping_sweep.txt
service_detection.txt
os_detection.txt
risk_analysis.txt
network_assessment_report.txt
```

---

## Screenshots

Example screenshots are available in the `screenshots/` directory.

---

## Future Improvements

- Automatic network topology generation
- CVE lookup for detected service versions
- Export reports in HTML and PDF
- Multi-threaded scanning
- GUI interface

---

## Disclaimer

This project is intended **only for educational purposes and authorized security assessments**.

Do not scan systems or networks without explicit permission.

---

## Author

Dhruv Chauhan

Jaypee Institute of Information Technology

Electronics and Communication Engineering (Advanced Communication)
