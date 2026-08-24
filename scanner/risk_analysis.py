import os

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

def load_service_results():

    file_path = os.path.join(

        "results",
        "service_detection.txt"
    )

    services = []

    if not os.path.exists(file_path):

        print("Service Detection Results Not Found.")

        return services
    
    with open(file_path, "r") as file:

        lines = file.readlines()

    current_service = {}

    for line in lines:

        line = line.strip()

        if line.startswith("Port:"):

            current_service["Port"] = line.split(":", 1)[1].strip()

        elif line.startswith("State:"):

            current_service["State"] = line.split(":", 1)[1].strip()

        elif line.startswith("Service:"):

            current_service["Service"] = line.split(":", 1)[1].strip().lower()

        elif line.startswith("Version:"):

            current_service["Version"] = line.split(":", 1)[1].strip()

        elif line.startswith("----------------------------------------"):

            services.append(current_service)

            current_service = {}

    if current_service:

        services.append(current_service)

    return services


def load_os_results():

    file_path = os.path.join(
        "results",
        "os_detection.txt"
    )

    os_info = {}

    if not os.path.exists(file_path):

        print("OS Detection Results Not Found.")

        return os_info

    with open(file_path, "r") as file:

        lines = file.readlines()

    for line in lines:

        line = line.strip()

        if line.startswith("Running:"):

            os_info["Running"] = line.split(":", 1)[1].strip()

        elif line.startswith("OS Details:"):

            os_info["OS Details"] = line.split(":", 1)[1].strip()

        elif line.startswith("Device Type:"):

            os_info["Device Type"] = line.split(":", 1)[1].strip()

        elif line.startswith("Network Distance:"):

            os_info["Network Distance"] = line.split(":", 1)[1].strip()

    return os_info


def analyze_services(services):

    findings = []

    total_risks = 0

    for service in services:

        service_name = service["Service"].lower()

        if service_name in RISK_DATABASE:

            risk = RISK_DATABASE[service_name]

            findings.append({

                "Type": "Service",

                "Name": service_name,

                "Port": service["Port"],

                "Level": risk["level"],

                "Risk": risk["risk"],

                "Recommendation": risk["recommendation"]

            })

            total_risks += 1

    return findings, total_risks

def analyze_os(os_info):

    findings = []

    total_reisks = 0

    running = os_info.get("Running", "").lower()

    if "windows" in running:

        findings.append({

            "Type": "Operating System",

            "Name": os_info["Running"],

            "Level": "Medium",

            "Risk": "Windows systems must be regularly updated to prevent exploitation of known vulnerabilities.",

            "Recommendation": "Enable automatic updates, keep Windows Defender active, and install security patches regularly."

        })

        total_risks += 1

    elif "linux" in running:

        findings.append({

            "Type": "Operating System",

            "Name": os_info["Running"],

            "Level": "Low",

            "Risk": "Outdated Linux packages and unnecessary services may introduce security vulnerabilities.",

            "Recommendation": "Keep packages updated and disable unnecessary services."

        })

        total_risks += 1

    else:

        findings.append({

            "Type": "Operating System",

            "Name": "Unknown",

            "Level": "Unknown",

            "Risk": "Operating system could not be identified.",

            "Recommendation": "Perform additional scanning or verify firewall settings."

        })

        total_risks += 1

    return findings, total_risks


def display_results(findings):

    print("\n")
    print("=" * 60)
    print("RISK ANALYSIS RESULTS")
    print("=" * 60)

    if not findings:

        print("No risks identified.")

        return

    for count, finding in enumerate(findings, start=1):

        print(f"\nRisk {count}")
        print("-" * 60)

        print(f"Type           : {finding['Type']}")
        print(f"Name           : {finding['Name']}")

        if finding["Type"] == "Service":
            print(f"Port           : {finding['Port']}")

        print(f"Risk Level     : {finding['Level']}")
        print(f"Risk           : {finding['Risk']}")
        print(f"Recommendation : {finding['Recommendation']}")

    print("\n")
    print("=" * 60)
    print(f"Total Risks Identified : {len(findings)}")
    print("=" * 60)


def save_results(findings):

    os.makedirs("results", exist_ok=True)

    file_path = os.path.join(
        "results",
        "risk_analysis.txt"
    )

    with open(file_path, "w") as file:

        file.write("RISK ANALYSIS RESULTS\n")
        file.write("=" * 60 + "\n\n")

        if not findings:

            file.write("No risks identified.\n")

        else:

            for count, finding in enumerate(findings, start=1):

                file.write(f"Risk {count}\n")
                file.write("-" * 60 + "\n")

                file.write(f"Type: {finding['Type']}\n")
                file.write(f"Name: {finding['Name']}\n")

                if finding["Type"] == "Service":
                    file.write(f"Port: {finding['Port']}\n")

                file.write(f"Risk Level: {finding['Level']}\n")
                file.write(f"Risk: {finding['Risk']}\n")
                file.write(f"Recommendation: {finding['Recommendation']}\n")
                file.write("\n")

            file.write("=" * 60 + "\n")
            file.write(f"Total Risks Identified: {len(findings)}\n")

    print(f"\nResults saved to: {file_path}")


def main():

    print("\nLoading Service Detection Results...")

    services = load_service_results()

    print("Loading OS Detection Results...")

    os_info = load_os_results()

    print("\nAnalyzing Services...")

    service_findings, service_risks = analyze_services(services)

    print("Analyzing Operating System...")

    os_findings, os_risks = analyze_os(os_info)

    findings = service_findings + os_findings

    total_risks = service_risks + os_risks

    display_results(findings)

    save_results(findings)

    print(f"\nAnalysis Complete. Total Risks Found: {total_risks}")
