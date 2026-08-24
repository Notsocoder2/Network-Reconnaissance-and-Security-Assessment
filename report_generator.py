import os

def read_file(filename):

    file_path = os.path.join("results", filename)

    if not os.path.exist(file_path):
        return f"{filename} not found.\n"
    
    with open(file_path, "r") as file:
        return file.read()
    
def generate_report():

    report = ""

    report += "=" * 70 + "\n"
    report += "NETWORK RECONNAISSANCE AND SECURITY ASSESSMENT REPORT\n"
    report += "=" * 70 + "\n\n"

    report += "1. HOST DISCOVERY\n"
    report += "-" * 70 + "\n"
    report += read_file("host_discovery.txt")
    report += "\n\n"

    report += "2. PING SWEEP\n"
    report += "-" * 70 + "\n"
    report += read_file("ping_sweep.txt")
    report += "\n\n"

    report += "3. SERVICE DETECTION\n"
    report += "-" * 70 + "\n"
    report += read_file("service_detection.txt")
    report += "\n\n"

    report += "4. OS DETECTION\n"
    report += "-" * 70 + "\n"
    report += read_file("os_detection.txt")
    report += "\n\n"

    report += "5. RISK ANALYSIS\n"
    report += "-" * 70 + "\n"
    report += read_file("risk_analysis.txt")
    report += "\n"

    return report

def display_report(report):

    print("\n")
    print("=" * 70)
    print("FINAL NETWORK ASSESSMENT REPORT")
    print("=" * 70)
    print(report)

def save_report(report):

    os.makedirs("results", exist_ok=True)

    file_path = os.path.join(
        "results",
        "network_assessment_report.txt"
    )

    with open(file_path, "w") as file:
        file.write(report)

    print(f"\nReport saved to: {file_path}")

def main():

    print("\nGenerating Final Assessment Report...")

    report = generate_report()

    display_report(report)

    save_report(report)

if __name__ == "__main__":
    main()