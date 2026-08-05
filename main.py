from scanner.host_discovery import main as host_discovery
from scanner.ping_sweep import main as ping_sweep
from scanner.service_detection import main as service_detection
from scanner.os_detection import main as os_detection
from scanner.risk_analysis import main as risk_analysis
from scanner.report_generator import main as report_generator


def main():

    print("=" * 70)
    print("NETWORK RECONNAISSANCE AND SECURITY ASSESSMENT")
    print("=" * 70)

    print("\n[1/6] Running Host Discovery...")
    host_discovery()

    print("\n[2/6] Running Ping Sweep...")
    ping_sweep()

    print("\n[3/6] Running Service Detection...")
    service_detection()

    print("\n[4/6] Running OS Detection...")
    os_detection()

    print("\n[5/6] Running Risk Analysis...")
    risk_analysis()

    print("\n[6/6] Generating Final Report...")
    report_generator()

    print("\n" + "=" * 70)
    print("ASSESSMENT COMPLETED SUCCESSFULLY")
    print("=" * 70)

    print("\nGenerated Files:")

    print("✓ results/host_discovery.txt")
    print("✓ results/ping_sweep.txt")
    print("✓ results/service_detection.txt")
    print("✓ results/os_detection.txt")
    print("✓ results/risk_analysis.txt")
    print("✓ results/network_assessment_report.txt")


if __name__ == "__main__":
    main()