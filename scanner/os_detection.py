import ipaddress
import os
import re
import subprocess

def get_target():

    while True:
        target = input("Enter Target IP:").strip()

        try:

            ipaddress.ip_address(target)

            return target
        except ValueError:
            print("Invalid IP address. Try Again")


def run_os_detection(target):

    print("\nRunning Nmap OS Detection...\n")

    try:

        result = subprocess.run(
            [
                "sudo",
                "nmap",
                "-O",
                target
            ],

            capture_output=True,
            text=True,
            timeout=120
        )

        return result.stdout
    
    except subprocess.TimeoutExpired:

        print("OS Detection Timed Out.")
        return ""
    
    except FileNotFoundError:
        print("Nmap is not installed.")

        return ""
    
    except Exception as e:

        print(f"Error : {e}")

        return ""
    
def extract_os_info(output):
    os_info = {

        "Running": "Unknown",
        "OS Details": "Unknown",
        "Device Type": "Unknown",
        "Network Distance": "Unknown"
    }

    running_match = re.search(r"running:\s*(.*)", output)

    if running_match:

        os_info["Running"] = running_match.group(1).strip()

    details_match = re.search(r"OS details:\s*(.*)", output)

    if details_match:

        os_info["OS Details"] = details_match.group(1).strip()

    device_match = re.search(r"Device type:\s*(.*)", output)

    if device_match:

        os_info["Device Type"] = device_match.group(1).strip()

    distance_match = re.search(r"Network Distance:\s*(.*)", output)

    if distance_match:

        os_info["Network Distance"] = distance_match.group(1).strip()

    return os_info

def display_os_info(os_info):
    print("\nOS Detection Results\n")

    print("-" * 50)

    print(f"RUnning           :{os_info['Running']}")

    print(f"OS Details        : {os_info['OS Details']}")

    print(f"Device Type       : {os_info['Device Type']}")

    print(f"Network Distance  : {os_info['Network Distance']}")

def save_results(os_info):

    os.makedirs("results", exist_ok=True)

    file_path = os.path.join(
        "results",
        "os_detection.txt"
    )

    with open(file_path, "w") as file:

        file.write("OS DETECTION RESULTS\n")
        file.write("=" * 60 + "\n\n")

        file.write(f"Running: {os_info['Running']}\n")
        file.write(f"OS Details: {os_info['OS Details']}\n")
        file.write(f"Device Type: {os_info['Device Type']}\n")
        file.write(f"Network Distance: {os_info['Network Distance']}\n")

    print(f"\nResults saved to {file_path}")


def main():
    target = get_target()

    print("\nValid Target Found")

    print(target)

    output = run_os_detection(target)

    os_info = extract_os_info(output)

    display_os_info(os_info)

    save_results(os_info)


if __name__ == "__main__":

    main()

