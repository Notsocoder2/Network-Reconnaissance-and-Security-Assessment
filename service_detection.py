import ipaddress
import os 
import subprocess

def get_target():

    while True:

        target = input("enter target IP: ").strip()

        try:

            ipaddress.ip_address(target)

            return target
        
        except ValueError:

            print("Invalid IP address. Try Again")
            

def get_port_range():

    while True:

        try:

            start_port = int(input("Enter starting port"))
            end_port = int(input("Enter ending port"))

            if start_port < 1 or end_port > 65535 or start_port> end_port:
                print("Invalid Port range. Try again.\n")

            else:
                return start_port,end_port
        
        except ValueError:

            print("Ports must be integers\n")


def run_service_detection(target,start_port,end_port):

    print("\nRunning Service Detection....\n")

    try:

        result = subprocess.run(
            [
                "sudo",
                "nmap",
                "-sV",
                target,
                "-p",
                f"{start_port}--{end_port}"
            ],

            capture_output=True,
            text=True,
            timeout=120
        )
        return result.stdout
    except subprocess.TimeoutExpired:

        print("Service Detection Timed out.")

        return ""
    
    except FileNotFoundError:
        print("Nmap is not installed.")

        return ""
    
    except Exception as e:
        print(f"Error :{e}")

        return ""


def extract_services(output):

    services = []

    lines = output.splitlines()

    for line in lines:

        if "/tcp" in line or "/udp" in line:

            parts = line.split()

            if len(parts) >=3:

                service = {

                    "Port": parts[0],
                    "State": parts[1],
                    "Service": parts[2],

                    "Version": " ".join(parts[3:]) if len(parts) > 3 else "Unknown"
                }

                services.append(service)

    return services

def display_services(services):
    print("\nSERVICE DETECTION RESULTS\n")

    if not services:

        print("No Services Detected.")

        return

    print("{:<12}{:<10}{:<15}{}".format(

        "Port",

        "State",

        "Service",

        "Version"

    ))

    print("-" * 80)

    for service in services:

        print(

            "{:<12}{:<10}{:<15}{}".format(

                service["Port"],

                service["State"],

                service["Service"],

                service["Version"]

            )

        )


def save_results(target, services):

    os.makedirs("results", exist_ok=True)

    file_path = os.path.join(

        "results",

        "service_detection.txt"

    )

    with open(file_path, "w") as file:

        file.write("SERVICE DETECTION RESULTS\n")
        file.write("=" * 60 + "\n\n")

        file.write(f"Target: {target}\n\n")

        if services:

            for service in services:

                file.write(f"Port: {service['Port']}\n")
                file.write(f"State: {service['State']}\n")
                file.write(f"Service: {service['Service']}\n")
                file.write(f"Version: {service['Version']}\n")
                file.write("-" * 40 + "\n")

        else:

            file.write("No Services Detected.\n")

    print(f"\nResults saved to {file_path}")


def main():

    target = get_target()

    start_port, end_port = get_port_range()

    output = run_service_detection(
        target,
        start_port,
        end_port
    )

    services = extract_services(output)

    display_services(services)

    save_results(

        target,

        services

    )
    
if __name__ == "__main__":

    main()




        
   
