import ipaddress
import os
import re
import subprocess



def get_network():

    while True:

        network = input("Enter subnet (Example: 192.168.1.0/24): ").strip()

        try:

            subnet = ipaddress.ip_network(network, strict=False)

            return subnet

        except ValueError:

            print("Invalid subnet. Try Again.")

def run_pingsweep(subnet):
    print("\nRunning Ping Sweep.....\n")

    try:
        result = subprocess.run(
            [
                "nmap",
                "-sn",
                str(subnet)
            ],
            capture_output = True,
            text = True,
            timeout = 60
        )

        return result.stdout
    except subprocess.TimeoutExpired:

        print("Ping Sweep Timed out.")

        return ""
    
    except FileNotFoundError:

        print("Nmap is not Installed.")

        return ""
    
    except Exception as e:
        print(f"Error : {e}")
        return ""
    


def extract_hosts(output):

    hosts = []

    host_pattern = r"Nmap scan report for (.+)"
    ip_pattern = r"\((\d+\.\d+\.\d+\.\d+)\)"

    lines = output.splitlines()

    current_host = {}

    for line in lines:

        if "Nmap scan report for" in line:

            current_host = {}

            ip_match = re.search(ip_pattern, line)

            if ip_match:

                current_host["IP"] = ip_match.group(1)

                hostname = line.replace(
                    f"Nmap scan report for {ip_match.group(0)}",
                    ""
                ).strip()

                current_host["Hostname"] = hostname if hostname else "N/A"

            else:

                current_host["IP"] = line.split()[-1]

                current_host["Hostname"] = "N/A"

        elif "Host is up" in line:

            current_host["Status"] = "Up"

            hosts.append(current_host)

    return hosts

def display_hosts(hosts):
    print("\nLive Hosts\n")

    if not hosts:
        print("No live Hosts found.")

        return
    print("{:<18}{:<30}{}".format("IP Address", "Hostname", "Status"))

    print("-" * 65)

    for host in hosts:
        
        print(

            "{:<18}{:<30}{}".format(

                host["IP"],

                host["Hostname"],

                host["Status"]

            )

        )

def save_results(hosts):

    os.makedirs("results", exist_ok = True)

    file_path = os.path.join("results", "ping_sweep.txt")

    with open(file_path, "w") as file:

        file.write("PING SWEEP RESULTS\n")

        file.write("-"*60 +"\n")
        
        if hosts:
            file.write("{:<18}{:<30}{}\n".format(

                "IP Address",

                "Hostname",

                "Status"

            ))

            file.write("-"*60 + "\n")

            for host in hosts:
                file.write(

                    "{:<18}{:<30}{}\n".format(

                        host["IP"],

                        host["Hostname"],

                        host["Status"]

                    )

                )

            file.write("\n")

            file.write(f"Total Live Hosts: {len(hosts)}\n")

        else:

            file.write("No Live Hosts Found.\n")

    print(f"\nResults saved to {file_path}")

    

def main():

    subnet = get_network()

    print("\nValid Network Found")

    print(subnet)

    output = run_pingsweep(subnet)

    hosts = extract_hosts(output)

    display_hosts(hosts)

    save_results(hosts)
    


if __name__ == "__main__":

    main()