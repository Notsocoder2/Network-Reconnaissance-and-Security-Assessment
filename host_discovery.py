import ipaddress
import os
import subprocess
import re


def get_network():

    while True:
        network = input("Enter subnet: ").strip()
        try:
            subnet = ipaddress.ip_network(network, strict=False)
            return subnet
        except ValueError:
            print("Invalid subnet. Try Again.")

def run_netdiscover(subnet):
    print("\nRunning Netdiscover...\n")

    try:
        result = subprocess.run(
            [
                "sudo",
                "netdiscover",
                "-r",
                str(subnet)

            ],
            capture_output=True,
            text=True,
            timeout=30
        )

        return result.stdout
    except subprocess.TimeoutExpired:

        print("Netdiscover scan timed out. ")

        return ""
    
    except FileNotFoundError:

        print("Netdiscover is not installed.")

        return ""
    except Exception as e:

        print(f"Error: {e}")

        return ""
    

def extract_hosts(output):

    hosts = []

    pattern = r"(\d+\.\d+\.\d+\.\d+)\s+([0-9A-Fa-f:]{17})"
    matches = re.findall(pattern, output)

    for ip, mac in matches:

        host = {

            "IP": ip,

            "MAC": mac

        }

        hosts.append(host)

    return hosts


def display_hosts(hosts):

    print("\nDiscovered Hosts\n")

    if not hosts:

        print("No hosts found.")

        return

    print("{:<18}{}".format("IP Address", "MAC Address"))

    print("-" * 40)

    for host in hosts:

        print("{:<18}{}".format(host["IP"], host["MAC"]))


def save_results(hosts):

    os.makedirs("results", exist_ok=True)

    file_path = os.path.join("results", "host_discovery.txt")

    with open(file_path, "w") as file:

        file.write("HOST DISCOVERY RESULTS\n")

        file.write("-" * 40 + "\n")

        if hosts:

            for host in hosts:

                file.write(f"{host['IP']:<18}{host['MAC']}\n")

            file.write("\n")

            file.write(f"Total Hosts Found: {len(hosts)}\n")

        else:

            file.write("No hosts found.\n")

    print(f"\nResults saved to {file_path}")



def main():

    subnet = get_network()

    print("\nValid network found")
    print(subnet)

    output = run_netdiscover(subnet)

    hosts = extract_hosts(output)

    display_hosts(hosts)

    save_results(hosts)
  

if __name__ == "__main__":

    main()
