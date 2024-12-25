#!/usr/bin/env python3

import socket
import sys
from scapy.all import sr1, IP, TCP
from colorama import Fore, Style, init
from tabulate import tabulate
import subprocess

# Initialize colorama for cross-platform support
init(autoreset=True)

class ReconXplorer:
    def __init__(self, text_file, options):
        self.results = []  # To store port scan results
        self.resolved_hosts = []  # To store resolved hostnames
        self.unresolved_hosts = []  # To store unresolved hostnames

        for n in text_file:
            try:
                if options["resolve"]:
                    ip_address = socket.gethostbyname(n)
                    print(f"{Fore.YELLOW}{ip_address} :\t{Style.DIM}{n}")
                    
                    # Perform WHOIS Lookup for netname
                    netname = self.get_netname(ip_address) if options["whois_lookup"] else "N/A"
                    
                    # Add to resolved hosts
                    self.resolved_hosts.append([f"{Style.DIM}{n}", f"{Fore.YELLOW}{ip_address}", netname])

                    if options["reverse_dns"]:
                        try:
                            reverse_dns = socket.gethostbyaddr(ip_address)[0]
                            print(f"{Fore.CYAN}Reverse DNS Lookup: {reverse_dns}")
                        except socket.herror:
                            print(f"{Fore.YELLOW}Reverse DNS Lookup: Not available")

                    if options["scan_ports"]:
                        print(f"{Fore.MAGENTA}Scanning ports on {ip_address}...")
                        self.scan_ports(ip_address, n)

            except socket.gaierror:
                if options["resolve"]:
                    print(f"{Fore.RED}Hostname Not Live: \t{n}")
                self.unresolved_hosts.append([f"{Fore.RED}{n}"])
            except Exception as e:
                print(f"{Fore.RED}Unexpected error: {e}")
                continue

        if options["display_results"]:
            self.display_results(options)

    def scan_ports(self, ip, hostname):
        ports = [80, 443, 8443, 9090, 8080, 8081, 9443, 8181]
        for port in ports:
            try:
                pkt = IP(dst=ip) / TCP(dport=port, flags="S")  # SYN Packet
                response = sr1(pkt, timeout=1, verbose=0)
                if response and response.haslayer(TCP):
                    if response[TCP].flags == "SA":  # SYN-ACK received
                        status = f"{Fore.GREEN}Open"
                    elif response[TCP].flags == "RA":  # RST-ACK received
                        status = f"{Fore.RED}Closed"
                else:
                    status = f"{Fore.RED}No Response"

                # Append result to the results table
                self.results.append([f"{Fore.YELLOW}{ip}", f"{Style.DIM}{hostname}", port, status])

            except Exception as e:
                print(f"{Fore.RED}Error scanning port {port} on {ip}: {e}")

    def get_netname(self, ip):
        try:
            # Run the 'whois' command
            result = subprocess.run(["whois", ip], capture_output=True, text=True)
            whois_data = result.stdout

            # Look for 'netname' in the WHOIS response
            for line in whois_data.splitlines():
                if line.lower().startswith("netname"):
                    return line.split(":")[1].strip()

            return "Unknown"  # Default if 'netname' is not found
        except Exception as e:
            print(f"{Fore.RED}WHOIS Lookup failed for {ip}: {e}")
            return "Unknown"

    def display_results(self, options):
        if options["display_ports"]:
            print(f"\n{Fore.CYAN}Scan Results:")
            headers_ports = ["IP Address", "Hostname", "Port", "Status"]
            print(tabulate(self.results, headers=headers_ports, tablefmt="grid"))

        if options["display_resolved"]:
            print(f"\n{Fore.GREEN}Resolved Hostnames:")
            headers_resolved = ["Hostname", "IP Address", "Netname"]
            print(tabulate(self.resolved_hosts, headers=headers_resolved, tablefmt="grid"))

        if options["display_unresolved"]:
            print(f"\n{Fore.RED}Unresolved Hostnames:")
            headers_unresolved = ["Hostname"]
            print(tabulate(self.unresolved_hosts, headers=headers_unresolved, tablefmt="grid"))

# Menu for user options
def get_user_options():
    print(f"{Fore.CYAN}Select the tasks you want the script to perform:")
    options = {
        "resolve": input("Resolve hostnames to IP addresses? (y/n): ").strip().lower() == "y",
        "reverse_dns": input("Perform reverse DNS lookups? (y/n): ").strip().lower() == "y",
        "scan_ports": input("Scan ports on resolved IPs? (y/n): ").strip().lower() == "y",
        "whois_lookup": input("Perform WHOIS lookup for netname? (y/n): ").strip().lower() == "y",
        "display_results": input("Display results in tables? (y/n): ").strip().lower() == "y",
        "display_ports": input("Include port scan results in output? (y/n): ").strip().lower() == "y",
        "display_resolved": input("Include resolved hostnames in output? (y/n): ").strip().lower() == "y",
        "display_unresolved": input("Include unresolved hostnames in output? (y/n): ").strip().lower() == "y",
    }
    return options

if len(sys.argv) != 2:
    print(f"{Fore.RED}Usage: python3 resolve.py <filename>")
    sys.exit(1)

try:
    with open(sys.argv[1], "r") as txt_file:
        content_list = txt_file.readlines()
except FileNotFoundError:
    print(f"{Fore.RED}Error: File '{sys.argv[1]}' not found.")
    sys.exit(1)

# Clean up and process the content
final = [i.strip() for i in content_list]

# Get user options
user_options = get_user_options()

# Run the script with user-selected options
ReconXplorer(final, user_options)
