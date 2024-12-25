# ReconXplorer

**ReconXplorer** is a multi-functional reconnaissance tool designed for penetration testers, bug bounty hunters, and cybersecurity enthusiasts. It combines subdomain resolution, reverse DNS lookups, port scanning, and WHOIS lookups into a single script, providing detailed insights about target hosts.

## Features

1. **Hostname Resolution**: Resolves hostnames to IP addresses.
2. **Reverse DNS Lookup**: Retrieves the hostname associated with an IP address.
3. **Port Scanning**: Scans for common HTTP/HTTPS ports and identifies their status (open, closed, no response).
4. **WHOIS Lookup**: Extracts the `netname` field for resolved IPs, providing additional context about the IP's ownership.
5. **Tabular Output**: Displays results in a clean, easy-to-read table format.
6. **Customizable Tasks**: Allows users to select specific functionalities for faster and targeted reconnaissance.

## Installation

### Prerequisites
- Python 3.x
- Required libraries: `scapy`, `colorama`, `tabulate`, `subprocess`, and `python-whois`

### Install Dependencies
```bash
pip install scapy colorama tabulate python-whois
```

### Clone the Repository
```bash
git clone https://github.com/your-username/ReconXplorer.git
cd ReconXplorer
```

## Usage

Run the script with an input file containing a list of hostnames or IP addresses:
```bash
python3 resolve.py <filename>
```

### Example Input File
`hosts.txt`:
```
example.com
google.com
nonexistenthost.xyz
```

### Running the Script
```bash
python3 resolve.py hosts.txt
```

### User Options
When you run the script, you will be prompted to select tasks:
1. Resolve hostnames to IP addresses.
2. Perform reverse DNS lookups.
3. Scan ports on resolved IPs.
4. Perform WHOIS lookup for netname.
5. Display results in tables.
6. Include specific outputs (e.g., port results, resolved/unresolved hosts).

## Output

### Resolved Hostnames Table
Displays hostnames resolved to IP addresses with their associated `netname` from WHOIS lookup:
```
+------------------------+----------------+-------------+
| Hostname               | IP Address     | Netname     |
+------------------------+----------------+-------------+
| example.com            | 93.184.216.34 | EXAMPLE-NET |
| nonexistenthost.xyz    | N/A            | Unknown     |
+------------------------+----------------+-------------+
```

### Port Scan Results
Displays the status of scanned ports:
```
+----------------+----------------+-------+--------------+
| IP Address     | Hostname       | Port  | Status       |
+----------------+----------------+-------+--------------+
| 93.184.216.34  | example.com    | 80    | Open         |
| 93.184.216.34  | example.com    | 443   | Closed       |
+----------------+----------------+-------+--------------+
```

## License
This project is licensed under the MIT License. See the `LICENSE` file for details.

## Contributing
Contributions are welcome! Please open an issue or submit a pull request to suggest improvements or report bugs.

## Acknowledgments
Special thanks to the open-source community for providing the tools and libraries that make ReconXplorer possible.

Special acknowledgment to ChatGPT for assisting in designing and refining the tool, as well as crafting this documentation.

