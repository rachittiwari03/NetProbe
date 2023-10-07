# NetProbe: Simple Network Scanner
NetProbe is a lightweight network scanning tool built with Python and Scapy. It allows users to perform both ARP scans and TCP scans for network reconnaissance.

# Features:

# ARP Scan:

1. Discover devices on the local network by sending ARP requests.
2. Collect ARP replies to map IP addresses to MAC addresses.

# TCP Scan:

1. Identify open ports by sending TCP SYN packets to specified ports.
2. Collect SYN+ACK replies to determine accessible ports.

# Usage:

1. Choose between ARP and TCP scans using simple command-line arguments.
2. Perform an ARP scan with an IP address or range, e.g., python3 scanner.py ARP 192.168.1.1/24.
3. Conduct a TCP scan with an IP address and specific ports or a range, e.g., python3 scanner.py TCP 192.168.1.1 --range 0 1000.

Note: For UNIX-based systems, run the script as root (use sudo) for optimal functionality.

# Getting Started:

1. Clone the repository: "git clone https://github.com/rachittiwari03/NetProbe"
2. Navigate to the project directory: cd netprobe
3. Run the scanner: python3 scanner.py
