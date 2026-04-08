# Subnet Discovery Utility

A lightweight, robust command-line utility built with Python and Scapy to perform localized Layer 2 network discovery via ARP sweeping.

## Overview
While standard tools like Nmap are heavy and noisy, this utility provides a stealthy, fast way to map a local collision domain or subnet by relying entirely on Address Resolution Protocol (ARP) broadcasts. It is designed to be easily integrated into larger automation workflows, offering JSON output support.

## Features
* **CIDR Support:** Accepts single IP targets or full CIDR blocks (e.g., `10.0.0.0/24`).
* **Automation Ready:** Use the `--json` flag to output pure JSON to standard out, allowing the data to be piped into `jq`, written to an API, or consumed by automation platforms like Ansible.
* **Graceful Exception Handling:** Catches permission errors and network timeouts without throwing raw Python tracebacks to the terminal.

## Installation

```bash
git clone [https://github.com/yourusername/subnet-discovery.git](https://github.com/yourusername/subnet-discovery.git)
cd subnet-discovery
pip install scapy


Usage

Note: Because this tool crafts custom Ethernet frames, it must be run with elevated privileges (sudo on Linux/macOS, or as Administrator on Windows).

Standard Human-Readable Output:
sudo python subnet_discovery.py --target 192.168.1.0/24

JSON Output for Pipelines:
sudo python subnet_discovery.py -t 10.10.10.0/24 --json > live_hosts.json

Available Arguments

    -t, --target: (Required) Target IP or CIDR range.

    -j, --json: (Optional) Output results in JSON format.

    --timeout: (Optional) Adjust the timeout in seconds for slow networks.