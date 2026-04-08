"""
Subnet Discovery Utility
A CLI tool that performs ARP-based local network discovery and outputs structured data.
"""
import argparse
import json
import logging
import sys
from typing import List, Dict

# Scapy throws warnings if IPv6 routes aren't perfect; this suppresses them
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import ARP, Ether, srp

# Configure standard logging for CLI
logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)

class NetworkScanner:
    def __init__(self, timeout: int = 2):
        self.timeout = timeout

    def scan_subnet(self, target_cidr: str) -> List[Dict[str, str]]:
        """
        Executes an ARP sweep across the specified CIDR block.
        """
        # Formulate the Layer 2 Broadcast and Layer 3 ARP Request
        arp_request = ARP(pdst=target_cidr)
        ether_broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether_broadcast / arp_request

        try:
            # srp requires elevated privileges to send crafted packets
            answered, _ = srp(packet, timeout=self.timeout, verbose=False)
        except PermissionError:
            logger.error("[!] Permission Denied: This tool requires Administrator/root privileges to forge Layer 2 packets.")
            sys.exit(1)
        except Exception as e:
            logger.error(f"[!] An unexpected network error occurred: {e}")
            sys.exit(1)

        # Parse responses into a structured format
        devices = []
        for sent, received in answered:
            devices.append({
                'ip': received.psrc, 
                'mac': received.hwsrc
            })
            
        return devices

def main():
    parser = argparse.ArgumentParser(description="ARP Network Scanner for Subnet Discovery")
    parser.add_argument("-t", "--target", required=True, help="Target IP or CIDR range (e.g., 192.168.1.0/24)")
    parser.add_argument("-j", "--json", action="store_true", help="Output results in JSON format for automation pipelines")
    parser.add_argument("--timeout", type=int, default=2, help="Seconds to wait for ARP replies (Default: 2)")
    
    args = parser.parse_args()

    # Initialize and execute
    if not args.json:
        logger.info(f"[*] Initiating ARP sweep on {args.target}...")
        
    scanner = NetworkScanner(timeout=args.timeout)
    discovered_devices = scanner.scan_subnet(args.target)

    # Handle Output
    if not discovered_devices:
        if not args.json:
            logger.warning("[-] No devices responded to the ARP requests. Verify subnet and interface routing.")
        else:
            print(json.dumps([]))
        sys.exit(0)

    if args.json:
        # Dump structured data to standard out for piping
        print(json.dumps(discovered_devices, indent=4))
    else:
        # Print human-readable table
        logger.info("\n[+] Discovery Complete. Live Hosts Found:")
        logger.info("-" * 45)
        logger.info(f"{'IP Address':<20} {'MAC Address':<20}")
        logger.info("-" * 45)
        for device in discovered_devices:
            logger.info(f"{device['ip']:<20} {device['mac']:<20}")
        logger.info("-" * 45)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("\n[-] Scan aborted by user.")
        sys.exit(0)