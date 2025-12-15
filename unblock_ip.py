#!/usr/bin/env python3
"""
Script to unblock an IP address from the SOC AI Agents system
Usage: python unblock_ip.py <IP_ADDRESS>
Example: python unblock_ip.py 192.168.1.100
"""

import sys
import os
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from security.real_remediation import RealRemediationEngine

def unblock_ip(ip_address: str):
    """Unblock an IP address"""
    print(f"Attempting to unblock IP: {ip_address}")

    # Initialize remediation engine
    engine = RealRemediationEngine()

    # Check if IP is currently blocked
    if ip_address in engine.blocked_ips:
        print(f"✓ IP {ip_address} is currently blocked")
        print(f"  Blocked at: {engine.blocked_ips[ip_address].get('timestamp', 'unknown')}")
        print(f"  Reason: {engine.blocked_ips[ip_address].get('reason', 'unknown')}")

        # Unblock the IP
        if engine.unblock_ip(ip_address):
            print(f"\n✅ Successfully unblocked IP: {ip_address}")
            return True
        else:
            print(f"\n❌ Failed to unblock IP: {ip_address}")
            return False
    else:
        print(f"ℹ IP {ip_address} is not currently blocked")
        return False

def list_blocked_ips():
    """List all currently blocked IPs"""
    print("Currently blocked IP addresses:")
    print("=" * 70)

    engine = RealRemediationEngine()

    if not engine.blocked_ips:
        print("No IPs are currently blocked")
        return

    for ip, info in engine.blocked_ips.items():
        print(f"\n📍 IP: {ip}")
        print(f"   Reason: {info.get('reason', 'unknown')}")
        print(f"   Blocked at: {info.get('timestamp', 'unknown')}")
        if 'duration' in info:
            print(f"   Duration: {info['duration']} seconds")
        if 'alert_id' in info:
            print(f"   Alert ID: {info['alert_id']}")

def main():
    """Main function"""
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python unblock_ip.py <IP_ADDRESS>    - Unblock a specific IP")
        print("  python unblock_ip.py --list          - List all blocked IPs")
        print("\nExamples:")
        print("  python unblock_ip.py 192.168.1.100")
        print("  python unblock_ip.py 10.0.0.50")
        print("  python unblock_ip.py --list")
        sys.exit(1)

    if sys.argv[1] == "--list":
        list_blocked_ips()
    else:
        ip_address = sys.argv[1]
        unblock_ip(ip_address)

if __name__ == "__main__":
    main()
