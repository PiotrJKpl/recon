#!/usr/bin/env python3
"""
Network Reconnaissance Tool (Python Version)
Performs ICMP-based host discovery via ping sweep

AUTHORIZATION WARNING:
- Requires written authorization for penetration testing
- Unauthorized network scanning may be illegal
- Use only in lab environments or with explicit approval

Usage:
    python3 network_recon.py [network_prefix] [timeout_ms] [threads]
    Example: python3 network_recon.py 192.168.0 100 20
"""

import sys
import subprocess
import threading
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ANSI color codes
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
RESET = '\033[0m'


def print_header():
    """Display authorization warning and tool header"""
    print(f"{YELLOW}[*] Network Reconnaissance Tool (Python){RESET}")
    print(f"{RED}[!] WARNING: Ensure written authorization before scanning{RESET}")
    print(f"{YELLOW}[*] Unauthorized network scanning is illegal{RESET}\n")


def validate_authorization():
    """ACTION 1: Confirm authorization before proceeding"""
    print(f"{YELLOW}[*] ACTION 1: Authorization Check{RESET}")
    response = input(f"{YELLOW}[?] Do you have authorization? (yes/no): {RESET}").lower()
    if response not in ['yes', 'y']:
        print(f"{RED}[-] Scanning aborted - authorization required{RESET}")
        sys.exit(1)
    print(f"{GREEN}[+] Authorization confirmed{RESET}\n")


def ping_host(ip_address, timeout_ms=100):
    """
    ACTION 3: Ping a single host
    
    Args:
        ip_address: IP to ping
        timeout_ms: Timeout in milliseconds
    
    Returns:
        tuple: (ip_address, is_alive, response_time)
    """
    try:
        # Use ping command with timeout
        # macOS: ping -c 1 -W [timeout_ms]
        # Linux: ping -c 1 -W [timeout_ms]
        result = subprocess.run(
            ['ping', '-c', '1', '-W', str(timeout_ms), ip_address],
            capture_output=True,
            timeout=5
        )
        
        if result.returncode == 0:
            return (ip_address, True, "UP")
        else:
            return (ip_address, False, "DOWN")
            
    except subprocess.TimeoutExpired:
        return (ip_address, False, "TIMEOUT")
    except Exception as e:
        return (ip_address, False, f"ERROR: {str(e)}")


def discover_hosts(network_prefix, timeout_ms=100, max_threads=20):
    """
    ACTION 2: Perform parallel ping sweep across network
    
    Args:
        network_prefix: Network prefix (e.g., "192.168.0")
        timeout_ms: Timeout per ping in milliseconds
        max_threads: Maximum parallel threads
    
    Returns:
        list: List of active IP addresses
    """
    print(f"{YELLOW}[*] ACTION 2: Host Discovery via Ping Sweep{RESET}")
    print(f"{YELLOW}[*] Network: {network_prefix}.0/24 (254 hosts){RESET}")
    print(f"{YELLOW}[*] Timeout: {timeout_ms}ms per ping{RESET}")
    print(f"{YELLOW}[*] Threads: {max_threads}{RESET}")
    print(f"{YELLOW}[*] This may take 30-60 seconds...{RESET}\n")
    
    active_hosts = []
    
    # Generate list of IPs to scan
    ips_to_scan = [f"{network_prefix}.{i}" for i in range(1, 255)]
    
    # Use ThreadPoolExecutor for parallel pinging
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {
            executor.submit(ping_host, ip, timeout_ms): ip 
            for ip in ips_to_scan
        }
        
        completed = 0
        for future in as_completed(futures):
            completed += 1
            ip, is_alive, status = future.result()
            
            if is_alive:
                print(f"{GREEN}[+] {ip} is {status}{RESET}")
                active_hosts.append(ip)
            
            # Progress indicator every 50 hosts
            if completed % 50 == 0:
                print(f"{YELLOW}[*] Progress: {completed}/254{RESET}")
    
    return sorted(active_hosts)


def main():
    """Main execution flow"""
    parser = argparse.ArgumentParser(
        description='Network Reconnaissance Tool',
        epilog='Example: python3 network_recon.py 192.168.0 100 20'
    )
    parser.add_argument(
        'network',
        nargs='?',
        default='192.168.0',
        help='Network prefix (e.g., 192.168.0 for 192.168.0.0/24)'
    )
    parser.add_argument(
        '-t', '--timeout',
        type=int,
        default=100,
        help='Timeout per ping in milliseconds (default: 100)'
    )
    parser.add_argument(
        '-T', '--threads',
        type=int,
        default=20,
        help='Maximum parallel threads (default: 20)'
    )
    parser.add_argument(
        '--skip-auth',
        action='store_true',
        help='Skip authorization check (not recommended)'
    )
    
    args = parser.parse_args()
    
    # Display header
    print_header()
    
    # ACTION 1: Authorization check
    if not args.skip_auth:
        validate_authorization()
    else:
        print(f"{RED}[!] Warning: Skipping authorization check{RESET}\n")
    
    # ACTION 2: Host discovery
    try:
        start_time = datetime.now()
        active_hosts = discover_hosts(args.network, args.timeout, args.threads)
        elapsed = (datetime.now() - start_time).total_seconds()
        
        # ACTION 4: Display results
        print(f"\n{GREEN}[+] Scan Complete{RESET}")
        print(f"{YELLOW}[*] Duration: {elapsed:.2f} seconds{RESET}")
        print(f"{GREEN}[+] Active Hosts Found: {len(active_hosts)}{RESET}\n")
        
        print(f"{YELLOW}Active Hosts:{RESET}")
        for ip in active_hosts:
            print(f"  {GREEN}✓{RESET} {ip}")
        
        print(f"\n{YELLOW}[*] Next Steps:{RESET}")
        print("  1. Perform service enumeration (nmap -sV <ip>)")
        print("  2. Attempt fingerprinting (nmap -O <ip>)")
        print("  3. Scan for vulnerabilities (nmap --script vuln <ip>)")
        print("  4. Document findings and report to authorized stakeholders")
        
    except KeyboardInterrupt:
        print(f"\n{RED}[-] Scan interrupted by user{RESET}")
        sys.exit(130)
    except Exception as e:
        print(f"{RED}[-] Error during scan: {str(e)}{RESET}")
        sys.exit(1)


if __name__ == '__main__':
    main()
