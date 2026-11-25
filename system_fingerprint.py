#!/usr/bin/env python3
"""
System Fingerprinting Tool
Identifies systems by probing open ports and banner grabbing

AUTHORIZATION WARNING:
- Requires written authorization for penetration testing
- Unauthorized network scanning may be illegal
- Use only in lab environments with explicit approval

Usage:
    python3 system_fingerprint.py [host_or_range]
    Example: python3 system_fingerprint.py 192.168.0.38
"""

import socket
import sys
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

# ANSI color codes
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'

# Common ports and their typical services
COMMON_PORTS = {
    21: {'name': 'FTP', 'banner_size': 100},
    22: {'name': 'SSH', 'banner_size': 100},
    23: {'name': 'Telnet', 'banner_size': 100},
    25: {'name': 'SMTP', 'banner_size': 100},
    53: {'name': 'DNS', 'banner_size': 100},
    80: {'name': 'HTTP', 'banner_size': 200},
    110: {'name': 'POP3', 'banner_size': 100},
    111: {'name': 'RPC', 'banner_size': 100},
    135: {'name': 'RPC-EPMAP', 'banner_size': 100},
    139: {'name': 'NetBIOS', 'banner_size': 100},
    143: {'name': 'IMAP', 'banner_size': 100},
    445: {'name': 'SMB', 'banner_size': 100},
    3306: {'name': 'MySQL', 'banner_size': 200},
    3389: {'name': 'RDP', 'banner_size': 100},
    5432: {'name': 'PostgreSQL', 'banner_size': 100},
    5900: {'name': 'VNC', 'banner_size': 100},
    8000: {'name': 'HTTP-ALT', 'banner_size': 200},
    8080: {'name': 'HTTP-ALT', 'banner_size': 200},
    8443: {'name': 'HTTPS-ALT', 'banner_size': 200},
    9000: {'name': 'HTTP-ALT', 'banner_size': 200},
}


def print_header():
    """Display authorization warning"""
    print(f"{YELLOW}[*] System Fingerprinting Tool{RESET}")
    print(f"{RED}[!] WARNING: Ensure written authorization before scanning{RESET}")
    print(f"{YELLOW}[*] Unauthorized network scanning is illegal{RESET}\n")


def banner_grab(host, port, timeout=2):
    """
    ACTION: Attempt to grab service banner from target
    
    Args:
        host: Target IP address
        port: Target port
        timeout: Connection timeout in seconds
    
    Returns:
        tuple: (port, banner_data, service_name)
    """
    service_name = COMMON_PORTS.get(port, {}).get('name', 'UNKNOWN')
    banner_size = COMMON_PORTS.get(port, {}).get('banner_size', 100)
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        # Attempt connection
        result = sock.connect_ex((host, port))
        
        if result == 0:
            # Connection successful - try to grab banner
            try:
                banner = sock.recv(banner_size).decode('utf-8', errors='ignore').strip()
                sock.close()
                return (port, service_name, banner, True)
            except socket.timeout:
                sock.close()
                return (port, service_name, "[No banner - connection timeout]", True)
            except:
                sock.close()
                return (port, service_name, "[Banner error]", True)
        else:
            sock.close()
            return (port, service_name, None, False)
            
    except socket.timeout:
        return (port, service_name, None, False)
    except Exception as e:
        return (port, service_name, f"Error: {str(e)}", False)


def scan_host(host, ports=None, max_threads=10):
    """
    ACTION: Scan single host for open ports and service identification
    
    Args:
        host: Target IP address
        ports: List of ports to scan
        max_threads: Maximum parallel threads
    
    Returns:
        dict: Results with open ports and banners
    """
    if ports is None:
        ports = list(COMMON_PORTS.keys())
    
    print(f"{BLUE}[*] Scanning {host}...{RESET}")
    print(f"{YELLOW}[*] Probing {len(ports)} ports for open services{RESET}\n")
    
    results = {
        'host': host,
        'open_ports': [],
        'services': [],
        'os_hints': []
    }
    
    # Scan ports in parallel
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {
            executor.submit(banner_grab, host, port): port 
            for port in ports
        }
        
        for future in as_completed(futures):
            port, service_name, banner, is_open = future.result()
            
            if is_open:
                results['open_ports'].append(port)
                results['services'].append({
                    'port': port,
                    'service': service_name,
                    'banner': banner
                })
                
                # Print result
                print(f"{GREEN}[+] Port {port:5d} ({service_name:12s}) OPEN{RESET}")
                if banner and banner.startswith("["):
                    print(f"    {YELLOW}{banner}{RESET}")
                elif banner:
                    print(f"    {YELLOW}Banner: {banner[:100]}{RESET}")
    
    return results


def analyze_fingerprint(results):
    """
    ACTION: Analyze scan results to identify OS/services
    
    Args:
        results: Dictionary with scan results
    
    Returns:
        dict: Analysis with OS guesses and service list
    """
    analysis = {
        'likely_os': [],
        'services': [],
        'confidence': 'Low'
    }
    
    open_ports = results.get('open_ports', [])
    services = results.get('services', [])
    
    # Extract service list
    for svc in services:
        analysis['services'].append(f"{svc['port']}/{svc['service']}")
    
    # OS Fingerprinting based on port signatures
    if 445 in open_ports and 139 in open_ports:
        analysis['likely_os'].append("Windows (SMB/NetBIOS active)")
        analysis['confidence'] = 'High'
    
    if 22 in open_ports and 111 in open_ports:
        analysis['likely_os'].append("Unix/Linux (SSH + RPC)")
        analysis['confidence'] = 'High'
    
    if 3389 in open_ports:
        analysis['likely_os'].append("Windows (RDP)")
        analysis['confidence'] = 'High'
    
    if 22 in open_ports:
        analysis['likely_os'].append("Unix/Linux/macOS variant")
        analysis['confidence'] = 'Medium'
    
    if 80 in open_ports or 8080 in open_ports:
        analysis['services'].append("Web Server (HTTP)")
    
    if 443 in open_ports or 8443 in open_ports:
        analysis['services'].append("Web Server (HTTPS)")
    
    if 3306 in open_ports:
        analysis['services'].append("MySQL Database")
    
    if 5432 in open_ports:
        analysis['services'].append("PostgreSQL Database")
    
    if not analysis['likely_os']:
        analysis['likely_os'].append("Unknown/Firewall protecting ports")
        analysis['confidence'] = 'Low'
    
    return analysis


def main():
    """Main execution"""
    parser = argparse.ArgumentParser(
        description='System Fingerprinting Tool',
        epilog='Example: python3 system_fingerprint.py 192.168.0.1'
    )
    parser.add_argument(
        'hosts',
        nargs='+',
        help='Target host(s) to fingerprint'
    )
    parser.add_argument(
        '-p', '--ports',
        help='Comma-separated list of ports to scan (default: common ports)',
        default=None
    )
    parser.add_argument(
        '-t', '--timeout',
        type=int,
        default=2,
        help='Connection timeout in seconds (default: 2)'
    )
    parser.add_argument(
        '-T', '--threads',
        type=int,
        default=10,
        help='Number of parallel threads (default: 10)'
    )
    parser.add_argument(
        '--skip-auth',
        action='store_true',
        help='Skip authorization check'
    )
    
    args = parser.parse_args()
    
    # Display header
    print_header()
    
    # Verify authorization
    if not args.skip_auth:
        response = input(
            f"{YELLOW}[?] Do you have authorization to fingerprint these systems? (yes/no): {RESET}"
        ).lower()
        if response not in ['yes', 'y']:
            print(f"{RED}[-] Scanning aborted{RESET}")
            sys.exit(1)
    
    print()
    
    # Parse ports if specified
    ports = list(COMMON_PORTS.keys())
    if args.ports:
        try:
            ports = [int(p.strip()) for p in args.ports.split(',')]
        except ValueError:
            print(f"{RED}[-] Invalid port list{RESET}")
            sys.exit(1)
    
    # Scan each host
    all_results = []
    for host in args.hosts:
        print(f"\n{'='*60}")
        print(f"{BLUE}[*] SCANNING: {host}{RESET}")
        print(f"{'='*60}\n")
        
        try:
            results = scan_host(host, ports, args.threads)
            analysis = analyze_fingerprint(results)
            all_results.append((host, results, analysis))
            
            # Display analysis
            print(f"\n{BLUE}{'='*60}{RESET}")
            print(f"{BLUE}[*] ANALYSIS: {host}{RESET}")
            print(f"{BLUE}{'='*60}{RESET}\n")
            
            if results['open_ports']:
                print(f"{GREEN}[+] Open Ports Found: {len(results['open_ports'])}{RESET}")
                for service in analysis['services']:
                    print(f"    {GREEN}✓{RESET} {service}")
            else:
                print(f"{YELLOW}[*] No open ports detected (may be firewalled){RESET}")
            
            print(f"\n{BLUE}[*] OS Identification:{RESET}")
            print(f"    {YELLOW}Confidence: {analysis['confidence']}{RESET}")
            for os_guess in analysis['likely_os']:
                print(f"    {GREEN}✓{RESET} {os_guess}")
        
        except KeyboardInterrupt:
            print(f"\n{RED}[-] Scan interrupted{RESET}")
            break
        except Exception as e:
            print(f"{RED}[-] Error scanning {host}: {str(e)}{RESET}")
    
    # Summary
    print(f"\n{'='*60}")
    print(f"{BLUE}[*] SCAN SUMMARY{RESET}")
    print(f"{'='*60}\n")
    
    print(f"{YELLOW}Hosts Scanned: {len(all_results)}{RESET}")
    for host, results, analysis in all_results:
        open_count = len(results['open_ports'])
        status = f"{GREEN}{open_count} open ports{RESET}" if open_count > 0 else f"{YELLOW}Firewalled{RESET}"
        print(f"  {host}: {status}")
    
    print(f"\n{YELLOW}[*] Next Steps:{RESET}")
    print("  1. Try service-specific exploits on identified services")
    print("  2. Perform more detailed version detection")
    print("  3. Run vulnerability scanners")
    print("  4. Document findings for report")


if __name__ == '__main__':
    main()
