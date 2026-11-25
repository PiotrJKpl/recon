#!/bin/bash
###############################################################################
# Network Reconnaissance Script
# Purpose: Discover active hosts on target network via ping sweep
# 
# AUTHORIZATION REQUIREMENTS:
# - Written authorization for network penetration testing required
# - Use only in authorized lab environments or with written approval
# - Unauthorized network scanning is illegal
#
# USAGE: 
#   ./network_recon.sh [network_range] [packet_timeout_ms]
#   Example: ./network_recon.sh "192.168.0" 100
###############################################################################

# Color output for better readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default parameters
NETWORK_PREFIX="${1:-192.168.0}"
TIMEOUT="${2:-100}"  # milliseconds per ping

# Validation: Check authorization
echo -e "${YELLOW}[*] Network Reconnaissance Tool${NC}"
echo -e "${YELLOW}[*] Target Network: ${NETWORK_PREFIX}.0/24${NC}"
echo -e "${RED}[!] WARNING: Ensure you have written authorization before proceeding${NC}"
echo ""

# ACTION 1: Verify prerequisite tools
echo -e "${YELLOW}[*] ACTION 1: Verifying tools${NC}"
if ! command -v ping &> /dev/null; then
    echo -e "${RED}[-] ping command not found${NC}"
    exit 1
fi
echo -e "${GREEN}[+] ping available${NC}"
echo ""

# ACTION 2: Perform parallel ping sweep
echo -e "${YELLOW}[*] ACTION 2: Performing ping sweep (this may take 30-60 seconds)${NC}"
echo -e "${YELLOW}[*] Scanning IPs: ${NETWORK_PREFIX}.1 through ${NETWORK_PREFIX}.254${NC}"
echo ""

# Array to store active hosts
declare -a ACTIVE_HOSTS

# Ping sweep with parallel execution for speed
# Each IP is pinged once with short timeout
for i in {1..254}; do
    (
        # ACTION 3: Send single ICMP echo request to each host
        if ping -c 1 -W "$TIMEOUT" "${NETWORK_PREFIX}.$i" 2>/dev/null | grep -q 'bytes from'; then
            ACTIVE_HOST="${NETWORK_PREFIX}.$i"
            echo -e "${GREEN}[+] ${ACTIVE_HOST} is UP${NC}"
        fi
    ) &
done

# Wait for all background pings to complete
wait
echo ""

# ACTION 4: Optional enhanced discovery with nmap (if available)
echo -e "${YELLOW}[*] ACTION 4: Optional additional reconnaissance${NC}"
if command -v nmap &> /dev/null; then
    echo -e "${YELLOW}[*] nmap available - run for service discovery:${NC}"
    echo "    nmap -sn ${NETWORK_PREFIX}.0/24    # Ping scan"
    echo "    nmap -p- ${NETWORK_PREFIX}.0/24    # Port scan"
    echo ""
fi

# ACTION 5: Optional ARP scan (if available)
if command -v arp-scan &> /dev/null; then
    echo -e "${YELLOW}[*] arp-scan available - run for MAC address enumeration:${NC}"
    echo "    sudo arp-scan -l"
    echo ""
fi

echo -e "${GREEN}[+] Reconnaissance complete${NC}"
echo -e "${YELLOW}[*] Next steps:${NC}"
echo "    1. Document findings"
echo "    2. Identify OS and services on active hosts"
echo "    3. Check for vulnerabilities"
echo "    4. Report to authorized stakeholders"
