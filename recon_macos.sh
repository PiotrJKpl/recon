#!/bin/zsh
###############################################################################
# macOS Initial Reconnaissance Script — White Hat Pentest
# -------------------------------------------------------
# Purpose : Gather system, user, network, process, software, file-system,
#           security-posture, and credential-indicator information from a
#           macOS workstation using ONLY built-in tools (no installs).
#
# Usage   : chmod +x recon_macos.sh && ./recon_macos.sh | tee recon_out.txt
#
# WARNING : Run ONLY with explicit written authorization from the asset owner.
###############################################################################

OUTDIR="./recon_results_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR"

banner() {
    echo ""
    echo "======================================================================="
    echo "  $1"
    echo "======================================================================="
}

###############################################################################
# 1. SYSTEM & HARDWARE INFORMATION
#    Collects: hostname, macOS version, kernel, CPU/memory, serial, UUID
###############################################################################
banner "1. SYSTEM & HARDWARE INFORMATION"

echo "[*] Hostname"
hostname

echo "[*] macOS version"
sw_vers

echo "[*] Kernel information"
uname -a

echo "[*] Hardware overview (model, chip, memory, serial)"
system_profiler SPHardwareDataType 2>/dev/null

echo "[*] Uptime"
uptime

###############################################################################
# 2. USER & ACCOUNT ENUMERATION
#    Collects: current user, UID/GID, group memberships, all local accounts,
#              admin group members, sudo capabilities, last logins
###############################################################################
banner "2. USER & ACCOUNT ENUMERATION"

echo "[*] Current user"
whoami

echo "[*] User ID and group memberships"
id

echo "[*] Currently logged-in users"
who

echo "[*] Recent logins (last 10)"
last -10 2>/dev/null

echo "[*] Local user accounts (excluding system underscored accounts)"
dscl . list /Users | grep -v '^_'

echo "[*] Admin group members"
dscl . -read /Groups/admin GroupMembership 2>/dev/null

echo "[*] Sudo privileges for current user"
sudo -l 2>&1 | head -20

###############################################################################
# 3. NETWORK RECONNAISSANCE
#    Collects: interfaces, IPs, MAC addresses, routing table, DNS config,
#              ARP neighbours, listening ports, established connections
###############################################################################
banner "3. NETWORK RECONNAISSANCE"

echo "[*] Network interfaces and IP addresses"
ifconfig -a 2>/dev/null | grep -E 'flags|inet |ether '

echo "[*] Default gateway(s)"
netstat -rn 2>/dev/null | grep default

echo "[*] DNS configuration (resolv.conf)"
cat /etc/resolv.conf 2>/dev/null

echo "[*] DNS nameservers and search domains (scutil)"
scutil --dns 2>/dev/null | grep -E 'nameserver|search domain' | sort -u

echo "[*] ARP table — nearby hosts on local segments"
arp -a 2>/dev/null

echo "[*] Listening TCP/UDP ports"
netstat -an 2>/dev/null | grep LISTEN

echo "[*] Established connections (top 30)"
netstat -an 2>/dev/null | grep ESTABLISHED | head -30

echo "[*] Wi-Fi SSID (if connected)"
/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I 2>/dev/null | grep -i ssid

###############################################################################
# 4. RUNNING PROCESSES & SERVICES
#    Collects: all processes, interesting security/VPN/management processes,
#              LaunchDaemons (system), LaunchAgents (user), cron jobs
###############################################################################
banner "4. RUNNING PROCESSES & SERVICES"

echo "[*] All running processes"
ps aux > "$OUTDIR/ps_aux.txt" 2>/dev/null
echo "    (saved to $OUTDIR/ps_aux.txt)"

echo "[*] Interesting processes (security, VPN, management, containers)"
ps aux 2>/dev/null | grep -iE 'vpn|cortex|jamf|netskop|ssh|docker|podman|proxy|agent|keychain|secur|vault|cyber' | grep -v grep

echo "[*] System LaunchDaemons"
ls /Library/LaunchDaemons/ 2>/dev/null

echo "[*] System LaunchAgents"
ls /Library/LaunchAgents/ 2>/dev/null

echo "[*] User LaunchAgents"
ls ~/Library/LaunchAgents/ 2>/dev/null

echo "[*] Cron jobs for current user"
crontab -l 2>/dev/null || echo "    No crontab for $(whoami)"

###############################################################################
# 5. INSTALLED SOFTWARE INVENTORY
#    Collects: /Applications, Homebrew packages, available dev tools, Python
###############################################################################
banner "5. INSTALLED SOFTWARE INVENTORY"

echo "[*] Applications in /Applications"
ls /Applications/ 2>/dev/null

echo "[*] Homebrew installed packages"
brew list 2>/dev/null || echo "    Homebrew not found"

echo "[*] Available developer tools (which)"
for tool in git python3 python node npm pip3 docker podman curl wget ssh scp sftp \
            nc ncat nmap openssl ruby perl php java javac go gcc make; do
    loc=$(which "$tool" 2>/dev/null)
    [[ -n "$loc" ]] && echo "    $tool -> $loc"
done

echo "[*] Python version"
python3 --version 2>/dev/null

echo "[*] Node version"
node --version 2>/dev/null

###############################################################################
# 6. FILE SYSTEM & SENSITIVE FILE DISCOVERY
#    Collects: home dir listing, interesting dot-files/configs, ssh keys,
#              cloud credential dirs, shell history, recent documents
###############################################################################
banner "6. FILE SYSTEM & SENSITIVE FILE DISCOVERY"

echo "[*] Home directory listing"
ls -la ~ 2>/dev/null

echo "[*] SSH directory"
ls -la ~/.ssh/ 2>/dev/null

echo "[*] SSH known_hosts — reveals previously accessed servers"
cat ~/.ssh/known_hosts 2>/dev/null | awk '{print $1}' | sort -u

echo "[*] Git global config (identity)"
git config --global --list 2>/dev/null

echo "[*] Cloud / container credential directories"
for d in ~/.aws ~/.azure ~/.config/gcloud ~/.kube ~/.docker; do
    if [[ -d "$d" ]]; then
        echo "    Found: $d"
        ls -la "$d" 2>/dev/null
    fi
done

echo "[*] Shell history (last 30 commands)"
tail -30 ~/.zsh_history 2>/dev/null || tail -30 ~/.bash_history 2>/dev/null

echo "[*] Recently modified files in home (last 24h)"
find ~ -maxdepth 3 -mtime -1 -type f 2>/dev/null | grep -vE 'Library|Cache|\.Trash' | head -30

###############################################################################
# 7. SECURITY POSTURE CHECK
#    Collects: firewall, FileVault, SIP, Gatekeeper, system extensions
###############################################################################
banner "7. SECURITY POSTURE CHECK"

echo "[*] Application Firewall status"
/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null

echo "[*] FileVault (disk encryption) status"
fdesetup status 2>/dev/null

echo "[*] System Integrity Protection (SIP)"
csrutil status 2>/dev/null

echo "[*] Gatekeeper status"
spctl --status 2>/dev/null

echo "[*] Security-related system extensions"
systemextensionsctl list 2>/dev/null

echo "[*] MDM enrollment check"
profiles status -type enrollment 2>/dev/null || echo "    Could not determine MDM status"

###############################################################################
# 8. ENVIRONMENT VARIABLES & CREDENTIAL INDICATORS
#    Collects: env vars with credential-related names, keychains, proxy config
###############################################################################
banner "8. ENVIRONMENT VARIABLES & CREDENTIAL INDICATORS"

echo "[*] Environment variables (filtered for interesting keywords)"
env 2>/dev/null | grep -iE 'proxy|token|key|secret|pass|auth|user|home|path|shell|http|ftp|ssh|api' | sort

echo "[*] Available keychains"
security list-keychains 2>/dev/null

echo "[*] HTTP proxy environment"
echo "    http_proxy  = ${http_proxy:-<not set>}"
echo "    https_proxy = ${https_proxy:-<not set>}"
echo "    no_proxy    = ${no_proxy:-<not set>}"

echo "[*] Network proxy system settings"
scutil --proxy 2>/dev/null

###############################################################################
# 9. SUMMARY
###############################################################################
banner "9. RECON COMPLETE"
echo "[*] Results saved to: $OUTDIR/"
echo "[*] Review output above for findings."
echo "[*] Timestamp: $(date)"
echo ""
