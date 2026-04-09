#!/usr/bin/env bash
# Memory Forensics — CTF Toolkit (Volatility 3 wrapper)
# Usage: ./memory_forensics.sh <memory.img> [profile]

set -euo pipefail
BLUE='\033[0;34m'; GREEN='\033[0;32m'; NC='\033[0m'
h1() { echo -e "\n${BLUE}═══ $* ═══${NC}"; }

IMG="${1:-}"
[[ -z "$IMG" ]] && { echo "Usage: $0 <memory_image>"; exit 1; }

# Volatility 3 is `vol` on most systems, `volatility3` on some
VOL=$(command -v vol3 2>/dev/null || command -v vol 2>/dev/null || command -v volatility3 2>/dev/null || echo "vol")

# Auto-detect OS from image
h1 "OS Detection"
$VOL -f "$IMG" windows.info 2>/dev/null | head -20 || \
$VOL -f "$IMG" linux.pslist 2>/dev/null | head -5 || \
echo "[!] Could not detect OS — check if vol3 is installed"

# Detect if Windows or Linux
OS_TYPE="windows"
if $VOL -f "$IMG" linux.pslist &>/dev/null 2>&1; then
    OS_TYPE="linux"
fi
echo "[*] Detected: $OS_TYPE"

run() {
    local plugin="$1"
    shift
    h1 "$plugin"
    $VOL -f "$IMG" "$plugin" "$@" 2>/dev/null || echo "[-] Plugin failed"
}

if [[ "$OS_TYPE" == "windows" ]]; then
    h1 "Windows Analysis"

    run windows.pslist           # Process list
    run windows.pstree           # Process tree
    run windows.cmdline          # Command lines
    run windows.netscan          # Network connections
    run windows.netstat          # Active sockets
    run windows.filescan         # File objects
    run windows.dlllist          # Loaded DLLs
    run windows.handles          # Open handles
    run windows.registry.hivelist # Registry hives
    run windows.malfind          # Injected code
    run windows.dumpfiles --physaddr 0  # Dump all files (large)

    h1 "Credential Extraction"
    run windows.hashdump         # NTLM hashes
    run windows.lsadump          # LSA secrets
    run windows.cachedump        # Cached credentials

    h1 "Clipboard"
    run windows.clipboard

    h1 "Screenshot"
    $VOL -f "$IMG" windows.screenshot --dump 2>/dev/null || true

else
    h1 "Linux Analysis"
    run linux.pslist
    run linux.pstree
    run linux.bash               # Bash history from memory
    run linux.netfilter          # Firewall rules
    run linux.check_syscall      # Syscall table (rootkit detection)
    run linux.lsmod              # Loaded kernel modules
    run linux.malfind
fi

h1 "Grep for Flags"
FLAG_PATTERNS=("CTF{" "FLAG{" "flag{" "HTB{" "picoCTF{")
for pat in "${FLAG_PATTERNS[@]}"; do
    echo "[*] Searching for $pat..."
    strings "$IMG" | grep -a "$pat" | head -5 || true
done

h1 "Useful string searches"
strings -a "$IMG" | grep -aE "(password|passwd|secret|key|token|flag)[=: ][^\s]{6,}" | head -20 || true

echo ""
echo "[*] Tip: For file extraction:"
echo "    vol -f $IMG windows.dumpfiles --virtaddr 0xADDR"
echo "    vol -f $IMG linux.proc.dump --pid PID"
