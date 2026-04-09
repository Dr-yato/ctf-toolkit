#!/usr/bin/env bash
# OSINT Reconnaissance — CTF Toolkit
# Usage: ./osint_recon.sh <target_domain_or_username>

set -euo pipefail
TARGET="${1:-}"
[[ -z "$TARGET" ]] && { echo "Usage: $0 <domain|username|IP>"; exit 1; }

BLUE='\033[0;34m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
h1()   { echo -e "\n${BLUE}═══ $* ═══${NC}"; }
ok()   { echo -e "${GREEN}[+]${NC} $*"; }
info() { echo -e "${YELLOW}[*]${NC} $*"; }

OUT_DIR="./osint_${TARGET//[^a-zA-Z0-9]/_}"
mkdir -p "$OUT_DIR"
info "Output: $OUT_DIR"

# Detect if domain or IP
is_domain() { echo "$1" | grep -qE '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'; }
is_ip()     { echo "$1" | grep -qE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'; }

h1 "WHOIS"
whois "$TARGET" 2>/dev/null | tee "$OUT_DIR/whois.txt" | head -30

h1 "DNS Enumeration"
if is_domain "$TARGET" || ! is_ip "$TARGET"; then
    echo "[A records]"
    dig +short "$TARGET" A | tee -a "$OUT_DIR/dns.txt"
    echo "[MX records]"
    dig +short "$TARGET" MX | tee -a "$OUT_DIR/dns.txt"
    echo "[TXT records]"
    dig +short "$TARGET" TXT | tee -a "$OUT_DIR/dns.txt"
    echo "[NS records]"
    dig +short "$TARGET" NS | tee -a "$OUT_DIR/dns.txt"
    echo "[CNAME]"
    dig +short "$TARGET" CNAME | tee -a "$OUT_DIR/dns.txt"
    # Zone transfer attempt
    info "Attempting zone transfer..."
    for ns in $(dig +short "$TARGET" NS 2>/dev/null); do
        dig axfr "$TARGET" @"$ns" 2>/dev/null | head -30 && ok "Zone transfer from $ns!" || true
    done
fi

h1 "Subdomain Discovery"
if command -v subfinder &>/dev/null; then
    info "subfinder..."
    subfinder -d "$TARGET" -silent 2>/dev/null | tee "$OUT_DIR/subdomains.txt"
fi
if command -v amass &>/dev/null; then
    info "amass enum (passive)..."
    amass enum -passive -d "$TARGET" 2>/dev/null | tee -a "$OUT_DIR/subdomains.txt"
fi
if command -v dnsenum &>/dev/null; then
    dnsenum --nocolor "$TARGET" 2>/dev/null | head -50 | tee -a "$OUT_DIR/subdomains.txt"
fi

h1 "Reverse IP Lookup"
if is_domain "$TARGET"; then
    IP=$(dig +short "$TARGET" A | head -1)
    info "IP: $IP"
    if [[ -n "$IP" ]]; then
        curl -s "https://ipinfo.io/$IP/json" 2>/dev/null | python3 -m json.tool || true
    fi
elif is_ip "$TARGET"; then
    curl -s "https://ipinfo.io/$TARGET/json" 2>/dev/null | python3 -m json.tool || true
fi

h1 "Port Scan (top 100)"
if command -v nmap &>/dev/null; then
    nmap -T4 -F --open "$TARGET" 2>/dev/null | tee "$OUT_DIR/nmap.txt"
fi

h1 "Certificate Transparency (subdomains from certs)"
info "Querying crt.sh..."
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" 2>/dev/null | \
    python3 -c "import sys,json; data=json.load(sys.stdin); [print(e['name_value']) for e in data]" 2>/dev/null | \
    sort -u | tee "$OUT_DIR/crt_sh.txt" | head -30 || info "crt.sh unavailable"

h1 "Web Recon (if HTTP)"
if command -v curl &>/dev/null; then
    for proto in http https; do
        url="${proto}://${TARGET}"
        info "Checking $url"
        curl -sI "$url" --connect-timeout 3 2>/dev/null | head -20 || true
    done
fi

h1 "Google Dork Suggestions"
cat << EOF
  [Copy these into your browser]
  site:$TARGET
  site:$TARGET filetype:pdf
  site:$TARGET filetype:doc OR filetype:xls OR filetype:ppt
  site:$TARGET inurl:admin OR inurl:login OR inurl:dashboard
  site:$TARGET intext:password OR intext:username
  intext:"$TARGET" filetype:txt
  "@$TARGET" (email hunt)
  "index of" site:$TARGET
EOF

h1 "Social Media Username Hunt"
if command -v python3 &>/dev/null && [[ -f ~/tools/sherlock/sherlock/sherlock.py ]]; then
    info "Running Sherlock for username: $TARGET"
    python3 ~/tools/sherlock/sherlock/sherlock.py "$TARGET" --timeout 5 2>/dev/null | \
        grep -v "Not Found" | tee "$OUT_DIR/sherlock.txt"
fi

h1 "Wayback Machine"
curl -s "https://archive.org/wayback/available?url=$TARGET" 2>/dev/null | \
    python3 -m json.tool 2>/dev/null | head -10 || true
info "Full archive: https://web.archive.org/web/*/$TARGET"

h1 "Summary"
ok "Results saved to: $OUT_DIR/"
ls -la "$OUT_DIR/"
