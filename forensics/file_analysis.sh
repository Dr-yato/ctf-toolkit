#!/usr/bin/env bash
# File Analysis — CTF Toolkit
# Quick triage script for unknown files in forensics challenges
# Usage: ./file_analysis.sh <file>

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
h1() { echo -e "\n${BLUE}═══ $* ═══${NC}"; }
ok() { echo -e "${GREEN}[+]${NC} $*"; }
info() { echo -e "${YELLOW}[*]${NC} $*"; }

FILE="${1:-}"
if [[ -z "$FILE" ]]; then
    echo "Usage: $0 <file>"
    exit 1
fi

if [[ ! -f "$FILE" ]]; then
    echo "File not found: $FILE"
    exit 1
fi

h1 "Basic Info"
file "$FILE"
echo "Size: $(wc -c < "$FILE") bytes | $(du -sh "$FILE" | cut -f1)"
echo "MD5:  $(md5sum "$FILE" 2>/dev/null | cut -d' ' -f1 || md5 -q "$FILE" 2>/dev/null)"
echo "SHA1: $(sha1sum "$FILE" 2>/dev/null | cut -d' ' -f1 || shasum "$FILE" 2>/dev/null | cut -d' ' -f1)"

h1 "Magic Bytes (hex)"
xxd "$FILE" | head -4

h1 "Strings (min 8 chars)"
strings -n 8 "$FILE" | head -50
echo "..."
echo "  [Full strings: strings -n 4 '$FILE' | less]"

h1 "Entropy"
if command -v ent &>/dev/null; then
    ent "$FILE"
elif command -v python3 &>/dev/null; then
    python3 - "$FILE" << 'PYEOF'
import sys, math, collections
data = open(sys.argv[1], 'rb').read()
freq = collections.Counter(data)
total = len(data)
entropy = -sum((c/total)*math.log2(c/total) for c in freq.values())
print(f"Entropy: {entropy:.4f} bits/byte  (8.0 = random/compressed/encrypted)")
PYEOF
fi

h1 "Embedded Files (binwalk)"
if command -v binwalk &>/dev/null; then
    binwalk "$FILE"
fi

h1 "Metadata (exiftool)"
if command -v exiftool &>/dev/null; then
    exiftool "$FILE" 2>/dev/null | head -30
fi

h1 "Archive Detection"
MIME=$(file --mime-type -b "$FILE" 2>/dev/null)
case "$MIME" in
    application/zip)         info "ZIP archive — try: unzip -l '$FILE'"; unzip -l "$FILE" 2>/dev/null | head -20 ;;
    application/x-tar)       info "TAR archive — try: tar tvf '$FILE'" ;;
    application/gzip)        info "GZIP — try: zcat '$FILE'" ;;
    application/x-7z-compressed) info "7-Zip — try: 7z l '$FILE'" ;;
    image/png)               info "PNG — checking for stego..." ;;
    image/jpeg)              info "JPEG — checking for stego..." ;;
    audio/mpeg|audio/ogg)    info "Audio — check spectogram in Audacity/Sonic Visualiser" ;;
    application/pdf)         info "PDF — try: pdftotext '$FILE' -" ;;
    application/x-executable|application/x-sharedlib)
                             info "ELF binary — run with: ./file_analysis_elf.sh '$FILE'" ;;
    text/*)                  ok "Text file — content below:" && head -30 "$FILE" ;;
esac

h1 "Stego Quick Check (images)"
case "$MIME" in
    image/png|image/jpeg|image/bmp|image/gif)
        if command -v zsteg &>/dev/null; then
            info "Running zsteg..."
            zsteg "$FILE" 2>/dev/null | head -20
        fi
        if command -v steghide &>/dev/null; then
            info "Steghide (no password)..."
            steghide extract -sf "$FILE" -p "" -xf /tmp/steghide_out.txt 2>/dev/null && \
                ok "Steghide extracted: $(cat /tmp/steghide_out.txt)" || true
        fi
        if command -v stegseek &>/dev/null; then
            info "Stegseek brute-force..."
            stegseek "$FILE" ~/wordlists/rockyou.txt 2>/dev/null | head -5 || true
        fi
        ;;
esac

h1 "Grep for Flags"
FLAG_PATTERNS=("CTF{" "FLAG{" "flag{" "ctf{" "DUCTF{" "HTB{" "picoCTF{")
for pat in "${FLAG_PATTERNS[@]}"; do
    if strings "$FILE" | grep -q "$pat" 2>/dev/null; then
        ok "Flag pattern found: $pat"
        strings "$FILE" | grep "$pat"
    fi
done

h1 "Done"
echo "Output dir suggestion: mkdir out && cd out"
echo "Full binwalk extract:  binwalk -e --run-as=root '$FILE'"
