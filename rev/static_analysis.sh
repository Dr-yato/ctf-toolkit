#!/usr/bin/env bash
# Static Analysis — CTF Toolkit
# Comprehensive static analysis of binaries for reverse engineering challenges
# Usage: ./static_analysis.sh <binary>

set -euo pipefail
BIN="${1:-}"
[[ -z "$BIN" ]] && { echo "Usage: $0 <binary>"; exit 1; }
[[ ! -f "$BIN" ]] && { echo "File not found: $BIN"; exit 1; }

BLUE='\033[0;34m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
h1()   { echo -e "\n${BLUE}═══ $* ═══${NC}"; }
ok()   { echo -e "${GREEN}[+]${NC} $*"; }
info() { echo -e "${YELLOW}[*]${NC} $*"; }

h1 "File Info"
file "$BIN"
ls -lh "$BIN"

h1 "Checksec"
if command -v checksec &>/dev/null; then
    checksec --file="$BIN" 2>/dev/null || checksec "$BIN" 2>/dev/null
elif python3 -c "import checksec" 2>/dev/null; then
    python3 -c "from checksec.elf import ELFSecurity; e=ELFSecurity('$BIN'); print(e)"
else
    info "checksec not found — checking manually..."
    readelf -l "$BIN" 2>/dev/null | grep -E "GNU_STACK|GNU_RELRO" || true
fi

h1 "Symbols"
nm -D "$BIN" 2>/dev/null || nm "$BIN" 2>/dev/null | head -40 || echo "(stripped)"

h1 "Dynamic Imports"
objdump -d -M intel "$BIN" 2>/dev/null | grep -A2 "call.*@plt" | head -40 || \
readelf -d "$BIN" 2>/dev/null | grep "NEEDED\|SONAME" || true

h1 "Sections"
readelf -S "$BIN" 2>/dev/null | head -40 || true

h1 "Strings (interesting only)"
info "Crypto/flag indicators:"
strings -a "$BIN" | grep -iE "(flag|ctf|secret|password|key|aes|rsa|sha|md5|base64|xor)" | head -20
info "Paths and URLs:"
strings -a "$BIN" | grep -E "^(/|http|https|ftp|file)" | head -10
info "Format strings (printf-like):"
strings -a "$BIN" | grep -E "%[0-9]*[sdxp]" | head -10

h1 "Disassembly (main)"
objdump -d -M intel "$BIN" 2>/dev/null | \
    awk '/^[0-9a-f]+ <main>:/,/^$/' | head -60 || true

h1 "Library Calls"
if command -v ltrace &>/dev/null; then
    timeout 3 ltrace "$BIN" 2>&1 | head -30 || true
fi

h1 "radare2 Quick Analysis"
if command -v r2 &>/dev/null; then
    echo -e "aaa\nafl\nq" | r2 -q "$BIN" 2>/dev/null | grep -v "^$" | head -30 || true
fi

h1 "Packed/Obfuscated Detection"
python3 - "$BIN" << 'PYEOF' 2>/dev/null
import sys, math, collections
data = open(sys.argv[1], 'rb').read()
freq = collections.Counter(data)
total = len(data)
if total == 0: sys.exit()
ent = -sum((c/total)*math.log2(c/total) for c in freq.values())
print(f"Entropy: {ent:.3f}")
if ent > 7.0:
    print("[!] High entropy — likely packed, compressed, or encrypted")
    print("    Try: upx -d binary")
else:
    print("[+] Normal entropy — likely not packed")
PYEOF

h1 "Anti-Debug Checks"
strings -a "$BIN" | grep -iE "(ptrace|IsDebugger|debugger|anti.?debug|sandbox)" | head -10 || true
objdump -d -M intel "$BIN" 2>/dev/null | grep -i "ptrace\|int 3\|int3\|0xcc" | head -10 || true

h1 "Common CTF Patterns"
strings -a "$BIN" | grep -iE "(compare|strcmp|memcmp|strncmp|check|verify)" | head -10 || true

h1 "GDB Quick Start"
cat << EOF
  gdb $BIN
    (gdb) info functions
    (gdb) disas main
    (gdb) b *main
    (gdb) run
    (gdb) x/20i \$pc
    (gdb) x/40wx \$rsp
EOF

h1 "Ghidra/Radare2 One-Liners"
cat << EOF
  r2 -A $BIN
    [0x...]> afl          # list functions
    [0x...]> pdf @ main   # disassemble main
    [0x...]> s sym.check_flag && pdf  # disassemble check_flag

  Ghidra: File > Import > $BIN > CodeBrowser > Window > Decompiler
EOF
