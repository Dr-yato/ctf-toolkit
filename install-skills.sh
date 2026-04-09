#!/usr/bin/env bash
# Install CTF Toolkit Agent Skills into Claude Code
# Copies all skills from ./skills/ into ~/.claude/skills/
# Usage: bash install-skills.sh

set -euo pipefail
GREEN='\033[0;32m'; BLUE='\033[0;34m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[+]${NC} $*"; }
info() { echo -e "${BLUE}[*]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILLS_SRC="$SCRIPT_DIR/skills"
SKILLS_DST="$HOME/.claude/skills"

if [[ ! -d "$SKILLS_SRC" ]]; then
    echo "Skills directory not found: $SKILLS_SRC"
    echo "Run this script from the ctf-toolkit root directory."
    exit 1
fi

mkdir -p "$SKILLS_DST"

info "Installing CTF Toolkit skills to $SKILLS_DST"
echo ""

for skill_dir in "$SKILLS_SRC"/*/; do
    skill_name=$(basename "$skill_dir")
    dst="$SKILLS_DST/$skill_name"

    if [[ -d "$dst" ]]; then
        warn "Overwriting existing skill: $skill_name"
    fi

    cp -r "$skill_dir" "$dst"
    ok "Installed: $skill_name"
done

echo ""
ok "All skills installed. Available in Claude Code as:"
echo ""
for skill_dir in "$SKILLS_SRC"/*/; do
    skill_name=$(basename "$skill_dir")
    echo "  /$skill_name"
done

echo ""
info "Skill routing:"
echo "  /ctf-toolkit          — master router, start here"
echo "  /ctf-toolkit-web      — SQLi, XSS, SSRF scripts"
echo "  /ctf-toolkit-pwn      — BOF, ROP, format string scripts"
echo "  /ctf-toolkit-crypto   — RSA, classical, XOR scripts"
echo "  /ctf-toolkit-forensics — file/PCAP/memory analysis scripts"
echo "  /ctf-toolkit-networking — protocol reversing, packet crafting"
echo "  /ctf-toolkit-ransomware — analysis and decryption"
echo "  /ctf-toolkit-vuln     — fuzzing, crash triage, angr"
echo "  /ctf-toolkit-osint    — domain/username/image recon"
echo "  /ctf-toolkit-rev      — static analysis, GDB, Ghidra"
echo ""
info "Reload Claude Code to pick up new skills."
