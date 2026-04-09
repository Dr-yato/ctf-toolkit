#!/usr/bin/env bash
# =============================================================================
# CTF Environment Master Installer
# Installs all tools needed for: web, pwn, crypto, rev, forensics, osint,
# networking, ransomware-analysis, vuln-research, client-side attacks
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()    { echo -e "${BLUE}[*]${NC} $*"; }
success() { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[-]${NC} $*"; }

OS="$(uname -s)"
ARCH="$(uname -m)"

detect_os() {
    if [[ "$OS" == "Darwin" ]]; then
        echo "macos"
    elif [[ -f /etc/debian_version ]]; then
        echo "debian"
    elif [[ -f /etc/redhat-release ]]; then
        echo "rhel"
    else
        echo "unknown"
    fi
}

OS_TYPE=$(detect_os)
info "Detected OS: $OS_TYPE ($OS/$ARCH)"

# =============================================================================
# PACKAGE MANAGERS
# =============================================================================

install_homebrew() {
    if ! command -v brew &>/dev/null; then
        info "Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    else
        success "Homebrew already installed"
    fi
}

update_apt() {
    info "Updating apt..."
    sudo apt-get update -qq
    sudo apt-get install -y build-essential git curl wget python3 python3-pip python3-venv \
        golang-go ruby ruby-dev nodejs npm default-jdk \
        libssl-dev libffi-dev zlib1g-dev
}

# =============================================================================
# CORE TOOLS
# =============================================================================

install_core() {
    info "Installing core tools..."
    if [[ "$OS_TYPE" == "macos" ]]; then
        brew install git curl wget jq nmap netcat tmux vim ripgrep fd bat hexyl
    elif [[ "$OS_TYPE" == "debian" ]]; then
        sudo apt-get install -y git curl wget jq nmap netcat-openbsd tmux vim \
            ripgrep fd-find bat xxd file binutils
    fi
    success "Core tools installed"
}

# =============================================================================
# PYTHON ECOSYSTEM
# =============================================================================

install_python_tools() {
    info "Installing Python CTF tools..."
    pip3 install --upgrade pip --quiet
    pip3 install --quiet \
        pwntools \
        pycryptodome \
        requests \
        flask \
        flask-unsign \
        sqlmap \
        impacket \
        scapy \
        paramiko \
        pillow \
        sympy \
        gmpy2 \
        z3-solver \
        angr \
        capstone \
        keystone-engine \
        unicorn \
        ropper \
        ropgadget \
        xortool \
        stegano \
        pwndbg \
        ipython \
        jupyter \
        matplotlib \
        numpy \
        sage \
        frida-tools \
        oletools \
        exiftool-py \
        python-magic \
        yara-python
    success "Python tools installed"
}

# =============================================================================
# WEB EXPLOITATION TOOLS
# =============================================================================

install_web_tools() {
    info "Installing web exploitation tools..."

    # Go-based tools
    if command -v go &>/dev/null; then
        go install github.com/ffuf/ffuf/v2@latest
        go install github.com/tomnomnom/httprobe@latest
        go install github.com/tomnomnom/waybackurls@latest
        go install github.com/tomnomnom/gf@latest
        go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
        go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
        go install github.com/projectdiscovery/httpx/cmd/httpx@latest
        go install github.com/hakluke/hakrawler@latest
        go install github.com/tomnomnom/assetfinder@latest
        go install github.com/hahwul/dalfox/v2@latest
        go install github.com/jaeles-project/jaeles@latest
        go install github.com/jaeles-project/gospider@latest
    else
        warn "Go not found, skipping Go-based web tools"
    fi

    # Platform-specific
    if [[ "$OS_TYPE" == "macos" ]]; then
        brew install nikto gobuster dirb sqlmap
    elif [[ "$OS_TYPE" == "debian" ]]; then
        sudo apt-get install -y nikto gobuster dirb sqlmap wfuzz feroxbuster
    fi

    # Node-based tools
    if command -v npm &>/dev/null; then
        npm install -g retire js-beautify node-serialize-utils
    fi

    success "Web tools installed"
}

# =============================================================================
# PWN / BINARY EXPLOITATION
# =============================================================================

install_pwn_tools() {
    info "Installing pwn tools..."

    if [[ "$OS_TYPE" == "macos" ]]; then
        brew install gdb radare2 patchelf nasm yasm binutils
    elif [[ "$OS_TYPE" == "debian" ]]; then
        sudo apt-get install -y gdb gdb-multiarch radare2 patchelf nasm yasm \
            binutils libc6-dbg libc6-i386 libc6-dev-i386 \
            gcc-multilib strace ltrace valgrind \
            python3-dev libseccomp-dev seccomp qemu-user qemu-user-static
    fi

    # pwndbg GDB plugin
    if [[ ! -d ~/.pwndbg ]]; then
        info "Installing pwndbg..."
        git clone https://github.com/pwndbg/pwndbg ~/.pwndbg
        cd ~/.pwndbg && ./setup.sh
    fi

    # peda (alternative GDB plugin)
    if [[ ! -d ~/peda ]]; then
        git clone https://github.com/longld/peda.git ~/peda
    fi

    # GEF (another GDB plugin)
    if ! grep -q "gef" ~/.gdbinit 2>/dev/null; then
        pip3 install --quiet capstone unicorn keystone-engine ropper
        wget -qO ~/.gef.py https://raw.githubusercontent.com/hugsy/gef/main/gef.py
    fi

    # one_gadget
    if command -v gem &>/dev/null; then
        gem install one_gadget --quiet
    fi

    # ROPgadget already via pip; also install via system
    pip3 install --quiet ROPgadget

    # checksec
    if ! command -v checksec &>/dev/null; then
        if [[ "$OS_TYPE" == "macos" ]]; then
            brew install checksec
        elif [[ "$OS_TYPE" == "debian" ]]; then
            pip3 install --quiet checksec.py || true
        fi
    fi

    success "Pwn tools installed"
}

# =============================================================================
# CRYPTOGRAPHY TOOLS
# =============================================================================

install_crypto_tools() {
    info "Installing crypto tools..."

    if [[ "$OS_TYPE" == "macos" ]]; then
        brew install hashcat john-jumbo openssl gnupg msieve
    elif [[ "$OS_TYPE" == "debian" ]]; then
        sudo apt-get install -y hashcat john openssl gnupg
        # rsatool
        pip3 install --quiet rsatool
    fi

    # SageMath (heavy install)
    if ! command -v sage &>/dev/null; then
        warn "SageMath not installed. Install manually from https://sagemath.org for advanced crypto"
        warn "  macOS: brew install --cask sage"
        warn "  Debian: sudo apt install sagemath"
    fi

    # factordb-python
    pip3 install --quiet factordb-pycli sympy

    # RsaCtfTool
    if [[ ! -d ~/tools/RsaCtfTool ]]; then
        mkdir -p ~/tools
        git clone https://github.com/RsaCtfTool/RsaCtfTool.git ~/tools/RsaCtfTool
        pip3 install -r ~/tools/RsaCtfTool/requirements.txt --quiet
    fi

    success "Crypto tools installed"
}

# =============================================================================
# REVERSE ENGINEERING
# =============================================================================

install_rev_tools() {
    info "Installing reverse engineering tools..."

    if [[ "$OS_TYPE" == "macos" ]]; then
        brew install radare2 binwalk capstone sleigh
    elif [[ "$OS_TYPE" == "debian" ]]; then
        sudo apt-get install -y radare2 binwalk capstone ltrace strace \
            upx-ucl strings objdump file
    fi

    # Ghidra (platform-independent Java)
    if [[ ! -d ~/tools/ghidra ]]; then
        info "Downloading Ghidra..."
        GHIDRA_VER="11.1.2"
        GHIDRA_DATE="20240709"
        GHIDRA_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VER}_build/ghidra_${GHIDRA_VER}_PUBLIC_${GHIDRA_DATE}.zip"
        mkdir -p ~/tools
        wget -qO /tmp/ghidra.zip "$GHIDRA_URL" && \
        unzip -q /tmp/ghidra.zip -d ~/tools && \
        mv ~/tools/ghidra_* ~/tools/ghidra && \
        rm /tmp/ghidra.zip
        echo 'alias ghidra="~/tools/ghidra/ghidraRun"' >> ~/.bashrc
        success "Ghidra installed at ~/tools/ghidra"
    fi

    # Binary Ninja (manual install required)
    warn "Binary Ninja requires a license — download from https://binary.ninja"

    # angr
    pip3 install --quiet angr

    # retdec
    if ! command -v retdec-decompiler &>/dev/null; then
        warn "RetDec: install from https://github.com/avast/retdec/releases"
    fi

    success "Rev tools installed"
}

# =============================================================================
# FORENSICS
# =============================================================================

install_forensics_tools() {
    info "Installing forensics tools..."

    if [[ "$OS_TYPE" == "macos" ]]; then
        brew install binwalk foremost testdisk exiftool p7zip imagemagick \
            steghide zsteg ffmpeg volatility3
    elif [[ "$OS_TYPE" == "debian" ]]; then
        sudo apt-get install -y binwalk foremost testdisk exiftool p7zip-full \
            imagemagick steghide pngcheck ffmpeg scalpel dc3dd \
            volatility3 wireshark tshark tcpdump
    fi

    pip3 install --quiet \
        oletools \
        python-magic \
        Pillow \
        stegano \
        invisible-watermark

    # stegseek (fast steghide brute-forcer)
    if ! command -v stegseek &>/dev/null && [[ "$OS_TYPE" == "debian" ]]; then
        wget -qO /tmp/stegseek.deb https://github.com/RickdeJager/stegseek/releases/download/v0.6/stegseek_0.6-1.deb
        sudo dpkg -i /tmp/stegseek.deb
    fi

    # zsteg (PNG/BMP LSB stego)
    if command -v gem &>/dev/null; then
        gem install zsteg --quiet
    fi

    # volatility3
    if ! command -v vol3 &>/dev/null; then
        pip3 install --quiet volatility3
    fi

    success "Forensics tools installed"
}

# =============================================================================
# OSINT
# =============================================================================

install_osint_tools() {
    info "Installing OSINT tools..."

    pip3 install --quiet \
        shodan \
        theHarvester \
        dnspython \
        whois \
        selenium \
        beautifulsoup4 \
        requests \
        Pillow

    if command -v go &>/dev/null; then
        go install github.com/tomnomnom/amass@latest || true
    fi

    if [[ "$OS_TYPE" == "macos" ]]; then
        brew install amass recon-ng
    elif [[ "$OS_TYPE" == "debian" ]]; then
        sudo apt-get install -y amass recon-ng maltego dnsrecon fierce
    fi

    # Sherlock (username OSINT)
    if [[ ! -d ~/tools/sherlock ]]; then
        git clone https://github.com/sherlock-project/sherlock ~/tools/sherlock
        pip3 install -r ~/tools/sherlock/requirements.txt --quiet
    fi

    success "OSINT tools installed"
}

# =============================================================================
# NETWORKING
# =============================================================================

install_networking_tools() {
    info "Installing networking tools..."

    if [[ "$OS_TYPE" == "macos" ]]; then
        brew install wireshark nmap masscan netcat socat scapy tcpdump \
            arp-scan mitmproxy
    elif [[ "$OS_TYPE" == "debian" ]]; then
        sudo apt-get install -y wireshark tshark nmap masscan netcat-openbsd \
            socat tcpdump arp-scan mitmproxy net-tools iproute2 \
            dnsutils whois traceroute
    fi

    pip3 install --quiet scapy impacket

    # Responder (credential capture in controlled environments)
    if [[ ! -d ~/tools/Responder ]]; then
        git clone https://github.com/lgandx/Responder ~/tools/Responder
    fi

    success "Networking tools installed"
}

# =============================================================================
# RANSOMWARE ANALYSIS (DEFENSE / REVERSE ENGINEERING)
# =============================================================================

install_ransomware_analysis_tools() {
    info "Installing ransomware analysis tools..."

    pip3 install --quiet \
        yara-python \
        pefile \
        capstone \
        oletools \
        python-magic \
        cryptography \
        pycryptodome

    # CAPE Sandbox dependencies (static analysis)
    if [[ "$OS_TYPE" == "debian" ]]; then
        sudo apt-get install -y yara clamav strings file ssdeep
    elif [[ "$OS_TYPE" == "macos" ]]; then
        brew install yara clamav ssdeep
    fi

    # VirusTotal CLI
    if command -v go &>/dev/null; then
        go install github.com/VirusTotal/vt-cli/vt@latest || true
    fi

    success "Ransomware analysis tools installed"
}

# =============================================================================
# VULNERABILITY RESEARCH (0-day hunting in CTF targets)
# =============================================================================

install_vuln_research_tools() {
    info "Installing vulnerability research tools..."

    pip3 install --quiet \
        angr \
        manticore \
        boofuzz \
        python-afl \
        atheris

    if [[ "$OS_TYPE" == "debian" ]]; then
        sudo apt-get install -y afl++ libfuzzer valgrind asan-build \
            american-fuzzy-lop
    elif [[ "$OS_TYPE" == "macos" ]]; then
        brew install afl-fuzz
    fi

    # honggfuzz
    if ! command -v honggfuzz &>/dev/null && [[ "$OS_TYPE" == "debian" ]]; then
        sudo apt-get install -y honggfuzz || \
        git clone https://github.com/google/honggfuzz ~/tools/honggfuzz && \
        make -C ~/tools/honggfuzz
    fi

    success "Vuln research tools installed"
}

# =============================================================================
# WORDLISTS
# =============================================================================

install_wordlists() {
    info "Installing wordlists..."
    mkdir -p ~/wordlists

    # SecLists
    if [[ ! -d ~/wordlists/SecLists ]]; then
        git clone --depth 1 https://github.com/danielmiessler/SecLists ~/wordlists/SecLists
    fi

    # rockyou (Debian has it in kali)
    if [[ "$OS_TYPE" == "debian" ]]; then
        if [[ -f /usr/share/wordlists/rockyou.txt.gz ]]; then
            gunzip -k /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true
            ln -sf /usr/share/wordlists/rockyou.txt ~/wordlists/rockyou.txt
        fi
    fi

    success "Wordlists installed at ~/wordlists"
}

# =============================================================================
# SHELL CONFIG
# =============================================================================

configure_shell() {
    info "Configuring shell..."
    SHELL_RC="$HOME/.bashrc"
    [[ -f "$HOME/.zshrc" ]] && SHELL_RC="$HOME/.zshrc"

    # Add Go binaries to PATH
    grep -q "go/bin" "$SHELL_RC" 2>/dev/null || \
        echo 'export PATH="$PATH:$HOME/go/bin:$HOME/.local/bin:$HOME/tools"' >> "$SHELL_RC"

    # CTF aliases
    cat >> "$SHELL_RC" << 'EOF'

# CTF Aliases
alias ctf='cd ~/ctf-toolkit'
alias hex='xxd | head -20'
alias strings='strings -a'
alias b64d='base64 -d'
alias b64e='base64'
alias urld='python3 -c "import sys,urllib.parse; print(urllib.parse.unquote(sys.stdin.read().strip()))"'
alias urle='python3 -c "import sys,urllib.parse; print(urllib.parse.quote(sys.stdin.read().strip()))"'
alias pwnpy='python3 ~/ctf-toolkit/pwn/pwn_template.py'
alias rsa='python3 ~/ctf-toolkit/crypto/rsa_attacks.py'
alias sqli='python3 ~/ctf-toolkit/web/sqli_tester.py'
EOF

    success "Shell configured"
}

# =============================================================================
# MAIN
# =============================================================================

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║         CTF Environment Master Installer         ║"
echo "║  web · pwn · crypto · rev · forensics · osint   ║"
echo "║  networking · ransomware-analysis · vuln-research║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

if [[ "$OS_TYPE" == "macos" ]]; then
    install_homebrew
elif [[ "$OS_TYPE" == "debian" ]]; then
    update_apt
fi

# Run all installers
install_core
install_python_tools
install_web_tools
install_pwn_tools
install_crypto_tools
install_rev_tools
install_forensics_tools
install_osint_tools
install_networking_tools
install_ransomware_analysis_tools
install_vuln_research_tools
install_wordlists
configure_shell

echo ""
success "╔══════════════════════════════════════════════╗"
success "║     Installation complete! Reload shell:     ║"
success "║         source ~/.bashrc  OR  source ~/.zshrc ║"
success "╚══════════════════════════════════════════════╝"
echo ""
info "Optional manual installs:"
info "  Binary Ninja: https://binary.ninja"
info "  IDA Free:     https://hex-rays.com/ida-free"
info "  SageMath:     brew install --cask sage  OR  apt install sagemath"
