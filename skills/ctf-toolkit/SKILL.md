---
name: ctf-toolkit
description: Master router for the CTF toolkit. Use when starting any CTF challenge to select the right category skill and toolkit script. Routes to ctf-toolkit-web, ctf-toolkit-pwn, ctf-toolkit-crypto, ctf-toolkit-forensics, ctf-toolkit-networking, ctf-toolkit-ransomware, ctf-toolkit-vuln, ctf-toolkit-osint, or ctf-toolkit-rev based on challenge type.
license: MIT
compatibility: Requires ~/ctf-toolkit to be cloned. Python 3, bash, and standard CTF tools.
allowed-tools: Bash Read Write Edit Glob Grep Task
metadata:
  user-invocable: "true"
---

# CTF Toolkit — Master Router

This skill routes to the correct category skill and executes toolkit scripts.

## Setup Check

Before anything else, verify the toolkit is installed:

```bash
ls ~/ctf-toolkit/ || git clone https://github.com/Dr-yato/ctf-toolkit ~/ctf-toolkit
```

## Routing Table

Read the challenge description, then pick the matching skill:

| Challenge indicators | Skill to invoke |
|----------------------|----------------|
| HTTP, web app, API, login, SQL, XSS, SSRF, JWT, template | `ctf-toolkit-web` |
| Binary, ELF, segfault, overflow, ROP, heap, format string | `ctf-toolkit-pwn` |
| Cipher, RSA, AES, encoded text, hash, math | `ctf-toolkit-crypto` |
| .pcap, .img, memory dump, steganography, file carving | `ctf-toolkit-forensics` |
| Network traffic, custom protocol, socket service | `ctf-toolkit-networking` |
| Ransomware binary, encrypted files, decryption challenge | `ctf-toolkit-ransomware` |
| Find the bug, fuzzing, source code audit, 0-day in binary | `ctf-toolkit-vuln` |
| Username, domain, metadata, geolocation, social media | `ctf-toolkit-osint` |
| Reverse engineering, decompile, patch binary, anti-debug | `ctf-toolkit-rev` |
| Admin bot, stored XSS, CSS exfil, CSP bypass, 0-click | `ctf-toolkit-web` + read client-side sections |

## First Actions on Any Challenge

```bash
# 1. Read the challenge prompt carefully
# 2. Download all provided files
file *                          # identify file types
strings -n 8 * | grep -iE "flag|ctf|key|pass"  # quick string search

# 3. Check for flags immediately
python3 ~/ctf-toolkit/common/ctf_utils.py  # self-test to confirm toolkit works

# 4. Invoke the relevant category skill
```

## Common Utility — Use Anywhere

```python
# In any solve script:
import sys; sys.path.insert(0, '~/ctf-toolkit')
from common.ctf_utils import *

# Decode anything quickly
decode_all("SGVsbG8gV29ybGQ=")   # tries base64/32/hex/url/rot13
extract_flags(response_text)      # finds CTF{...} patterns
hexdump(binary_data)              # formatted hex dump
p64(0xdeadbeef)                   # struct pack helpers
```

## After Solving

Document the solution:
- What was the vulnerability / bug class?
- Which script / command got the flag?
- What was the flag?

Use `/ctf-writeup` skill to write up the solution.
