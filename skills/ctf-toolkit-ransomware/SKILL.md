---
name: ctf-toolkit-ransomware
description: Executes ransomware analysis and recovery toolkit scripts for CTF challenges. Use when the challenge provides a ransomware binary to reverse and encrypted files to recover. Runs analyze_ransomware.py from ~/ctf-toolkit/ransomware-analysis/.
license: MIT
compatibility: Requires ~/ctf-toolkit, pycryptodome, pefile (optional), yara-python (optional).
allowed-tools: Bash Read Write Edit Glob Grep Task
metadata:
  user-invocable: "true"
---

# CTF Toolkit — Ransomware Analysis

Operational skill: analyze and recover. Pivot to `/ctf-ransomware` for detailed technique notes.

## Step 1 — Initial Triage

```bash
TOOLKIT=~/ctf-toolkit
BIN=./ransomware     # the ransomware binary
ENC_DIR=./encrypted  # directory of encrypted files

# Static analysis
python3 $TOOLKIT/ransomware-analysis/analyze_ransomware.py --mode analyze --binary $BIN

# Check for common CTF weaknesses (hardcoded key, time PRNG)
python3 $TOOLKIT/ransomware-analysis/analyze_ransomware.py --mode check-weak --binary $BIN

# Look for embedded key candidates (32/16-byte sequences)
python3 $TOOLKIT/ransomware-analysis/analyze_ransomware.py --mode extract-key --binary $BIN
```

## Step 2 — Identify Encryption Algorithm

```bash
# String search in binary
strings $BIN | grep -iE "(aes|des|rsa|chacha|rc4|blowfish|xor|key|nonce|iv|seed)"

# Check entropy (high = encrypted/packed binary)
python3 - << 'EOF'
import math, collections
d = open("$BIN", "rb").read()
f = collections.Counter(d)
e = -sum((c/len(d))*math.log2(c/len(d)) for c in f.values())
print(f"entropy: {e:.3f}  {'(packed)' if e > 7.0 else '(ok)'}")
EOF

# Check encrypted file size (AES block alignment)
python3 - << 'EOF'
import os
for f in os.listdir("$ENC_DIR"):
    size = os.path.getsize(f"$ENC_DIR/{f}")
    print(f"{f}: {size} bytes  {'(AES-aligned)' if size % 16 == 0 else ''}")
EOF

# Check first 16 bytes of encrypted file (IV prepended?)
xxd "$ENC_DIR/$(ls $ENC_DIR | head -1)" | head -2
```

## Step 3 — Recover the Key

### Hardcoded Key

```bash
# Hex strings of 32/64 chars
strings $BIN | grep -E '^[A-Fa-f0-9]{32,64}$'

# Base64 strings of length 24/44
strings $BIN | grep -E '^[A-Za-z0-9+/]{24,}={0,2}$'

# Print all 16-byte printable sequences
python3 - << 'EOF'
d = open("$BIN","rb").read()
for i in range(len(d)-16):
    c = d[i:i+16]
    if all(32 <= b < 127 for b in c) and len(set(c)) > 8:
        print(f"0x{i:08x}: {c.hex()}  {c!r}")
EOF
```

### XOR Key (Known Plaintext)

```bash
# Use known file header to recover key fragment
python3 - << 'EOF'
known_pt = b"\x89PNG\r\n\x1a\n"   # PNG magic — adjust to file type
ct = open("$ENC_DIR/some_file.png.locked", "rb").read()
key = bytes(p ^ c for p, c in zip(known_pt, ct))
print(f"XOR key fragment: {key.hex()}  {key!r}")
# If key repeats, full key length = pattern repeat
EOF
```

### Time-Based PRNG

```bash
# Brute force timestamp seed (within last 24h)
python3 - << 'EOF'
import time, random
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

ct = open("$ENC_DIR/sample.locked", "rb").read()
now = int(time.time())
for t in range(now - 86400, now):
    random.seed(t)
    key = bytes([random.randint(0, 255) for _ in range(32)])
    iv  = bytes([random.randint(0, 255) for _ in range(16)])
    try:
        plain = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16)
        if plain.startswith(b"\x89PNG") or b"flag" in plain.lower():
            print(f"[+] Found! seed={t} key={key.hex()} iv={iv.hex()}")
            break
    except Exception:
        pass
EOF
```

## Step 4 — Decrypt Files

```bash
# AES-CBC
python3 $TOOLKIT/ransomware-analysis/analyze_ransomware.py \
  --mode recover \
  --encrypted $ENC_DIR \
  --key "$KEY_HEX" \
  --iv "$IV_HEX" \
  --cipher aes-cbc \
  --out ./recovered

# AES-ECB (no IV needed)
python3 $TOOLKIT/ransomware-analysis/analyze_ransomware.py \
  --mode recover \
  --encrypted $ENC_DIR \
  --key "$KEY_HEX" \
  --cipher aes-ecb \
  --out ./recovered

# XOR
python3 $TOOLKIT/ransomware-analysis/analyze_ransomware.py \
  --mode recover \
  --encrypted $ENC_DIR \
  --key "$KEY_HEX" \
  --cipher xor \
  --out ./recovered

# RC4
python3 $TOOLKIT/ransomware-analysis/analyze_ransomware.py \
  --mode recover \
  --encrypted $ENC_DIR \
  --key "$KEY_HEX" \
  --cipher rc4 \
  --out ./recovered
```

## Step 5 — Find the Flag

```bash
# In recovered files
strings ./recovered/* | grep -iE "(CTF\{|FLAG\{|flag\{)"
file ./recovered/*     # check file types
grep -r "flag" ./recovered/ 2>/dev/null

# May be split across multiple files
cat ./recovered/*.txt 2>/dev/null
```

## Decision Map

```
Source code given          → read it, find key derivation, skip to Step 4
Binary given               → Steps 1-3, then Step 4
XOR-based                  → known-plaintext recovery (Step 3)
AES + hardcoded key        → strings search → Step 4
AES + time-seeded random   → brute timestamp (Step 3)
RSA-encrypted AES key      → factor RSA N → /ctf-toolkit-crypto → decrypt AES key
ChaCha20 / Salsa20         → find nonce in file header (first 8/12 bytes)
```

## Pivot

- Reverse engineering the binary: `/ctf-toolkit-rev`
- Breaking the crypto scheme: `/ctf-toolkit-crypto`
- Deep analysis notes: `/ctf-ransomware`
