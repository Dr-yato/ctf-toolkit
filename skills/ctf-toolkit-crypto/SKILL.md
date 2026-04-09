---
name: ctf-toolkit-crypto
description: Executes cryptography toolkit scripts for CTF challenges. Use when the challenge involves RSA, classical ciphers, XOR, AES, hash cracking, or encoded text. Runs rsa_attacks.py and classical.py from ~/ctf-toolkit/crypto/.
license: MIT
compatibility: Requires ~/ctf-toolkit, pycryptodome, gmpy2, sympy. SageMath optional for lattice attacks.
allowed-tools: Bash Read Write Edit Glob Grep Task
metadata:
  user-invocable: "true"
---

# CTF Toolkit — Cryptography

Operational skill: run the scripts. Pivot to `/ctf-crypto` for deep technique notes.

## Step 1 — Identify the Cipher

```bash
# Check if it's encoded (not encrypted)
python3 ~/ctf-toolkit/crypto/classical.py --mode bases --text "$CIPHERTEXT"

# Check character set
echo "$CIPHERTEXT" | python3 -c "
import sys, collections
t = sys.stdin.read().strip()
print('chars:', sorted(set(t)))
print('length:', len(t))
print('freq:', collections.Counter(t).most_common(5))
"
```

| What you see | Try |
|-------------|-----|
| Only A-Z letters | Caesar brute-force or Vigenere |
| Letters + numbers + `=` at end | Base64 |
| Only 0-9 A-F | Hex |
| Very long number | RSA ciphertext |
| Repeating blocks | AES-ECB |
| `n, e, c` given | RSA attack |
| Binary/octal digits | Base decode |
| `$` substitution | Bacon / Polybius |

## Step 2 — Classical Ciphers

```bash
TOOLKIT=~/ctf-toolkit

# Caesar brute force (top 5 by English frequency score)
python3 $TOOLKIT/crypto/classical.py --mode caesar --text "$CT"

# Decode with known shift
python3 $TOOLKIT/crypto/classical.py --mode caesar --text "$CT" --shift 13 --decrypt

# ROT13
python3 $TOOLKIT/crypto/classical.py --mode rot13 --text "$CT"

# Atbash (A↔Z)
python3 $TOOLKIT/crypto/classical.py --mode atbash --text "$CT"

# Auto-break Vigenere (IC method + freq analysis)
python3 $TOOLKIT/crypto/classical.py --mode vigenere-break --text "$CT"

# Vigenere with known key
python3 $TOOLKIT/crypto/classical.py --mode vigenere --text "$CT" --key "secret" --decrypt

# Rail-fence (default 3 rails)
python3 $TOOLKIT/crypto/classical.py --mode railfence --text "$CT" --rails 3 --decrypt

# Columnar transposition
python3 $TOOLKIT/crypto/classical.py --mode columnar --text "$CT" --key "CRYPTO" --decrypt

# Frequency analysis (identify monoalphabetic substitution)
python3 $TOOLKIT/crypto/classical.py --mode freq --text "$CT"
```

## Step 3 — XOR

```bash
# Single-byte XOR brute force
python3 $TOOLKIT/crypto/classical.py --mode xor-brute --text "$HEX_CT"

# Estimate repeating XOR key length (Hamming distance)
python3 - << 'EOF'
import sys
sys.path.insert(0, '$TOOLKIT')
from crypto.classical import xor_key_size
data = bytes.fromhex("$HEX_CT")
for ks, score in xor_key_size(data):
    print(f"key_len={ks}  hamming_score={score:.3f}")
EOF

# Decrypt with known key (hex)
python3 $TOOLKIT/crypto/classical.py --mode xor --text "$HEX_CT" --key "deadbeef"

# xortool (auto key size + key)
xortool -x "$HEX_CT_FILE"
```

## Step 4 — RSA

```bash
# Try factoring N first
python3 $TOOLKIT/crypto/rsa_attacks.py --mode factor --n "$N" --e "$E" --c "$C"

# Fermat factorization (p, q close together)
python3 $TOOLKIT/crypto/rsa_attacks.py --mode fermat --n "$N"

# Small public exponent (e=3, no padding)
python3 $TOOLKIT/crypto/rsa_attacks.py --mode small-e --n "$N" --e 3 --c "$C"

# Wiener's attack (e very large → d is small)
python3 $TOOLKIT/crypto/rsa_attacks.py --mode wiener --n "$N" --e "$E"

# Decrypt with known private key
python3 $TOOLKIT/crypto/rsa_attacks.py --mode decrypt --n "$N" --d "$D" --c "$C"

# From PEM public key file
python3 $TOOLKIT/crypto/rsa_attacks.py --mode factor --pubkey pub.pem --c "$C"

# RsaCtfTool (tries all attacks automatically)
python3 ~/tools/RsaCtfTool/RsaCtfTool.py --publickey pub.pem --uncipher "$C"

# factordb lookup
python3 -c "
from factordb.factordb import FactorDB
f = FactorDB($N); f.connect()
print(f.get_factor_list())
"
```

## Step 5 — AES / Block Ciphers

```bash
# AES-ECB detection: identical 16-byte blocks in ciphertext = ECB mode
python3 - << 'EOF'
ct = bytes.fromhex("$HEX_CT")
blocks = [ct[i:i+16].hex() for i in range(0, len(ct), 16)]
from collections import Counter
dupes = [b for b,c in Counter(blocks).items() if c > 1]
if dupes: print("ECB mode detected — repeated blocks:", dupes)
else: print("No repeated blocks — CBC/CTR likely")
EOF

# CBC padding oracle (manual — write custom script)
# AES-CTR: if nonce reused across messages, XOR ciphertexts to cancel keystream

# Decrypt with known key+IV
python3 - << 'EOF'
from Crypto.Cipher import AES; from Crypto.Util.Padding import unpad
key = bytes.fromhex("$KEY_HEX")
iv  = bytes.fromhex("$IV_HEX")
ct  = bytes.fromhex("$CT_HEX")
print(unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16))
EOF
```

## Step 6 — Hash Cracking

```bash
# Identify hash type
hash-identifier "$HASH" 2>/dev/null || python3 -c "
h = '$HASH'
print('MD5' if len(h)==32 else 'SHA1' if len(h)==40 else 'SHA256' if len(h)==64 else 'SHA512' if len(h)==128 else 'unknown')
"

# Crack with hashcat
hashcat -m 0   "$HASH" ~/wordlists/rockyou.txt   # MD5
hashcat -m 100 "$HASH" ~/wordlists/rockyou.txt   # SHA1
hashcat -m 1400 "$HASH" ~/wordlists/rockyou.txt  # SHA256

# Online: crackstation.net — paste hash
```

## Decision Map

```
Letters only, high freq E/T/A  → Caesar or Vigenere (use classical.py)
n, e, c integers               → RSA (use rsa_attacks.py, try all modes)
XOR'd hex blob                 → xor-brute then xor_key_size
Base64/hex/binary              → classical.py --mode bases
AES with repeated blocks       → ECB mode, exploit block patterns
AES with oracle/padding error  → padding oracle attack
Large prime factored easily    → factor --mode fermat or factor db
```

## Pivot

- Deep technique notes: `/ctf-crypto`
- Ransomware decryption: `/ctf-toolkit-ransomware`
