#!/usr/bin/env python3
"""
Ransomware Analysis & Recovery — CTF Toolkit
Purpose: REVERSE-ENGINEER and DECRYPT ransomware challenges in CTFs.
Covers: key extraction, XOR/AES/RSA decryption, IV/key recovery,
        static analysis, entropy checks, file recovery

NOTE: This script is for CTF ransomware ANALYSIS challenges — decrypting
      files and recovering keys from intentionally vulnerable implementations.
"""
import argparse, os, sys, struct, hashlib, itertools
from pathlib import Path

try:
    from Crypto.Cipher import AES, DES, DES3, Blowfish, ARC4
    from Crypto.Util.Padding import unpad
    from Crypto.Util.number import long_to_bytes
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    print("[!] Install pycryptodome: pip install pycryptodome")

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False


# ─── STATIC ANALYSIS ──────────────────────────────────────────────────────────

def analyze_binary(path: str) -> dict:
    """Static analysis of ransomware binary."""
    results = {}
    with open(path, "rb") as f:
        data = f.read()

    # File type
    if data[:4] == b"\x7fELF":
        results["type"] = "ELF"
    elif data[:2] == b"MZ":
        results["type"] = "PE (Windows)"
    else:
        results["type"] = "Unknown"
    print(f"[*] Type: {results['type']}")

    # Entropy
    import math, collections
    freq = collections.Counter(data)
    total = len(data)
    ent = -sum((c/total)*math.log2(c/total) for c in freq.values())
    print(f"[*] Entropy: {ent:.3f} (>7.5 = likely packed/encrypted)")
    results["entropy"] = ent

    # Extract strings
    strings = []
    current = b""
    for b in data:
        if 32 <= b <= 126:
            current += bytes([b])
        else:
            if len(current) >= 6:
                strings.append(current.decode())
            current = b""

    crypto_indicators = [
        "AES", "RSA", "DES", "Blowfish", "ChaCha", "Salsa", "RC4",
        "CryptGenRandom", "CryptEncrypt", "BCryptGenRandom",
        "openssl", "mbedtls", "crypto",
        "ransom", "bitcoin", "decrypt", "payment",
    ]
    print("\n[*] Crypto-related strings:")
    for s in strings:
        if any(ind.lower() in s.lower() for ind in crypto_indicators):
            print(f"  {s}")

    print("\n[*] URL/path strings:")
    for s in strings:
        if s.startswith(("http://", "https://", "/", "C:\\", "\\\\")) or ".onion" in s:
            print(f"  {s}")

    # PE analysis
    if results["type"] == "PE (Windows)" and HAS_PEFILE:
        pe = pefile.PE(path)
        print("\n[*] PE Imports (suspicious):")
        for entry in pe.DIRECTORY_ENTRY_IMPORT if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else []:
            dll = entry.dll.decode()
            funcs = [f.name.decode() if f.name else hex(f.ordinal)
                     for f in entry.imports if f.name]
            crypto_funcs = [f for f in funcs if any(c in f for c in
                           ["Crypt", "Rand", "AES", "RSA", "Hash", "Encrypt"])]
            if crypto_funcs:
                print(f"  {dll}: {', '.join(crypto_funcs)}")

    return results


# ─── KEY RECOVERY ─────────────────────────────────────────────────────────────

def extract_key_from_binary(path: str, key_len: int = 16) -> list:
    """Look for potential AES keys in binary (sequences of high-entropy bytes)."""
    with open(path, "rb") as f:
        data = f.read()
    candidates = []
    for i in range(len(data) - key_len):
        chunk = data[i:i+key_len]
        unique = len(set(chunk))
        if unique > key_len * 0.7:  # High variety = possibly random key
            candidates.append((i, chunk))
    print(f"[*] Found {len(candidates)} key candidates (showing first 10):")
    for offset, key in candidates[:10]:
        print(f"  offset 0x{offset:08x}: {key.hex()} ({key!r})")
    return candidates


def recover_xor_key(plaintext: bytes, ciphertext: bytes) -> bytes:
    """Recover XOR key given known plaintext."""
    return bytes(p ^ c for p, c in zip(plaintext, ciphertext))


# ─── DECRYPTION ───────────────────────────────────────────────────────────────

def decrypt_aes(ciphertext: bytes, key: bytes,
                iv: bytes = None, mode: str = "cbc") -> bytes:
    if not HAS_CRYPTO:
        return b""
    mode_map = {"cbc": AES.MODE_CBC, "ecb": AES.MODE_ECB,
                "ctr": AES.MODE_CTR, "gcm": AES.MODE_GCM,
                "cfb": AES.MODE_CFB, "ofb": AES.MODE_OFB}
    m = mode_map.get(mode.lower(), AES.MODE_CBC)
    if m == AES.MODE_ECB:
        cipher = AES.new(key, m)
    else:
        cipher = AES.new(key, m, iv or b"\x00" * 16)
    try:
        plaintext = cipher.decrypt(ciphertext)
        return unpad(plaintext, 16)
    except Exception:
        return cipher.decrypt(ciphertext)  # return without unpadding


def decrypt_xor(ciphertext: bytes, key: bytes) -> bytes:
    return bytes(c ^ key[i % len(key)] for i, c in enumerate(ciphertext))


def decrypt_rc4(ciphertext: bytes, key: bytes) -> bytes:
    if not HAS_CRYPTO:
        return b""
    cipher = ARC4.new(key)
    return cipher.decrypt(ciphertext)


def brute_xor_key(encrypted_files: list, known_ext: str = None) -> bytes:
    """
    Brute force XOR key by trying known file headers.
    encrypted_files: list of (original_name, encrypted_bytes) tuples
    """
    MAGIC = {
        ".jpg":  b"\xff\xd8\xff",
        ".png":  b"\x89PNG",
        ".pdf":  b"%PDF",
        ".zip":  b"PK\x03\x04",
        ".docx": b"PK\x03\x04",
        ".txt":  None,
    }
    for ext, magic in MAGIC.items():
        if known_ext and ext != known_ext:
            continue
        if not magic:
            continue
        for fname, data in encrypted_files:
            # Try key lengths 1-32
            for key_len in range(1, 33):
                for combo in itertools.product(range(256), repeat=key_len):
                    key = bytes(combo)
                    decrypted = decrypt_xor(data[:len(magic)], key)
                    if decrypted == magic:
                        print(f"[+] XOR key found! key={key.hex()}")
                        return key
    return b""


def recover_files(encrypted_dir: str, key: bytes,
                  cipher: str = "xor", iv: bytes = None,
                  out_dir: str = "./recovered") -> list:
    """Decrypt all files in a directory."""
    os.makedirs(out_dir, exist_ok=True)
    recovered = []
    for f in Path(encrypted_dir).rglob("*"):
        if not f.is_file():
            continue
        data = f.read_bytes()
        if cipher == "xor":
            plain = decrypt_xor(data, key)
        elif cipher == "aes-cbc":
            plain = decrypt_aes(data, key, iv, "cbc")
        elif cipher == "aes-ecb":
            plain = decrypt_aes(data, key, mode="ecb")
        elif cipher == "rc4":
            plain = decrypt_rc4(data, key)
        else:
            plain = data

        out_path = Path(out_dir) / f.name.rsplit(".", 1)[0]  # strip ransomware extension
        out_path.write_bytes(plain)
        print(f"[+] Recovered: {out_path}")
        recovered.append(str(out_path))
    return recovered


# ─── COMMON CTF PATTERNS ──────────────────────────────────────────────────────

def check_weak_implementation(path: str):
    """Check for common CTF ransomware weaknesses."""
    print("[*] Checking for common CTF weaknesses:")
    with open(path, "rb") as f:
        data = f.read()

    issues = []

    # Hardcoded key
    AES_KEY_PATTERNS = [b"\x00" * 16, bytes(range(16)), b"0123456789abcdef"]
    for pattern in AES_KEY_PATTERNS:
        if pattern in data:
            issues.append(f"Hardcoded key: {pattern.hex()}")

    # Time-based seed (PRNG with time() seeded)
    if b"time" in data.lower() and b"rand" in data.lower():
        issues.append("Possible time-based PRNG seeding (brute-force timestamp)")

    # Same key for all files
    strings_out = [data[i:i+16] for i in range(0, len(data)-16, 16)
                   if all(32 <= b <= 126 for b in data[i:i+16])]
    if issues:
        for issue in issues:
            print(f"  [!] {issue}")
    else:
        print("  [-] No obvious weaknesses found — deeper analysis needed")


# ─── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Ransomware Analysis/Recovery — CTF")
    parser.add_argument("--mode",
                        choices=["analyze","recover","extract-key","check-weak"],
                        required=True)
    parser.add_argument("--binary",     help="Ransomware binary to analyze")
    parser.add_argument("--encrypted",  help="Encrypted file or directory")
    parser.add_argument("--key",        help="Decryption key (hex)")
    parser.add_argument("--iv",         help="IV (hex, for AES-CBC)")
    parser.add_argument("--cipher",     default="xor",
                        choices=["xor","aes-cbc","aes-ecb","rc4"])
    parser.add_argument("--out",        default="./recovered")
    args = parser.parse_args()

    if args.mode == "analyze":
        if not args.binary:
            print("[-] Provide --binary")
            return
        analyze_binary(args.binary)

    elif args.mode == "extract-key":
        if not args.binary:
            print("[-] Provide --binary")
            return
        extract_key_from_binary(args.binary)

    elif args.mode == "check-weak":
        if not args.binary:
            print("[-] Provide --binary")
            return
        check_weak_implementation(args.binary)

    elif args.mode == "recover":
        if not args.encrypted or not args.key:
            print("[-] Provide --encrypted and --key")
            return
        key = bytes.fromhex(args.key)
        iv  = bytes.fromhex(args.iv) if args.iv else None
        if os.path.isdir(args.encrypted):
            recover_files(args.encrypted, key, args.cipher, iv, args.out)
        else:
            data = open(args.encrypted, "rb").read()
            if args.cipher == "xor":
                plain = decrypt_xor(data, key)
            elif "aes" in args.cipher:
                plain = decrypt_aes(data, key, iv, args.cipher.split("-")[1])
            elif args.cipher == "rc4":
                plain = decrypt_rc4(data, key)
            else:
                plain = data
            out = args.out + "/decrypted"
            os.makedirs(args.out, exist_ok=True)
            with open(out, "wb") as f:
                f.write(plain)
            print(f"[+] Decrypted to: {out}")
            print(f"[+] Preview: {plain[:100]!r}")


if __name__ == "__main__":
    main()
