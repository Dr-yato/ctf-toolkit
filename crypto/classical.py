#!/usr/bin/env python3
"""
Classical Cipher Solver — CTF Toolkit
Covers: Caesar, ROT13/N, Vigenère, Atbash, Rail-fence, columnar transposition,
        XOR brute-force, base-N decoding, frequency analysis
Usage: python3 classical.py --mode <cipher> --text "..." [options]
"""
import argparse, string, collections, itertools, base64, binascii


ENGLISH_FREQ = "etaoinshrdlcumwfgypbvkjxqz"
ALPHABET = string.ascii_lowercase


# ─── SUBSTITUTION ─────────────────────────────────────────────────────────────

def caesar(text: str, shift: int, decrypt: bool = False) -> str:
    shift = (-shift) % 26 if decrypt else shift % 26
    result = []
    for c in text:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((ord(c) - base + shift) % 26 + base))
        else:
            result.append(c)
    return "".join(result)


def caesar_brute(text: str) -> list:
    results = []
    for i in range(26):
        dec = caesar(text, i, decrypt=True)
        score = freq_score(dec.lower())
        results.append((i, score, dec))
    results.sort(key=lambda x: -x[1])
    return results


def rot13(text: str) -> str:
    return caesar(text, 13)


def atbash(text: str) -> str:
    result = []
    for c in text:
        if c.isalpha():
            base = 'A' if c.isupper() else 'a'
            result.append(chr(ord(base) + 25 - (ord(c) - ord(base))))
        else:
            result.append(c)
    return "".join(result)


def vigenere(text: str, key: str, decrypt: bool = False) -> str:
    key = key.lower()
    result = []
    ki = 0
    for c in text:
        if c.isalpha():
            shift = ord(key[ki % len(key)]) - ord('a')
            if decrypt:
                shift = -shift
            base = 'A' if c.isupper() else 'a'
            result.append(chr((ord(c) - ord(base) + shift) % 26 + base))
            ki += 1
        else:
            result.append(c)
    return "".join(result)


def vigenere_ic(text: str, max_key_len: int = 20) -> int:
    """Estimate Vigenère key length using Index of Coincidence."""
    text = "".join(c for c in text.lower() if c.isalpha())
    best_ic = 0
    best_len = 1
    for kl in range(1, max_key_len + 1):
        ic_total = 0
        for i in range(kl):
            sub = text[i::kl]
            n = len(sub)
            if n < 2:
                continue
            freq = collections.Counter(sub)
            ic = sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))
            ic_total += ic
        avg_ic = ic_total / kl
        if avg_ic > best_ic:
            best_ic = avg_ic
            best_len = kl
    return best_len


def vigenere_break(ciphertext: str, max_key_len: int = 20) -> tuple:
    """Break Vigenère by IC + frequency analysis."""
    text = "".join(c for c in ciphertext.lower() if c.isalpha())
    key_len = vigenere_ic(text, max_key_len)
    print(f"[*] Estimated key length: {key_len}")
    key = ""
    for i in range(key_len):
        sub = text[i::key_len]
        best_shift = max(range(26), key=lambda s: freq_score(caesar(sub, s, decrypt=True)))
        key += ALPHABET[best_shift]
    plaintext = vigenere(ciphertext, key, decrypt=True)
    return key, plaintext


# ─── TRANSPOSITION ────────────────────────────────────────────────────────────

def rail_fence(text: str, rails: int, decrypt: bool = False) -> str:
    if not decrypt:
        fence = [[] for _ in range(rails)]
        rail = 0; direction = 1
        for c in text:
            fence[rail].append(c)
            if rail == 0: direction = 1
            elif rail == rails - 1: direction = -1
            rail += direction
        return "".join("".join(r) for r in fence)
    else:
        n = len(text)
        pattern = []
        rail = 0; direction = 1
        for i in range(n):
            pattern.append(rail)
            if rail == 0: direction = 1
            elif rail == rails - 1: direction = -1
            rail += direction
        indices = sorted(range(n), key=lambda i: pattern[i])
        result = [""] * n
        for pos, char in zip(indices, text):
            result[pos] = char
        return "".join(result)


def columnar_transposition(text: str, key: str, decrypt: bool = False) -> str:
    order = sorted(range(len(key)), key=lambda i: key[i])
    cols = len(key)
    rows = -(-len(text) // cols)
    padded = text.ljust(rows * cols)

    if not decrypt:
        grid = [list(padded[i*cols:(i+1)*cols]) for i in range(rows)]
        return "".join(grid[r][c] for c in order for r in range(rows))
    else:
        col_len = rows
        result = [""] * (rows * cols)
        pos = 0
        for c in order:
            for r in range(col_len):
                result[r * cols + c] = text[pos]
                pos += 1
        return "".join(result).rstrip()


# ─── FREQUENCY ANALYSIS ───────────────────────────────────────────────────────

def freq_score(text: str) -> float:
    """Score text against English letter frequencies."""
    freq_map = {c: i for i, c in enumerate(reversed(ENGLISH_FREQ))}
    return sum(freq_map.get(c, 0) for c in text.lower() if c.isalpha())


def frequency_analysis(text: str) -> list:
    """Return letter frequencies sorted by count."""
    text = "".join(c for c in text.lower() if c.isalpha())
    total = len(text)
    freq = collections.Counter(text)
    return [(c, n, n/total*100) for c, n in freq.most_common()]


# ─── BASE DECODING ────────────────────────────────────────────────────────────

def decode_all_bases(text: str):
    """Try all common base decodings."""
    text = text.strip()
    results = {}

    # Base64
    try:
        dec = base64.b64decode(text + "==").decode(errors="replace")
        results["base64"] = dec
    except Exception: pass

    # Base32
    try:
        dec = base64.b32decode(text.upper() + "=" * ((8 - len(text) % 8) % 8)).decode(errors="replace")
        results["base32"] = dec
    except Exception: pass

    # Base16 / hex
    try:
        dec = bytes.fromhex(text.replace(" ","")).decode(errors="replace")
        results["base16/hex"] = dec
    except Exception: pass

    # Base58
    try:
        BASE58_CHARS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        num = 0
        for c in text:
            num = num * 58 + BASE58_CHARS.index(c)
        dec = num.to_bytes((num.bit_length() + 7) // 8, "big").decode(errors="replace")
        results["base58"] = dec
    except Exception: pass

    # Base85
    try:
        dec = base64.b85decode(text).decode(errors="replace")
        results["base85"] = dec
    except Exception: pass

    for name, val in results.items():
        print(f"  [{name}] {val[:120]}")
    return results


# ─── XOR ──────────────────────────────────────────────────────────────────────

def xor_single(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


def xor_brute(data: bytes, max_key: int = 256) -> list:
    results = []
    for k in range(max_key):
        dec = xor_single(data, k)
        try:
            text = dec.decode()
            score = freq_score(text)
            results.append((k, score, text))
        except Exception:
            pass
    results.sort(key=lambda x: -x[1])
    return results[:5]


def xor_repeating(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def xor_key_size(data: bytes, max_ks: int = 40) -> list:
    """Estimate XOR key size using Hamming distance."""
    def hamming(a: bytes, b: bytes) -> int:
        return bin(int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).count("1")

    scores = []
    for ks in range(2, min(max_ks, len(data) // 2)):
        chunks = [data[i*ks:(i+1)*ks] for i in range(min(4, len(data)//ks))]
        dists = []
        for a, b in itertools.combinations(chunks, 2):
            if len(a) == len(b) == ks:
                dists.append(hamming(a, b) / ks)
        if dists:
            scores.append((ks, sum(dists)/len(dists)))
    scores.sort(key=lambda x: x[1])
    return scores[:5]


# ─── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Classical Cipher Solver")
    parser.add_argument("--mode", required=True,
                        choices=["caesar","rot13","atbash","vigenere","vigenere-break",
                                 "railfence","columnar","freq","bases","xor","xor-brute"])
    parser.add_argument("--text",  help="Plaintext/ciphertext")
    parser.add_argument("--file",  help="Input file")
    parser.add_argument("--key",   default="", help="Key (for Vigenère, columnar, etc.)")
    parser.add_argument("--shift", type=int, default=0)
    parser.add_argument("--rails", type=int, default=3)
    parser.add_argument("--decrypt", action="store_true")
    args = parser.parse_args()

    text = args.text
    if args.file:
        with open(args.file) as f:
            text = f.read().strip()
    if not text:
        text = input("Input text: ")

    if args.mode == "caesar":
        if args.shift:
            print(caesar(text, args.shift, args.decrypt))
        else:
            for shift, score, dec in caesar_brute(text)[:5]:
                print(f"  shift={shift:2d}  score={score:4.0f}  {dec[:60]}")

    elif args.mode == "rot13":
        print(rot13(text))

    elif args.mode == "atbash":
        print(atbash(text))

    elif args.mode == "vigenere":
        if not args.key:
            args.key = input("Key: ")
        print(vigenere(text, args.key, args.decrypt))

    elif args.mode == "vigenere-break":
        key, plain = vigenere_break(text)
        print(f"[+] Key:       {key}")
        print(f"[+] Plaintext: {plain}")

    elif args.mode == "railfence":
        print(rail_fence(text, args.rails, args.decrypt))

    elif args.mode == "columnar":
        if not args.key:
            args.key = input("Key: ")
        print(columnar_transposition(text, args.key, args.decrypt))

    elif args.mode == "freq":
        for c, n, pct in frequency_analysis(text)[:10]:
            print(f"  {c}: {n:4d}  ({pct:.1f}%)")

    elif args.mode == "bases":
        decode_all_bases(text)

    elif args.mode == "xor":
        key = bytes.fromhex(args.key) if args.key else bytes([0])
        print(xor_repeating(text.encode(), key).hex())

    elif args.mode == "xor-brute":
        data = bytes.fromhex(text) if all(c in "0123456789abcdefABCDEF " for c in text.strip()) \
               else text.encode()
        for k, score, dec in xor_brute(data):
            print(f"  key=0x{k:02x}  {dec[:80]}")


if __name__ == "__main__":
    main()
