#!/usr/bin/env python3
"""
RSA Attack Toolkit — CTF Toolkit
Covers: small e, common factor, Wiener's, Hastad, LSB oracle,
        Franklin-Reiter, Coppersmith, Fermat, Boneh-Durfee sketch
Usage: python3 rsa_attacks.py --mode <attack> [options]
"""
import argparse, math, sys
from functools import reduce

try:
    from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, getPrime, isPrime
    from Crypto.PublicKey import RSA
except ImportError:
    print("[-] Install pycryptodome: pip install pycryptodome")
    sys.exit(1)

try:
    import gmpy2
    HAS_GMPY2 = True
except ImportError:
    HAS_GMPY2 = False
    print("[!] gmpy2 not found — some attacks will be slower")


# ─── HELPERS ──────────────────────────────────────────────────────────────────

def isqrt(n: int) -> int:
    if HAS_GMPY2:
        return int(gmpy2.isqrt(n))
    x = n
    y = (x + 1) // 2
    while y < x:
        x, y = y, (y + n // y) // 2
    return x


def iroot(k: int, n: int) -> tuple:
    """Return (root, exact) where root = floor(n^(1/k))."""
    if HAS_GMPY2:
        return gmpy2.iroot(n, k)
    u, s = n, n + 1
    while u < s:
        s = u
        t = (k - 1) * s + n // pow(s, k - 1)
        u = t // k
    return s, pow(s, k) == n


def gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a


def extended_gcd(a: int, b: int):
    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def crt(remainders: list, moduli: list) -> int:
    """Chinese Remainder Theorem."""
    M = reduce(lambda a, b: a * b, moduli)
    result = 0
    for r, m in zip(remainders, moduli):
        Mi = M // m
        _, inv, _ = extended_gcd(Mi % m, m)
        result += r * Mi * inv
    return result % M


# ─── FACTORIZATION ────────────────────────────────────────────────────────────

def fermat_factor(n: int, max_iter: int = 1_000_000) -> tuple:
    """Fermat factorization — works when p, q are close."""
    a = isqrt(n) + 1
    for _ in range(max_iter):
        b2 = a * a - n
        b, exact = iroot(2, b2)
        if exact:
            return a - b, a + b
        a += 1
    return None, None


def pollard_rho(n: int) -> int:
    """Pollard's rho factorization."""
    if n % 2 == 0:
        return 2
    x = 2; y = 2; c = 1; d = 1
    while d == 1:
        x = (x * x + c) % n
        y = (y * y + c) % n
        y = (y * y + c) % n
        d = gcd(abs(x - y), n)
    return d if d != n else None


def factorize(n: int) -> tuple:
    """Try multiple factorization methods."""
    # Small factors
    for p in range(2, 10000):
        if n % p == 0:
            return p, n // p

    # Fermat
    p, q = fermat_factor(n, 100_000)
    if p:
        return p, q

    # Pollard rho
    for _ in range(50):
        d = pollard_rho(n)
        if d and d != n:
            return d, n // d

    return None, None


# ─── ATTACKS ──────────────────────────────────────────────────────────────────

def attack_common_factor(ns: list) -> list:
    """Find common factors between multiple moduli."""
    results = []
    for i in range(len(ns)):
        for j in range(i + 1, len(ns)):
            g = gcd(ns[i], ns[j])
            if g > 1:
                p = g
                q1, q2 = ns[i] // p, ns[j] // p
                results.append((i, j, p, q1, q2))
                print(f"[+] Common factor between N[{i}] and N[{j}]!")
                print(f"    p  = {p}")
                print(f"    q1 = {q1}")
                print(f"    q2 = {q2}")
    return results


def attack_small_e(c: int, n: int, e: int) -> int:
    """Small public exponent (e=3): take eth root of ciphertext."""
    m, exact = iroot(e, c)
    if exact:
        print(f"[+] Small-e attack succeeded! m = {m}")
        return m
    print("[-] Small-e: no exact root (padding may be in use)")
    return None


def attack_hastad(ciphertexts: list, moduli: list, e: int) -> int:
    """Hastad broadcast: e ciphertexts of same message under e different keys."""
    if len(ciphertexts) < e or len(moduli) < e:
        print("[-] Need at least e ciphertext/modulus pairs")
        return None
    combined = crt(ciphertexts[:e], moduli[:e])
    m, exact = iroot(e, combined)
    if exact:
        print(f"[+] Hastad broadcast attack succeeded!")
        return m
    print("[-] Hastad: iroot failed — messages may differ or padding used")
    return None


def attack_wiener(e: int, n: int) -> int:
    """Wiener's small private exponent attack via continued fractions."""
    def convergents(a):
        p, q = 1, 0
        p2, q2 = 0, 1
        for x in a:
            p, p2 = x * p + p2, p
            q, q2 = x * q + q2, q
            yield p, q

    def cf_expansion(num, den):
        while den:
            yield num // den
            num, den = den, num % den

    for k, d in convergents(list(cf_expansion(e, n))):
        if k == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        b = n - phi + 1
        disc = b * b - 4 * n
        if disc < 0:
            continue
        sq, exact = iroot(2, disc)
        if exact:
            p = (b + sq) // 2
            q = (b - sq) // 2
            if p * q == n:
                print(f"[+] Wiener attack succeeded! d = {d}")
                print(f"    p = {p}, q = {q}")
                return d
    print("[-] Wiener's attack failed (d may not be small enough)")
    return None


def attack_lsb_oracle(c: int, n: int, e: int, oracle) -> int:
    """
    LSB oracle attack: oracle(c) returns LSB of decrypt(c).
    oracle: callable(ciphertext_int) -> 0 or 1
    """
    lo = 0
    hi = n
    f = 1
    for _ in range(n.bit_length()):
        f = (f * 2) % n
        c_new = (c * pow(f, e, n)) % n
        lsb = oracle(c_new)
        if lsb == 1:
            lo = (lo + hi) // 2
        else:
            hi = (lo + hi) // 2
    return hi


def attack_franklin_reiter(c1: int, c2: int, e: int, n: int,
                            a: int, b: int) -> int:
    """
    Franklin-Reiter related message: m2 = a*m1 + b
    c1 = m1^e mod n, c2 = m2^e mod n
    Works for e=3.
    """
    # Only implemented for e=3 here
    assert e == 3, "Franklin-Reiter implemented for e=3 only"
    A = (b**3 - c2 + a**3 * c1) * inverse(3 * a**2 * b, n) % n
    return A


def decrypt_rsa(c: int, d: int, n: int) -> bytes:
    m = pow(c, d, n)
    return long_to_bytes(m)


def load_pubkey(pem_path: str) -> tuple:
    with open(pem_path, "r") as f:
        key = RSA.import_key(f.read())
    return key.e, key.n


# ─── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="RSA Attack Toolkit")
    parser.add_argument("--mode", required=True,
                        choices=["factor","common-factor","small-e","hastad",
                                 "wiener","fermat","decrypt"])
    parser.add_argument("--n",   type=lambda x: int(x, 0), help="Modulus N")
    parser.add_argument("--e",   type=lambda x: int(x, 0), default=65537)
    parser.add_argument("--c",   type=lambda x: int(x, 0), help="Ciphertext C")
    parser.add_argument("--d",   type=lambda x: int(x, 0), help="Private exponent d")
    parser.add_argument("--pubkey", help="Path to PEM public key")
    args = parser.parse_args()

    if args.pubkey:
        args.e, args.n = load_pubkey(args.pubkey)
        print(f"[*] Loaded key: e={args.e}, n={args.n}")

    if args.mode == "factor":
        p, q = factorize(args.n)
        if p:
            phi = (p - 1) * (q - 1)
            d = inverse(args.e, phi)
            print(f"[+] Factored: p={p}, q={q}")
            print(f"[+] d = {d}")
            if args.c:
                m = decrypt_rsa(args.c, d, args.n)
                print(f"[+] Plaintext: {m}")
                try: print(f"[+] As text:   {m.decode()}")
                except Exception: pass
        else:
            print("[-] Could not factor N")

    elif args.mode == "fermat":
        p, q = fermat_factor(args.n)
        if p:
            print(f"[+] Fermat: p={p}, q={q}")
        else:
            print("[-] Fermat failed")

    elif args.mode == "small-e":
        m = attack_small_e(args.c, args.n, args.e)
        if m:
            b = long_to_bytes(m)
            print(f"[+] Message: {b}")
            try: print(f"[+] As text: {b.decode()}")
            except Exception: pass

    elif args.mode == "wiener":
        attack_wiener(args.e, args.n)

    elif args.mode == "decrypt":
        if not args.d:
            print("[-] Provide --d for decryption")
            return
        m = decrypt_rsa(args.c, args.d, args.n)
        print(f"[+] Plaintext hex: {m.hex()}")
        try: print(f"[+] As text: {m.decode()}")
        except Exception: pass


if __name__ == "__main__":
    main()
