#!/usr/bin/env python3
"""
CTF Utility Library — shared helpers for all toolkit scripts
Import: from common.ctf_utils import *
"""
import base64, binascii, struct, re, hashlib, os, socket, urllib.parse
from itertools import product


# ─── ENCODING / DECODING ──────────────────────────────────────────────────────

def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()

def b64d(s: str) -> bytes:
    return base64.b64decode(s + "==")

def b32e(data: bytes) -> str:
    return base64.b32encode(data).decode()

def b32d(s: str) -> bytes:
    return base64.b32decode(s.upper() + "=" * ((8 - len(s) % 8) % 8))

def hexe(data: bytes) -> str:
    return data.hex()

def hexd(s: str) -> bytes:
    return bytes.fromhex(s.replace(" ", "").replace("\\x", ""))

def url_encode(s: str) -> str:
    return urllib.parse.quote(s, safe="")

def url_decode(s: str) -> str:
    return urllib.parse.unquote(s)

def html_decode(s: str) -> str:
    import html
    return html.unescape(s)

def rot13(s: str) -> str:
    return s.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
    ))

def decode_all(s: str) -> dict:
    """Try all common decodings and return non-empty results."""
    results = {}
    decoders = [
        ("base64",  lambda: b64d(s).decode(errors="replace")),
        ("base32",  lambda: b32d(s).decode(errors="replace")),
        ("hex",     lambda: hexd(s).decode(errors="replace")),
        ("url",     lambda: url_decode(s)),
        ("html",    lambda: html_decode(s)),
        ("rot13",   lambda: rot13(s)),
        ("binary",  lambda: "".join(chr(int(s[i:i+8], 2)) for i in range(0, len(s)//8*8, 8))),
        ("decimal", lambda: "".join(chr(int(x)) for x in s.split())),
    ]
    for name, fn in decoders:
        try:
            val = fn()
            if val and val != s and val.isprintable():
                results[name] = val
        except Exception:
            pass
    return results


# ─── HASHING ──────────────────────────────────────────────────────────────────

def md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()

def sha1(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def sha512(data: bytes) -> str:
    return hashlib.sha512(data).hexdigest()


# ─── NUMBER THEORY ────────────────────────────────────────────────────────────

def gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a

def egcd(a: int, b: int):
    if a == 0:
        return b, 0, 1
    g, x, y = egcd(b % a, a)
    return g, y - (b // a) * x, x

def modinv(a: int, m: int) -> int:
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError(f"No inverse: gcd({a},{m})={g}")
    return x % m

def isprime(n: int) -> bool:
    if n < 2: return False
    if n < 4: return True
    if n % 2 == 0 or n % 3 == 0: return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i+2) == 0:
            return False
        i += 6
    return True


# ─── BINARY HELPERS ───────────────────────────────────────────────────────────

def p8(n):  return struct.pack("B", n & 0xff)
def p16(n): return struct.pack("<H", n & 0xffff)
def p32(n): return struct.pack("<I", n & 0xffffffff)
def p64(n): return struct.pack("<Q", n & 0xffffffffffffffff)
def u8(b):  return struct.unpack("B", b[:1])[0]
def u16(b): return struct.unpack("<H", b[:2])[0]
def u32(b): return struct.unpack("<I", b[:4])[0]
def u64(b): return struct.unpack("<Q", b[:8])[0]

def hexdump(data: bytes, width: int = 16) -> str:
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        hex_part = " ".join(f"{b:02x}" for b in chunk).ljust(width*3)
        txt_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:08x}  {hex_part} |{txt_part}|")
    return "\n".join(lines)


# ─── NETWORK ──────────────────────────────────────────────────────────────────

def tcp_send_recv(host: str, port: int, data: bytes, timeout: int = 10) -> bytes:
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(data)
        response = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk: break
                response += chunk
        except socket.timeout:
            pass
    return response


# ─── FLAG EXTRACTION ──────────────────────────────────────────────────────────

FLAG_RE = re.compile(r"[A-Z]{2,10}\{[A-Za-z0-9_!@#$%^&*()\-+.]+\}", re.IGNORECASE)

def extract_flags(text: str) -> list:
    return FLAG_RE.findall(text)

def find_flag(data: bytes) -> list:
    try:
        text = data.decode(errors="replace")
    except Exception:
        text = ""
    return extract_flags(text)


# ─── QUICK RECON ──────────────────────────────────────────────────────────────

def magic_bytes(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read(16)

def file_entropy(path: str) -> float:
    import math, collections
    data = open(path, "rb").read()
    freq = collections.Counter(data)
    total = len(data)
    if total == 0: return 0.0
    return -sum((c/total)*math.log2(c/total) for c in freq.values())


if __name__ == "__main__":
    # Quick self-test
    assert b64d(b64e(b"hello")) == b"hello"
    assert hexd(hexe(b"test")) == b"test"
    assert rot13(rot13("hello")) == "hello"
    assert modinv(3, 11) == 4
    assert u64(p64(0xdeadbeef)) == 0xdeadbeef
    print("[+] ctf_utils self-test passed")
