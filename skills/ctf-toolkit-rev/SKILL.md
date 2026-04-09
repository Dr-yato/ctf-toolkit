---
name: ctf-toolkit-rev
description: Executes reverse engineering toolkit scripts for CTF challenges. Use when the challenge is a binary to decompile, patch, or understand — without exploitation. Runs static_analysis.sh from ~/ctf-toolkit/rev/ and guides use of Ghidra, radare2, and GDB.
license: MIT
compatibility: Requires ~/ctf-toolkit. radare2, GDB, Ghidra (~/tools/ghidra/), binutils, strings, objdump.
allowed-tools: Bash Read Write Edit Glob Grep Task
metadata:
  user-invocable: "true"
---

# CTF Toolkit — Reverse Engineering

Operational skill: analyze, understand, extract. Pivot to `/ctf-reverse` for deep notes.

## Step 1 — Static Analysis

```bash
TOOLKIT=~/ctf-toolkit
BIN=./challenge

# Full static triage
bash $TOOLKIT/rev/static_analysis.sh $BIN
```

Output includes: file type, protections, symbols, interesting strings, disassembly of `main`, entropy, anti-debug indicators, radare2 function list.

## Step 2 — String Hunting

```bash
# All strings
strings -a $BIN | less

# Target: flag fragments, passwords, comparison values
strings -a $BIN | grep -iE "(flag|ctf|key|pass|secret|correct|wrong|win|lose)"

# Encoded strings (look for base64/hex looking strings)
strings -a $BIN | grep -E '^[A-Za-z0-9+/]{20,}={0,2}$'   # base64
strings -a $BIN | grep -E '^[0-9a-f]{32,}$'               # hex

# Decode found strings
echo "$STRING" | base64 -d
python3 -c "print(bytes.fromhex('$HEX_STRING'))"
```

## Step 3 — radare2 Analysis

```bash
r2 -A $BIN

# Key commands inside r2:
# afl          — list all functions
# pdf @ main   — disassemble main
# pdf @ sym.check_flag  — disassemble check_flag function
# axt @ str.   — find xrefs to string
# iz           — list strings in binary
# /r 0xDEAD    — find xrefs to constant
# s sym.main; pdf  — seek + disassemble
# VV           — visual flowgraph
# q            — quit
```

One-liner:
```bash
# List all functions
echo -e "aaa\nafl\nq" | r2 -q $BIN 2>/dev/null

# Disassemble main
echo -e "aaa\npdf @ main\nq" | r2 -q $BIN 2>/dev/null | head -80

# Find strings
echo -e "aaa\niz\nq" | r2 -q $BIN 2>/dev/null | grep -i flag
```

## Step 4 — Ghidra Decompilation

```bash
# Launch Ghidra (GUI)
~/tools/ghidra/ghidraRun

# Headless analysis (no GUI, extract decompiled C)
~/tools/ghidra/support/analyzeHeadless /tmp/ghidra_proj proj \
  -import $BIN -postScript /tmp/decompile.py -deleteProject

# /tmp/decompile.py
cat > /tmp/decompile.py << 'EOF'
from ghidra.app.decompiler import DecompInterface
decomp = DecompInterface()
decomp.openProgram(currentProgram)
for func in currentProgram.getFunctionManager().getFunctions(True):
    result = decomp.decompileFunction(func, 30, monitor)
    if result.decompileCompleted():
        print(f"\n// {func.getName()}")
        print(result.getDecompiledFunction().getC())
EOF
```

## Step 5 — GDB Dynamic Analysis

```bash
gdb $BIN

# Essential commands
(gdb) info functions         # list all functions
(gdb) b main                 # break at main
(gdb) b *0x401234            # break at address
(gdb) run                    # start
(gdb) run < input.txt        # run with stdin
(gdb) ni / si                # next/step instruction
(gdb) c                      # continue
(gdb) x/20i $pc              # disassemble at PC
(gdb) x/40wx $rsp            # stack dump
(gdb) x/s 0x402000           # print string at address
(gdb) info regs              # all registers
(gdb) set $rax = 1           # modify register
(gdb) set {int}0x601234 = 0  # patch memory
(gdb) finish                 # run to end of function
(gdb) call check_flag(0x4141) # call function directly
```

## Step 6 — Anti-Debug Bypass

```bash
# ptrace anti-debug: patch the call
# Find: objdump -d $BIN | grep -A3 "ptrace"
# Patch NOP: printf '\x90\x90\x90\x90\x90\x90' | dd of=$BIN bs=1 seek=$OFFSET conv=notrunc

# IsDebuggerPresent (Windows PE in Wine)
# Set ZF after the call to bypass

# Timing anti-debug: RDTSC
# Patch with NOP or set a constant delta in GDB

# LD_PRELOAD intercept ptrace
cat > /tmp/noptrace.c << 'EOF'
#include <sys/ptrace.h>
long ptrace(int req, ...) { return 0; }
EOF
gcc -shared -fPIC -o /tmp/noptrace.so /tmp/noptrace.c
LD_PRELOAD=/tmp/noptrace.so ./$BIN
```

## Step 7 — Binary Patching

```bash
# Find offset of instruction to patch
objdump -d $BIN | grep -n "jne\|jz\|je\|call" | head -20

# Patch JNE → JE (flip jump condition)
# JNE = 0x75, JE = 0x74 (short jumps)
python3 - << 'EOF'
import sys
offset = 0x1234   # TODO: offset of byte to patch
new_byte = 0x74   # JE
data = bytearray(open("$BIN", "rb").read())
data[offset] = new_byte
open("${BIN}_patched", "wb").write(data)
print(f"Patched byte at 0x{offset:x} → 0x{new_byte:02x}")
EOF
chmod +x ${BIN}_patched
```

## Common CTF Rev Patterns

| Observation | Approach |
|-------------|----------|
| String comparisons in main | Find expected string in .rodata |
| Loop with XOR/ADD on bytes | Reverse the transform on each byte |
| check_flag() returns 0/1 | Set breakpoint at ret, inspect return |
| Multiple checks, flag built char by char | Trace each comparison, reconstruct |
| VM / custom bytecode | Map opcodes, write disassembler |
| Packed binary (UPX) | `upx -d $BIN` then analyze |
| Obfuscated Python | uncompyle6 / decompile3 |
| Java .class | jadx, jd-gui |
| .NET / C# | dnSpy, ILSpy |
| Android APK | jadx-gui, apktool |

## Pivot

- Found a memory bug? → `/ctf-toolkit-pwn`
- Need to crack crypto/obfuscation? → `/ctf-toolkit-crypto`
- Deep technique notes: `/ctf-reverse`
