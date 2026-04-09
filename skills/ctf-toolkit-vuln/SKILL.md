---
name: ctf-toolkit-vuln
description: Executes vulnerability research toolkit scripts for CTF challenges. Use when the challenge requires finding a bug in a provided binary or service through fuzzing, source audit, or symbolic execution. Runs fuzzer.py from ~/ctf-toolkit/vuln-research/.
license: MIT
compatibility: Requires ~/ctf-toolkit. GDB, pwntools, angr (optional), AFL++ (optional).
allowed-tools: Bash Read Write Edit Glob Grep Task
metadata:
  user-invocable: "true"
---

# CTF Toolkit — Vulnerability Research

Operational skill: find the bug, then pivot to `/ctf-toolkit-pwn` to exploit it.

## Step 1 — Understand the Target

```bash
TOOLKIT=~/ctf-toolkit
BIN=./target

# Protections
python3 $TOOLKIT/pwn/bof_helper.py --binary $BIN --checksec

# Static analysis
bash $TOOLKIT/rev/static_analysis.sh $BIN

# Run it, observe behavior
echo "hello" | ./$BIN
./$BIN --help 2>&1
```

## Step 2 — Source Code Audit (if source given)

Look for these patterns in order:

```bash
# Dangerous C functions
grep -n "gets\|scanf\|strcpy\|strcat\|sprintf\|memcpy\|read(" *.c

# Format string without format arg
grep -n "printf\s*(" *.c | grep -v '"%'

# Integer overflow → heap overflow
grep -n "malloc\|calloc\|realloc" *.c | head -20

# Use-after-free
grep -n "free(" *.c
# Check if pointer is used after free call

# Off-by-one
grep -n "<=" *.c | grep -iE "(len|size|count|max|buf)"

# Command injection
grep -n "system\|popen\|exec" *.c

# TOCTOU
grep -n "access\|stat\|open\|fopen" *.c
```

## Step 3 — Dynamic Fuzzing

```bash
# Stdin fuzzer (crashes saved to crash_*.bin)
python3 $TOOLKIT/vuln-research/fuzzer.py --mode binary --binary $BIN --iters 5000

# With seed corpus
python3 $TOOLKIT/vuln-research/fuzzer.py --mode binary --binary $BIN \
  --seed valid_input.bin --iters 5000

# Network service fuzzer
python3 $TOOLKIT/vuln-research/fuzzer.py --mode network \
  --host 127.0.0.1 --port 9999 --iters 2000

# Show integer boundary and string test cases
python3 $TOOLKIT/vuln-research/fuzzer.py --mode gen
```

## Step 4 — Format String Detection

```bash
python3 $TOOLKIT/vuln-research/fuzzer.py --mode detect-fmt --binary $BIN
# Sends %p%p%p%p — if output contains 0x... addresses, format string bug confirmed
```

## Step 5 — Crash Triage

```bash
# GDB backtrace for a crash input
python3 $TOOLKIT/vuln-research/fuzzer.py --mode triage --binary $BIN \
  --crash $(xxd -p crash_42.bin | tr -d '\n')

# Manual GDB
gdb $BIN
(gdb) run < crash_42.bin
(gdb) bt           # backtrace
(gdb) info regs    # register state at crash
(gdb) x/20wx $rsp  # stack at crash
```

## Step 6 — Symbolic Execution (angr)

```python
import angr, sys

proj = angr.Project("$BIN", auto_load_libs=False)
state = proj.factory.entry_state(
    args=["$BIN"],
    add_options=angr.options.unicorn
)
simgr = proj.factory.simulation_manager(state)

# Replace with actual addresses (from: objdump -d $BIN | grep -E "win|flag|correct")
WIN_ADDR  = 0x401200   # TODO
FAIL_ADDR = 0x401400   # TODO

simgr.explore(find=WIN_ADDR, avoid=FAIL_ADDR)

if simgr.found:
    s = simgr.found[0]
    print("[+] Input:", s.posix.dumps(0))
    print("[+] Flag:", s.posix.dumps(1))
```

## Step 7 — AFL++ (Instrumented Fuzzing)

```bash
# Requires recompilation
AFL_HARDEN=1 afl-clang-fast -o target_afl target.c

# Or QEMU mode (no source)
mkdir seeds && echo "hello" > seeds/seed1
afl-fuzz -i seeds/ -o findings/ -Q -- ./$BIN @@

# Check results
ls findings/crashes/
afl-plot findings/ afl_plot/
```

## Common Vulnerability Indicators

```bash
# Crash with SIGSEGV or SIGABRT
# RIP/EIP controlled = buffer overflow
# RIP = 0x4141414141414141 = classic BOF

# Output contains memory addresses
# e.g. "0x7fff..." in response = format string / info leak

# Crash inside malloc/free = heap corruption
# Crash with __stack_chk_fail = canary detected overflow

# gdb: info signals
# SIGSEGV = bad memory access
# SIGFPE  = divide by zero
# SIGILL  = illegal instruction
```

## Once You Find the Bug

Pivot to the correct exploitation skill:

| Bug | Next skill |
|-----|------------|
| Stack overflow | `/ctf-toolkit-pwn` → bof_helper + pwn_template |
| Format string | `/ctf-toolkit-pwn` → fmt_string.py |
| Heap bug | `/ctf-toolkit-pwn` → deep heap notes |
| Command injection | Run `id`, `cat /flag.txt` directly |
| Logic bug | Write custom exploit without binary exploitation |

## Pivot

- Exploit the bug: `/ctf-toolkit-pwn`
- Decompile to understand flow: `/ctf-toolkit-rev`
- Deep notes: `/ctf-vuln-research`
