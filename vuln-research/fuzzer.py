#!/usr/bin/env python3
"""
Fuzzer — CTF Toolkit (Vulnerability Research)
For finding bugs in CTF-provided binaries, services, and parsers.
Covers: mutation fuzzing, generation fuzzing, network fuzzing, format string detection
"""
import socket, subprocess, random, struct, argparse, sys, os, time, signal
from pathlib import Path


# ─── MUTATION FUZZER ──────────────────────────────────────────────────────────

class MutationFuzzer:
    """Mutate known-good inputs to find crashes."""

    MUTATIONS = [
        lambda d: d + b"\xff" * 100,                          # append
        lambda d: b"\x00" * len(d),                           # zero out
        lambda d: b"\xff" * len(d),                           # fill 0xff
        lambda d: d[:len(d)//2] + b"\x41" * (len(d)//2),     # half overwrite
        lambda d: d * 2,                                       # double length
        lambda d: b"\x41" * 10000,                            # large input
        lambda d: b"A" * 512 + b"B" * 512,                    # boundary
        lambda d: b"%s" * 100,                                 # format string
        lambda d: b"../../../etc/passwd\x00",                  # path traversal
        lambda d: b"' OR 1=1--",                               # SQL
        lambda d: b"<script>alert(1)</script>",                # XSS
        lambda d: struct.pack("<I", 0xffffffff) * 4,           # INT_MAX
        lambda d: struct.pack("<I", 0x00000000) * 4,           # INT_MIN
        lambda d: struct.pack("<I", 0x7fffffff) * 4,           # LONG_MAX
        lambda d: bytes(random.getrandbits(8) for _ in range(len(d))),  # random
    ]

    def __init__(self, seed_inputs: list):
        self.seeds = seed_inputs
        self.crashes = []

    def mutate(self, data: bytes) -> bytes:
        mut = random.choice(self.MUTATIONS)
        return mut(data)

    def fuzz_process(self, binary: str, iterations: int = 1000,
                     timeout: float = 2.0) -> list:
        """Fuzz a local binary via stdin."""
        crashes = []
        seeds = self.seeds or [b"hello"]
        for i in range(iterations):
            seed = random.choice(seeds)
            mutated = self.mutate(seed)
            try:
                proc = subprocess.run(
                    [binary],
                    input=mutated,
                    capture_output=True,
                    timeout=timeout
                )
                if proc.returncode != 0:
                    crashes.append({
                        "input": mutated,
                        "returncode": proc.returncode,
                        "stderr": proc.stderr[:200],
                    })
                    print(f"[CRASH #{len(crashes)}] iter={i} rc={proc.returncode} "
                          f"input={mutated[:30]!r}")
                    with open(f"crash_{i}.bin", "wb") as f:
                        f.write(mutated)
            except subprocess.TimeoutExpired:
                print(f"[HANG] iter={i} — possible infinite loop with: {mutated[:30]!r}")
                crashes.append({"input": mutated, "returncode": "HANG"})
        return crashes

    def fuzz_network(self, host: str, port: int, iterations: int = 1000) -> list:
        """Fuzz a network service."""
        crashes = []
        seeds = self.seeds or [b"hello\r\n"]
        for i in range(iterations):
            seed = random.choice(seeds)
            mutated = self.mutate(seed)
            try:
                s = socket.create_connection((host, port), timeout=3)
                banner = s.recv(1024)
                s.sendall(mutated)
                s.settimeout(2)
                try:
                    resp = s.recv(4096)
                    if b"error" in resp.lower() or b"exception" in resp.lower():
                        print(f"[ERROR RESPONSE] {mutated[:30]!r} -> {resp[:80]!r}")
                except socket.timeout:
                    pass
                s.close()
            except ConnectionRefusedError:
                print(f"[CRASH #{len(crashes)}] Service crashed after: {mutated[:30]!r}")
                crashes.append({"input": mutated, "returncode": "REFUSED"})
                time.sleep(1)
            except Exception as e:
                print(f"[EXCEPTION] {e}")
        return crashes


# ─── GENERATION FUZZER ────────────────────────────────────────────────────────

class ProtocolFuzzer:
    """Generate structured protocol inputs to test parsers."""

    @staticmethod
    def int_boundaries() -> list:
        return [
            0, 1, -1, 127, 128, 255, 256, -128, -129,
            0x7fff, 0x8000, 0xffff, 0x10000,
            0x7fffffff, 0x80000000, 0xffffffff, 0x100000000,
            0x7fffffffffffffff, 0x8000000000000000, 0xffffffffffffffff,
        ]

    @staticmethod
    def string_fuzz() -> list:
        return [
            b"", b" ", b"\x00", b"\n", b"\r\n",
            b"A" * 100, b"A" * 1000, b"A" * 10000,
            b"%s" * 100, b"%n" * 100, b"%x" * 100,
            b"../../../etc/passwd",
            b"\xff\xfe" * 50,  # Unicode BOM
            b"\xc0\x80",  # Overlong UTF-8 null
            b"'\";<>",  # Injection chars
        ]

    @staticmethod
    def format_string_detect(binary: str) -> bool:
        """Quick check: does the binary reflect format string specifiers?"""
        probe = b"%s%s%s%s%p%p%p"
        try:
            proc = subprocess.run(
                [binary],
                input=probe,
                capture_output=True,
                timeout=2
            )
            output = proc.stdout + proc.stderr
            if b"0x" in output or b"(nil)" in output:
                print("[!] POSSIBLE FORMAT STRING VULNERABILITY DETECTED")
                print(f"    Output: {output[:200]!r}")
                return True
        except Exception:
            pass
        return False


# ─── CRASH TRIAGE ─────────────────────────────────────────────────────────────

def triage_crash(binary: str, crash_input: bytes) -> dict:
    """Run crash input under GDB to get backtrace."""
    crash_file = "/tmp/crash_input.bin"
    with open(crash_file, "wb") as f:
        f.write(crash_input)

    gdb_cmd = f"""
set pagination off
run < {crash_file}
bt
info registers
x/20x $rsp
quit
"""
    gdb_script = "/tmp/triage.gdb"
    with open(gdb_script, "w") as f:
        f.write(gdb_cmd)

    try:
        result = subprocess.run(
            ["gdb", "-batch", "-x", gdb_script, binary],
            capture_output=True, timeout=15
        )
        output = result.stdout.decode(errors="replace")
        print("[*] GDB Output:")
        print(output[:2000])
        return {"backtrace": output}
    except Exception as e:
        print(f"[-] GDB failed: {e}")
        return {}


# ─── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="CTF Fuzzer — Vulnerability Research")
    parser.add_argument("--mode",
                        choices=["binary","network","detect-fmt","triage","gen"],
                        required=True)
    parser.add_argument("--binary",     help="Binary to fuzz")
    parser.add_argument("--host",       help="Host to fuzz")
    parser.add_argument("--port",       type=int, help="Port to fuzz")
    parser.add_argument("--seed",       help="Seed input file or hex string")
    parser.add_argument("--iters",      type=int, default=1000)
    parser.add_argument("--crash",      help="Crash input file for triage (hex)")
    args = parser.parse_args()

    seeds = []
    if args.seed:
        if os.path.isfile(args.seed):
            seeds = [open(args.seed, "rb").read()]
        else:
            seeds = [bytes.fromhex(args.seed)]

    fuzzer = MutationFuzzer(seeds)

    if args.mode == "binary":
        crashes = fuzzer.fuzz_process(args.binary, args.iters)
        print(f"\n[+] Total crashes: {len(crashes)}")

    elif args.mode == "network":
        crashes = fuzzer.fuzz_network(args.host, args.port, args.iters)
        print(f"\n[+] Total crashes: {len(crashes)}")

    elif args.mode == "detect-fmt":
        ProtocolFuzzer.format_string_detect(args.binary)

    elif args.mode == "triage":
        crash_input = bytes.fromhex(args.crash) if args.crash else seeds[0] if seeds else b""
        triage_crash(args.binary, crash_input)

    elif args.mode == "gen":
        print("[*] Integer boundaries:")
        for v in ProtocolFuzzer.int_boundaries():
            print(f"  {v} = {hex(v & 0xffffffffffffffff)}")
        print("\n[*] String fuzzing inputs:")
        for s in ProtocolFuzzer.string_fuzz():
            print(f"  {s!r}")


if __name__ == "__main__":
    main()
