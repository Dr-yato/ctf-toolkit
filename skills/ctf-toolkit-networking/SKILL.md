---
name: ctf-toolkit-networking
description: Executes networking toolkit scripts for CTF challenges. Use when the challenge involves a custom TCP/UDP service, protocol reversing, packet crafting, or network traffic analysis. Runs network_analysis.py from ~/ctf-toolkit/networking/.
license: MIT
compatibility: Requires ~/ctf-toolkit. nmap, scapy, pwntools, netcat, socat.
allowed-tools: Bash Read Write Edit Glob Grep Task
metadata:
  user-invocable: "true"
---

# CTF Toolkit — Networking

Operational skill: run the scripts. Pivot to `/ctf-networking` for deeper notes.

## Step 1 — Service Fingerprint

```bash
TOOLKIT=~/ctf-toolkit
HOST=challenge.ctf.io
PORT=1337

# Banner grab
python3 $TOOLKIT/networking/network_analysis.py --host $HOST --port $PORT --mode banner

# Protocol probe (HTTP/SSH/FTP/SMTP probes + raw null bytes)
python3 $TOOLKIT/networking/network_analysis.py --host $HOST --port $PORT --mode probe

# nmap service detection
nmap -sV -sC -p $PORT $HOST
```

## Step 2 — Interactive Session

```bash
# Start interactive TCP session (reads stdin, sends to server)
python3 $TOOLKIT/networking/network_analysis.py --host $HOST --port $PORT --mode connect

# Or simpler:
nc $HOST $PORT
socat TCP:$HOST:$PORT STDIN

# SSL/TLS wrapped service
openssl s_client -connect $HOST:$PORT
socat STDIN SSL:$HOST:$PORT,verify=0
```

## Step 3 — Port Scan

```bash
# Fast TCP scan
python3 $TOOLKIT/networking/network_analysis.py --host $HOST --mode scan --ports 1-65535

# SYN scan (requires root, scapy)
python3 $TOOLKIT/networking/network_analysis.py --host $HOST --mode syn-scan --ports 1-1024

# nmap full scan
nmap -T4 -p- --open $HOST
nmap -sU --top-ports 100 $HOST  # UDP
```

## Step 4 — Protocol Reversing

```python
# Connect and dump everything received
from pwn import *
io = remote("$HOST", $PORT)
print(repr(io.recv(4096)))

# Send probes
io.send(b"\x00" * 16)                  # null
io.send(b"HELP\r\n")                   # text command
io.send(b"\x01\x02\x03\x04")           # raw bytes
io.send(b"A" * 256)                    # overflow probe
io.sendline(b"?")                      # query

# Parse binary protocol
import struct
pkt = io.recv(20)
magic, version, length, cmd = struct.unpack(">IBBH", pkt[:8])
payload = pkt[8:8+length]
print(f"magic={hex(magic)} ver={version} len={length} cmd={hex(cmd)}")
print(f"payload: {payload.hex()}")
```

## Step 5 — Custom Packet Crafting

```bash
# Send raw TCP payload (scapy)
python3 - << 'EOF'
from scapy.all import *
payload = bytes.fromhex("DEADBEEF01020304")
python3 $TOOLKIT/networking/network_analysis.py --host $HOST --port $PORT \
  --mode craft --payload DEADBEEF01020304
EOF

# UDP packet
python3 - << 'EOF'
from scapy.all import send, IP, UDP, Raw
send(IP(dst="$HOST") / UDP(dport=$PORT) / Raw(load=b"\x01\x02\x03"))
EOF
```

## Step 6 — LAN Discovery (internal challenge)

```bash
# ARP scan to find hosts
python3 $TOOLKIT/networking/network_analysis.py --mode arp --network 192.168.1.0/24

# Then scan found hosts
for ip in $(arp -a | awk '{print $2}' | tr -d '()'); do
  nmap -T4 -F --open $ip 2>/dev/null | grep -E "open|Nmap scan"
done
```

## Step 7 — TLV / Binary Protocol Parser

```python
# If the protocol uses TLV (Type-Length-Value) framing:
import sys; sys.path.insert(0, '~/ctf-toolkit')
from networking.network_analysis import parse_tlv

data = bytes.fromhex("$HEX_RESPONSE")
fields = parse_tlv(data)
for f in fields:
    print(f"tag={f['tag']:#x} len={f['length']} val={f['value'].hex()} ({f['value']!r})")
```

## Common Challenge Patterns

| Pattern | Approach |
|---------|----------|
| Server sends binary blob, then waits | Reverse the struct — use `struct.unpack` |
| Send type+length+data | Build TLV frame matching the format |
| Service echoes input | Look for overflow / format string |
| Server does math, asks for result | Parse + calculate + send back (pwntools) |
| Service requires auth token | Reverse token generation algorithm |
| Encryption before send | Find key in binary → `/ctf-toolkit-pwn` + `/ctf-toolkit-crypto` |

## pwntools Network Template

```python
from pwn import *

io = remote("$HOST", $PORT)

# Receive until prompt
io.recvuntil(b"> ")

# Send response to challenge
data = io.recvline().strip()
answer = int(data) * 2   # example: compute answer
io.sendline(str(answer).encode())

io.interactive()
```

## Pivot

- Binary behind service: `/ctf-toolkit-pwn`
- Crypto in protocol: `/ctf-toolkit-crypto`
- Traffic capture: `/ctf-toolkit-forensics`
- Deep notes: `/ctf-networking`
