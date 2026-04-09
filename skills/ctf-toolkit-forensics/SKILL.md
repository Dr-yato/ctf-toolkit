---
name: ctf-toolkit-forensics
description: Executes forensics toolkit scripts for CTF challenges. Use when the challenge provides a file to analyze, a PCAP, a disk image, a memory dump, or a steganography image. Runs file_analysis.sh, pcap_analysis.py, and memory_forensics.sh from ~/ctf-toolkit/forensics/.
license: MIT
compatibility: Requires ~/ctf-toolkit. binwalk, exiftool, steghide, zsteg, volatility3, scapy, Wireshark/tshark.
allowed-tools: Bash Read Write Edit Glob Grep Task
metadata:
  user-invocable: "true"
---

# CTF Toolkit — Forensics

Operational skill: run the scripts directly. Pivot to `/ctf-forensics` for deep technique notes.

## Step 1 — Identify File Type

```bash
TOOLKIT=~/ctf-toolkit
F=./challenge_file   # set this

file "$F"
xxd "$F" | head -4   # magic bytes
```

Then jump to the matching section below.

## Unknown File

```bash
# Full automated triage
bash $TOOLKIT/forensics/file_analysis.sh "$F"
```

Checks: file type, entropy, strings, binwalk, exiftool, steghide, zsteg, flag patterns.

## PCAP / Network Capture

```bash
# Full analysis: HTTP, credentials, DNS, TCP streams, file carving, flags
python3 $TOOLKIT/forensics/pcap_analysis.py --pcap "$F" --mode all

# Individual modes
python3 $TOOLKIT/forensics/pcap_analysis.py --pcap "$F" --mode creds    # cleartext passwords
python3 $TOOLKIT/forensics/pcap_analysis.py --pcap "$F" --mode flags     # scan for CTF{} patterns
python3 $TOOLKIT/forensics/pcap_analysis.py --pcap "$F" --mode dns       # DNS tunneling check
python3 $TOOLKIT/forensics/pcap_analysis.py --pcap "$F" --mode carve --out ./carved  # extract files
python3 $TOOLKIT/forensics/pcap_analysis.py --pcap "$F" --mode streams --port 80     # TCP reassembly

# Wireshark one-liners
tshark -r "$F" -Y "http" -T fields -e http.request.uri -e http.file_data | head -20
tshark -r "$F" --export-objects http,./http_objects/
tshark -r "$F" -Y 'frame contains "CTF{"' -T text
```

## Memory Dump

```bash
# Full Volatility 3 analysis
bash $TOOLKIT/forensics/memory_forensics.sh "$F"

# Individual vol3 plugins
vol3 -f "$F" windows.pslist          # process list
vol3 -f "$F" windows.cmdline         # command lines
vol3 -f "$F" windows.netscan         # network connections
vol3 -f "$F" windows.hashdump        # NTLM hashes
vol3 -f "$F" windows.malfind         # injected code
vol3 -f "$F" windows.dumpfiles --virtaddr 0xADDR  # extract file
vol3 -f "$F" windows.clipboard       # clipboard contents
vol3 -f "$F" linux.bash              # bash history (Linux images)
```

## Steganography — Image

```bash
# Automated: LSB, bit planes, metadata, steghide
bash $TOOLKIT/forensics/file_analysis.sh "$F"

# zsteg (PNG/BMP LSB)
zsteg "$F"
zsteg -a "$F"     # all methods

# steghide (JPEG/BMP, password required)
steghide extract -sf "$F" -p ""
steghide extract -sf "$F" -p "password"
stegseek "$F" ~/wordlists/rockyou.txt   # brute-force

# binwalk (embedded files)
binwalk "$F"
binwalk -e "$F" --run-as=root

# exiftool (metadata)
exiftool "$F"

# Check image color channels
python3 - << 'EOF'
from PIL import Image
img = Image.open("$F")
print(img.mode, img.size)
r, g, b = img.split() if img.mode == 'RGB' else (None, None, None)
# Check LSB of each channel
if r:
    lsb = bytes([p & 1 for p in r.getdata()])
    print("R LSB:", lsb[:64])
EOF
```

## Steganography — Audio

```bash
# Spectrogram (look for image in spectrogram)
# Open in Audacity or Sonic Visualiser → Spectrogram view

# Extract LSB from WAV
python3 - << 'EOF'
import wave, struct
with wave.open("$F", 'r') as w:
    frames = w.readframes(w.getnframes())
samples = struct.unpack(f'<{len(frames)//2}h', frames)
bits = ''.join(str(s & 1) for s in samples)
text = ''.join(chr(int(bits[i:i+8], 2)) for i in range(0, len(bits)-8, 8))
print(text[:200])
EOF

# morse code in audio → use online decoder or audacity
# DTMF tones → multimon-ng -t WAV -a DTMF audio.wav
```

## Disk Image

```bash
# List partitions
fdisk -l "$F"
mmls "$F"         # sleuthkit

# Mount partition (offset in sectors × 512)
sudo mount -o loop,offset=$((OFFSET*512)) "$F" /mnt/img

# File recovery
photorec "$F"
foremost -i "$F" -o ./recovered/
scalpel "$F" -o ./scalpel_out/

# File system analysis
fls -r "$F"       # list files recursively (sleuthkit)
icat "$F" INODE   # extract file by inode
```

## Encrypted Archive

```bash
# Identify type
file "$F"

# ZIP with password
zip2john "$F" > hash.txt && john hash.txt --wordlist=~/wordlists/rockyou.txt
hashcat -m 13600 hash.txt ~/wordlists/rockyou.txt

# RAR
rar2john "$F" > hash.txt && john hash.txt --wordlist=~/wordlists/rockyou.txt

# 7z
7z2john "$F" > hash.txt && john hash.txt --wordlist=~/wordlists/rockyou.txt
```

## Decision Map

```
Unknown file          → bash file_analysis.sh
.pcap / .cap          → python3 pcap_analysis.py --mode all
.raw / .vmem / .dmp   → bash memory_forensics.sh
.png / .jpg / .bmp    → zsteg + steghide + binwalk
.wav / .mp3           → spectrogram + LSB
.img / .dd / .iso     → mount + foremost + fls
.zip / .rar / .7z     → john + hashcat
```

## Pivot

- Deep technique notes: `/ctf-forensics`
- Network protocol reversing: `/ctf-toolkit-networking`
- Crypto for decrypting found data: `/ctf-toolkit-crypto`
