#!/usr/bin/env python3
"""
PCAP Analysis — CTF Toolkit
Covers: HTTP extraction, credential sniffing, DNS tunneling, file carving, TCP stream reassembly
Usage: python3 pcap_analysis.py --pcap capture.pcap [--mode all]
"""
import argparse, os, re, sys, collections
from pathlib import Path

try:
    from scapy.all import (rdpcap, TCP, UDP, IP, DNS, DNSQR, Raw,
                           HTTPRequest, HTTPResponse, sniff)
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False
    print("[!] scapy not installed: pip install scapy")

try:
    import dpkt
    HAS_DPKT = True
except ImportError:
    HAS_DPKT = False


# ─── SCAPY HELPERS ────────────────────────────────────────────────────────────

def load_pcap(path: str):
    if not HAS_SCAPY:
        sys.exit("Install scapy: pip install scapy")
    return rdpcap(path)


def stats(pkts) -> dict:
    """Print basic statistics."""
    proto_count = collections.Counter()
    ip_pairs = collections.Counter()
    for p in pkts:
        if IP in p:
            src, dst = p[IP].src, p[IP].dst
            ip_pairs[(src, dst)] += 1
            if TCP in p:
                proto_count["TCP"] += 1
            elif UDP in p:
                proto_count["UDP"] += 1
        if DNS in p:
            proto_count["DNS"] += 1
    print("[*] Protocol counts:", dict(proto_count))
    print("[*] Top IP pairs:")
    for pair, count in ip_pairs.most_common(10):
        print(f"    {pair[0]} -> {pair[1]}: {count} packets")
    return {"protos": proto_count, "ip_pairs": ip_pairs}


def extract_http(pkts) -> list:
    """Extract HTTP requests and responses."""
    results = []
    for p in pkts:
        if p.haslayer(HTTPRequest):
            req = p[HTTPRequest]
            print(f"[HTTP] {req.Method.decode()} {req.Host.decode()}{req.Path.decode()}")
            if p.haslayer(Raw):
                body = p[Raw].load
                print(f"  Body: {body[:200]}")
            results.append(req)
        if p.haslayer(HTTPResponse):
            resp = p[HTTPResponse]
            if p.haslayer(Raw):
                print(f"[HTTP Response] {resp.Status_Code} | Body: {p[Raw].load[:100]}")
    return results


def extract_credentials(pkts) -> list:
    """Look for cleartext credentials."""
    creds = []
    patterns = [
        (r"(?i)(user|username|login)[=%: ]+([^\s&\"'<>]+)", "username"),
        (r"(?i)(pass|password|passwd|pwd)[=%: ]+([^\s&\"'<>]+)", "password"),
        (r"(?i)Authorization:\s*(Basic|Bearer)\s+([^\r\n]+)", "auth_header"),
        (r"(?i)Cookie:\s*([^\r\n]+)", "cookie"),
    ]
    for p in pkts:
        if p.haslayer(Raw):
            try:
                data = p[Raw].load.decode(errors="replace")
                for pattern, label in patterns:
                    m = re.search(pattern, data)
                    if m:
                        src = p[IP].src if IP in p else "?"
                        dst = p[IP].dst if IP in p else "?"
                        print(f"[CRED] {label} from {src} -> {dst}: {m.group()[:100]}")
                        creds.append((label, m.group()))
            except Exception:
                pass
    return creds


def extract_dns(pkts) -> list:
    """Extract DNS queries — useful for DNS tunneling detection."""
    queries = []
    for p in pkts:
        if p.haslayer(DNSQR):
            qname = p[DNSQR].qname.decode(errors="replace")
            queries.append(qname)
    # Check for long subdomains (DNS tunneling indicator)
    long = [q for q in queries if len(q.split(".")[0]) > 40]
    if long:
        print(f"[!] Possible DNS tunneling ({len(long)} suspicious queries):")
        for q in long[:10]:
            print(f"    {q}")
    # Count unique queries
    unique = set(queries)
    print(f"[DNS] {len(queries)} total, {len(unique)} unique queries")
    for q, c in collections.Counter(queries).most_common(10):
        print(f"  {q}: {c}")
    return queries


def reassemble_tcp_streams(pkts, port: int = None) -> dict:
    """Reassemble TCP streams by stream ID."""
    streams = collections.defaultdict(bytes)
    for p in pkts:
        if TCP in p and p.haslayer(Raw):
            src = (p[IP].src if IP in p else "?", p[TCP].sport)
            dst = (p[IP].dst if IP in p else "?", p[TCP].dport)
            if port and p[TCP].dport != port and p[TCP].sport != port:
                continue
            key = tuple(sorted([src, dst]))
            streams[key] += p[Raw].load
    print(f"[*] {len(streams)} TCP streams reassembled")
    for key, data in sorted(streams.items(), key=lambda x: -len(x[1]))[:5]:
        print(f"  {key[0][0]}:{key[0][1]} <-> {key[1][0]}:{key[1][1]}: {len(data)} bytes")
        print(f"    Preview: {data[:100]!r}")
    return streams


def carve_files(pkts, out_dir: str = "./carved_files") -> list:
    """Carve files from raw packet data."""
    os.makedirs(out_dir, exist_ok=True)
    MAGIC = {
        b"\xff\xd8\xff": ("jpg", "image/jpeg"),
        b"\x89PNG\r\n": ("png", "image/png"),
        b"GIF8": ("gif", "image/gif"),
        b"PK\x03\x04": ("zip", "application/zip"),
        b"%PDF": ("pdf", "application/pdf"),
        b"RIFF": ("wav", "audio/wav"),
        b"\x1f\x8b": ("gz", "application/gzip"),
        b"ELF": ("elf", "application/elf"),
        b"\x7fELF": ("elf", "application/elf"),
    }
    carved = []
    all_data = b"".join(p[Raw].load for p in pkts if p.haslayer(Raw))

    for magic, (ext, mime) in MAGIC.items():
        pos = 0
        while True:
            idx = all_data.find(magic, pos)
            if idx == -1:
                break
            fname = f"{out_dir}/carved_{idx}.{ext}"
            with open(fname, "wb") as f:
                f.write(all_data[idx:idx+10*1024*1024])  # max 10MB
            print(f"[+] Carved {mime}: {fname}")
            carved.append(fname)
            pos = idx + 1
    return carved


def search_flags(pkts, patterns: list = None) -> list:
    """Search for flag patterns in packet data."""
    if patterns is None:
        patterns = [r"[A-Z]{2,10}\{[A-Za-z0-9_!@#$%^&*()\-+]+\}",
                    r"flag\{[^}]+\}", r"FLAG\{[^}]+\}"]
    found = []
    for p in pkts:
        if p.haslayer(Raw):
            try:
                data = p[Raw].load.decode(errors="replace")
                for pat in patterns:
                    for m in re.finditer(pat, data, re.IGNORECASE):
                        print(f"[FLAG] {m.group()}")
                        found.append(m.group())
            except Exception:
                pass
    return list(set(found))


# ─── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="CTF PCAP Analyzer")
    parser.add_argument("--pcap",  required=True)
    parser.add_argument("--mode",
                        choices=["stats","http","creds","dns","streams","carve","flags","all"],
                        default="all")
    parser.add_argument("--port",  type=int, help="Filter TCP streams by port")
    parser.add_argument("--out",   default="./carved_files")
    args = parser.parse_args()

    print(f"[*] Loading {args.pcap}...")
    pkts = load_pcap(args.pcap)
    print(f"[*] {len(pkts)} packets loaded")

    if args.mode in ("stats", "all"):   stats(pkts)
    if args.mode in ("http", "all"):    extract_http(pkts)
    if args.mode in ("creds", "all"):   extract_credentials(pkts)
    if args.mode in ("dns", "all"):     extract_dns(pkts)
    if args.mode in ("streams", "all"): reassemble_tcp_streams(pkts, args.port)
    if args.mode in ("flags", "all"):   search_flags(pkts)
    if args.mode in ("carve", "all"):   carve_files(pkts, args.out)


if __name__ == "__main__":
    main()
