#!/usr/bin/env python3
"""
Network Analysis — CTF Toolkit
Covers: service fingerprinting, protocol reversing, custom TCP clients,
        packet crafting, ARP scan, port scan via scapy
Usage: python3 network_analysis.py --mode <mode> [options]
"""
import socket, argparse, struct, sys, time, threading, concurrent.futures
from contextlib import suppress

try:
    from scapy.all import (sr1, sr, IP, TCP, UDP, ICMP, ARP, Ether,
                            send, sendp, sniff, Raw, conf)
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


# ─── TCP CLIENT ───────────────────────────────────────────────────────────────

class NetClient:
    """Interactive TCP/UDP client for protocol reversing."""

    def __init__(self, host: str, port: int, udp: bool = False, timeout: int = 10):
        self.host = host
        self.port = port
        self.udp = udp
        self.timeout = timeout
        self.sock = None

    def connect(self):
        if self.udp:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect((self.host, self.port))
        print(f"[+] Connected to {self.host}:{self.port} ({'UDP' if self.udp else 'TCP'})")

    def recv(self, size: int = 4096) -> bytes:
        data = b""
        self.sock.settimeout(2)
        try:
            while True:
                chunk = self.sock.recv(size)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        return data

    def send(self, data: bytes):
        if self.udp:
            self.sock.sendto(data, (self.host, self.port))
        else:
            self.sock.sendall(data)

    def sendline(self, line: str):
        self.send(line.encode() + b"\n")

    def interact(self):
        """Start interactive session."""
        import select
        self.connect()
        print("[*] Interactive mode. Ctrl+C to quit.")
        while True:
            ready = select.select([self.sock, sys.stdin], [], [], 1)[0]
            if self.sock in ready:
                data = self.recv()
                if data:
                    try: print(data.decode(), end="")
                    except: print(data.hex())
            if sys.stdin in ready:
                line = sys.stdin.readline()
                if not line:
                    break
                self.send(line.encode())

    def close(self):
        if self.sock:
            self.sock.close()


# ─── PORT SCANNER ─────────────────────────────────────────────────────────────

def tcp_port_scan(host: str, ports: list, timeout: float = 1.0) -> list:
    """Threaded TCP port scanner."""
    open_ports = []
    lock = threading.Lock()

    def check_port(port):
        try:
            with socket.create_connection((host, port), timeout=timeout):
                with lock:
                    open_ports.append(port)
                    print(f"  [+] {port}/tcp OPEN")
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=200) as ex:
        ex.map(check_port, ports)

    return sorted(open_ports)


def syn_scan(host: str, ports: list) -> list:
    """SYN scan using scapy (requires root)."""
    if not HAS_SCAPY:
        print("[-] scapy not available")
        return []
    conf.verb = 0
    open_ports = []
    ans, _ = sr(
        IP(dst=host) / TCP(dport=ports, flags="S"),
        timeout=2, verbose=False
    )
    for sent, recv in ans:
        if recv.haslayer(TCP) and recv[TCP].flags == "SA":
            open_ports.append(recv[TCP].sport)
            print(f"  [+] {recv[TCP].sport}/tcp OPEN")
    return sorted(open_ports)


def service_banner(host: str, port: int) -> str:
    """Grab service banner."""
    try:
        s = socket.create_connection((host, port), timeout=5)
        s.settimeout(3)
        try:
            banner = s.recv(1024)
        except socket.timeout:
            s.send(b"\r\n")
            banner = s.recv(1024)
        s.close()
        return banner.decode(errors="replace").strip()
    except Exception as e:
        return f"Error: {e}"


# ─── ARP SCAN ─────────────────────────────────────────────────────────────────

def arp_scan(network: str) -> list:
    """Discover hosts on LAN via ARP (requires root/scapy)."""
    if not HAS_SCAPY:
        print("[-] scapy required for ARP scan")
        return []
    conf.verb = 0
    ans, _ = sr(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network),
                timeout=3, verbose=False)
    hosts = []
    for sent, recv in ans:
        print(f"  {recv[ARP].psrc}  MAC: {recv[Ether].src}")
        hosts.append({"ip": recv[ARP].psrc, "mac": recv[Ether].src})
    return hosts


# ─── PACKET CRAFTING ──────────────────────────────────────────────────────────

def send_custom_tcp(host: str, port: int, payload: bytes,
                    flags: str = "PA") -> bytes:
    """Send custom TCP packet and get response."""
    if not HAS_SCAPY:
        return b""
    conf.verb = 0
    pkt = IP(dst=host) / TCP(dport=port, flags=flags) / Raw(load=payload)
    resp = sr1(pkt, timeout=5, verbose=False)
    if resp and resp.haslayer(Raw):
        return resp[Raw].load
    return b""


def tcp_handshake_manual(host: str, port: int) -> socket.socket:
    """Manual TCP connection with verbose output."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    print(f"[*] Connecting to {host}:{port}")
    s.connect((host, port))
    print(f"[+] TCP handshake complete")
    return s


# ─── PROTOCOL HELPERS ─────────────────────────────────────────────────────────

def parse_tlv(data: bytes) -> list:
    """Parse TLV (Type-Length-Value) encoded data."""
    result = []
    i = 0
    while i < len(data):
        if i + 2 > len(data):
            break
        tag = data[i]
        length = data[i+1]
        value = data[i+2:i+2+length]
        result.append({"tag": tag, "length": length, "value": value})
        print(f"  TLV: tag=0x{tag:02x} len={length} value={value.hex()} ({value!r})")
        i += 2 + length
    return result


def probe_protocol(host: str, port: int) -> str:
    """Send common protocol probes to identify unknown service."""
    probes = {
        "HTTP":    b"GET / HTTP/1.0\r\n\r\n",
        "SSH":     b"SSH-2.0-OpenSSH_8.0\r\n",
        "FTP":     None,
        "SMTP":    None,
        "IMAP":    None,
        "raw":     b"\x00" * 8,
        "nl":      b"\n",
    }
    banner = service_banner(host, port)
    if banner:
        print(f"[+] Banner: {banner[:200]}")

    for name, probe in probes.items():
        try:
            s = socket.create_connection((host, port), timeout=5)
            s.settimeout(3)
            if probe:
                s.sendall(probe)
            resp = s.recv(4096)
            s.close()
            print(f"  [{name}] {resp[:100]!r}")
        except Exception:
            pass
    return banner


# ─── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Network Analysis — CTF")
    parser.add_argument("--host",    default="127.0.0.1")
    parser.add_argument("--port",    type=int, default=80)
    parser.add_argument("--mode",
                        choices=["scan","syn-scan","banner","arp","probe",
                                 "connect","craft"],
                        default="scan")
    parser.add_argument("--ports",   default="1-1024",
                        help="Port range: 1-1024 or 22,80,443")
    parser.add_argument("--network", default="192.168.1.0/24")
    parser.add_argument("--payload", default="", help="Hex payload for craft mode")
    parser.add_argument("--udp",     action="store_true")
    args = parser.parse_args()

    # Parse port range
    if "-" in args.ports:
        start, end = map(int, args.ports.split("-"))
        ports = list(range(start, end + 1))
    else:
        ports = list(map(int, args.ports.split(",")))

    if args.mode == "scan":
        print(f"[*] TCP port scan: {args.host} ports {args.ports}")
        open_ports = tcp_port_scan(args.host, ports)
        print(f"\n[+] Open: {open_ports}")

    elif args.mode == "syn-scan":
        print(f"[*] SYN scan: {args.host}")
        syn_scan(args.host, ports)

    elif args.mode == "banner":
        print(f"[*] Banner grab: {args.host}:{args.port}")
        print(service_banner(args.host, args.port))

    elif args.mode == "arp":
        print(f"[*] ARP scan: {args.network}")
        arp_scan(args.network)

    elif args.mode == "probe":
        print(f"[*] Protocol probe: {args.host}:{args.port}")
        probe_protocol(args.host, args.port)

    elif args.mode == "connect":
        c = NetClient(args.host, args.port, udp=args.udp)
        c.interact()

    elif args.mode == "craft":
        payload = bytes.fromhex(args.payload) if args.payload else b"\x00"
        resp = send_custom_tcp(args.host, args.port, payload)
        print(f"[+] Response: {resp.hex()}")
        print(f"[+] As text:  {resp!r}")


if __name__ == "__main__":
    main()
