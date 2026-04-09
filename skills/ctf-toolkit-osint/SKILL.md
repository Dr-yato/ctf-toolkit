---
name: ctf-toolkit-osint
description: Executes OSINT toolkit scripts for CTF challenges. Use when the challenge requires gathering intelligence from public sources — domains, usernames, images, social media, or geolocation. Runs osint_recon.sh from ~/ctf-toolkit/osint/.
license: MIT
compatibility: Requires ~/ctf-toolkit. whois, dig, nmap, curl, subfinder, amass, sherlock (optional).
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch
metadata:
  user-invocable: "true"
---

# CTF Toolkit — OSINT

Operational skill: run recon scripts and document findings. Pivot to `/ctf-osint` for deep notes.

## Step 1 — Run Automated Recon

```bash
TOOLKIT=~/ctf-toolkit
TARGET="example.com"   # or username, IP

bash $TOOLKIT/osint/osint_recon.sh $TARGET
# Saves results to ./osint_<target>/
```

## Step 2 — Domain Recon

```bash
# DNS full enumeration
dig $TARGET ANY
dig $TARGET A MX NS TXT CNAME

# Zone transfer attempt
for ns in $(dig +short $TARGET NS); do
  dig axfr $TARGET @$ns
done

# Subdomain discovery
subfinder -d $TARGET -silent
amass enum -passive -d $TARGET
# crt.sh (cert transparency)
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | \
  python3 -c "import sys,json; [print(e['name_value']) for e in json.load(sys.stdin)]" | sort -u

# Historical DNS
# Check: https://securitytrails.com/domain/$TARGET/history/a
```

## Step 3 — Username Hunt

```bash
# Sherlock (100+ platforms)
python3 ~/tools/sherlock/sherlock/sherlock.py "$USERNAME" --timeout 5

# Manual checks
# GitHub:    https://github.com/$USERNAME
# Twitter/X: https://x.com/$USERNAME
# Reddit:    https://reddit.com/u/$USERNAME
# LinkedIn:  search manually
# HackTheBox: https://app.hackthebox.com/profile/search?q=$USERNAME
```

## Step 4 — Image / Metadata OSINT

```bash
# Extract all metadata
exiftool image.jpg
exiftool -all image.jpg | grep -iE "(gps|location|author|comment|create|software)"

# GPS coordinates from EXIF
python3 - << 'EOF'
import subprocess
out = subprocess.check_output(["exiftool", "-GPS*", "-json", "image.jpg"]).decode()
import json; data = json.loads(out)[0]
print(data)
# Paste GPS into: https://maps.google.com/?q=LAT,LON
EOF

# Reverse image search
# Google Images: https://images.google.com (upload or URL)
# TinEye: https://tineye.com
# Yandex: https://yandex.com/images
```

## Step 5 — Web Archive / Wayback

```bash
# Check archived versions
curl -s "https://archive.org/wayback/available?url=$TARGET" | python3 -m json.tool

# Browse all snapshots: https://web.archive.org/web/*/$TARGET

# Extract all archived URLs
curl -s "https://web.archive.org/cdx/search/cdx?url=*.$TARGET&output=text&fl=original&collapse=urlkey" \
  | sort -u | head -50
```

## Step 6 — Google Dorks

```bash
# Generate and run in browser
python3 - << 'EOF'
target = "$TARGET"
dorks = [
    f"site:{target}",
    f"site:{target} filetype:pdf OR filetype:doc OR filetype:xls",
    f"site:{target} inurl:admin OR inurl:login OR inurl:backup",
    f"site:{target} intext:password OR intext:secret OR intext:token",
    f'"@{target}" email',
    f'"{target}" filetype:txt',
    f'"index of" site:{target}',
    f'site:{target} ext:env OR ext:config OR ext:bak OR ext:log',
]
for d in dorks:
    print(f"https://www.google.com/search?q={d.replace(' ', '+')}")
EOF
```

## Step 7 — Social Media Scrape

```bash
# Shodan (if API key configured)
shodan search "org:$TARGET" --fields ip_str,port,hostnames | head -20
shodan host $IP

# theHarvester (emails, names, subdomains)
theHarvester -d $TARGET -b google,bing,yahoo,linkedin,twitter -l 500

# LinkedIn (manual search)
# Search: site:linkedin.com "$COMPANY_NAME"
```

## Common CTF OSINT Patterns

| Clue | Action |
|------|--------|
| Username given | sherlock + GitHub profile search |
| Email address | search username part, check breachdb |
| Image file | exiftool GPS, reverse image search |
| Company name | LinkedIn employees, theHarvester |
| Domain given | crt.sh subdomains, zone transfer, Wayback |
| "Find the location" | GPS EXIF, building/street visual search |
| Social media post | check all platforms with that username |
| Source code reference | search GitHub `github.com/search?q=` |

## Pivot

- Deep notes: `/ctf-osint`
- Network scanning after host discovery: `/ctf-toolkit-networking`
