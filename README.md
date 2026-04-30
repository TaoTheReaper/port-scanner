# port-scanner

![Python](https://img.shields.io/badge/python-3.10+-blue.svg) ![License](https://img.shields.io/badge/license-MIT-green.svg) ![Last Commit](https://img.shields.io/github/last-commit/TaoTheReaper/port-scanner) ![CI](https://github.com/TaoTheReaper/port-scanner/actions/workflows/ci.yml/badge.svg)


Async TCP port scanner with banner grabbing and service detection.

## Features

- **Async** scanning — up to 200 concurrent connections
- **Banner grabbing** on open ports
- **Service detection** from banners (SSH, FTP, SMTP, MySQL, Redis, MongoDB…)
- Port states: `open` / `closed` / `filtered` / `error`
- Top 100 common ports shortcut (`--top100`)
- Flexible port spec: `80,443`, `1-1024`, `22,80,443,8080-8090`
- JSON report output

## Install

No external dependencies — stdlib only.

```bash
python port-scanner.py --help
```

## Usage

```bash
# Scan default range (1-1024)
python port-scanner.py 192.168.1.1

# Scan top 100 ports
python port-scanner.py example.com --top100

# Custom ports, save report
python port-scanner.py 10.0.0.1 -p 80,443,8080,8443 -o scan.json

# Full range with lower timeout
python port-scanner.py 192.168.1.1 -p 1-65535 -t 0.5 -c 500
```

## Example output

```
============================================================
  PORT SCANNER — 192.168.1.1 (192.168.1.1)
============================================================

Open ports (3):
  PORT     STATE      SERVICE          BANNER/INFO
  ────────────────────────────────────────────────────────
  22/tcp   open       SSH              SSH-2.0-OpenSSH_8.9
  80/tcp   open       HTTP
  443/tcp  open       HTTPS
```

## Legal notice

Use only against systems you own or have written authorisation to test.
