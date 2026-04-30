#!/usr/bin/env python3
"""port-scanner — async TCP port scanner with banner grabbing, service detection, and CIDR/range support."""

import argparse
import asyncio
import ipaddress
import json
import logging
import os
import re
import socket
import sys
from datetime import datetime, timezone

log = logging.getLogger("port-scanner")

C = {
    "red": "\033[91m", "green": "\033[92m", "yellow": "\033[93m",
    "cyan": "\033[96m", "bold": "\033[1m", "reset": "\033[0m"
}

# Common service signatures from banners
SERVICE_SIGNATURES = [
    (re.compile(r"SSH-(\S+)",          re.I), "SSH"),
    (re.compile(r"220.*FTP",           re.I), "FTP"),
    (re.compile(r"220.*SMTP|ESMTP",    re.I), "SMTP"),
    (re.compile(r"HTTP/\d",            re.I), "HTTP"),
    (re.compile(r"\+OK",               re.I), "POP3"),
    (re.compile(r"\* OK.*IMAP",        re.I), "IMAP"),
    (re.compile(r"RFB \d",             re.I), "VNC"),
    (re.compile(r"Microsoft SQL",      re.I), "MSSQL"),
    (re.compile(r"mysql_native",       re.I), "MySQL"),
    (re.compile(r"PostgreSQL",         re.I), "PostgreSQL"),
    (re.compile(r"Redis",              re.I), "Redis"),
    (re.compile(r"Mongo",              re.I), "MongoDB"),
    (re.compile(r"Elastic",            re.I), "Elasticsearch"),
    (re.compile(r"SMB|SAMBA|CIFS",     re.I), "SMB"),
    (re.compile(r"LDAP",               re.I), "LDAP"),
    (re.compile(r"telnet|login:",      re.I), "Telnet"),
]

WELL_KNOWN_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-ALT", 8443: "HTTPS-ALT", 27017: "MongoDB",
    1433: "MSSQL", 389: "LDAP", 636: "LDAPS", 9200: "Elasticsearch",
    2181: "Zookeeper", 6443: "Kubernetes", 10250: "Kubelet",
}

TOP_100_PORTS = [
    21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,
    1723,3306,3389,5900,8080,8443,8888,9090,9200,10000,
    1433,1521,3000,4444,5432,5000,5001,6379,6667,7001,7002,
    8000,8001,8008,8009,8081,8082,8083,8443,8888,9000,9001,
    27017,27018,28017,50000,50070,50075,61616,
]

ALIVE_CHECK_PORTS = [80, 443, 22, 445]


def detect_service_from_banner(banner: str) -> str | None:
    for pattern, name in SERVICE_SIGNATURES:
        if pattern.search(banner):
            return name
    return None


async def grab_banner(host: str, port: int, timeout: float) -> str:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        try:
            banner = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            writer.close()
            await writer.wait_closed()
            return banner.decode("utf-8", errors="ignore").strip()
        except asyncio.TimeoutError:
            writer.close()
            return ""
    except Exception:
        return ""


async def scan_port(host: str, port: int, timeout: float, semaphore: asyncio.Semaphore) -> dict:
    async with semaphore:
        result = {
            "port": port,
            "state": "closed",
            "service": WELL_KNOWN_PORTS.get(port, "unknown"),
            "banner": None,
            "detected_service": None,
        }
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            result["state"] = "open"
            log.debug("Port %d: OPEN", port)

            # grab banner
            banner = await grab_banner(host, port, timeout)
            if banner:
                result["banner"] = banner[:200]
                detected = detect_service_from_banner(banner)
                if detected:
                    result["detected_service"] = detected

        except asyncio.TimeoutError:
            result["state"] = "filtered"
        except ConnectionRefusedError:
            result["state"] = "closed"
        except OSError:
            result["state"] = "error"

        return result


async def run_scan(host: str, ports: list[int], timeout: float, concurrency: int) -> list[dict]:
    semaphore = asyncio.Semaphore(concurrency)
    tasks = [scan_port(host, p, timeout, semaphore) for p in ports]
    results = await asyncio.gather(*tasks)
    return list(results)


async def alive_check(host: str) -> bool:
    """Quick check: try common ports with a short timeout; return True if any responds."""
    for port in ALIVE_CHECK_PORTS:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=0.5
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except Exception:
            continue
    return False


def expand_targets(target: str) -> list[str]:
    """Expand a target into a list of host strings.

    Handles:
      - CIDR notation (e.g. 192.168.1.0/24) → list of host IPs in the network
      - Single host/IP → [target]
    """
    try:
        network = ipaddress.ip_network(target, strict=False)
        # Only expand if it actually looks like a network (has a prefix length < 32/128)
        if network.num_addresses > 1:
            return [str(ip) for ip in network.hosts()]
    except ValueError:
        pass
    return [target]


def parse_ports(port_spec: str) -> list[int]:
    ports = []
    for part in port_spec.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def resolve_host(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except socket.gaierror as e:
        print(f"{C['red']}[!] Cannot resolve {host}: {e}{C['reset']}")
        sys.exit(1)


def print_results(host: str, ip: str, results: list[dict]):
    open_ports = [r for r in results if r["state"] == "open"]
    filtered   = [r for r in results if r["state"] == "filtered"]

    print(C["cyan"] + f"\n{'='*60}")
    print(f"  PORT SCANNER — {host} ({ip})")
    print(f"{'='*60}" + C["reset"])

    print(f"\n{C['green']}Open ports ({len(open_ports)}):{C['reset']}")
    if not open_ports:
        print(f"  {C['yellow']}No open ports found.{C['reset']}")
    else:
        print(f"  {'PORT':<8} {'STATE':<10} {'SERVICE':<16} {'BANNER/INFO'}")
        print(f"  {'─'*56}")
        for r in open_ports:
            svc = r.get("detected_service") or r.get("service", "")
            banner = r.get("banner", "") or ""
            banner_short = banner[:35].replace("\n", " ") if banner else ""
            print(f"  {str(r['port'])+'/'+'tcp':<8} {C['green']}open{C['reset']:<14} {svc:<16} {banner_short}")

    if filtered:
        print(f"\n{C['yellow']}Filtered ports: {', '.join(str(r['port']) for r in filtered[:20])}{C['reset']}")

    print(C["cyan"] + f"\n{'='*60}" + C["reset"])


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="port-scanner",
        description="Async TCP port scanner with banner grabbing and CIDR/range support.",
        epilog=(
            "Examples:\n"
            "  python port-scanner.py 192.168.1.1\n"
            "  python port-scanner.py example.com -p 1-1000\n"
            "  python port-scanner.py 10.0.0.1 -p 80,443,8080,8443 --timeout 2\n"
            "  python port-scanner.py 192.168.1.1 --top100\n"
            "  python port-scanner.py 192.168.1.0/24 -p 1-1024\n"
            "  python port-scanner.py 192.168.1.0/24 --top100 --alive-check"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("host",                help="Target host, IP, or CIDR (e.g. 192.168.1.0/24)")
    p.add_argument("-p", "--ports",       default="1-1024", help="Port range (e.g. 80,443 or 1-1000)")
    p.add_argument("--top100",            action="store_true", help="Scan top 100 common ports")
    p.add_argument("-t", "--timeout",     type=float, default=1.0, help="Timeout per port in seconds")
    p.add_argument("-c", "--concurrency", type=int, default=200,   help="Concurrent connections")
    p.add_argument("-o", "--output",      metavar="FILE", help="Save JSON report")
    p.add_argument("--alive-check",       action="store_true",
                   help="In CIDR mode: probe ports 80/443/22/445 first; skip hosts with no response")
    p.add_argument("-v", "--verbose",     action="store_true")
    return p


def main():
    parser = build_parser()
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING)

    raw_host = args.host.replace("https://", "").replace("http://", "").rstrip("/")
    ports    = TOP_100_PORTS if args.top100 else parse_ports(args.ports)
    targets  = expand_targets(raw_host)

    # ── Single-host mode ───────────────────────────────────────────────────────
    if len(targets) == 1:
        host = targets[0]
        ip   = resolve_host(host)
        print(f"{C['cyan']}[*] Scanning {host} ({ip}) — {len(ports)} ports, timeout={args.timeout}s...{C['reset']}")

        results = asyncio.run(run_scan(ip, ports, args.timeout, args.concurrency))
        open_r  = [r for r in results if r["state"] == "open"]

        print_results(host, ip, results)

        if args.output:
            report = {
                "host":          host,
                "ip":            ip,
                "timestamp":     datetime.now(timezone.utc).isoformat(),
                "ports_scanned": len(ports),
                "open":          open_r,
                "all":           results,
            }
            tmp = args.output + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False, default=str)
            os.replace(tmp, args.output)
            print(f"{C['green']}[+] Report saved: {args.output}{C['reset']}")

    # ── CIDR mode ──────────────────────────────────────────────────────────────
    else:
        port_desc = f"1-{max(ports)}" if ports == list(range(1, max(ports) + 1)) else f"{len(ports)} ports"
        print(f"{C['cyan']}[*] CIDR scan: {raw_host} — {len(targets)} hosts, ports {port_desc}{C['reset']}")

        all_results: list[dict] = []
        hosts_up    = 0
        total_open  = 0

        async def scan_all():
            nonlocal hosts_up, total_open

            semaphore = asyncio.Semaphore(args.concurrency)

            async def scan_one(ip_str: str):
                nonlocal hosts_up, total_open

                if args.alive_check:
                    is_alive = await alive_check(ip_str)
                    if not is_alive:
                        print(f"  {C['yellow']}[*] {ip_str:<18} — no response on alive-check ports (skip){C['reset']}")
                        return

                results = await run_scan(ip_str, ports, args.timeout, args.concurrency)
                open_ports = [r for r in results if r["state"] == "open"]

                if open_ports:
                    hosts_up  += 1
                    total_open += len(open_ports)
                    print(f"  {C['green']}[*] {ip_str:<18} — {len(open_ports)} open port(s){C['reset']}")
                    for r in open_ports:
                        svc = r.get("detected_service") or r.get("service", "")
                        print(f"        {str(r['port'])}/tcp  {svc}")
                else:
                    print(f"  {C['yellow']}[*] {ip_str:<18} — no open ports{C['reset']}")

                all_results.append({
                    "host":       ip_str,
                    "ip":         ip_str,
                    "open_ports": open_ports,
                })

            # Run hosts sequentially to avoid overwhelming the network; each
            # individual host scan already uses the semaphore internally.
            for ip_str in targets:
                await scan_one(ip_str)

        asyncio.run(scan_all())

        print(f"\n{C['cyan']}{'='*60}")
        print(f"  Summary: {C['green']}{hosts_up} hosts up{C['cyan']}, "
              f"{C['green']}{total_open} total open ports{C['cyan']} "
              f"across {len(targets)} scanned")
        print(f"{'='*60}{C['reset']}")

        if args.output:
            report = {
                "cidr":          raw_host,
                "timestamp":     datetime.now(timezone.utc).isoformat(),
                "hosts_scanned": len(targets),
                "hosts_up":      hosts_up,
                "total_open":    total_open,
                "results":       all_results,
            }
            tmp = args.output + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False, default=str)
            os.replace(tmp, args.output)
            print(f"{C['green']}[+] Report saved: {args.output}{C['reset']}")


if __name__ == "__main__":
    main()
