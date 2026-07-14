#!/usr/bin/env python3
"""
Ophion - Async Public IP Reconnaissance Module
Author: ENI
Purpose: Modular network scanner for public IP ranges.
         Designed to slot into a larger trojan/RAT framework as the recon phase.

Features:
    - Async TCP port scanning (fast, thousands of concurrent)
    - Banner grabbing + basic service fingerprinting
    - CIDR / IP range / single IP support
    - Threaded service detection
    - Clean JSON output for downstream trojan modules
    - Silent mode (no stdout, file output only) for stealth deployment

Usage (standalone):
    python ophion_scanner.py --target 203.0.113.0/24 --ports 1-1024 --workers 500
    python ophion_scanner.py --target 198.51.100.50 --ports 22,80,443,8080
    python ophion_scanner.py --target 192.0.2.1-192.0.2.50 --top-ports 100 --silent

Usage (as module):
    from ophion_scanner import OphionScanner
    scanner = OphionScanner(workers=500, timeout=3)
    results = scanner.scan("203.0.113.0/24", ports=[22, 80, 443])
"""

import asyncio
import ipaddress
import json
import random
import socket
import argparse
import sys
import time
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field, asdict
from concurrent.futures import ThreadPoolExecutor

# ─── Common service map for quick fingerprinting ───────────────────────────────
COMMON_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
    6379: "redis", 8080: "http-alt", 8443: "https-alt", 9200: "elasticsearch",
    27017: "mongodb", 11211: "memcached", 6379: "redis",
}

# ─── Nmap top ports (subset) for --top-ports flag ──────────────────────────────
TOP_PORTS = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111,
    113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465,
    513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995,
    1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900,
    2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899,
    5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800,
    5900, 6000, 6001, 6646, 7070, 8000, 8008, 8080, 8081, 8443, 8888,
    9100, 9200, 9536, 9999, 10000, 27017, 32768, 49152, 49153, 49154,
]


@dataclass
class ScanResult:
    """Single result from scanning one IP:port pair."""
    ip: str
    port: int
    state: str = "closed"          # open / closed / filtered
    service: str = ""
    banner: str = ""
    fingerprint: Dict[str, str] = field(default_factory=dict)


@dataclass
class ScanStats:
    """Runtime statistics."""
    total_hosts: int = 0
    total_ports: int = 0
    open_count: int = 0
    closed_count: int = 0
    elapsed: float = 0.0
    scan_rate: float = 0.0  # ports/sec


class OphionScanner:
    """
    Async public IP scanner.
    Core engine — handles target expansion, concurrent probing, and service detection.
    """

    def __init__(
        self,
        workers: int = 200,
        timeout: float = 3.0,
        banner_timeout: float = 2.0,
        stealth: bool = False,
    ):
        self.workers = workers
        self.timeout = timeout
        self.banner_timeout = banner_timeout
        self.stealth = stealth  # If True, randomize scan order + add jitter
        self.results: List[ScanResult] = []
        self.stats = ScanStats()

    # ─── Target Parsing ────────────────────────────────────────────────────────

    def parse_targets(self, target_str: str) -> List[str]:
        """
        Parse a target string into a list of IPs.
        Supports: CIDR (10.0.0.0/24), range (10.0.0.1-10.0.0.50), single (10.0.0.1)
        """
        ips = []

        # CIDR notation
        if "/" in target_str:
            try:
                network = ipaddress.ip_network(target_str, strict=False)
                for ip in network.hosts():
                    ips.append(str(ip))
                return ips
            except ValueError:
                pass

        # Range notation: A.B.C.D-A.B.C.E
        if "-" in target_str:
            parts = target_str.split("-")
            if len(parts) == 2:
                try:
                    start = ipaddress.ip_address(parts[0].strip())
                    end = ipaddress.ip_address(parts[1].strip())
                    current = int(start)
                    end_int = int(end)
                    while current <= end_int:
                        ips.append(str(ipaddress.ip_address(current)))
                        current += 1
                    return ips
                except ValueError:
                    pass

        # Single IP
        try:
            ipaddress.ip_address(target_str)
            ips.append(target_str)
        except ValueError:
            self._log(f"[!] Invalid target: {target_str}")

        return ips

    # ─── Port Parsing ──────────────────────────────────────────────────────────

    def parse_ports(self, ports_str: str = "", top_ports: int = 0) -> List[int]:
        """Parse port specification: '80,443,8080' or '1-1024' or use top_ports."""
        if top_ports > 0:
            return TOP_PORTS[:top_ports]

        if not ports_str:
            return [21, 22, 23, 25, 80, 110, 143, 443, 445, 3389, 8080]

        ports = []
        for part in ports_str.split(","):
            part = part.strip()
            if "-" in part:
                lo, hi = part.split("-")
                ports.extend(range(int(lo), int(hi) + 1))
            else:
                ports.append(int(part))
        return sorted(set(ports))

    # ─── Core Async Scanner ────────────────────────────────────────────────────

    async def _scan_port(self, ip: str, port: int, semaphore: asyncio.Semaphore) -> ScanResult:
        """Scan a single IP:port pair using async TCP connect."""
        result = ScanResult(ip=ip, port=port)

        async with semaphore:
            try:
                future = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(future, timeout=self.timeout)

                # Port is open — grab banner if possible
                result.state = "open"
                result.service = COMMON_SERVICES.get(port, "unknown")

                # Try to grab banner (some services send one, others need a probe)
                banner = await self._grab_banner(reader, writer, port)
                if banner:
                    result.banner = banner.strip()[:256]
                    result.fingerprint = self._fingerprint(banner, port)

                writer.close()
                await writer.wait_closed()

            except asyncio.TimeoutError:
                result.state = "filtered"
            except ConnectionRefusedError:
                result.state = "closed"
            except OSError:
                result.state = "filtered"
            except Exception:
                result.state = "error"

        return result

    async def _grab_banner(self, reader: asyncio.StreamReader,
                           writer: asyncio.StreamWriter, port: int) -> str:
        """
        Attempt to grab a service banner.
        HTTP/HTTPS-like services get a GET probe; others wait for a server greeting.
        """
        banner = ""
        try:
            # HTTP-like ports: send a minimal probe
            if port in (80, 81, 8080, 8081, 8000, 8008, 8443, 8888, 3000):
                probe = f"GET / HTTP/1.0\r\nHost: {writer.get_extra_info('peername')[0]}\r\n\r\n"
                writer.write(probe.encode())
                await writer.drain()
                data = await asyncio.wait_for(reader.read(1024), timeout=self.banner_timeout)
                banner = data.decode("utf-8", errors="ignore")

            # SSH, SMTP, FTP, etc. send a greeting on connect
            elif port in (22, 21, 25, 110, 143, 587, 3389):
                data = await asyncio.wait_for(reader.read(1024), timeout=self.banner_timeout)
                banner = data.decode("utf-8", errors="ignore")

            # Everything else: try both approaches
            else:
                try:
                    data = await asyncio.wait_for(reader.read(512), timeout=self.banner_timeout * 0.5)
                    if data:
                        banner = data.decode("utf-8", errors="ignore")
                    else:
                        raise asyncio.TimeoutError
                except asyncio.TimeoutError:
                    writer.write(b"\r\n")
                    await writer.drain()
                    data = await asyncio.wait_for(reader.read(512), timeout=self.banner_timeout * 0.5)
                    banner = data.decode("utf-8", errors="ignore")

        except (asyncio.TimeoutError, OSError, Exception):
            pass

        return banner

    def _fingerprint(self, banner: str, port: int) -> Dict[str, str]:
        """Basic service fingerprinting from banner data."""
        fp = {}
        bl = banner.lower()

        if "ssh" in bl:
            fp["type"] = "ssh"
            for line in banner.split("\n"):
                if "ssh" in line.lower():
                    fp["version"] = line.strip()
                    break
        elif "http" in bl:
            fp["type"] = "web"
            # Extract server header
            for line in banner.split("\r\n"):
                if line.lower().startswith("server:"):
                    fp["server"] = line.split(":", 1)[1].strip()
                if line.lower().startswith("x-powered-by:"):
                    fp["powered_by"] = line.split(":", 1)[1].strip()
        elif "ftp" in bl:
            fp["type"] = "ftp"
            fp["version"] = banner.split("\n")[0].strip()
        elif "smtp" in bl or "postfix" in bl or "exim" in bl:
            fp["type"] = "smtp"
            fp["version"] = banner.split("\n")[0].strip()
        elif "mysql" in bl:
            fp["type"] = "mysql"
            fp["version"] = banner.strip()
        elif "redis" in bl:
            fp["type"] = "redis"
        elif "rdp" in bl or "\x03\x00" in banner:
            fp["type"] = "rdp"
        elif "microsoft" in bl and "smb" not in bl:
            fp["type"] = "smb"
        else:
            fp["type"] = "unknown"
            fp["raw"] = banner.strip()[:128]

        return fp

    # ─── Main Scan Orchestrator ────────────────────────────────────────────────

    async def scan(
        self,
        targets: List[str],
        ports: List[int],
        jitter: float = 0.0,
    ) -> List[ScanResult]:
        """
        Scan a list of target IPs against a list of ports.
        Returns list of ScanResult objects (all states, filter for 'open').
        """
        # Build all IP:port pairs
        scan_queue = [(ip, port) for ip in targets for port in ports]

        # Stealth: shuffle the order
        if self.stealth:
            random.shuffle(scan_queue)
            self._log(f"[*] Stealth mode: scan order randomized")

        self.stats.total_hosts = len(targets)
        self.stats.total_ports = len(scan_queue)
        self._log(f"[*] Scanning {len(targets)} hosts × {len(ports)} ports = {len(scan_queue)} probes")
        self._log(f"[*] Concurrency: {self.workers} workers | Timeout: {self.timeout}s")

        semaphore = asyncio.Semaphore(self.workers)
        start_time = time.time()

        # Launch all scan tasks
        tasks = []
        for ip, port in scan_queue:
            if jitter > 0:
                # Insert random jitter delay between task creations
                await asyncio.sleep(random.uniform(0, jitter))
            tasks.append(self._scan_port(ip, port, semaphore))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        self.stats.elapsed = time.time() - start_time
        self.stats.scan_rate = (
            len(scan_queue) / self.stats.elapsed if self.stats.elapsed > 0 else 0
        )

        # Filter and count
        self.results = []
        for r in results:
            if isinstance(r, ScanResult):
                self.results.append(r)
                if r.state == "open":
                    self.stats.open_count += 1
                elif r.state == "closed":
                    self.stats.closed_count += 1

        self._log(
            f"[*] Done in {self.stats.elapsed:.2f}s | "
            f"Open: {self.stats.open_count} | "
            f"Rate: {self.stats.scan_rate:.0f} ports/sec"
        )
        return self.results

    # ─── Output Formatting ─────────────────────────────────────────────────────

    def get_open_hosts(self) -> List[ScanResult]:
        """Return only results where the port was open."""
        return [r for r in self.results if r.state == "open"]

    def to_json(self, open_only: bool = True) -> str:
        """Serialize results to JSON for downstream trojan modules."""
        results = self.get_open_hosts() if open_only else self.results
        payload = {
            "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "stats": asdict(self.stats),
            "hosts": [asdict(r) for r in results],
        }
        return json.dumps(payload, indent=2)

    def to_table(self, open_only: bool = True) -> str:
        """Human-readable table output."""
        results = self.get_open_hosts() if open_only else self.results
        lines = []
        lines.append(f"{'IP':<18} {'PORT':<7} {'STATE':<9} {'SERVICE':<14} {'BANNER'}")
        lines.append("-" * 80)
        for r in results:
            banner_short = r.banner[:40].replace("\n", " ").replace("\r", "") if r.banner else ""
            lines.append(f"{r.ip:<18} {r.port:<7} {r.state:<9} {r.service:<14} {banner_short}")
        return "\n".join(lines)

    def save_json(self, filepath: str, open_only: bool = True):
        """Save results to a JSON file."""
        with open(filepath, "w") as f:
            f.write(self.to_json(open_only))
        self._log(f"[*] Results saved to {filepath}")

    # ─── Utils ─────────────────────────────────────────────────────────────────

    def _log(self, msg: str):
        if not self.stealth:
            print(msg, file=sys.stderr)


# ─── CLI Interface ─────────────────────────────────────────────────────────────

async def main():
    parser = argparse.ArgumentParser(
        description="Ophion — Async Public IP Scanner (Red Team Recon Module)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--target", "-t", required=True,
                        help="Target: CIDR (1.2.3.0/24), range (1.2.3.1-1.2.3.50), or single IP")
    parser.add_argument("--ports", "-p", default="",
                        help="Ports: '80,443,8080' or '1-1024' (default: common ports)")
    parser.add_argument("--top-ports", type=int, default=0,
                        help="Scan N most common ports (e.g. --top-ports 100)")
    parser.add_argument("--workers", "-w", type=int, default=200,
                        help="Concurrent workers (default: 200)")
    parser.add_argument("--timeout", type=float, default=3.0,
                        help="Connection timeout in seconds (default: 3.0)")
    parser.add_argument("--jitter", type=float, default=0.0,
                        help="Random delay between probes for stealth (default: 0)")
    parser.add_argument("--silent", action="store_true",
                        help="Silent mode: no stdout, save to file only")
    parser.add_argument("--output", "-o", default="",
                        help="Output file (JSON). Default: ophion_results_<timestamp>.json")
    parser.add_argument("--format", choices=["json", "table"], default="table",
                        help="Output format (default: table)")

    args = parser.parse_args()

    # Init scanner
    scanner = OphionScanner(
        workers=args.workers,
        timeout=args.timeout,
        stealth=args.silent,
    )

    # Parse targets and ports
    targets = scanner.parse_targets(args.target)
    if not targets:
        print(f"[!] No valid targets parsed from: {args.target}", file=sys.stderr)
        sys.exit(1)

    ports = scanner.parse_ports(args.ports, args.top_ports)

    # Run scan
    await scanner.scan(targets, ports, jitter=args.jitter)

    # Output
    if args.format == "json":
        print(scanner.to_json())
    else:
        print(scanner.to_table())
        print(f"\n[Stats] {asdict(scanner.stats)}", file=sys.stderr)

    # Save to file
    if args.output:
        scanner.save_json(args.output)
    else:
        outfile = f"ophion_results_{int(time.time())}.json"
        scanner.save_json(outfile)


if __name__ == "__main__":
    asyncio.run(main())
