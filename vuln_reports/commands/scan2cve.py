"""``scan2cve.py``: list the CVEs in a scanner export, per host and service."""

import argparse
import logging
import os
import sys

from vuln_reports.console import Colors, colorize
from vuln_reports.enrichment.pipeline import cves_for_service, lookup_cpes, specific_cpes
from vuln_reports.parsers import SCANNER_TYPES, detect_scanner, parse_file

logger = logging.getLogger("scan2cve")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Scan2CVE - Unified CVE Discovery (Nmap, Nessus, Qualys)")
    parser.add_argument("file", help="Scanner output file (XML, .nessus, or CSV)")
    parser.add_argument("-t", "--type", choices=SCANNER_TYPES, help="Force scanner type (auto-detected by default)")
    parser.add_argument("-o", "--output", help="Save discovered CVE IDs to a text file")
    parser.add_argument("-n", "--no-color", action="store_true", help="Disable terminal colors")
    return parser


def run(argv=None) -> None:
    args = build_parser().parse_args(argv)
    use_colors = not args.no_color and sys.stdout.isatty()
    if not os.path.exists(args.file):
        print(f"[!] File not found: {args.file}")
        return
    scanner_type = args.type or detect_scanner(args.file)
    if not scanner_type:
        print(f"[!] Could not detect scanner type for {args.file}. Use -t to specify.")
        return
    print(f"[*] Detected type: {scanner_type}")
    scan = parse_file(args.file, scanner_type, use_colors)
    if not scan.hosts:
        print("[!] No scan data found or parsing failed.")
        return

    global_cves = set()
    nvd_key = os.getenv("NVD_API_KEY")
    print(f"[*] Analyzing {len(scan.hosts)} hosts...\n")

    cpe_to_cves = {}
    if scanner_type == "nmap_xml":
        cpes = specific_cpes(scan, on_broad=lambda cpe: logger.debug(f"Skipping broad CPE: {cpe}"))
        print(f"[*] Fetching CVEs for {len(cpes)} unique specific CPEs...")
        cpe_to_cves = lookup_cpes(cpes, nvd_key, max_workers=10, use_colors=use_colors)

    for host_id, host in sorted(scan.hosts.items()):
        if not host.services:
            continue
        h_info = [v for v in (host.ip, host.hostname) if v]
        print(f"[{colorize(' / '.join(h_info) or host_id, Colors.BLUE, use_colors)}]")
        for s in host.services:
            print(f"  └─ {s.port_proto} ({s.name}):", end=" ", flush=True)
            if scanner_type == "nmap_xml":
                s.cves = cves_for_service(s, cpe_to_cves)
            unique_ids = sorted(list(s.cves))
            if unique_ids:
                print(f"{colorize(len(unique_ids), Colors.GREEN, use_colors)} CVEs found.")
                for cid in unique_ids[:3]:
                    print(f"     - {cid}")
                if len(unique_ids) > 3:
                    print(f"     - ... and {len(unique_ids) - 3} more.")
                global_cves.update(unique_ids)
            else:
                print("No CVEs.")
        print()
    if args.output:
        try:
            with open(args.output, "w") as f:
                for cve in sorted(list(global_cves)):
                    f.write(f"{cve}\n")
            print(f"[+] Saved {len(global_cves)} unique CVEs to {args.output}")
        except Exception as e:
            print(f"[!] Error saving output: {e}")
