"""``cve_lookup.py``: research CVE IDs and export the intelligence.

Automation contract (e.g. a Tines Run Script action): ``cve_lookup.py -c /tmp/results.csv "<ids>"``
or ``-f <file>``, stdin closed, keys in environment variables. Keep the CSV columns stable.
"""

import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from vuln_reports.console import Colors, colorize
from vuln_reports.enrichment.keys import get_keys, prompt_for_missing_keys
from vuln_reports.enrichment.lookup import extract_cve_ids, get_cve_data
from vuln_reports.reporting.lookup_formats import (
    get_output_path,
    print_pretty,
    save_csv,
    save_grep,
    save_json,
    save_text,
    save_xml,
)

VERSION = "2.2.1"
MAX_WORKERS = 10


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="CVE Lookup Tool Pro - Intelligence Edition")
    p.add_argument("cve_ids", nargs="*", help="CVE IDs")
    p.add_argument("-f", "--file", help="Input file")
    p.add_argument(
        "-p", "--poc", action="store_true", help="PoC Mode: Filter for results with exploits and show minimal output"
    )
    p.add_argument("-j", "--json", nargs="?", const="results", help="JSON export (default: results.json)")
    p.add_argument("-c", "--csv", nargs="?", const="results", help="CSV export (default: results.csv)")
    p.add_argument("-t", "--text", nargs="?", const="results", help="Text report (default: results.txt)")
    p.add_argument("-G", "--grep", nargs="?", const="results", help="Grep export (default: results.grep)")
    p.add_argument("-x", "--xml", nargs="?", const="results", help="XML export (default: results.xml)")
    p.add_argument(
        "-A",
        "--all",
        nargs="?",
        const="results",
        help="Generate all output formats. Optionally specify a base filename (default: 'results')",
    )
    p.add_argument("-n", "--no-color", action="store_true", help="Disable colors")
    p.add_argument(
        "-v", "--version", action="version", version=f"CVE Lookup Tool Pro v{VERSION} (Intelligence Edition)"
    )
    return p


def run(argv=None, max_workers: int = MAX_WORKERS) -> None:
    p = build_parser()
    args = p.parse_args(argv)

    use_colors = not args.no_color and sys.stdout.isatty()

    if not args.poc:
        banner = f"--- CVE Lookup Tool Pro v{VERSION} (Intelligence Edition) ---"
        print(colorize(banner, Colors.BLUE + Colors.BOLD, use_colors))

    keys = get_keys()
    # Only prompt when a human is at the terminal (never in Tines/CI, where stdin is closed).
    if sys.stdin.isatty() and not args.poc:
        keys = prompt_for_missing_keys(keys)
    github_token, nvd_key, vulners_key, circl_key = keys

    cve_list = extract_cve_ids(args.cve_ids)
    if args.file:
        try:
            with open(args.file, encoding="utf-8", errors="ignore") as f:
                extract_cve_ids([f.read()], into=cve_list)
        except Exception as e:
            print(f"Error: {e}")
            sys.exit(1)

    if not cve_list:
        p.print_help()
        sys.exit(0)
    results = []
    session = requests.Session()
    print(f"[*] Analyzing {len(cve_list)} CVEs...")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(get_cve_data, session, cid, github_token, nvd_key, vulners_key, circl_key): cid
            for cid in cve_list
        }
        for f in as_completed(futures):
            data = f.result()
            # PoC mode keeps only CVEs exploited in the wild or with a PoC
            if args.poc:
                if data.get("exploitability") == "Theoretical / Unknown" or "error" in data:
                    continue
            results.append(data)
            print_pretty(data, use_colors, args.poc)

    all_base = args.all if args.all else None

    if args.json or all_base:
        fname = get_output_path(args.json or all_base, "json")
        save_json(results, fname)
        print(f"[+] JSON report saved to: {fname}")
    if args.csv or all_base:
        fname = get_output_path(args.csv or all_base, "csv")
        save_csv(results, fname)
        print(f"[+] CSV report saved to: {fname}")
    if args.text or all_base:
        fname = get_output_path(args.text or all_base, "txt")
        save_text(results, fname)
        print(f"[+] Text report saved to: {fname}")
    if args.grep or all_base:
        fname = get_output_path(args.grep or all_base, "grep")
        save_grep(results, fname)
        print(f"[+] Grep report saved to: {fname}")
    if args.xml or all_base:
        fname = get_output_path(args.xml or all_base, "xml")
        save_xml(results, fname)
        print(f"[+] XML report saved to: {fname}")

    print(f"\n[+] Done. Processed {len(results)} items.")
