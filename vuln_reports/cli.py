"""``python3 -m vuln_reports <command>``: the pipeline as separate stages.

    parse   scanner export      -> findings.json  (hosts, services, CVEs/CPEs)
    enrich  findings.json       -> enriched.json  (CPE->CVE, CVE intelligence)
    report  enriched.json       -> CSV/HTML/MD/PDF/XLSX/DOCX
    run     scanner export      -> reports        (same as vuln_report.py)

Stages exchange the JSON form of ``vuln_reports.models`` (schema_version 1), so
an expensive enrichment can be saved once and rendered into reports many times.
"""

import argparse
import json
import os
import sys

from vuln_reports import __version__


def _write_json(data, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def _read_json(path: str):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def cmd_parse(args) -> int:
    from vuln_reports.parsers import detect_scanner, parse_file

    if not os.path.exists(args.file):
        print(f"[!] File not found: {args.file}")
        return 1
    scanner_type = args.type or detect_scanner(args.file)
    if not scanner_type:
        print(f"[!] Could not detect scanner type for {args.file}. Use -t to specify.")
        return 1
    print(f"[*] Detected scanner type: {scanner_type}")
    scan = parse_file(args.file, scanner_type, use_colors=False)
    if not scan.hosts:
        print("[!] No scan data found.")
        return 1
    _write_json(scan.to_dict(), args.output)
    services = sum(len(h.services) for h in scan.hosts.values())
    print(f"[+] Parsed {len(scan.hosts)} hosts, {services} services, {len(scan.all_cve_ids())} CVEs -> {args.output}")
    return 0


def cmd_enrich(args) -> int:
    from vuln_reports.commands.report import announce_keys, resolve_scan_cpes
    from vuln_reports.enrichment.keys import get_keys
    from vuln_reports.enrichment.pipeline import enrich_cves
    from vuln_reports.models import EnrichedScan, ScanResult

    try:
        scan = ScanResult.from_dict(_read_json(args.input))
    except (OSError, ValueError, KeyError) as e:
        print(f"[!] Cannot read findings from {args.input}: {e}")
        return 1
    keys = get_keys()
    announce_keys(keys)
    github_token, nvd_key, vulners_key, circl_key = keys
    resolve_scan_cpes(scan, nvd_key, args.threads)
    intel = enrich_cves(sorted(scan.all_cve_ids()), github_token, nvd_key, vulners_key, circl_key, args.threads)
    _write_json(EnrichedScan(scan=scan, intel=intel).to_dict(), args.output)
    errors = sum(1 for d in intel.values() if "error" in d)
    print(f"[+] Enriched {len(intel)} CVEs ({errors} failed) -> {args.output}")
    return 0


def cmd_report(args) -> int:
    from vuln_reports.commands.report import apply_severity_filter, resolve_outputs, write_reports
    from vuln_reports.models import EnrichedScan

    try:
        enriched = EnrichedScan.from_dict(_read_json(args.input))
    except (OSError, ValueError, KeyError) as e:
        print(f"[!] Cannot read enriched findings from {args.input}: {e}")
        return 1
    outputs = resolve_outputs(args.csv, args.html, args.markdown, args.pdf, args.xlsx, args.docx, args.all)
    enriched.intel = apply_severity_filter(enriched.scan, enriched.intel, args.severity)
    write_reports(enriched, outputs)
    return 0


def cmd_run(args) -> int:
    from vuln_reports.commands.report import run_args

    run_args(args)
    return 0


def build_parser() -> argparse.ArgumentParser:
    from vuln_reports.commands.report import add_output_arguments, add_severity_argument, add_threads_argument
    from vuln_reports.parsers import SCANNER_TYPES

    parser = argparse.ArgumentParser(
        prog="vuln_reports",
        description="Vuln-Reports: parse scanner output, enrich CVEs, and generate reports.",
    )
    parser.add_argument("--version", action="version", version=f"vuln-reports {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="{parse,enrich,report,run}")

    p = sub.add_parser("parse", help="parse a scanner export into findings JSON")
    p.add_argument("file", help="Nmap XML, Nessus (.nessus/CSV) or Qualys (XML/CSV) export")
    p.add_argument("-t", "--type", choices=SCANNER_TYPES, help="force scanner type (auto-detected by default)")
    p.add_argument("-o", "--output", default="findings.json", help="output file (default: findings.json)")
    p.set_defaults(func=cmd_parse)

    p = sub.add_parser("enrich", help="resolve CPEs and fetch CVE intelligence for parsed findings")
    p.add_argument("input", help="findings JSON written by 'parse'")
    p.add_argument("-o", "--output", default="enriched.json", help="output file (default: enriched.json)")
    add_threads_argument(p)
    p.set_defaults(func=cmd_enrich)

    p = sub.add_parser("report", help="render reports from enriched findings")
    p.add_argument("input", help="enriched JSON written by 'enrich'")
    add_output_arguments(p)
    add_severity_argument(p)
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("run", help="parse + enrich + report in one step (same as vuln_report.py)")
    p.add_argument("file", help="Input scan file (Nmap/Nessus/Qualys)")
    add_output_arguments(p)
    add_threads_argument(p)
    add_severity_argument(p)
    p.set_defaults(func=cmd_run)
    return parser


def main(argv=None) -> None:
    args = build_parser().parse_args(argv)
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
