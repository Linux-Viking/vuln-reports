"""``vuln_report.py`` / ``vuln_reports run``: parse -> enrich -> report in one go."""

from __future__ import annotations

import argparse
import os

from vuln_reports.enrichment.keys import get_keys
from vuln_reports.enrichment.pipeline import apply_cpe_results, enrich_cves, lookup_cpes, specific_cpes
from vuln_reports.models import EnrichedScan, ScanResult
from vuln_reports.parsers import detect_scanner, parse_file
from vuln_reports.reporting.common import get_severity
from vuln_reports.reporting.csv_report import save_scan_csv
from vuln_reports.reporting.docx_report import save_docx_report
from vuln_reports.reporting.html_report import save_html_report, save_markdown_report, save_pdf_report
from vuln_reports.reporting.xlsx_report import save_xlsx_report

DEFAULT_CSV = "vulnerability_report.csv"


def add_output_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("-C", "--csv", help="Output CSV filename")
    p.add_argument("-H", "--html", help="Output HTML report filename")
    p.add_argument("-M", "--markdown", help="Output Markdown report filename")
    p.add_argument("-P", "--pdf", help="Output PDF report filename")
    p.add_argument("-X", "--xlsx", help="Output XLSX report filename")
    p.add_argument("-D", "--docx", help="Output Word DOCX report filename")
    p.add_argument("-A", "--all", help="Generate ALL formats using this base filename")


def add_severity_argument(p: argparse.ArgumentParser) -> None:
    p.add_argument("-s", "--severity", help="Filter by severity: Info, Low, Medium, High, Critical (comma-separated)")


def add_threads_argument(p: argparse.ArgumentParser) -> None:
    p.add_argument("-t", "--threads", type=int, default=10, help="Number of concurrent threads (default: 10)")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="VulnReport - Unified Scan Reporting Tool")
    p.add_argument("file", help="Input scan file (Nmap/Nessus/Qualys)")
    add_output_arguments(p)
    add_threads_argument(p)
    add_severity_argument(p)
    return p


def resolve_outputs(
    csv_file=None, html_file=None, md_file=None, pdf_file=None, xlsx_file=None, docx_file=None, all_base=None
):
    """Apply ``--all`` and the CSV fallback. Returns the 6 output paths (or None each)."""
    if all_base:
        csv_file = f"{all_base}.csv"
        html_file = f"{all_base}.html"
        md_file = f"{all_base}.md"
        pdf_file = f"{all_base}.pdf"
        xlsx_file = f"{all_base}.xlsx"
        docx_file = f"{all_base}.docx"
    if not any([csv_file, html_file, md_file, pdf_file, xlsx_file, docx_file]):
        csv_file = DEFAULT_CSV
        print(f"[*] No output format specified. Defaulting to CSV: {csv_file}")
    return csv_file, html_file, md_file, pdf_file, xlsx_file, docx_file


def parse_scan(scan_file: str):
    """Detect and parse; prints progress like v1.0.0. Returns a ScanResult or None."""
    scanner_type = detect_scanner(scan_file)
    if not scanner_type:
        print(f"[!] Could not detect scanner type for {scan_file}")
        return None
    print(f"[*] Detected scanner type: {scanner_type}")
    scan = parse_file(scan_file, scanner_type)
    if not scan.hosts:
        print("[!] No scan data found.")
        return None
    return scan


def resolve_scan_cpes(scan: ScanResult, nvd_key, threads: int) -> None:
    """Nmap only: turn service CPEs into CVEs via NVD."""
    if scan.scanner_type != "nmap_xml":
        return
    cpes = specific_cpes(scan, on_broad=lambda cpe: print(f"  [-] Skipping broad/generic CPE: {cpe}"))
    if cpes:
        print(f"[*] Fetching CVEs for {len(cpes)} unique specific CPEs using {threads} threads...")
        apply_cpe_results(scan, lookup_cpes(cpes, nvd_key, max_workers=threads))


def apply_severity_filter(scan: ScanResult, enrichment: dict, severity: str | None) -> dict:
    """Drop CVEs outside the requested severities from the scan and the enrichment."""
    allowed = [s.strip().lower() for s in severity.split(",")] if severity else None
    if not allowed:
        return enrichment
    print(f"[*] Filtering results for severities: {', '.join(allowed)}")
    filtered_cves = set()
    for cve_id, d in enrichment.items():
        if get_severity(d.get("cvss_score", "N/A")) in allowed:
            filtered_cves.add(cve_id)
    for host in scan.hosts.values():
        for service in host.services:
            service.cves = {cid for cid in service.cves if cid in filtered_cves}
    return {cid: data for cid, data in enrichment.items() if cid in filtered_cves}


def write_reports(enriched: EnrichedScan, outputs) -> None:
    csv_file, html_file, md_file, pdf_file, xlsx_file, docx_file = outputs
    scan, intel = enriched.scan, enriched.intel
    cve_to_hosts = scan.cve_to_hosts()
    if csv_file:
        save_scan_csv(enriched, csv_file)
    if html_file:
        save_html_report(intel, cve_to_hosts, scan.scanner_type, scan.source_file, html_file)
    if md_file:
        save_markdown_report(intel, cve_to_hosts, scan.scanner_type, scan.source_file, md_file)
    if pdf_file:
        save_pdf_report(intel, cve_to_hosts, scan.scanner_type, scan.source_file, pdf_file)
    if xlsx_file:
        save_xlsx_report(intel, cve_to_hosts, xlsx_file)
    if docx_file:
        save_docx_report(intel, cve_to_hosts, scan.scanner_type, scan.source_file, docx_file)


def generate_report(
    scan_file: str,
    csv_file: str = None,
    github_token: str = None,
    nvd_key: str = None,
    vulners_key: str = None,
    circl_key: str = None,
    html_file: str = None,
    md_file: str = None,
    pdf_file: str = None,
    xlsx_file: str = None,
    docx_file: str = None,
    all_base: str = None,
    threads: int = 10,
    severity: str = None,
):
    """Same signature and behaviour as v1.0.0 ``vuln_report.generate_report``."""
    outputs = resolve_outputs(csv_file, html_file, md_file, pdf_file, xlsx_file, docx_file, all_base)

    scan = parse_scan(scan_file)
    if scan is None:
        return
    resolve_scan_cpes(scan, nvd_key, threads)

    enrichment = enrich_cves(
        list(scan.all_cve_ids()), github_token, nvd_key, vulners_key, circl_key, max_workers=threads
    )
    enrichment = apply_severity_filter(scan, enrichment, severity)
    write_reports(EnrichedScan(scan=scan, intel=enrichment), outputs)


def announce_keys(keys) -> None:
    github_token, nvd_key, vulners_key, circl_key = keys
    if nvd_key:
        print("[*] Using NVD API Key for accelerated lookups.")
    if github_token:
        print("[*] Using GitHub Token for PoC research.")
    if vulners_key:
        print("[*] Using Vulners API Key for enhanced intelligence.")
    if circl_key:
        print("[*] Using CIRCL API Key for accelerated lookups.")


def run_args(args) -> None:
    if not os.path.exists(args.file):
        print(f"[!] File not found: {args.file}")
        return
    keys = get_keys()
    announce_keys(keys)
    github_token, nvd_key, vulners_key, circl_key = keys
    generate_report(
        args.file,
        args.csv,
        github_token,
        nvd_key,
        vulners_key,
        circl_key,
        args.html,
        args.markdown,
        args.pdf,
        args.xlsx,
        args.docx,
        args.all,
        args.threads,
        args.severity,
    )


def run(argv=None) -> None:
    run_args(build_parser().parse_args(argv))
