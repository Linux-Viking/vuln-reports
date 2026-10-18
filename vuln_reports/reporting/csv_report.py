"""Host-based detailed CSV (one row per host/service/CVE) for scan reports."""

import csv

from vuln_reports.models import EnrichedScan
from vuln_reports.reporting.common import affected_summary

HEADERS = [
    "IP",
    "Hostname (FQDN)",
    "CVE ID",
    "Port",
    "Service",
    "Title",
    "Description",
    "CVSS Score",
    "CISA KEV",
    "EPSS Score",
    "Exploitability",
    "PoC Available",
    "PoC Link",
    "Threat Vector",
    "User Interaction",
    "Complexity",
    "Affected Products",
    "Remediation",
    "References",
]


def save_scan_csv(enriched: EnrichedScan, output_file: str) -> None:
    try:
        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(HEADERS)
            for row in enriched.findings():
                d = row.intel
                writer.writerow(
                    [
                        row.ip,
                        row.hostname,
                        row.cve_id,
                        row.port_proto,
                        row.service,
                        d.get("title", "N/A"),
                        d.get("description", "N/A"),
                        d.get("cvss_score", "N/A"),
                        d.get("cisa_kev", "N/A"),
                        d.get("epss_score", "N/A"),
                        d.get("exploitability", "N/A"),
                        d.get("poc_available", "N/A"),
                        d.get("poc_link", "N/A"),
                        d.get("threat_vector", "N/A"),
                        d.get("user_interaction", "N/A"),
                        d.get("attack_complexity", "N/A"),
                        affected_summary(d.get("affected", [])),
                        d.get("remediation", "N/A"),
                        "; ".join(d.get("references", [])),
                    ]
                )
        print(f"[+] Detailed CSV report saved to: {output_file}")
    except Exception as e:
        print(f"[!] Error writing CSV: {e}")
