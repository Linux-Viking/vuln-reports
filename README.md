# Vuln-Reports Suite

A unified vulnerability reporting toolkit for pentesters. This suite combines scanner output parsing, CVE intelligence, and exploit research into a professional reporting pipeline.

## Tools in the Suite

1.  **`vuln_report.py` (The Orchestrator)**:
    - Automatically detects scan types (Nmap, Nessus, Qualys).
    - Extracts Host IPs and FQDNs.
    - Enriches findings with CVSS scores, CISA KEV status, and exploit links.
    - Generates a professional CSV report.

2.  **`scan2cve.py` (The Parser)**:
    - Parses XML/CSV exports from major scanners.
    - Translates Nmap CPEs to CVEs via the NVD API.
    - Can be run standalone to generate a simple text list of unique CVEs.

3.  **`cve_lookup.py` (The Enricher)**:
    - Researches specific CVEs for intelligence and PoCs.
    - Supports JSON, CSV, Text, and Grep-able outputs.
    - Can be run standalone for quick vulnerability research.

## Installation

```bash
pip install -r requirements.txt
```

## End-to-End Reporting

```bash
python3 vuln_report.py my_scan.nessus -o final_report.csv --group-by host
```

## Standalone Usage

**Research a single CVE:**
```bash
python3 cve_lookup.py CVE-2023-48795 -p
```

**Convert Nmap XML to unique CVE list:**
```bash
python3 scan2cve.py scan.xml -o unique_cves.txt
```

## Workflow Integration

This suite is designed to take you from a raw scanner export to a prioritized vulnerability list in one command.

---
**Note**: This repository replaces the legacy `scan2cve` and `cve-lookup` standalone repositories.
