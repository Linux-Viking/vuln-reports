#!/usr/bin/env python3
"""
VulnReport: Unified vulnerability report generator.
Combines Scan2CVE (parsing) and CVE-Lookup (enrichment) to produce a detailed CSV.
"""

import sys
import os
import csv
import argparse
import requests
import time
from typing import List, Dict, Any

# Dynamic imports are no longer needed as all files live in the same directory
try:
    import scan2cve
    import cve_lookup
except ImportError as e:
    print(f"[!] Error: Could not import scan2cve or cve_lookup. Ensure they are in the same folder.")
    print(f"    Missing module: {e.name}")
    sys.exit(1)

def get_detailed_cve_info(cve_ids: List[str], github_token: str = None, nvd_key: str = None) -> Dict[str, Dict[str, Any]]:
    """Fetch details for a list of CVEs using cve_lookup logic."""
    session = requests.Session()
    cve_details = {}
    print(f"[*] Fetching enrichment data for {len(cve_ids)} unique CVEs...")
    for cve_id in sorted(cve_ids):
        try:
            data = cve_lookup.get_cve_data(session, cve_id, github_token, nvd_key)
            if "error" not in data: cve_details[cve_id] = data
            else: cve_details[cve_id] = {"cve_id": cve_id, "error": data["error"]}
        except Exception as e: cve_details[cve_id] = {"cve_id": cve_id, "error": str(e)}
    return cve_details

def generate_report(scan_file: str, output_file: str, group_by: str, github_token: str = None, nvd_key: str = None):
    scanner_type = scan2cve.detect_scanner(scan_file)
    if not scanner_type: print(f"[!] Could not detect scanner type for {scan_file}"); return
    print(f"[*] Detected scanner type: {scanner_type}")
    session = requests.Session()
    if scanner_type == 'nmap_xml': parser = scan2cve.NmapParser(scan_file, session)
    elif scanner_type == 'nessus_xml': parser = scan2cve.NessusXMLParser(scan_file)
    elif scanner_type == 'nessus_csv': parser = scan2cve.NessusCSVParser(scan_file)
    elif scanner_type == 'qualys_xml': parser = scan2cve.QualysXMLParser(scan_file)
    elif scanner_type == 'qualys_csv': parser = scan2cve.QualysCSVParser(scan_file)
    else: print("[!] Unsupported scanner type."); return

    parser.parse()
    if not parser.hosts: print("[!] No scan data found."); return
    all_cve_ids = set()
    for _, host_data in parser.hosts.items():
        for s in host_data["services"]:
            if scanner_type == 'nmap_xml':
                service_cves = []
                for cpe in s.get('cpes', []):
                    ids = parser.get_cves_for_cpe(cpe); service_cves.extend(ids); time.sleep(scan2cve.NVD_API_DELAY)
                s['cves'] = set(service_cves)
            all_cve_ids.update(s['cves'])

    cve_enrichment = get_detailed_cve_info(list(all_cve_ids), github_token, nvd_key)
    headers = [
        "IP", "Hostname (FQDN)", "CVE ID", "Port", "Service",
        "Title", "Description", "CVSS Score", "CISA KEV", "EPSS Score",
        "Exploitability", "PoC Available", "PoC Link", "User Interaction", "Complexity", 
        "Affected Products", "References"
    ]

    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            if group_by == 'host':
                for _, host_data in sorted(parser.hosts.items()):
                    ip, hostname = host_data.get('ip', ''), host_data.get('hostname', '')
                    for s in host_data["services"]:
                        port_proto = f"{s['port']}/{s['proto']}" if s['port'] != "0" else "Host-level"
                        for cve_id in sorted(list(s['cves'])):
                            d = cve_enrichment.get(cve_id, {})
                            writer.writerow([
                                ip, hostname, cve_id, port_proto, s['name'],
                                d.get('title', 'N/A'), d.get('description', 'N/A'), d.get('cvss_score', 'N/A'),
                                d.get('cisa_kev', 'N/A'), d.get('epss_score', 'N/A'), d.get('exploitability', 'N/A'),
                                d.get('poc_available', 'N/A'), d.get('poc_link', 'N/A'), d.get('user_interaction', 'N/A'),
                                d.get('attack_complexity', 'N/A'),
                                "; ".join([f"{a['product']} ({', '.join(a['versions'])})" for a in d.get('affected', [])]),
                                "; ".join(d.get('references', []))
                            ])
            else: # group by cve
                cve_to_hosts = {}
                for _, host_data in parser.hosts.items():
                    ip, hostname = host_data.get('ip', ''), host_data.get('hostname', '')
                    for s in host_data["services"]:
                        port_proto = f"{s['port']}/{s['proto']}" if s['port'] != "0" else "Host-level"
                        for cve_id in s['cves']:
                            if cve_id not in cve_to_hosts: cve_to_hosts[cve_id] = []
                            cve_to_hosts[cve_id].append((ip, hostname, port_proto, s['name']))
                for cve_id in sorted(list(all_cve_ids)):
                    d = cve_enrichment.get(cve_id, {})
                    for ip, hostname, port, svc in sorted(cve_to_hosts.get(cve_id, [])):
                        writer.writerow([
                            ip, hostname, cve_id, port, svc,
                            d.get('title', 'N/A'), d.get('description', 'N/A'), d.get('cvss_score', 'N/A'),
                            d.get('cisa_kev', 'N/A'), d.get('epss_score', 'N/A'), d.get('exploitability', 'N/A'),
                            d.get('poc_available', 'N/A'), d.get('poc_link', 'N/A'), d.get('user_interaction', 'N/A'),
                            d.get('attack_complexity', 'N/A'),
                            "; ".join([f"{a['product']} ({', '.join(a['versions'])})" for a in d.get('affected', [])]),
                            "; ".join(d.get('references', []))
                        ])
        print(f"[+] Detailed report saved to: {output_file}")
    except Exception as e: print(f"[!] Error writing CSV: {e}")

def main():
    p = argparse.ArgumentParser(description="VulnReport - Unified Scan Reporting Tool")
    p.add_argument("file", help="Input scan file (Nmap/Nessus/Qualys)")
    p.add_argument("-o", "--output", default="vulnerability_report.csv", help="Output CSV filename")
    p.add_argument("-g", "--group-by", choices=['host', 'cve'], default='host', help="Group rows by host or CVE")
    p.add_argument("-T", "--token", help="GitHub Token for PoC lookup")
    p.add_argument("-N", "--nvd-key", help="NVD API Key")
    args = p.parse_args()
    if not os.path.exists(args.file): print(f"[!] File not found: {args.file}"); return
    generate_report(args.file, args.output, args.group_by, args.token, args.nvd_key)

if __name__ == "__main__": main()
