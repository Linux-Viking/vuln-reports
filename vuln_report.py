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

from concurrent.futures import ThreadPoolExecutor, as_completed

def get_detailed_cve_info(cve_ids: List[str], github_token: str = None, nvd_key: str = None) -> Dict[str, Dict[str, Any]]:
    """Fetch details for a list of CVEs using cve_lookup logic with concurrency."""
    session = requests.Session()
    cve_details = {}
    print(f"[*] Fetching enrichment data for {len(cve_ids)} unique CVEs...")
    
    max_workers = 10
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(cve_lookup.get_cve_data, session, cve_id, github_token, nvd_key): cve_id for cve_id in cve_ids}
        for future in as_completed(futures):
            cve_id = futures[future]
            try:
                data = future.result()
                if "error" not in data:
                    cve_details[cve_id] = data
                else:
                    print(f"  [!] Error enriching {cve_id}: {data['error']}")
                    cve_details[cve_id] = {"cve_id": cve_id, "error": data["error"]}
            except Exception as e:
                print(f"  [!] Exception enriching {cve_id}: {e}")
                cve_details[cve_id] = {"cve_id": cve_id, "error": str(e)}
    return cve_details

from datetime import datetime

try:
    from jinja2 import Environment, FileSystemLoader
    HAS_JINJA = True
except ImportError:
    HAS_JINJA = False

try:
    from weasyprint import HTML
    HAS_WEASYPRINT = True
except ImportError:
    HAS_WEASYPRINT = False

def save_markdown_report(vulnerabilities, cve_to_hosts, scanner_type, target_file, output_file):
    if not HAS_JINJA: return
    
    # Calculate statistics
    stats = {
        "total_hosts": len(set(h[0] for hosts in cve_to_hosts.values() for h in hosts)),
        "total_cves": len(vulnerabilities),
        "critical_count": sum(1 for v in vulnerabilities.values() if isinstance(v.get('cvss_score'), (int, float)) and v['cvss_score'] >= 9),
        "kev_count": sum(1 for v in vulnerabilities.values() if v.get('cisa_kev') == 'Yes')
    }

    try:
        env = Environment(loader=FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')))
        template = env.get_template('report_template.md')
        
        # Sort vulnerabilities by CVSS score descending
        def get_score(v):
            s = v.get('cvss_score', 0)
            return float(s) if s != 'N/A' else 0

        sorted_vulns = dict(sorted(vulnerabilities.items(), key=lambda x: get_score(x[1]), reverse=True))

        md_out = template.render(
            vulnerabilities=sorted_vulns,
            cve_to_hosts=cve_to_hosts,
            stats=stats,
            date=datetime.now().strftime("%Y-%m-%d %H:%M"),
            scanner_type=scanner_type,
            target_file=os.path.basename(target_file)
        )
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(md_out)
        print(f"[+] Markdown report saved to: {output_file}")
    except Exception as e:
        print(f"[!] Error generating Markdown report: {e}")

def save_pdf_report(vulnerabilities, cve_to_hosts, scanner_type, target_file, output_file):
    if not HAS_WEASYPRINT or not HAS_JINJA:
        print("[!] WeasyPrint or Jinja2 not installed. PDF report skipped.")
        return

    # Generate HTML first (temporarily or in memory)
    stats = {
        "total_hosts": len(set(h[0] for hosts in cve_to_hosts.values() for h in hosts)),
        "total_cves": len(vulnerabilities),
        "critical_count": sum(1 for v in vulnerabilities.values() if isinstance(v.get('cvss_score'), (int, float)) and v['cvss_score'] >= 9),
        "kev_count": sum(1 for v in vulnerabilities.values() if v.get('cisa_kev') == 'Yes')
    }

    try:
        env = Environment(loader=FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')))
        template = env.get_template('report_template.html')
        
        def get_score(v):
            s = v.get('cvss_score', 0)
            return float(s) if s != 'N/A' else 0

        sorted_vulns = dict(sorted(vulnerabilities.items(), key=lambda x: get_score(x[1]), reverse=True))

        html_out = template.render(
            vulnerabilities=sorted_vulns,
            cve_to_hosts=cve_to_hosts,
            stats=stats,
            date=datetime.now().strftime("%Y-%m-%d %H:%M"),
            scanner_type=scanner_type,
            target_file=os.path.basename(target_file)
        )
        
        HTML(string=html_out).write_pdf(output_file)
        print(f"[+] PDF intelligence report saved to: {output_file}")
    except Exception as e:
        print(f"[!] Error generating PDF report: {e}")

def save_html_report(vulnerabilities, cve_to_hosts, scanner_type, target_file, output_file):
    if not HAS_JINJA:
        print("[!] Jinja2 not installed. HTML report skipped.")
        return

    # Calculate statistics
    stats = {
        "total_hosts": len(set(h[0] for hosts in cve_to_hosts.values() for h in hosts)),
        "total_cves": len(vulnerabilities),
        "critical_count": sum(1 for v in vulnerabilities.values() if isinstance(v.get('cvss_score'), (int, float)) and v['cvss_score'] >= 9),
        "kev_count": sum(1 for v in vulnerabilities.values() if v.get('cisa_kev') == 'Yes')
    }

    try:
        env = Environment(loader=FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')))
        template = env.get_template('report_template.html')
        
        # Sort vulnerabilities by CVSS score descending
        def get_score(v):
            s = v.get('cvss_score', 0)
            return float(s) if s != 'N/A' else 0

        sorted_vulns = dict(sorted(vulnerabilities.items(), key=lambda x: get_score(x[1]), reverse=True))

        html_out = template.render(
            vulnerabilities=sorted_vulns,
            cve_to_hosts=cve_to_hosts,
            stats=stats,
            date=datetime.now().strftime("%Y-%m-%d %H:%M"),
            scanner_type=scanner_type,
            target_file=os.path.basename(target_file)
        )
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_out)
        print(f"[+] HTML intelligence report saved to: {output_file}")
    except Exception as e:
        print(f"[!] Error generating HTML report: {e}")

def generate_report(scan_file: str, output_file: str, group_by: str, github_token: str = None, nvd_key: str = None, html_file: str = None, md_file: str = None, pdf_file: str = None):
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
        "Affected Products", "Remediation", "References"
    ]

    # Prepare host mapping for reporting
    cve_to_hosts = {}
    for _, host_data in parser.hosts.items():
        ip, hostname = host_data.get('ip', ''), host_data.get('hostname', '')
        for s in host_data["services"]:
            port_proto = f"{s['port']}/{s['proto']}" if s['port'] != "0" else "Host-level"
            for cve_id in s['cves']:
                if cve_id not in cve_to_hosts: cve_to_hosts[cve_id] = []
                cve_to_hosts[cve_id].append((ip, hostname, port_proto, s['name']))

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
                                d.get('remediation', 'N/A'),
                                "; ".join(d.get('references', []))
                            ])
            else: # group by cve
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
                            d.get('remediation', 'N/A'),
                            "; ".join(d.get('references', []))
                        ])
        print(f"[+] Detailed report saved to: {output_file}")
        
        if html_file:
            save_html_report(cve_enrichment, cve_to_hosts, scanner_type, scan_file, html_file)
        if md_file:
            save_markdown_report(cve_enrichment, cve_to_hosts, scanner_type, scan_file, md_file)
        if pdf_file:
            save_pdf_report(cve_enrichment, cve_to_hosts, scanner_type, scan_file, pdf_file)
            
    except Exception as e: print(f"[!] Error writing CSV: {e}")

def main():
    p = argparse.ArgumentParser(description="VulnReport - Unified Scan Reporting Tool")
    p.add_argument("file", help="Input scan file (Nmap/Nessus/Qualys)")
    p.add_argument("-o", "--output", default="vulnerability_report.csv", help="Output CSV filename")
    p.add_argument("-H", "--html", help="Output HTML report filename")
    p.add_argument("-M", "--markdown", help="Output Markdown report filename")
    p.add_argument("-P", "--pdf", help="Output PDF report filename")
    p.add_argument("-g", "--group-by", choices=['host', 'cve'], default='host', help="Group rows by host or CVE")
    p.add_argument("-T", "--token", help="GitHub Token for PoC lookup")
    p.add_argument("-N", "--nvd-key", help="NVD API Key")
    args = p.parse_args()
    if not os.path.exists(args.file): print(f"[!] File not found: {args.file}"); return
    generate_report(args.file, args.output, args.group_by, args.token, args.nvd_key, args.html, args.markdown, args.pdf)

if __name__ == "__main__": main()
