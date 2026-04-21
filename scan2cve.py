#!/usr/bin/env python3
"""
Scan2CVE: Unified scanner parser (Nmap, Nessus, Qualys) to extract CVEs for cve_lookup.py integration.
"""

import sys
import os

# Suppress GLib-GIO warnings
os.environ["GIO_USE_VFS"] = "local"
if "G_MESSAGES_DEBUG" not in os.environ:
    os.environ["G_MESSAGES_DEBUG"] = "none"

import requests
import argparse
import time
import xml.etree.ElementTree as ET
import logging
import csv
import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Set

# Configuration Constants
USER_AGENT = "Scan2CVE-Tool/1.0 (Unified Parser)"
NVD_API_DELAY = 0.6  # Seconds between NVD API calls (accelerated with key)

# Global rate limiting state for NVD API
nvd_api_lock = threading.Lock()
last_nvd_api_call = [0.0]

# Setup Logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

class Colors:
    RED = '\033[91m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'

def colorize(text: str, color_code: str, use_colors: bool) -> str:
    if not use_colors: return str(text)
    return f"{color_code}{text}{Colors.END}"

def is_ip(string: str) -> bool:
    """Check if a string is a valid IPv4 address."""
    if not string: return False
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", string))

def is_broad_cpe(cpe: str) -> bool:
    """
    Check if a CPE is too broad (lacks a specific version).
    E.g., 'cpe:/a:adobe:acrobat_reader' matches everything if not versioned.
    """
    parts = cpe.split(':')
    if len(parts) < 5:
        return True
    version = parts[4]
    if not version or version in ['-', '*']:
        return True
    return False

class BaseParser:
    def __init__(self, file_path: str, use_colors: bool = True):
        self.file_path = file_path
        self.use_colors = use_colors
        self.hosts = {} # Structure: { host_id: { "hostname": ..., "ip": ..., "services": [...] } }

    def parse(self):
        raise NotImplementedError("Subclasses must implement parse()")

class NmapParser(BaseParser):
    def __init__(self, file_path: str, session: requests.Session, use_colors: bool = True):
        super().__init__(file_path, use_colors)
        self.session = session

    def get_cves_for_cpe(self, cpe: str, nvd_key: str = None) -> List[str]:
        if cpe.startswith("cpe:/"):
            cpe = cpe.replace("cpe:/", "cpe:2.3:")
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {"virtualMatchString": cpe}
        headers = {'User-Agent': USER_AGENT}
        if nvd_key:
            headers['X-ApiKey'] = nvd_key

        # Thread-safe NVD Rate Limiting
        # Without key: 5 requests / 30s (~6s delay)
        # With key: 50 requests / 30s (~0.6s delay)
        with nvd_api_lock:
            now = time.time()
            elapsed = now - last_nvd_api_call[0]
            delay = 0.65 if nvd_key else 6.5
            if elapsed < delay:
                time.sleep(delay - elapsed)
            last_nvd_api_call[0] = time.time()

        try:
            resp = self.session.get(url, params=params, headers=headers, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                return [v['cve']['id'] for v in data.get('vulnerabilities', []) if 'cve' in v]
            elif resp.status_code == 403:
                print(colorize(f"\n  [!] NVD Rate Limit (403). Use an API key for higher limits.", Colors.RED, self.use_colors))
        except Exception as e:
            logger.debug(f"NVD API Error for {cpe}: {e}")
        return []

    def parse(self):
        try:
            tree = ET.parse(self.file_path)
            root = tree.getroot()
            for host_node in root.findall('host'):
                addr_tag = host_node.find('address')
                raw_addr = addr_tag.get('addr') if addr_tag is not None else ""
                
                # Logic: If it's an IP, use it. If not, it's a hostname.
                ip = ""
                hostname = ""
                
                if is_ip(raw_addr):
                    ip = raw_addr
                else:
                    hostname = raw_addr
                
                # Check for explicit hostname nodes
                hostname_node = host_node.find('.//hostname')
                if hostname_node is not None:
                    name = hostname_node.get('name', '')
                    if name: hostname = name

                host_id = raw_addr or ip or hostname or "Unknown"
                if host_id not in self.hosts:
                    self.hosts[host_id] = {"ip": ip, "hostname": hostname, "services": []}
                ports_tag = host_node.find('ports')
                if ports_tag is None: continue
                for port_node in ports_tag.findall('port'):
                    service_tag = port_node.find('service')
                    if service_tag is not None:
                        cpes = [c.text for c in service_tag.findall('cpe')]
                        if not cpes: continue
                        service_info = {
                            "port": port_node.get('portid'), "proto": port_node.get('protocol'),
                            "name": f"{service_tag.get('product', service_tag.get('name', 'unknown'))} {service_tag.get('version', '')}".strip(),
                            "cpes": cpes, "cves": set()
                        }
                        self.hosts[host_id]["services"].append(service_info)
        except Exception as e: print(f"Error parsing Nmap XML: {e}")

class NessusXMLParser(BaseParser):
    def parse(self):
        try:
            tree = ET.parse(self.file_path)
            root = tree.getroot()
            for host_node in root.findall('.//ReportHost'):
                name = host_node.get('name')
                ip = name if is_ip(name) else ""
                hostname = ""
                tag_ip = host_node.find('.//tag[@name="host-ip"]')
                if tag_ip is not None and not ip: ip = tag_ip.text
                tag_fqdn = host_node.find('.//tag[@name="host-fqdn"]')
                if tag_fqdn is not None: hostname = tag_fqdn.text
                if not hostname and not is_ip(name): hostname = name
                
                # Final check: if 'ip' field contains something that is not an IP, move it to hostname
                if ip and not is_ip(ip):
                    if not hostname: hostname = ip
                    ip = ""

                host_id = name or ip or hostname
                if host_id not in self.hosts: self.hosts[host_id] = {"ip": ip, "hostname": hostname, "services": []}
                service_map = {}
                for item in host_node.findall('ReportItem'):
                    port, proto, svc_name = item.get('port'), item.get('protocol'), item.get('svc_name')
                    key = (port, proto, svc_name)
                    if key not in service_map: service_map[key] = set()
                    for cve in item.findall('cve'): service_map[key].add(cve.text)
                for (port, proto, svc_name), cves in service_map.items():
                    if cves: self.hosts[host_id]["services"].append({"port": port, "proto": proto, "name": svc_name, "cves": cves})
        except Exception as e: print(f"Error parsing Nessus XML: {e}")

class NessusCSVParser(BaseParser):
    def parse(self):
        try:
            with open(self.file_path, mode='r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                service_map, host_data = {}, {}
                for row in reader:
                    raw_host = row.get('Host') or row.get('IP Address')
                    if not raw_host: continue
                    ip = raw_host if is_ip(raw_host) else ""
                    hostname = row.get('FQDN') or row.get('DNS Name') or ""
                    if not hostname and not is_ip(raw_host): hostname = raw_host
                    if ip and not is_ip(ip):
                        if not hostname: hostname = ip
                        ip = ""
                    if raw_host not in host_data: host_data[raw_host] = {"ip": ip, "hostname": hostname}
                    port, proto, svc_name, cve = row.get('Port'), row.get('Protocol'), row.get('Name'), row.get('CVE')
                    key = (raw_host, port, proto, svc_name)
                    if key not in service_map: service_map[key] = set()
                    if cve:
                        for c in cve.split(','):
                            c = c.strip()
                            if c: service_map[key].add(c)
                for (host_id, port, proto, svc_name), cves in service_map.items():
                    if host_id not in self.hosts: self.hosts[host_id] = {"ip": host_data[host_id]["ip"], "hostname": host_data[host_id]["hostname"], "services": []}
                    if cves: self.hosts[host_id]["services"].append({"port": port, "proto": proto, "name": svc_name, "cves": cves})
        except Exception as e: print(f"Error parsing Nessus CSV: {e}")

class QualysXMLParser(BaseParser):
    def parse(self):
        try:
            tree = ET.parse(self.file_path)
            root = tree.getroot()
            ips = root.findall('.//IP') or root.findall('.//ASSET')
            for asset in ips:
                val = asset.get('value') or asset.findtext('IP_ADDRESS')
                if not val: continue
                ip = val if is_ip(val) else ""
                hostname = asset.get('name') or asset.findtext('DNS') or asset.findtext('DNS_NAME') or ""
                if not hostname and not is_ip(val): hostname = val
                if ip and not is_ip(ip):
                    if not hostname: hostname = ip
                    ip = ""
                if val not in self.hosts: self.hosts[val] = {"ip": ip, "hostname": hostname, "services": []}
                for cat in asset.findall('.//CAT'):
                    port, proto, svc_name = cat.get('port'), cat.get('protocol'), cat.get('value')
                    for vuln in cat.findall('VULN'):
                        cves = set()
                        cve_attr = vuln.get('cveid')
                        if cve_attr:
                            for c in cve_attr.split(','): cves.add(c.strip())
                        cve_list = vuln.find('CVE_ID_LIST')
                        if cve_list is not None:
                            for cve_id_node in cve_list.findall('CVE_ID'): cves.add(cve_id_node.findtext('ID'))
                        if cves: self.hosts[val]["services"].append({"port": port or "0", "proto": proto or "tcp", "name": svc_name or "unknown", "cves": cves})
                for vuln in asset.findall('./VULN_LIST/VULN') or asset.findall('.//VULN'):
                    if any(s for s in self.hosts[val]["services"] if vuln in asset.findall('.//CAT/VULN')): continue
                    port, proto, svc_name = vuln.findtext('PORT'), vuln.findtext('PROTOCOL'), vuln.findtext('SERVICE')
                    cves = set()
                    cve_list = vuln.find('CVE_ID_LIST')
                    if cve_list is not None:
                        for cve_id_node in cve_list.findall('CVE_ID'): cves.add(cve_id_node.findtext('ID'))
                    if cves: self.hosts[val]["services"].append({"port": port or "0", "proto": proto or "tcp", "name": svc_name or "unknown", "cves": cves})
        except Exception as e: print(f"Error parsing Qualys XML: {e}")

class QualysCSVParser(BaseParser):
    def parse(self):
        try:
            with open(self.file_path, mode='r', encoding='utf-8-sig') as f:
                lines = f.readlines()
                header_index = -1
                for i, line in enumerate(lines):
                    if '"IP"' in line and '"Port"' in line and '"CVE ID"' in line: header_index = i; break
                    if 'IP,' in line and 'Port,' in line and 'CVE ID' in line: header_index = i; break
                if header_index == -1:
                    for i, line in enumerate(lines):
                        if 'IP' in line and 'Port' in line and 'CVE ID' in line: header_index = i; break
                if header_index == -1: print(f"[!] Could not find header in Qualys CSV: {self.file_path}"); return
                reader = csv.DictReader(lines[header_index:])
                service_map, host_data = {}, {}
                for row in reader:
                    val = row.get('IP')
                    if not val: continue
                    ip = val if is_ip(val) else ""
                    hostname = row.get('DNS') or row.get('FQDN') or ""
                    if not hostname and not is_ip(val): hostname = val
                    if ip and not is_ip(ip):
                        if not hostname: hostname = ip
                        ip = ""
                    if val not in host_data: host_data[val] = {"ip": ip, "hostname": hostname}
                    port, proto, svc_name, cve = row.get('Port'), row.get('Protocol'), row.get('Title') or row.get('Service'), row.get('CVE ID')
                    key = (val, port, proto, svc_name)
                    if key not in service_map: service_map[key] = set()
                    if cve:
                        for c in cve.split(','):
                            c = c.strip()
                            if c: service_map[key].add(c)
                for (val, port, proto, svc_name), cves in service_map.items():
                    if val not in self.hosts: self.hosts[val] = {"ip": host_data[val]["ip"], "hostname": host_data[val]["hostname"], "services": []}
                    if cves: self.hosts[val]["services"].append({"port": port or "0", "proto": proto or "tcp", "name": svc_name or "unknown", "cves": cves})
        except Exception as e: print(f"Error parsing Qualys CSV: {e}")

def detect_scanner(file_path):
    ext = os.path.splitext(file_path)[1].lower()
    if ext == '.nessus': return 'nessus_xml'
    if ext == '.xml':
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                head = f.read(2048)
                if '<nmaprun' in head: return 'nmap_xml'
                if '<NessusClientData_v2' in head: return 'nessus_xml'
                if '<QUALYS' in head or '<SCAN' in head or '<ASSET_DATA_REPORT' in head: return 'qualys_xml'
        except: pass
    if ext == '.csv':
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                head = f.read(2048)
                if 'Plugin ID' in head and 'CVE' in head: return 'nessus_csv'
                if 'IP' in head and 'CVE ID' in head: return 'qualys_csv'
        except: pass
    return None

def main():
    parser = argparse.ArgumentParser(description="Scan2CVE - Unified CVE Discovery (Nmap, Nessus, Qualys)")
    parser.add_argument("file", help="Scanner output file (XML, .nessus, or CSV)")
    parser.add_argument("-t", "--type", choices=['nmap_xml', 'nessus_xml', 'nessus_csv', 'qualys_xml', 'qualys_csv'], help="Force scanner type (auto-detected by default)")
    parser.add_argument("-o", "--output", help="Save discovered CVE IDs to a text file")
    parser.add_argument("-n", "--no-color", action="store_true", help="Disable terminal colors")
    args = parser.parse_args()
    use_colors = not args.no_color and sys.stdout.isatty()
    if not os.path.exists(args.file): print(f"[!] File not found: {args.file}"); return
    scanner_type = args.type or detect_scanner(args.file)
    if not scanner_type: print(f"[!] Could not detect scanner type for {args.file}. Use -t to specify."); return
    print(f"[*] Detected type: {scanner_type}")
    session = requests.Session()
    if scanner_type == 'nmap_xml': p = NmapParser(args.file, session, use_colors)
    elif scanner_type == 'nessus_xml': p = NessusXMLParser(args.file, use_colors)
    elif scanner_type == 'nessus_csv': p = NessusCSVParser(args.file, use_colors)
    elif scanner_type == 'qualys_xml': p = QualysXMLParser(args.file, use_colors)
    elif scanner_type == 'qualys_csv': p = QualysCSVParser(args.file, use_colors)
    else: print("[!] Unsupported scanner type."); return
    p.parse()
    if not p.hosts: print("[!] No scan data found or parsing failed."); return
    # Analysis
    global_cves = set()
    nvd_key = os.getenv("NVD_API_KEY")
    print(f"[*] Analyzing {len(p.hosts)} hosts...\n")

    # Step 1: Collect unique valid CPEs for concurrent lookup
    unique_valid_cpes = set()
    if scanner_type == 'nmap_xml':
        for val, data in p.hosts.items():
            for s in data["services"]:
                for cpe in s.get('cpes', []):
                    if not is_broad_cpe(cpe):
                        unique_valid_cpes.add(cpe)
                    else:
                        logger.debug(f"Skipping broad CPE: {cpe}")

        print(f"[*] Fetching CVEs for {len(unique_valid_cpes)} unique specific CPEs...")
        cpe_to_cves = {}
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(p.get_cves_for_cpe, cpe, nvd_key): cpe for cpe in unique_valid_cpes}
            for f in as_completed(futures):
                cpe = futures[f]
                try:
                    cpe_to_cves[cpe] = f.result()
                except Exception as e:
                    print(f"  [!] Error fetching {cpe}: {e}")
                    cpe_to_cves[cpe] = []

    # Step 2: Display results
    for val, data in sorted(p.hosts.items()):
        if not data["services"]: continue
        h_info = []
        if data['ip']: h_info.append(data['ip'])
        if data['hostname']: h_info.append(data['hostname'])
        print(f"[{colorize(' / '.join(h_info) or val, Colors.BLUE, use_colors)}]")
        for s in data["services"]:
            port_proto = f"{s['port']}/{s['proto']}" if s['port'] != "0" else "Host-level"
            print(f"  └─ {port_proto} ({s['name']}):", end=" ", flush=True)
            if scanner_type == 'nmap_xml':
                service_cve_ids = []
                for cpe in s.get('cpes', []):
                    if cpe in cpe_to_cves:
                        service_cve_ids.extend(cpe_to_cves[cpe])
                s['cves'] = set(service_cve_ids)
            unique_ids = sorted(list(s['cves']))
            if unique_ids:
                print(f"{colorize(len(unique_ids), Colors.GREEN, use_colors)} CVEs found.")
                for cid in unique_ids[:3]: print(f"     - {cid}")
                if len(unique_ids) > 3: print(f"     - ... and {len(unique_ids)-3} more.")
                global_cves.update(unique_ids)
            else: print("No CVEs.")
        print()
    if args.output:
        try:
            with open(args.output, 'w') as f:
                for cve in sorted(list(global_cves)): f.write(f"{cve}\n")
            print(f"[+] Saved {len(global_cves)} unique CVEs to {args.output}")
        except Exception as e: print(f"[!] Error saving output: {e}")

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: print("\n[!] Interrupted."); sys.exit(0)
