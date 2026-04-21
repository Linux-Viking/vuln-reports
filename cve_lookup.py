#!/usr/bin/env python3
import sys
import os

# Suppress GLib-GIO warnings on Windows (e.g., UWP app extension/verb warnings)
if os.name == 'nt':
    os.environ["GIO_USE_VFS"] = "local"

import json
import csv
import requests
import argparse
import re
import time
import os
import keyring
import getpass
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

# Constants
VERSION = "2.2.1"
CVE_REGEX = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
DEFAULT_TIMEOUT = 10
MAX_WORKERS = 10 

# ANSI Colors
class Colors:
    RED = '\033[91m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

print_lock = Lock()
nvd_lock = Lock()
last_nvd_call = [0.0]

def colorize(text: str, color_code: str, use_colors: bool) -> str:
    if not use_colors: return text
    return f"{color_code}{text}{Colors.END}"

def validate_cve_id(cve_id: str) -> bool:
    return bool(CVE_REGEX.match(cve_id))

def csv_safe(value: Any) -> str:
    val = str(value)
    if val.startswith(('=', '+', '-', '@')): return f"'{val}"
    return val

def get_config_dir() -> Path:
    if os.name == 'nt':
        return Path(os.environ.get('APPDATA', '~')).expanduser() / 'cve-lookup'
    return Path.home() / '.config' / 'cve-lookup'

def get_poc_from_github(session: requests.Session, cve_id: str, github_token: Optional[str]) -> Optional[str]:
    queries = [f'"{cve_id}"', f'"{cve_id.replace("CVE-", "")}"']
    headers = {'Accept': 'application/vnd.github.v3+json', 'User-Agent': USER_AGENT}
    token_to_use = github_token.strip() if github_token else None
    
    for q in queries:
        current_headers = headers.copy()
        if token_to_use: current_headers['Authorization'] = f'Bearer {token_to_use}'
        try:
            params = {'q': f"{q} exploit OR poc", 'sort': 'stars', 'order': 'desc'}
            resp = session.get("https://api.github.com/search/repositories", headers=current_headers, params=params, timeout=5)
            if resp.status_code in [401, 403] and token_to_use:
                resp = session.get("https://api.github.com/search/repositories", headers=headers, params=params, timeout=5)
            if resp.status_code == 200:
                results = resp.json()
                if results.get('total_count', 0) > 0:
                    for item in results['items']:
                        name = item.get('name', '').lower()
                        desc = (item.get('description', '') or "").lower()
                        
                        # Filter out analysis, scanners, and checkers
                        exclude_keywords = ['analysis', 'scanner', 'checker', 'detect', 'nuclei', 'overview']
                        if any(k in name or k in desc for k in exclude_keywords):
                            continue
                            
                        if cve_id.lower() in name or cve_id.lower() in desc:
                            return item.get('html_url')
            elif resp.status_code == 403: break
        except requests.RequestException: continue
    return None

def normalize_text(text: Any) -> str:
    if not text or not isinstance(text, str): return str(text) if text is not None else "N/A"
    text = text.replace('\u00a0', ' ').replace('\\n', ' ')
    return re.sub(r'\s+', ' ', text).strip()

def get_cve_data(session: requests.Session, cve_id: str, github_token: Optional[str], nvd_key: Optional[str] = None) -> Dict[str, Any]:
    if not validate_cve_id(cve_id): return {"cve_id": cve_id, "error": f"Invalid format: {cve_id}"}
    circl_url = f"https://cve.circl.lu/api/cve/{cve_id}"
    epss_url = "https://api.first.org/data/v1/epss"
    headers = {'User-Agent': USER_AGENT}
    
    max_retries = 3
    circl_data = None
    for attempt in range(max_retries):
        try:
            circl_resp = session.get(circl_url, headers=headers, timeout=DEFAULT_TIMEOUT)
            circl_resp.raise_for_status()
            circl_data = circl_resp.json()
            break
        except Exception as e:
            if attempt == max_retries - 1: return {"cve_id": cve_id, "error": str(e)}
            time.sleep(1)

    epss_data = {}
    try:
        epss_resp = session.get(epss_url, headers=headers, params={'cve': cve_id}, timeout=DEFAULT_TIMEOUT)
        if epss_resp.status_code == 200: epss_data = epss_resp.json()
    except Exception: pass

    if not circl_data: return {"cve_id": cve_id, "error": "Not found"}

    containers = circl_data.get('containers', {})
    cna = containers.get('cna', {})
    adp_list = containers.get('adp', [])
    
    title = cna.get('title')
    if not title:
        for adp in adp_list:
            adp_title = adp.get('title', '')
            if adp_title and "ADP" not in adp_title.upper() and "CVE Program" not in adp_title:
                title = adp_title; break
    
    description = normalize_text(cna.get('descriptions', [{}])[0].get('value', 'N/A'))
    affected_raw = cna.get('affected', [])
    product = affected_raw[0].get('product', '') if affected_raw else ''
    if product.lower() in ['n/a', 'unknown', 'none', '']: product = ''

    # Fallback product detection from description if missing
    detected_products = []
    
    # Pre-check for common high-value products
    if "openssh" in description.lower():
        product = "OpenSSH"; detected_products = ["OpenSSH"]
    elif "apache http server" in description.lower() or "httpd" in description.lower():
        product = "Apache HTTP Server"; detected_products = ["Apache HTTP Server"]
    
    if not product:
        # 1. Try matching at the start of the description
        multi_match = re.match(r"^([A-Z][a-zA-Z0-9]+(?:\s+[A-Z][a-zA-Z0-9]+)*(?:,\s+[A-Z][a-zA-Z0-9]+(?:\s+[A-Z][a-zA-Z0-9]+)*)*)", description)
        if multi_match:
            products_str = multi_match.group(1)
            detected_products = [p.strip() for p in re.split(r",| and ", products_str) if p.strip()]
            product = detected_products[0] if detected_products else ''
        
        if not product or product.lower() in ['the', 'in', 'an', 'a']:
            pm = re.search(r"(?:discovered in|\bin\b|\bat\b|\bof\b) ([A-Z][a-zA-Z0-9]+(?:\s+[A-Z][a-zA-Z0-9]+)*)", description)
            if pm:
                product = pm.group(1).strip()
                detected_products = [product]
            elif "owncloud" in description.lower():
                product = "ownCloud"; detected_products = [product]
            elif "log4j" in description.lower():
                product = "Apache Log4j"; detected_products = [product]

    # Clean product name from noise
    def clean_noise(text):
        if not text: return ""
        prev = ""
        while text != prev:
            prev = text
            text = re.sub(r"^(?:the|in|an|a|at|of|on|issue was discovered in|multiple|use-after-free vulnerability in|vulnerability in)\s+", "", text, flags=re.IGNORECASE).strip()
        return text

    product = clean_noise(product)
    
    # Validation: Products should generally not be just common verbs or descriptors
    noise_words = ['issue', 'use', 'vulnerability', 'multiple', 'all', 'certain', 'use-after-free', 'an', 'the']
    if product.lower() in noise_words:
        product = ""

    detected_products = [clean_noise(p) for p in detected_products if clean_noise(p)]
    detected_products = [p for p in detected_products if p.lower() not in noise_words]
    
    if not product and detected_products: product = detected_products[0]

    # Enhanced Title Logic
    aka_match = re.search(r"aka a? ([A-Z][a-zA-Z0-9\s\-]+?)(?:\s+attack|\.|$)", description, re.IGNORECASE)
    aka_title = aka_match.group(1).strip() if aka_match else None
    
    generic_vulns = [
        "information disclosure", "remote code execution", "command injection", "cross-site scripting", 
        "buffer overflow", "denial of service", "privilege escalation", "sql injection", "path traversal", 
        "directory traversal", "authentication bypass", "incorrect authorization", "input validation", 
        "cross-site request forgery", "csrf", "xss", "rce", "use-after-free", "user enumeration",
        "impersonation", "crlf injection", "side-channel", "race condition", "memory corruption"
    ]
    
    # Try to extract a vulnerability type from the description
    vuln_type = None
    for gv in generic_vulns:
        if gv in description.lower():
            vuln_type = gv.title()
            if len(vuln_type) <= 4: vuln_type = vuln_type.upper() # CSRF, XSS, RCE
            break
    
    if not vuln_type:
        # Try to extract what the attacker can do or what is broken
        # Matches: "allows ... to [action]", "mishandles [feature]", "is vulnerable to [type]", "Due to [reason]"
        patterns = [
            r"allows (?:remote )?attackers to ([^,\.\(;]+)",
            r"mishandles ([^,\.\(;]+)",
            r"is vulnerable to ([^,\.\(;]+)",
            r"could allow (?:remote )?attackers to ([^,\.\(;]+)",
            r"due to ([^,\.\(;]+)",
            r"lacks ([^,\.\(;]+)",
            r"provides ([^,\.\(;]+)",
            r"creates ([^,\.\(;]+)",
            r"triggering ([^,\.\(;]+)",
            r"allows ([^,\.\(;]+)"
        ]
        for pattern in patterns:
            action_match = re.search(pattern, description, re.IGNORECASE)
            if action_match:
                action = action_match.group(1).strip()
                vuln_type = action.capitalize()
                break
    # Try to get a clean CWE title as a secondary fallback
    cwe_title = None
    all_problem_types = cna.get('problemTypes', []) + [pt for adp in adp_list for pt in adp.get('problemTypes', [])]
    for pt in all_problem_types:
        for desc in pt.get('descriptions', []):
            if desc.get('lang') == 'en' and desc.get('description') and desc.get('description').lower() != "n/a":
                cwe_title = re.sub(r'^CWE-\d+\s+', '', desc.get('description'), flags=re.IGNORECASE)
                break
        if cwe_title: break

    current_title = normalize_text(title)
    if not title or current_title == "N/A" or any(gv in current_title.lower() for gv in generic_vulns):
        # Generate a better title
        if product:
            base = product
            detail = aka_title or vuln_type or (current_title if current_title != "N/A" else None) or cwe_title
            
            # If description starts with "FILE.c in SERVICE", use that as detail
            file_match = re.match(r"^([a-zA-Z0-9_\-\./]+\.[a-z]{1,4}(?:\s+in\s+[a-zA-Z0-9_\-]+)?)", description)
            if file_match and not aka_title:
                detail = file_match.group(1)

            if detail:
                detail = clean_noise(detail)
                if detail.lower() in base.lower(): current_title = base
                else: current_title = f"{base}: {detail}"
            else:
                current_title = f"Vulnerability in {base}"
        elif aka_title:
            current_title = aka_title
        elif vuln_type:
            current_title = vuln_type
        elif cwe_title:
            current_title = cwe_title
    
    affected_structured = []
    if not affected_raw or (len(affected_raw) == 1 and affected_raw[0].get('product', '').lower() in ['n/a', '']):
        if detected_products:
            # ... (extract versions logic)
            # Ensure detected products are also cleaned
            for i in range(len(detected_products)):
                if detected_products[i].lower().startswith('in '):
                    detected_products[i] = detected_products[i][3:].strip()
            
            # Try to extract versions from description: "X.Y before Z.W" or "X.Y through Z.W"
            all_versions = re.findall(r"(\d+(?:\.\d+)* (?:before|through) (?:build )?\d+(?:\.\d+)*)", description)
            if not all_versions:
                all_versions = re.findall(r"v(?:ersion)?\s?(\d+(?:\.\d+)*)", description)
            
            for p in detected_products:
                p_versions = ["N/A"]
                if all_versions:
                    p_versions = all_versions
                elif "SDK" in description or "software development kit" in description.lower():
                    p_versions = ["SDK (All Versions)"]
                
                affected_structured.append({
                    "vendor": "Unknown", 
                    "product": p, 
                    "versions": p_versions
                })
        elif product:
            affected_structured.append({"vendor": "Unknown", "product": product, "versions": ["N/A"]})
    
    if not affected_structured:
        for a in affected_raw:
            versions = []
            for v in a.get('versions', []):
                if v.get('status') == 'unaffected': continue
                ver = v.get('version', 'N/A')
                lt = v.get('lessThan')
                ltoe = v.get('lessThanOrEqual')
                if lt and lt != 'n/a':
                    ver = f"{ver} to <{lt}"
                elif ltoe and ltoe != 'n/a':
                    ver = f"{ver} to {ltoe}"
                versions.append(ver)
            
            if not versions: versions = ["N/A"]
            affected_structured.append({
                "vendor": a.get('vendor', 'Unknown'),
                "product": a.get('product', 'Unknown'),
                "versions": versions
            })

    cvss_score, attack_complexity, user_interaction = "N/A", "N/A", "N/A"
    all_metrics = cna.get('metrics', []) + [m for adp in adp_list for m in adp.get('metrics', [])]
    
    # Prioritize CVSS v4.0 -> v3.1 -> v3.0, using ADP (CVE.org) as a fallback
    for version in ['cvssV4_0', 'cvssV3_1', 'cvssV3_0']:
        for m in all_metrics:
            v = m.get(version)
            if v and cvss_score == "N/A":
                cvss_score = v.get('baseScore', "N/A")
                attack_complexity = v.get('attackComplexity', "N/A")
                user_interaction = v.get('userInteraction', "N/A")
        if cvss_score != "N/A": break

    # NVD Fallback for older CVEs
    if cvss_score == "N/A":
        max_retries = 3
        for attempt in range(max_retries):
            # Optimized thread-safe rate limiting
            with nvd_lock:
                now = time.time()
                elapsed = now - last_nvd_call[0]
                delay = 0.65 if nvd_key else 6.5
                if elapsed < delay:
                    time.sleep(delay - elapsed)
                last_nvd_call[0] = time.time()

            try:
                nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
                headers_nvd = {'User-Agent': USER_AGENT}
                if nvd_key: headers_nvd['X-ApiKey'] = nvd_key
                
                req = urllib.request.Request(nvd_url, headers=headers_nvd)
                with urllib.request.urlopen(req, timeout=15) as nvd_resp:
                    code = nvd_resp.getcode()
                    if code == 200:
                        nvd_data = json.loads(nvd_resp.read().decode())
                        vulnerabilities = nvd_data.get('vulnerabilities', [])
                        if vulnerabilities:
                            metrics = vulnerabilities[0].get('cve', {}).get('metrics', {})
                            for m_type in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                                m_list = metrics.get(m_type, [])
                                if m_list:
                                    cvss_data = m_list[0].get('cvssData', {})
                                    cvss_score = cvss_data.get('baseScore', "N/A")
                                    attack_complexity = cvss_data.get('attackComplexity', cvss_data.get('accessComplexity', "N/A"))
                                    user_interaction = cvss_data.get('userInteraction', "N/A")
                                    break
                        break # Success
                    else:
                        if code == 503 or code == 429:
                            time.sleep(2 * (attempt + 1))
                            continue
                        break
            except Exception:
                time.sleep(1)
                continue

    cisa_kev = "No"
    for m in all_metrics:
        if m.get('other', {}).get('type') == 'kev': cisa_kev = "Yes"; break
            
    raw_refs = cna.get('references', [])
    poc_available, poc_link = "No", "N/A"
    combined_refs = [f"https://nvd.nist.gov/vuln/detail/{cve_id}", f"https://www.cve.org/CVERecord?id={cve_id}"]
    
    # Identify PoC links and build combined references
    poc_keywords = ["exploit-db", "packetstorm", "metasploit", "0day.today", "/poc", "/exploit"]
    for r in raw_refs:
        url = r.get('url', '')
        if url and url not in combined_refs: combined_refs.append(url)
        if poc_available == "No" and url:
            if any(k in url.lower() for k in poc_keywords) or ("github.com" in url.lower() and "poc" in url.lower() and cve_id.lower() in url.lower()):
                poc_available = "Yes"; poc_link = url

    # Final check for KEV in tags or references
    if cisa_kev == "No":
        all_tags = cna.get('tags', [])
        for adp in adp_list:
            all_tags.extend(adp.get('tags', []))
        kev_indicators = ['known-exploited-vulnerability', 'exploited-in-the-wild', 'active-exploitation', 'cisa-kev']
        if any(any(ki in str(t).lower() for ki in kev_indicators) for t in all_tags):
            cisa_kev = "Yes"
            
    if cisa_kev == "No":
        kev_url = "cisa.gov/known-exploited-vulnerabilities-catalog"
        for r in combined_refs:
            if kev_url in r.lower():
                cisa_kev = "Yes"; break

    epss_score = "N/A"
    if epss_data.get('status') == 'OK' and epss_data.get('data'):
        epss_score = epss_data['data'][0].get('epss', 'N/A')
    
    if poc_available == "No":
        gh_poc = get_poc_from_github(session, cve_id, github_token)
        if gh_poc: poc_available = "Yes (GitHub)"; poc_link = gh_poc; combined_refs.append(gh_poc)

    exploitability = "Exploited in the wild" if cisa_kev == "Yes" else "PoC Available" if poc_available != "No" else "Theoretical / Unknown"

    # Extract Remediation / Mitigation
    remediation = "Apply the latest security patches from the vendor."
    
    # 1. Check for explicit solution/mitigation fields in the record
    solutions = cna.get('solutions', [])
    if solutions and isinstance(solutions, list) and solutions[0].get('value'):
        remediation = solutions[0]['value']
    
    # 2. Try to extract from description (common pattern)
    if remediation == "Apply the latest security patches from the vendor.":
        # Matches: "Users are recommended to upgrade to version X", "fixed in version X", "Patch is available at X"
        rem_patterns = [
            r"recommended to upgrade to ([^,\.\(;]+)",
            r"fixed in (?:version )?([^,\.\(;]+)",
            r"update to (?:version )?([^,\.\(;]+)",
            r"mitigated by ([^,\.\(;]+)"
        ]
        for pattern in rem_patterns:
            rem_match = re.search(pattern, description, re.IGNORECASE)
            if rem_match:
                version = rem_match.group(1).strip()
                remediation = f"Upgrade to {version} or later."
                break
    
    # 3. Check references for 'advisory' or 'patch'
    if remediation == "Apply the latest security patches from the vendor.":
        for ref in combined_refs:
            if any(k in ref.lower() for k in ['advisory', 'patch', 'fix', 'update']):
                remediation = f"Review vendor advisory and apply available patches: {ref}"
                break

    return {
        "cve_id": cve_id, "title": current_title, "description": description, "affected": affected_structured,
        "cisa_kev": cisa_kev, "cvss_score": cvss_score, "exploitability": exploitability,
        "poc_available": poc_available, "poc_link": poc_link, "user_interaction": user_interaction,
        "epss_score": epss_score, "attack_complexity": attack_complexity, "references": combined_refs,
        "remediation": remediation
    }

def print_pretty(data: Dict[str, Any], use_colors: bool, minimal: bool = False):
    with print_lock:
        if "error" in data:
            if not minimal: print(f"\n[!] {colorize(f'Error for {data.get(r'cve_id')}: {data[r'error']}', Colors.RED, use_colors)}")
            return
        
        if minimal:
            poc = data['poc_link']
            if poc == "N/A": return # Suppress if no PoC link found
            print(f"{colorize(data['cve_id'], Colors.BLUE + Colors.BOLD, use_colors)}: {colorize(poc, Colors.YELLOW, use_colors)}")
            return

        cvss = data['cvss_score']
        cvss_str = colorize(str(cvss), Colors.RED if (isinstance(cvss, (int, float)) and cvss >= 7) else Colors.END, use_colors)
        kev_str = colorize(data['cisa_kev'], Colors.RED + Colors.BOLD, use_colors) if data['cisa_kev'] == "Yes" else data['cisa_kev']
        
        aff_lines = []
        for a in data['affected'][:3]:
            # For each product, list a limited number of versions for the terminal
            vers = ", ".join(a['versions'][:5])
            if len(a['versions']) > 5: vers += ", ..."
            aff_lines.append(f"  - {a['product']} ({vers})")
        aff_str = "\n".join(aff_lines)
        if len(data['affected']) > 3: aff_str += "\n  - ..."

        print(f"\n{'='*60}")
        print(f"CVE ID: {colorize(data['cve_id'], Colors.BLUE + Colors.BOLD, use_colors)}")
        print(f"Vulnerability Title: {data['title']}")
        print(f"Description: {data['description']}")
        print(f"Affected Products:\n{aff_str}")
        print(f"CISA KEV?: {kev_str}")
        print(f"CVSS Score: {cvss_str}")
        print(f"Exploitability: {data['exploitability']}")
        print(f"PoC Available: {data['poc_available']}")
        print(f"PoC Link: {colorize(data['poc_link'], Colors.YELLOW, use_colors)}")
        print(f"User Interaction: {data['user_interaction']}")
        print(f"EPSS Score: {data['epss_score']}")
        print(f"Attack Complexity: {data['attack_complexity']}")
        print("References:")
        for ref in data['references'][:5]: print(f"  - {ref}")
        print(f"{'='*60}")

def save_text(results: List[Dict[str, Any]], filename: str):
    with open(filename, 'w', encoding='utf-8') as f:
        for d in results:
            if "error" in d: continue
            f.write(f"{'='*60}\nCVE ID: {d['cve_id']}\nTitle: {d['title']}\nDescription: {d['description']}\n")
            f.write(f"CVSS: {d['cvss_score']} | KEV: {d['cisa_kev']} | EPSS: {d['epss_score']}\n")
            f.write(f"Exploitability: {d['exploitability']} | PoC: {d['poc_link']}\n")
            f.write(f"User Interaction: {d['user_interaction']} | Complexity: {d['attack_complexity']}\n")
            
            aff_list = []
            for a in d['affected']:
                aff_list.append(f"{a['product']} ({', '.join(a['versions'])})")
            aff_str = " | ".join(aff_list)
            
            f.write(f"Affected: {aff_str}\nReferences: {', '.join(d['references'])}\n\n")

def save_csv(results: List[Dict[str, Any]], filename: str):
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(["CVE ID", "Title", "Description", "CVSS", "KEV", "EPSS", "Exploitability", "PoC Link", "User Interaction", "Complexity", "Affected", "References"])
        for d in results:
            if "error" in d: continue
            aff = "; ".join([f"{a['product']} ({', '.join(a['versions'])})" for a in d['affected']])
            w.writerow([csv_safe(d['cve_id']), csv_safe(d['title']), csv_safe(d['description']), d['cvss_score'], d['cisa_kev'], d['epss_score'], d['exploitability'], d['poc_link'], d['user_interaction'], d['attack_complexity'], csv_safe(aff), csv_safe("; ".join(d['references']))])

def get_output_path(base_name: Optional[str], extension: str) -> str:
    if not base_name: base_name = "results"
    if base_name.endswith(f".{extension}"):
        base_name = base_name[:-(len(extension)+1)]
    
    filename = f"{base_name}.{extension}"
    if not os.path.exists(filename): return filename
    
    counter = 1
    while os.path.exists(f"{base_name}_{counter}.{extension}"):
        counter += 1
    return f"{base_name}_{counter}.{extension}"

def get_keys(args_token=None, args_nvd=None):
    """Retrieve GitHub and NVD keys from args, env, config, or keyring."""
    config_dir = get_config_dir()
    config_file = config_dir / "config.json"
    local_config = {}
    if config_file.exists():
        try:
            with open(config_file, 'r') as f: local_config = json.load(f)
        except Exception: pass

    # GitHub Token
    github_token = args_token or os.getenv("GITHUB_TOKEN") or local_config.get("github_token")
    if not github_token:
        try:
            github_token = keyring.get_password("cve-lookup-tool", "github-token")
        except Exception: github_token = None
    
    # NVD Key
    nvd_key = args_nvd or os.getenv("NVD_API_KEY") or local_config.get("nvd_key")
    if not nvd_key:
        try:
            nvd_key = keyring.get_password("cve-lookup-tool", "nvd-key")
        except Exception: nvd_key = None

    return github_token, nvd_key, local_config

def main():
    p = argparse.ArgumentParser(description="CVE Lookup Tool Pro - Intelligence Edition")
    p.add_argument("cve_ids", nargs="*", help="CVE IDs")
    p.add_argument("-f", "--file", help="Input file")
    p.add_argument("-T", "--token", help="GitHub Token")
    p.add_argument("-N", "--nvd-key", help="NVD API Key")
    p.add_argument("-p", "--poc", action="store_true", help="PoC Mode: Filter for results with exploits and show minimal output")
    p.add_argument("-j", "--json", nargs="?", const="results", help="JSON export (default: results.json)")
    p.add_argument("-c", "--csv", nargs="?", const="results", help="CSV export (default: results.csv)")
    p.add_argument("-t", "--text", nargs="?", const="results", help="Text report (default: results.txt)")
    p.add_argument("-G", "--grep", nargs="?", const="results", help="Grep export (default: results.grep)")
    p.add_argument("-x", "--xml", nargs="?", const="results", help="XML export (default: results.xml)")
    p.add_argument("-A", "--all", nargs="?", const="results", help="Generate all output formats. Optionally specify a base filename (default: 'results')")
    p.add_argument("-n", "--no-color", action="store_true", help="Disable colors")
    p.add_argument("-v", "--version", action="version", version=f"CVE Lookup Tool Pro v{VERSION} (Intelligence Edition)")
    args = p.parse_args()

    use_colors = not args.no_color and sys.stdout.isatty()
    
    if not args.poc:
        banner = f"--- CVE Lookup Tool Pro v{VERSION} (Intelligence Edition) ---"
        print(colorize(banner, Colors.BLUE + Colors.BOLD, use_colors))
    
    config_dir = get_config_dir()
    config_file = config_dir / "config.json"
    github_token, nvd_key, local_config = get_keys(args.token, args.nvd_key)
            
    if not github_token and not args.poc:
        github_token = getpass.getpass("[?] GitHub Token not found. Enter Token (optional, press Enter to skip): ").strip()
        if github_token:
            save = input("[?] Save this token? (k: keyring, f: config file, n: don't save): ").lower().strip()
            if save == 'k':
                try:
                    keyring.set_password("cve-lookup-tool", "github-token", github_token)
                    print("[+] Token saved to keyring.")
                except Exception as e: print(f"[!] Failed: {e}")
            elif save == 'f':
                config_dir.mkdir(parents=True, exist_ok=True)
                local_config["github_token"] = github_token
                with open(config_file, 'w') as f: json.dump(local_config, f)
                print(f"[+] Token saved to {config_file}")

    if not nvd_key and not args.poc:
        nvd_key = getpass.getpass("[?] NVD API Key not found. Enter Key (optional, press Enter to skip): ").strip()
        if nvd_key:
            save = input("[?] Save this key? (k: keyring, f: config file, n: don't save): ").lower().strip()
            if save == 'k':
                try:
                    keyring.set_password("cve-lookup-tool", "nvd-key", nvd_key)
                    print("[+] Key saved to keyring.")
                except Exception as e: print(f"[!] Failed: {e}")
            elif save == 'f':
                config_dir.mkdir(parents=True, exist_ok=True)
                local_config["nvd_key"] = nvd_key
                with open(config_file, 'w') as f: json.dump(local_config, f)
                print(f"[+] Key saved to {config_file}")

    cve_list = list(dict.fromkeys([c.strip().upper() for c in args.cve_ids]))
    if args.file:
        try:
            with open(args.file, 'r') as f:
                for line in f:
                    c = line.strip().upper()
                    if c and c not in cve_list: cve_list.append(c)
        except Exception as e: print(f"Error: {e}"); sys.exit(1)

    if not cve_list: p.print_help(); sys.exit(0)
    results = []
    session = requests.Session()
    print(f"[*] Analyzing {len(cve_list)} CVEs...")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(get_cve_data, session, cid, github_token, nvd_key): cid for cid in cve_list}
        for f in as_completed(futures):
            data = f.result()
            # Filter Logic: Include anything exploited in the wild OR with a PoC
            if args.poc:
                if data.get("exploitability") == "Theoretical / Unknown" or "error" in data:
                    continue
            results.append(data)
            print_pretty(data, use_colors, args.poc)


    # Determine unique base name for -A or individual outputs
    all_base = args.all if args.all else None
    
    if args.json or all_base:
        fname = get_output_path(args.json or all_base, "json")
        with open(fname, 'w') as f: json.dump(results, f, indent=4)
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
        with open(fname, 'w') as f:
            for d in results:
                if "error" in d: continue
                # Sanitize fields: remove newlines and pipes to preserve grep format
                def s(val):
                    return str(val).replace('\n', ' ').replace('\r', ' ').replace('|', ' ').strip()
                
                aff_str = "; ".join([f"{a['product']} ({', '.join(a['versions'])})" for a in d['affected']])
                ref_str = "; ".join(d['references'])
                
                # Ordered fields: 1.ID, 2.Title, 3.Description, 4.CVSS, 5.KEV, 6.EPSS, 7.Exploitability, 
                # 8.PoC, 9.Interaction, 10.Complexity, 11.Affected, 12.References, 13.PoC_Link
                line = [
                    s(d['cve_id']), s(d['title']), s(d['description']), s(d['cvss_score']),
                    s(d['cisa_kev']), s(d['epss_score']), s(d['exploitability']), s(d['poc_available']),
                    s(d['user_interaction']), s(d['attack_complexity']), s(aff_str), s(ref_str), s(d['poc_link'])
                ]
                f.write(f"{'|'.join(line)}\n")
        print(f"[+] Grep report saved to: {fname}")
    if args.xml or all_base:
        fname = get_output_path(args.xml or all_base, "xml")
        root = ET.Element("CVEList")
        for d in results:
            if "error" in d: continue
            c = ET.SubElement(root, "CVE")
            for k, v in d.items(): ET.SubElement(c, k).text = str(v)
        ET.ElementTree(root).write(fname, encoding='utf-8', xml_declaration=True)
        print(f"[+] XML report saved to: {fname}")

    print(f"\n[+] Done. Processed {len(results)} items.")

if __name__ == "__main__": main()
