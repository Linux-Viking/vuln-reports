#!/usr/bin/env python3
import sys
import os

# Suppress GLib-GIO warnings
os.environ["GIO_USE_VFS"] = "local"
if "G_MESSAGES_DEBUG" not in os.environ:
    os.environ["G_MESSAGES_DEBUG"] = "none"

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
circl_lock = Lock()
last_circl_call = [0.0]

def colorize(text: str, color_code: str, use_colors: bool) -> str:
    if not use_colors: return text
    return f"{color_code}{text}{Colors.END}"

def validate_cve_id(cve_id: str) -> bool:
    return bool(CVE_REGEX.match(cve_id))

def csv_safe(value: Any) -> str:
    val = str(value)
    if val.startswith(('=', '+', '-', '@')): return f"'{val}"
    return val

def get_poc_from_github(session: requests.Session, cve_id: str, github_token: Optional[str], aliases: Optional[list] = None) -> Optional[str]:
    queries = [f'"{cve_id}"', f'"{cve_id.replace("CVE-", "")}"']
    if aliases:
        for alias in aliases:
            if alias and len(alias) > 3 and alias not in queries:
                queries.append(f'"{alias}"')
                
    headers = {'Accept': 'application/vnd.github.v3+json', 'User-Agent': USER_AGENT}
    token_to_use = github_token.strip() if github_token else None
    
    for q in queries:
        current_headers = headers.copy()
        if token_to_use: current_headers['Authorization'] = f'Bearer {token_to_use}'
        for attempt in range(3):
            try:
                params = {'q': f"{q} exploit OR poc", 'sort': 'stars', 'order': 'desc'}
                resp = session.get("https://api.github.com/search/repositories", headers=current_headers, params=params, timeout=5)
                if resp.status_code in [401, 403] and token_to_use and attempt == 0:
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
                                
                            match_found = cve_id.lower() in name or cve_id.lower() in desc
                            if not match_found and aliases:
                                for alias in aliases:
                                    if alias and (alias.lower() in name or alias.lower() in desc):
                                        match_found = True
                                        break
                                        
                            if match_found:
                                return item.get('html_url')
                    break # Success but no poc in repos
                elif resp.status_code in [403, 429]:
                    time.sleep(3 * (attempt + 1))
                    continue
                else: break
            except requests.RequestException:
                time.sleep(2)
                continue
                
        # Fallback to code search if aliases are present and we have a token
        if token_to_use and aliases and any(a in q for a in aliases):
            for attempt in range(3):
                try:
                    # Code search requires path or language or simpler query
                    params = {'q': f"{q} in:path"} 
                    resp = session.get("https://api.github.com/search/code", headers=current_headers, params=params, timeout=5)
                    if resp.status_code == 200:
                        results = resp.json()
                        if results.get('total_count', 0) > 0:
                             for item in results['items']:
                                 repo_url = item.get('repository', {}).get('html_url')
                                 if repo_url:
                                     path = item.get('path', '')
                                     if path:
                                        dir_path = '/'.join(path.split('/')[:-1])
                                        if dir_path:
                                            return f"{repo_url}/tree/main/{dir_path}"
                                     return repo_url
                        break
                    elif resp.status_code in [403, 429]:
                         time.sleep(3 * (attempt + 1))
                         continue
                    else:
                         break
                except requests.RequestException:
                    time.sleep(2)
                    continue
    return None

def normalize_text(text: Any) -> str:
    if not text or not isinstance(text, str): return str(text) if text is not None else "N/A"
    text = text.replace('\u00a0', ' ').replace('\\n', ' ')
    return re.sub(r'\s+', ' ', text).strip()

def get_cve_data(session: requests.Session, cve_id: str, github_token: Optional[str], nvd_key: Optional[str] = None, vulners_key: Optional[str] = None, circl_key: Optional[str] = None) -> Dict[str, Any]:
    if not validate_cve_id(cve_id): return {"cve_id": cve_id, "error": f"Invalid format: {cve_id}"}
    
    vulners_data_list = []
    if vulners_key:
        try:
            v_resp = session.post("https://vulners.com/api/v3/search/lucene/", 
                                 json={"query": f"id:{cve_id}"}, 
                                 headers={'User-Agent': USER_AGENT, 'X-Api-Key': vulners_key}, 
                                 timeout=DEFAULT_TIMEOUT)
            if v_resp.status_code == 200:
                v_json = v_resp.json()
                if v_json.get('result') == 'OK':
                    search_results = v_json.get('data', {}).get('search', [])
                    for res in search_results:
                        vulners_data_list.append(res.get('_source', {}))
        except Exception: pass

    circl_url = f"https://cve.circl.lu/api/cve/{cve_id}"
    epss_url = "https://api.first.org/data/v1/epss"
    headers = {'User-Agent': USER_AGENT}
    circl_headers = headers.copy()
    if circl_key:
        # Some endpoints/instances use Authorization, some X-API-KEY.
        # We supply both to maximize compatibility with the CIRCL backend.
        circl_headers['Authorization'] = f"Token {circl_key}"
        circl_headers['X-API-KEY'] = circl_key

    max_retries = 8
    circl_data = None
    for attempt in range(max_retries):
        with circl_lock:
            now = time.time()
            elapsed = now - last_circl_call[0]
            # Reduce delay significantly if we have an API key
            delay = 0.65 if circl_key else 6.5
            if elapsed < delay:
                time.sleep(delay - elapsed)
            last_circl_call[0] = time.time()

        try:
            circl_resp = session.get(circl_url, headers=circl_headers, timeout=DEFAULT_TIMEOUT)
            if circl_resp.status_code == 429:
                if attempt == max_retries - 1: return {"cve_id": cve_id, "error": "HTTP 429: Too Many Requests"}
                time.sleep(5 * (attempt + 1)) # Wait longer before retrying
                continue
            circl_resp.raise_for_status()
            circl_data = circl_resp.json()
            break
        except Exception as e:
            if attempt == max_retries - 1: return {"cve_id": cve_id, "error": str(e)}
            time.sleep(2 * (attempt + 1))

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
    
    # Improved Title Heuristic: catch commit messages like "crypto: algif_aead - ..."
    is_commit_msg = ":" in current_title and " - " in current_title
    is_generic = any(gv in current_title.lower() for gv in generic_vulns) or current_title.lower().startswith("vulnerability in") or current_title.endswith(": Privilege Escalation")
    
    if not title or current_title == "N/A" or is_generic or is_commit_msg:
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

    # Vulners Enrichment: Prefer high-quality titles and descriptions from any matched record
    if vulners_data_list:
        # Sort Vulners records to prioritize cisa_kev and nvd
        def type_priority(v):
            t = v.get('type', '').lower()
            if t == 'cisa_kev': return 0
            if t == 'nvd': return 1
            if t == 'osv': return 2
            return 3
        
        sorted_v = sorted(vulners_data_list, key=type_priority)
        
        for v in sorted_v:
            v_title = v.get('title')
            # If our current title is ID, commit message, or generic, and Vulners has something better
            v_is_good = v_title and len(v_title) > len(cve_id)
            curr_is_weak = "resolved" in str(current_title).lower() or "N/A" in str(current_title) or str(current_title) == cve_id or is_generic or is_commit_msg
            
            if v_is_good and curr_is_weak:
                current_title = v_title
            
            v_desc = v.get('description')
            if v_desc and len(v_desc) > 20 and ("resolved" in description.lower() or "N/A" in description):
                description = normalize_text(v_desc)
                break # Take the best description found

    # Vulners Affected Parsing: Aggregate from all records
    vulners_affected = []
    seen_sw = set()
    for v in vulners_data_list:
        if v.get('affectedSoftware'):
            for sw in v['affectedSoftware']:
                product_name = sw.get('name', 'Unknown')
                version_range = sw.get('version', 'N/A')
                operator = sw.get('operator', '')
                
                sw_key = (product_name, version_range, operator)
                if sw_key in seen_sw: continue
                seen_sw.add(sw_key)
                
                display_version = version_range
                if operator == 'lt': display_version = f"before {version_range}"
                elif operator == 'le': display_version = f"up to {version_range}"
                
                vulners_affected.append({
                    "vendor": "Unknown",
                    "product": product_name,
                    "versions": [display_version]
                })

    # Try to extract versions from description: "X.Y before Z.W" or "X.Y through Z.W"
    # Improved regex to handle various versioning formats
    desc_version_patterns = [
        r"(\d+(?:\.\d+)* (?:before|through|prior to) (?:build )?\d+(?:\.\d+)*)",
        r"v(?:ersion)?\s?(\d+(?:\.\d+)*)",
        r"(\d+(?:\.\d+)+)"
    ]
    all_versions_from_desc = []
    for pattern in desc_version_patterns:
        matches = re.findall(pattern, description)
        if matches:
            all_versions_from_desc.extend(matches)
            break # Use the first pattern that yields results

    affected_structured = []
    if not affected_raw or (len(affected_raw) == 1 and affected_raw[0].get('product', '').lower() in ['n/a', '']):
        if detected_products:
            # Ensure detected products are also cleaned
            for i in range(len(detected_products)):
                if detected_products[i].lower().startswith('in '):
                    detected_products[i] = detected_products[i][3:].strip()
            
            for p in detected_products:
                p_versions = ["N/A"]
                if all_versions_from_desc:
                    p_versions = all_versions_from_desc # Include all matches
                elif "SDK" in description or "software development kit" in description.lower():
                    p_versions = ["SDK (All Versions)"]
                
                affected_structured.append({
                    "vendor": "Unknown", 
                    "product": p, 
                    "versions": p_versions
                })
        elif product:
            p_versions = ["N/A"]
            if all_versions_from_desc: p_versions = all_versions_from_desc
            affected_structured.append({"vendor": "Unknown", "product": product, "versions": p_versions})
    
    if not affected_structured:
        # Group by product to merge git and semver records
        product_map = {}
        for a in affected_raw:
            prod = a.get('product', 'Unknown')
            if prod not in product_map:
                product_map[prod] = {"vendor": a.get('vendor', 'Unknown'), "versions": [], "has_semver": False}
            
            for v in a.get('versions', []):
                v_type = v.get('versionType', '')
                status = v.get('status', 'unknown')
                ver = v.get('version', 'N/A')
                lt = v.get('lessThan')
                ltoe = v.get('lessThanOrEqual')
                
                # Heuristic for version vs git hash
                looks_like_version = re.match(r"^\d+(\.\d+)*", str(ver))
                if v_type == 'semver' or (not v_type and looks_like_version):
                    product_map[prod]["has_semver"] = True
                    item_type = 'semver'
                else:
                    item_type = v_type
                
                if status == 'affected':
                    if lt and lt != 'n/a': ver = f"{ver} to <{lt}"
                    elif ltoe and ltoe != 'n/a': ver = f"{ver} to {ltoe}"
                    
                    if ver != 'N/A':
                        product_map[prod]["versions"].append({"ver": ver, "type": item_type, "status": "affected"})
                elif status == 'unaffected':
                    if ver and ver != '0' and ver != 'N/A' and not str(ver).startswith('*'):
                        product_map[prod]["versions"].append({"ver": ver, "type": item_type, "status": "unaffected"})
        
        for prod, info in product_map.items():
            # If we have semver, filter out the git hashes for the same product
            all_vers = info["versions"]
            if info["has_semver"]:
                all_vers = [v for v in all_vers if v["type"] == "semver"]
            
            # Identify affected ranges vs fixed versions
            affected_display = []
            affected_items = [v["ver"] for v in all_vers if v["status"] == "affected"]
            unaffected_items = [v["ver"] for v in all_vers if v["status"] == "unaffected"]
            
            if affected_items:
                if unaffected_items:
                    # Group patches
                    patched_str = ", ".join(unaffected_items)
                    for a in affected_items:
                        if "to " not in a:
                            affected_display.append(f"{a} and later (Patched in: {patched_str})")
                        else:
                            affected_display.append(a)
                else:
                    affected_display.extend(affected_items)
            
            if not affected_display: 
                # Fallback to description versions if still empty
                if all_versions_from_desc: affected_display = all_versions_from_desc
                else: affected_display = ["N/A"]
            
            affected_structured.append({
                "vendor": info["vendor"],
                "product": prod,
                "versions": affected_display
            })

    # Final Affected Sanity Check: Prefer Vulners if we have Git hashes or empty results
    has_git_hashes = any(any(len(v) > 30 for v in a['versions']) for a in affected_structured)
    if (not affected_structured or has_git_hashes) and vulners_affected:
        affected_structured = vulners_affected

    cvss_score, attack_complexity, user_interaction, threat_vector = "N/A", "N/A", "N/A", "N/A"
    all_metrics = cna.get('metrics', []) + [m for adp in adp_list for m in adp.get('metrics', [])]
    
    # Prioritize CVSS v4.0 -> v3.1 -> v3.0, using ADP (CVE.org) as a fallback
    for version in ['cvssV4_0', 'cvssV3_1', 'cvssV3_0']:
        for m in all_metrics:
            v = m.get(version)
            if v and cvss_score == "N/A":
                cvss_score = v.get('baseScore', "N/A")
                attack_complexity = v.get('attackComplexity', "N/A")
                user_interaction = v.get('userInteraction', "N/A")
                threat_vector = v.get('attackVector', "N/A")
        if cvss_score != "N/A": break

    # NVD Fallback for older CVEs
    if cvss_score == "N/A":
        max_retries = 6
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
                                    threat_vector = cvss_data.get('attackVector', cvss_data.get('accessVector', "N/A"))
                                    break
                        break # Success
                    else:
                        if code == 503 or code == 429:
                            time.sleep(5 * (attempt + 1)) # Longer delay for rate limits
                            continue
                        break
            except Exception:
                time.sleep(2 * (attempt + 1))
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
        aliases_to_search = []
        if aka_title:
            aliases_to_search.append(aka_title)
        if current_title and current_title != "N/A" and not is_generic and not is_commit_msg:
            # Add short/distinct titles as potential aliases (e.g., DirtyDecrypt)
            if len(current_title.split()) <= 3 and len(current_title) < 30:
                if current_title not in aliases_to_search:
                    aliases_to_search.append(current_title)
                    
        gh_poc = get_poc_from_github(session, cve_id, github_token, aliases=aliases_to_search)
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
        for f_ref in combined_refs:
            if any(k in f_ref.lower() for k in ['advisory', 'patch', 'fix', 'update']):
                remediation = f"Review vendor advisory and apply available patches: {f_ref}"
                break

    return {
        "cve_id": cve_id, "title": current_title, "description": description, "affected": affected_structured,
        "cisa_kev": cisa_kev, "cvss_score": cvss_score, "exploitability": exploitability,
        "poc_available": poc_available, "poc_link": poc_link, "threat_vector": threat_vector, "user_interaction": user_interaction,
        "epss_score": epss_score, "attack_complexity": attack_complexity, "references": combined_refs,
        "remediation": remediation
    }

def print_pretty(data: Dict[str, Any], use_colors: bool, minimal: bool = False):
    with print_lock:
        if "error" in data:
            if not minimal:
                c_id = data.get("cve_id", "Unknown")
                err = data.get("error", "Unknown error")
                print(f"\n[!] {colorize(f'Error for {c_id}: {err}', Colors.RED, use_colors)}")
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
        print(f"Threat Vector: {data.get('threat_vector', 'N/A')}")
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
            f.write(f"Threat Vector: {d['threat_vector']} | User Interaction: {d['user_interaction']} | Complexity: {d['attack_complexity']}\n")
            
            aff_list = []
            for a in d['affected']:
                aff_list.append(f"{a['product']} ({', '.join(a['versions'])})")
            aff_str = " | ".join(aff_list)
            
            f.write(f"Affected: {aff_str}\nReferences: {', '.join(d['references'])}\n\n")

def save_csv(results: List[Dict[str, Any]], filename: str):
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(["CVE ID", "Title", "Description", "CVSS", "KEV", "EPSS", "Exploitability", "PoC Link", "Threat Vector", "User Interaction", "Complexity", "Affected", "References"])
        for d in results:
            if "error" in d: continue
            aff = "; ".join([f"{a['product']} ({', '.join(a['versions'])})" for a in d['affected']])
            w.writerow([csv_safe(d['cve_id']), csv_safe(d['title']), csv_safe(d['description']), d['cvss_score'], d['cisa_kev'], d['epss_score'], d['exploitability'], d['poc_link'], d['threat_vector'], d['user_interaction'], d['attack_complexity'], csv_safe(aff), csv_safe("; ".join(d['references']))])

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

def get_keys():
    """Retrieve GitHub, NVD, Vulners, and CIRCL keys from env or keyring."""
    # GitHub Token
    github_token = os.getenv("GITHUB_TOKEN")
    if not github_token:
        try:
            github_token = keyring.get_password("cve-lookup-tool", "github-token")
        except Exception: github_token = None
    
    # NVD Key
    nvd_key = os.getenv("NVD_API_KEY")
    if not nvd_key:
        try:
            nvd_key = keyring.get_password("cve-lookup-tool", "nvd-key")
        except Exception: nvd_key = None

    # Vulners Key
    vulners_key = os.getenv("VULNERS_API_KEY")
    if not vulners_key:
        try:
            vulners_key = keyring.get_password("cve-lookup-tool", "vulners-key")
        except Exception: vulners_key = None

    # CIRCL Key
    circl_key = os.getenv("CIRCL_API_KEY")
    if not circl_key:
        try:
            circl_key = keyring.get_password("cve-lookup-tool", "circl-key")
        except Exception: circl_key = None

    return github_token, nvd_key, vulners_key, circl_key

def main():
    p = argparse.ArgumentParser(description="CVE Lookup Tool Pro - Intelligence Edition")
    p.add_argument("cve_ids", nargs="*", help="CVE IDs")
    p.add_argument("-f", "--file", help="Input file")
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

    github_token, nvd_key, vulners_key, circl_key = get_keys()

    if sys.stdin.isatty():
        if not github_token and not args.poc:
            github_token = getpass.getpass("[?] GitHub Token not found. Enter Token (optional, press Enter to skip): ").strip()
            if github_token:
                save = input("[?] Save this token to keyring/credential manager? (y/N): ").lower().strip()
                if save == 'y':
                    try:
                        keyring.set_password("cve-lookup-tool", "github-token", github_token)
                        print("[+] Token saved to keyring.")
                    except Exception as e: print(f"[!] Failed: {e}")

        if not nvd_key and not args.poc:
            nvd_key = getpass.getpass("[?] NVD API Key not found. Enter Key (optional, press Enter to skip): ").strip()
            if nvd_key:
                save = input("[?] Save this key to keyring/credential manager? (y/N): ").lower().strip()
                if save == 'y':
                    try:
                        keyring.set_password("cve-lookup-tool", "nvd-key", nvd_key)
                        print("[+] Key saved to keyring.")
                    except Exception as e: print(f"[!] Failed: {e}")

        if not vulners_key and not args.poc:
            vulners_key = getpass.getpass("[?] Vulners API Key not found. Enter Key (optional, press Enter to skip): ").strip()
            if vulners_key:
                save = input("[?] Save this key to keyring/credential manager? (y/N): ").lower().strip()
                if save == 'y':
                    try:
                        keyring.set_password("cve-lookup-tool", "vulners-key", vulners_key)
                        print("[+] Key saved to keyring.")
                    except Exception as e: print(f"[!] Failed: {e}")

        if not circl_key and not args.poc:
            circl_key = getpass.getpass("[?] CIRCL API Key not found. Enter Key (optional, press Enter to skip): ").strip()
            if circl_key:
                save = input("[?] Save this key to keyring/credential manager? (y/N): ").lower().strip()
                if save == 'y':
                    try:
                        keyring.set_password("cve-lookup-tool", "circl-key", circl_key)
                        print("[+] Key saved to keyring.")
                    except Exception as e: print(f"[!] Failed: {e}")
    
    cve_list = []
    for arg in args.cve_ids:
        for c in re.findall(r"\bCVE-\d{4}-\d{4,7}\b", arg, re.IGNORECASE):
            c_upper = c.upper()
            if c_upper not in cve_list:
                cve_list.append(c_upper)
    if args.file:
        try:
            with open(args.file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                found_cves = re.findall(r"\bCVE-\d{4}-\d{4,7}\b", content, re.IGNORECASE)
                for c in found_cves:
                    c_upper = c.upper()
                    if c_upper not in cve_list:
                        cve_list.append(c_upper)
        except Exception as e: print(f"Error: {e}"); sys.exit(1)

    if not cve_list: p.print_help(); sys.exit(0)
    results = []
    session = requests.Session()
    print(f"[*] Analyzing {len(cve_list)} CVEs...")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(get_cve_data, session, cid, github_token, nvd_key, vulners_key, circl_key): cid for cid in cve_list}
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
                # 8.PoC, 9.Threat Vector, 10.Interaction, 11.Complexity, 12.Affected, 13.References, 14.PoC_Link
                line = [
                    s(d['cve_id']), s(d['title']), s(d['description']), s(d['cvss_score']),
                    s(d['cisa_kev']), s(d['epss_score']), s(d['exploitability']), s(d['poc_available']),
                    s(d['threat_vector']), s(d['user_interaction']), s(d['attack_complexity']), s(aff_str), s(ref_str), s(d['poc_link'])
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
