"""NVD: CVSS fallback for CVE records without v3+/v4 metrics, and CPE -> CVE lookups."""

from __future__ import annotations

import json
import logging
import time
import urllib.request

import requests

from vuln_reports.console import Colors, colorize
from vuln_reports.enrichment.http import SCAN_USER_AGENT, USER_AGENT, api_delay, nvd_cpe_limiter, nvd_cve_limiter

NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Local overrides for 0-days / "Awaiting Analysis" CVEs NVD cannot match by CPE yet.
LOCAL_OVERRIDES = {
    "cpe:2.3:a:igor_sysoev:nginx:1.29.8": ["CVE-2026-42945"],
    "cpe:2.3:a:f5:nginx:1.29.8": ["CVE-2026-42945"],
    "cpe:2.3:a:nginx:nginx:1.29.8": ["CVE-2026-42945"],
}

logger = logging.getLogger(__name__)


def fetch_cvss(cve_id: str, nvd_key: str | None = None):
    """CVSS from NVD (v3.1, v3.0, then v2). Returns the same 4-tuple as ``record.extract_cvss``."""
    cvss_score, attack_complexity, user_interaction, threat_vector = "N/A", "N/A", "N/A", "N/A"
    max_retries = 6
    for attempt in range(max_retries):
        nvd_cve_limiter.wait(api_delay(nvd_key))
        try:
            headers = {"User-Agent": USER_AGENT}
            if nvd_key:
                headers["X-ApiKey"] = nvd_key
            # Fixed https:// URL; urlopen is called via the module so tests can mock it.
            req = urllib.request.Request(f"{NVD_CVE_API}?cveId={cve_id}", headers=headers)
            with urllib.request.urlopen(req, timeout=15) as resp:  # nosec B310
                code = resp.getcode()
                if code == 200:
                    vulnerabilities = json.loads(resp.read().decode()).get("vulnerabilities", [])
                    if vulnerabilities:
                        metrics = vulnerabilities[0].get("cve", {}).get("metrics", {})
                        for m_type in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                            m_list = metrics.get(m_type, [])
                            if m_list:
                                cvss_data = m_list[0].get("cvssData", {})
                                cvss_score = cvss_data.get("baseScore", "N/A")
                                attack_complexity = cvss_data.get(
                                    "attackComplexity", cvss_data.get("accessComplexity", "N/A")
                                )
                                user_interaction = cvss_data.get("userInteraction", "N/A")
                                threat_vector = cvss_data.get("attackVector", cvss_data.get("accessVector", "N/A"))
                                break
                    break
                else:
                    if code == 503 or code == 429:
                        time.sleep(5 * (attempt + 1))
                        continue
                    break
        except Exception:
            time.sleep(2 * (attempt + 1))
            continue
    return cvss_score, attack_complexity, user_interaction, threat_vector


def cves_for_cpe(session: requests.Session, cpe: str, nvd_key: str | None = None, use_colors: bool = True) -> list:
    """CVE IDs NVD matches to ``cpe`` (plus local overrides and known vendor aliases)."""
    if cpe.startswith("cpe:/"):
        cpe = cpe.replace("cpe:/", "cpe:2.3:")

    cpe_aliases = [cpe]
    if ":igor_sysoev:nginx:" in cpe:
        cpe_aliases.append(cpe.replace(":igor_sysoev:nginx:", ":f5:nginx:"))
        cpe_aliases.append(cpe.replace(":igor_sysoev:nginx:", ":nginx:nginx:"))

    all_cves = set()
    for base_cpe in cpe_aliases:
        for override_cpe, cves in LOCAL_OVERRIDES.items():
            if base_cpe.startswith(override_cpe):
                all_cves.update(cves)

        headers = {"User-Agent": SCAN_USER_AGENT}
        if nvd_key:
            headers["X-ApiKey"] = nvd_key

        nvd_cpe_limiter.wait(api_delay(nvd_key))
        try:
            resp = session.get(NVD_CVE_API, params={"virtualMatchString": base_cpe}, headers=headers, timeout=30)
            if resp.status_code == 200:
                for v in resp.json().get("vulnerabilities", []):
                    if "cve" in v:
                        all_cves.add(v["cve"]["id"])
            elif resp.status_code == 403:
                print(
                    colorize("\n  [!] NVD Rate Limit (403). Use an API key for higher limits.", Colors.RED, use_colors)
                )
        except Exception as e:
            logger.debug(f"NVD API Error for {base_cpe}: {e}")

    return list(all_cves)
