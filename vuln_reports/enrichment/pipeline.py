"""Concurrent enrichment of whole scans: CPE -> CVE resolution and CVE intelligence."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import requests

from vuln_reports.enrichment.lookup import get_cve_data
from vuln_reports.enrichment.nvd import cves_for_cpe
from vuln_reports.models import ScanResult
from vuln_reports.parsers.util import is_broad_cpe


def specific_cpes(scan: ScanResult, on_broad=None) -> set:
    """Unique versioned CPEs in the scan; ``on_broad(cpe)`` is called for each skipped generic CPE."""
    cpes = set()
    for host in scan.hosts.values():
        for service in host.services:
            for cpe in service.cpes or []:
                if not is_broad_cpe(cpe):
                    cpes.add(cpe)
                elif on_broad is not None:
                    on_broad(cpe)
    return cpes


def lookup_cpes(cpes, nvd_key: str | None, max_workers: int, use_colors: bool = True) -> dict:
    """Map each CPE to its CVE list using ``max_workers`` concurrent NVD queries."""
    session = requests.Session()
    cpe_to_cves = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(cves_for_cpe, session, cpe, nvd_key, use_colors): cpe for cpe in cpes}
        for f in as_completed(futures):
            cpe = futures[f]
            try:
                cpe_to_cves[cpe] = f.result()
            except Exception as e:
                print(f"  [!] Error fetching {cpe}: {e}")
                cpe_to_cves[cpe] = []
    return cpe_to_cves


def apply_cpe_results(scan: ScanResult, cpe_to_cves: dict) -> None:
    """Set each CPE-bearing service's CVEs from the lookup results."""
    for host in scan.hosts.values():
        for service in host.services:
            if service.cpes is None:
                continue
            service.cves = cves_for_service(service, cpe_to_cves)


def cves_for_service(service, cpe_to_cves: dict) -> set:
    service_cves = []
    for cpe in service.cpes or []:
        if cpe in cpe_to_cves:
            service_cves.extend(cpe_to_cves[cpe])
    return set(service_cves)


def enrich_cves(
    cve_ids: list,
    github_token: str | None = None,
    nvd_key: str | None = None,
    vulners_key: str | None = None,
    circl_key: str | None = None,
    max_workers: int = 10,
) -> dict[str, dict[str, Any]]:
    """Fetch intelligence for every CVE concurrently. Failed lookups map to ``{"cve_id", "error"}``."""
    session = requests.Session()
    cve_details = {}
    print(f"[*] Fetching enrichment data for {len(cve_ids)} unique CVEs...")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(get_cve_data, session, cve_id, github_token, nvd_key, vulners_key, circl_key): cve_id
            for cve_id in cve_ids
        }
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
