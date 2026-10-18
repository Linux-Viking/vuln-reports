"""CVE enrichment: CIRCL records, NVD (CVSS fallback, CPE -> CVE), EPSS, KEV status,
exploit/PoC discovery and optional Vulners data.

Import submodules directly (``from vuln_reports.enrichment.lookup import get_cve_data``);
this package intentionally imports nothing so ``cve_lookup.py`` stays lightweight.
"""
