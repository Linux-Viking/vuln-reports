#!/usr/bin/env python3
"""
Scan2CVE: Unified scanner parser (Nmap, Nessus, Qualys) to extract CVEs for cve_lookup.py integration.

Thin entry point kept for backward compatibility. The implementation lives in
``vuln_reports``; the parser classes below keep the v1.0.0 API (``parse()``
fills ``self.hosts`` with plain dicts) for code that imports this module.
"""

import os
import sys

# Suppress GLib-GIO warnings
os.environ["GIO_USE_VFS"] = "local"
if "G_MESSAGES_DEBUG" not in os.environ:
    os.environ["G_MESSAGES_DEBUG"] = "none"

import logging  # noqa: E402

from vuln_reports import parsers as _parsers  # noqa: E402
from vuln_reports.commands.scan2cve import run  # noqa: E402
from vuln_reports.console import Colors, colorize  # noqa: E402
from vuln_reports.enrichment.http import SCAN_USER_AGENT as USER_AGENT  # noqa: E402
from vuln_reports.enrichment.nvd import cves_for_cpe  # noqa: E402
from vuln_reports.parsers import detect_scanner, is_broad_cpe, is_ip  # noqa: E402

NVD_API_DELAY = 0.6  # Kept for compatibility; limiter delays live in vuln_reports.enrichment.http

# v1.0.0 configured root logging at import time; vuln_report.py output depends on it.
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def _legacy_hosts(scan):
    hosts = {}
    for host_id, host in scan.hosts.items():
        services = []
        for s in host.services:
            service = {"port": s.port, "proto": s.proto, "name": s.name}
            if s.cpes is not None:
                service["cpes"] = s.cpes
            service["cves"] = s.cves
            services.append(service)
        hosts[host_id] = {"ip": host.ip, "hostname": host.hostname, "services": services}
    return hosts


class _LegacyParseMixin:
    def parse(self):
        self.hosts = _legacy_hosts(super().parse())


class BaseParser(_parsers.BaseParser):
    pass


class NmapParser(_LegacyParseMixin, _parsers.NmapParser):
    def __init__(self, file_path: str, session, use_colors: bool = True):
        super().__init__(file_path, use_colors)
        self.session = session

    def get_cves_for_cpe(self, cpe: str, nvd_key: str = None):
        return cves_for_cpe(self.session, cpe, nvd_key, self.use_colors)


class NessusXMLParser(_LegacyParseMixin, _parsers.NessusXMLParser):
    pass


class NessusCSVParser(_LegacyParseMixin, _parsers.NessusCSVParser):
    pass


class QualysXMLParser(_LegacyParseMixin, _parsers.QualysXMLParser):
    pass


class QualysCSVParser(_LegacyParseMixin, _parsers.QualysCSVParser):
    pass


__all__ = [
    "NVD_API_DELAY",
    "USER_AGENT",
    "BaseParser",
    "Colors",
    "NessusCSVParser",
    "NessusXMLParser",
    "NmapParser",
    "QualysCSVParser",
    "QualysXMLParser",
    "colorize",
    "detect_scanner",
    "is_broad_cpe",
    "is_ip",
    "main",
]


def main():
    run(sys.argv[1:])


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(0)
