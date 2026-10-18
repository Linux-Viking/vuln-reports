"""Scanner parsers: Nmap, Nessus and Qualys exports -> :class:`ScanResult`."""

from __future__ import annotations

import os

from vuln_reports.models import ScanResult
from vuln_reports.parsers.base import BaseParser
from vuln_reports.parsers.nessus import NessusCSVParser, NessusXMLParser
from vuln_reports.parsers.nmap import NmapParser
from vuln_reports.parsers.qualys import QualysCSVParser, QualysXMLParser
from vuln_reports.parsers.util import is_broad_cpe, is_ip

PARSERS = {
    "nmap_xml": NmapParser,
    "nessus_xml": NessusXMLParser,
    "nessus_csv": NessusCSVParser,
    "qualys_xml": QualysXMLParser,
    "qualys_csv": QualysCSVParser,
}
SCANNER_TYPES = list(PARSERS)


def detect_scanner(file_path: str) -> str | None:
    """Guess the scanner type from the extension and the first 2 KB of the file."""
    ext = os.path.splitext(file_path)[1].lower()
    if ext == ".nessus":
        return "nessus_xml"
    if ext == ".xml":
        try:
            with open(file_path, encoding="utf-8", errors="ignore") as f:
                head = f.read(2048)
            if "<nmaprun" in head:
                return "nmap_xml"
            if "<NessusClientData_v2" in head:
                return "nessus_xml"
            if "<QUALYS" in head or "<SCAN" in head or "<ASSET_DATA_REPORT" in head:
                return "qualys_xml"
        except OSError:
            pass
    if ext == ".csv":
        try:
            with open(file_path, encoding="utf-8", errors="ignore") as f:
                head = f.read(2048)
            if "Plugin ID" in head and "CVE" in head:
                return "nessus_csv"
            if "IP" in head and "CVE ID" in head:
                return "qualys_csv"
        except OSError:
            pass
    return None


def get_parser(scanner_type: str, file_path: str, use_colors: bool = True) -> BaseParser:
    return PARSERS[scanner_type](file_path, use_colors)


def parse_file(file_path: str, scanner_type: str, use_colors: bool = True) -> ScanResult:
    return get_parser(scanner_type, file_path, use_colors).parse()


__all__ = [
    "PARSERS",
    "SCANNER_TYPES",
    "BaseParser",
    "NessusCSVParser",
    "NessusXMLParser",
    "NmapParser",
    "QualysCSVParser",
    "QualysXMLParser",
    "detect_scanner",
    "get_parser",
    "is_broad_cpe",
    "is_ip",
    "parse_file",
]
