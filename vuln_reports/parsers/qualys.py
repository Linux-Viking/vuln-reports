"""Qualys parsers: XML scan/asset reports and CSV exports (with report preamble)."""

from __future__ import annotations

import csv

from defusedxml import ElementTree as ET

from vuln_reports.models import Host, ScanResult, Service
from vuln_reports.parsers.base import BaseParser
from vuln_reports.parsers.util import add_cve_list, split_host


def _cve_id_list(vuln, cves: set) -> None:
    cve_list = vuln.find("CVE_ID_LIST")
    if cve_list is not None:
        for cve_id_node in cve_list.findall("CVE_ID"):
            cves.add(cve_id_node.findtext("ID"))


class QualysXMLParser(BaseParser):
    scanner_type = "qualys_xml"

    def parse(self) -> ScanResult:
        try:
            tree = ET.parse(self.file_path)
            root = tree.getroot()
            assets = root.findall(".//IP") or root.findall(".//ASSET")
            for asset in assets:
                val = asset.get("value") or asset.findtext("IP_ADDRESS")
                if not val:
                    continue
                hostname = asset.get("name") or asset.findtext("DNS") or asset.findtext("DNS_NAME") or ""
                ip, hostname = split_host(val, hostname)
                if val not in self.hosts:
                    self.hosts[val] = Host(ip=ip, hostname=hostname)
                services = self.hosts[val].services
                for cat in asset.findall(".//CAT"):
                    port, proto, svc_name = cat.get("port"), cat.get("protocol"), cat.get("value")
                    for vuln in cat.findall("VULN"):
                        cves = set()
                        cve_attr = vuln.get("cveid")
                        if cve_attr:
                            for c in cve_attr.split(","):
                                cves.add(c.strip())
                        _cve_id_list(vuln, cves)
                        if cves:
                            services.append(
                                Service(port=port or "0", proto=proto or "tcp", name=svc_name or "unknown", cves=cves)
                            )
                for vuln in asset.findall("./VULN_LIST/VULN") or asset.findall(".//VULN"):
                    # Skip VULNs already handled under a CAT (v1.0.0 semantics, kept as-is).
                    if any(s for s in services if vuln in asset.findall(".//CAT/VULN")):
                        continue
                    port, proto, svc_name = vuln.findtext("PORT"), vuln.findtext("PROTOCOL"), vuln.findtext("SERVICE")
                    cves = set()
                    _cve_id_list(vuln, cves)
                    if cves:
                        services.append(
                            Service(port=port or "0", proto=proto or "tcp", name=svc_name or "unknown", cves=cves)
                        )
        except Exception as e:
            print(f"Error parsing Qualys XML: {e}")
        return self.result()


def _find_header(lines: list[str]) -> int:
    for i, line in enumerate(lines):
        if '"IP"' in line and '"Port"' in line and '"CVE ID"' in line:
            return i
        if "IP," in line and "Port," in line and "CVE ID" in line:
            return i
    for i, line in enumerate(lines):
        if "IP" in line and "Port" in line and "CVE ID" in line:
            return i
    return -1


class QualysCSVParser(BaseParser):
    scanner_type = "qualys_csv"

    def parse(self) -> ScanResult:
        try:
            with open(self.file_path, encoding="utf-8-sig") as f:
                lines = f.readlines()
            header_index = _find_header(lines)
            if header_index == -1:
                print(f"[!] Could not find header in Qualys CSV: {self.file_path}")
                return self.result()
            reader = csv.DictReader(lines[header_index:])
            service_map, host_data = {}, {}
            for row in reader:
                val = row.get("IP")
                if not val:
                    continue
                ip, hostname = split_host(val, row.get("DNS") or row.get("FQDN") or "")
                if val not in host_data:
                    host_data[val] = (ip, hostname)
                svc_name = row.get("Title") or row.get("Service")
                key = (val, row.get("Port"), row.get("Protocol"), svc_name)
                if key not in service_map:
                    service_map[key] = set()
                add_cve_list(service_map[key], row.get("CVE ID"))
            for (val, port, proto, svc_name), cves in service_map.items():
                if val not in self.hosts:
                    ip, hostname = host_data[val]
                    self.hosts[val] = Host(ip=ip, hostname=hostname)
                if cves:
                    self.hosts[val].services.append(
                        Service(port=port or "0", proto=proto or "tcp", name=svc_name or "unknown", cves=cves)
                    )
        except Exception as e:
            print(f"Error parsing Qualys CSV: {e}")
        return self.result()
