"""Nessus parsers: .nessus (v2 XML) and CSV exports."""

import csv

from defusedxml import ElementTree as ET

from vuln_reports.models import Host, ScanResult, Service
from vuln_reports.parsers.base import BaseParser
from vuln_reports.parsers.util import add_cve_list, is_ip, split_host


class NessusXMLParser(BaseParser):
    scanner_type = "nessus_xml"

    def parse(self) -> ScanResult:
        try:
            tree = ET.parse(self.file_path)
            root = tree.getroot()
            for host_node in root.findall(".//ReportHost"):
                name = host_node.get("name")
                ip = name if is_ip(name) else ""
                hostname = ""
                tag_ip = host_node.find('.//tag[@name="host-ip"]')
                if tag_ip is not None and not ip:
                    ip = tag_ip.text
                tag_fqdn = host_node.find('.//tag[@name="host-fqdn"]')
                if tag_fqdn is not None:
                    hostname = tag_fqdn.text
                if not hostname and not is_ip(name):
                    hostname = name

                # If the IP slot holds something that is not an IP, move it to hostname.
                if ip and not is_ip(ip):
                    if not hostname:
                        hostname = ip
                    ip = ""

                host_id = name or ip or hostname
                if host_id not in self.hosts:
                    self.hosts[host_id] = Host(ip=ip, hostname=hostname)
                service_map = {}
                for item in host_node.findall("ReportItem"):
                    key = (item.get("port"), item.get("protocol"), item.get("svc_name"))
                    if key not in service_map:
                        service_map[key] = set()
                    for cve in item.findall("cve"):
                        service_map[key].add(cve.text)
                for (port, proto, svc_name), cves in service_map.items():
                    if cves:
                        self.hosts[host_id].services.append(Service(port=port, proto=proto, name=svc_name, cves=cves))
        except Exception as e:
            print(f"Error parsing Nessus XML: {e}")
        return self.result()


class NessusCSVParser(BaseParser):
    scanner_type = "nessus_csv"

    def parse(self) -> ScanResult:
        try:
            with open(self.file_path, encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                service_map, host_data = {}, {}
                for row in reader:
                    raw_host = row.get("Host") or row.get("IP Address")
                    if not raw_host:
                        continue
                    ip, hostname = split_host(raw_host, row.get("FQDN") or row.get("DNS Name") or "")
                    if raw_host not in host_data:
                        host_data[raw_host] = (ip, hostname)
                    key = (raw_host, row.get("Port"), row.get("Protocol"), row.get("Name"))
                    if key not in service_map:
                        service_map[key] = set()
                    add_cve_list(service_map[key], row.get("CVE"))
                for (host_id, port, proto, svc_name), cves in service_map.items():
                    if host_id not in self.hosts:
                        ip, hostname = host_data[host_id]
                        self.hosts[host_id] = Host(ip=ip, hostname=hostname)
                    if cves:
                        self.hosts[host_id].services.append(Service(port=port, proto=proto, name=svc_name, cves=cves))
        except Exception as e:
            print(f"Error parsing Nessus CSV: {e}")
        return self.result()
