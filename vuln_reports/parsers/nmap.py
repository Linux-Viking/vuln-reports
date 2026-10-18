"""Nmap XML (-oX) parser. Services carry CPEs; CVEs are resolved during enrichment."""

from defusedxml import ElementTree as ET

from vuln_reports.models import Host, ScanResult, Service
from vuln_reports.parsers.base import BaseParser
from vuln_reports.parsers.util import is_ip


class NmapParser(BaseParser):
    scanner_type = "nmap_xml"

    def parse(self) -> ScanResult:
        try:
            tree = ET.parse(self.file_path)
            root = tree.getroot()
            for host_node in root.findall("host"):
                addr_tag = host_node.find("address")
                raw_addr = addr_tag.get("addr") if addr_tag is not None else ""

                # If the address is an IP use it, otherwise it's a hostname.
                ip = ""
                hostname = ""
                if is_ip(raw_addr):
                    ip = raw_addr
                else:
                    hostname = raw_addr

                hostname_node = host_node.find(".//hostname")
                if hostname_node is not None:
                    name = hostname_node.get("name", "")
                    if name:
                        hostname = name

                host_id = raw_addr or ip or hostname or "Unknown"
                if host_id not in self.hosts:
                    self.hosts[host_id] = Host(ip=ip, hostname=hostname)
                ports_tag = host_node.find("ports")
                if ports_tag is None:
                    continue
                for port_node in ports_tag.findall("port"):
                    service_tag = port_node.find("service")
                    if service_tag is not None:
                        cpes = [c.text for c in service_tag.findall("cpe")]
                        if not cpes:
                            continue
                        product = service_tag.get("product", service_tag.get("name", "unknown"))
                        self.hosts[host_id].services.append(
                            Service(
                                port=port_node.get("portid"),
                                proto=port_node.get("protocol"),
                                name=f"{product} {service_tag.get('version', '')}".strip(),
                                cpes=cpes,
                            )
                        )
        except Exception as e:
            print(f"Error parsing Nmap XML: {e}")
        return self.result()
