"""Common data model passed between the parse, enrich and report stages.

Values deliberately keep the sentinels the original scripts used ("N/A",
"Yes"/"No", a CVSS score that is a number or "N/A") so every output format is
byte-for-byte identical to v1.0.0. ``to_dict``/``from_dict`` give the JSON form
used to hand data between ``vuln_reports parse | enrich | report``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SCHEMA_VERSION = 1


@dataclass
class Service:
    """A port/protocol/service on a host and the CVEs (or CPEs) found there.

    ``port`` is the string "0" for host-level findings. ``cpes`` is only set by
    the Nmap parser; those services get their CVEs during enrichment.
    """

    port: str | None
    proto: str | None
    name: str | None
    cves: set[str] = field(default_factory=set)
    cpes: list[str] | None = None

    @property
    def port_proto(self) -> str:
        return f"{self.port}/{self.proto}" if self.port != "0" else "Host-level"

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"port": self.port, "proto": self.proto, "name": self.name}
        if self.cpes is not None:
            data["cpes"] = list(self.cpes)
        data["cves"] = sorted(self.cves)
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Service:
        return cls(
            port=data.get("port"),
            proto=data.get("proto"),
            name=data.get("name"),
            cves=set(data.get("cves", [])),
            cpes=list(data["cpes"]) if data.get("cpes") is not None else None,
        )


@dataclass
class Host:
    ip: str
    hostname: str
    services: list[Service] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"ip": self.ip, "hostname": self.hostname, "services": [s.to_dict() for s in self.services]}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Host:
        return cls(
            ip=data.get("ip", ""),
            hostname=data.get("hostname", ""),
            services=[Service.from_dict(s) for s in data.get("services", [])],
        )


@dataclass
class ScanResult:
    """Output of a parser: hosts keyed by the scanner's own host identifier."""

    scanner_type: str
    source_file: str
    hosts: dict[str, Host] = field(default_factory=dict)

    def all_cve_ids(self) -> set[str]:
        cve_ids: set[str] = set()
        for host in self.hosts.values():
            for service in host.services:
                cve_ids.update(service.cves)
        return cve_ids

    def cve_to_hosts(self) -> dict[str, list[tuple[str, str, str, str | None]]]:
        """Map CVE -> unique (ip, hostname, port/proto, service name) tuples, in scan order."""
        mapping: dict[str, list[tuple[str, str, str, str | None]]] = {}
        for host in self.hosts.values():
            for service in host.services:
                for cve_id in service.cves:
                    entries = mapping.setdefault(cve_id, [])
                    entry = (host.ip, host.hostname, service.port_proto, service.name)
                    if entry not in entries:
                        entries.append(entry)
        return mapping

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": "scan",
            "scanner_type": self.scanner_type,
            "source_file": self.source_file,
            "hosts": {host_id: host.to_dict() for host_id, host in self.hosts.items()},
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScanResult:
        _check_schema(data)
        return cls(
            scanner_type=data["scanner_type"],
            source_file=data["source_file"],
            hosts={host_id: Host.from_dict(h) for host_id, h in data.get("hosts", {}).items()},
        )


@dataclass
class AffectedProduct:
    vendor: str
    product: str
    versions: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {"vendor": self.vendor, "product": self.product, "versions": list(self.versions)}

    @property
    def display(self) -> str:
        return f"{self.product} ({', '.join(self.versions)})"


@dataclass
class CveIntel:
    """Enrichment result for one CVE. ``error`` is set when the lookup failed."""

    cve_id: str
    title: str = "N/A"
    description: str = "N/A"
    affected: list[AffectedProduct] = field(default_factory=list)
    cisa_kev: str = "No"
    cvss_score: Any = "N/A"
    exploitability: str = "Theoretical / Unknown"
    poc_available: str = "No"
    poc_link: str = "N/A"
    threat_vector: Any = "N/A"
    user_interaction: Any = "N/A"
    epss_score: Any = "N/A"
    attack_complexity: Any = "N/A"
    references: list[str] = field(default_factory=list)
    remediation: str = "N/A"
    error: str | None = None

    # Key order matches the dict v1.0.0 returned; JSON/XML exports depend on it.
    _FIELDS = (
        "cve_id",
        "title",
        "description",
        "affected",
        "cisa_kev",
        "cvss_score",
        "exploitability",
        "poc_available",
        "poc_link",
        "threat_vector",
        "user_interaction",
        "epss_score",
        "attack_complexity",
        "references",
        "remediation",
    )

    def to_dict(self) -> dict[str, Any]:
        if self.error is not None:
            return {"cve_id": self.cve_id, "error": self.error}
        data = {name: getattr(self, name) for name in self._FIELDS}
        data["affected"] = [a.to_dict() for a in self.affected]
        data["references"] = list(self.references)
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CveIntel:
        if "error" in data:
            return cls(cve_id=data.get("cve_id", "Unknown"), error=data["error"])
        kwargs = {name: data[name] for name in cls._FIELDS if name in data}
        kwargs["affected"] = [
            AffectedProduct(a.get("vendor", "Unknown"), a.get("product", "Unknown"), list(a.get("versions", [])))
            for a in data.get("affected", [])
        ]
        kwargs["references"] = list(data.get("references", []))
        return cls(**kwargs)


@dataclass
class Finding:
    """One flattened (host, service, CVE) row — the unit every report is built from."""

    ip: str
    hostname: str
    cve_id: str
    port_proto: str
    service: str | None
    intel: dict[str, Any]


@dataclass
class EnrichedScan:
    """A parsed scan plus enrichment for every CVE it references."""

    scan: ScanResult
    intel: dict[str, dict[str, Any]] = field(default_factory=dict)

    def findings(self) -> list[Finding]:
        """Rows in report order: hosts sorted by id, services in scan order, CVEs sorted."""
        rows = []
        for _, host in sorted(self.scan.hosts.items()):
            for service in host.services:
                for cve_id in sorted(service.cves):
                    rows.append(
                        Finding(
                            ip=host.ip,
                            hostname=host.hostname,
                            cve_id=cve_id,
                            port_proto=service.port_proto,
                            service=service.name,
                            intel=self.intel.get(cve_id, {}),
                        )
                    )
        return rows

    def to_dict(self) -> dict[str, Any]:
        data = self.scan.to_dict()
        data["kind"] = "enriched"
        data["intel"] = self.intel
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EnrichedScan:
        if data.get("kind") != "enriched":
            raise ValueError("expected output of 'vuln_reports enrich' (kind=enriched)")
        return cls(scan=ScanResult.from_dict(data), intel=dict(data.get("intel", {})))


def _check_schema(data: dict[str, Any]) -> None:
    version = data.get("schema_version")
    if version != SCHEMA_VERSION:
        raise ValueError(f"unsupported schema_version {version!r} (expected {SCHEMA_VERSION})")
