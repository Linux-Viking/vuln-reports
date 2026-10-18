import pytest

from vuln_reports.models import (
    SCHEMA_VERSION,
    AffectedProduct,
    CveIntel,
    EnrichedScan,
    Host,
    ScanResult,
    Service,
)


def make_scan():
    return ScanResult(
        scanner_type="nessus_xml",
        source_file="scan.nessus",
        hosts={
            "b-host": Host("192.0.2.2", "b.example.test", [Service("443", "tcp", "www", {"CVE-2021-2"})]),
            "a-host": Host(
                "192.0.2.1",
                "",
                [
                    Service("22", "tcp", "ssh", {"CVE-2021-2", "CVE-2021-1"}),
                    Service("0", "tcp", "general", {"CVE-2021-1"}),
                ],
            ),
        },
    )


def test_port_proto_host_level():
    assert Service("22", "tcp", "ssh").port_proto == "22/tcp"
    assert Service("0", "tcp", "general").port_proto == "Host-level"


def test_all_cve_ids():
    assert make_scan().all_cve_ids() == {"CVE-2021-1", "CVE-2021-2"}


def test_cve_to_hosts_keeps_scan_order_and_dedupes():
    scan = make_scan()
    scan.hosts["a-host"].services.append(Service("22", "tcp", "ssh", {"CVE-2021-2"}))
    mapping = scan.cve_to_hosts()
    assert mapping["CVE-2021-2"] == [
        ("192.0.2.2", "b.example.test", "443/tcp", "www"),
        ("192.0.2.1", "", "22/tcp", "ssh"),
    ]
    assert mapping["CVE-2021-1"] == [("192.0.2.1", "", "22/tcp", "ssh"), ("192.0.2.1", "", "Host-level", "general")]


def test_scan_result_round_trip():
    scan = make_scan()
    scan.hosts["a-host"].services[0].cpes = ["cpe:/a:openbsd:openssh:8.9p1"]
    data = scan.to_dict()
    assert data["schema_version"] == SCHEMA_VERSION and data["kind"] == "scan"
    assert data["hosts"]["a-host"]["services"][0]["cves"] == ["CVE-2021-1", "CVE-2021-2"]
    assert ScanResult.from_dict(data) == scan


def test_schema_version_is_checked():
    data = make_scan().to_dict()
    data["schema_version"] = 99
    with pytest.raises(ValueError, match="schema_version"):
        ScanResult.from_dict(data)


def test_cve_intel_dict_matches_legacy_key_order():
    intel = CveIntel(cve_id="CVE-2021-1", affected=[AffectedProduct("V", "P", ["1.0"])], references=["r"])
    assert list(intel.to_dict()) == [
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
    ]
    assert CveIntel.from_dict(intel.to_dict()) == intel


def test_cve_intel_error_form():
    assert CveIntel(cve_id="CVE-2099-1", error="Not found").to_dict() == {"cve_id": "CVE-2099-1", "error": "Not found"}
    assert CveIntel.from_dict({"cve_id": "CVE-2099-1", "error": "x"}).error == "x"


def test_affected_display():
    assert AffectedProduct("V", "OpenSSH", ["8.5p1", "9.0"]).display == "OpenSSH (8.5p1, 9.0)"


def test_findings_row_order():
    enriched = EnrichedScan(make_scan(), {"CVE-2021-1": {"title": "one"}})
    rows = [(f.ip, f.port_proto, f.cve_id) for f in enriched.findings()]
    assert rows == [
        ("192.0.2.1", "22/tcp", "CVE-2021-1"),
        ("192.0.2.1", "22/tcp", "CVE-2021-2"),
        ("192.0.2.1", "Host-level", "CVE-2021-1"),
        ("192.0.2.2", "443/tcp", "CVE-2021-2"),
    ]
    assert enriched.findings()[0].intel == {"title": "one"}
    assert enriched.findings()[1].intel == {}


def test_enriched_round_trip_and_kind_check():
    enriched = EnrichedScan(make_scan(), {"CVE-2021-1": {"cve_id": "CVE-2021-1", "error": "x"}})
    data = enriched.to_dict()
    assert data["kind"] == "enriched"
    assert EnrichedScan.from_dict(data) == enriched
    with pytest.raises(ValueError, match="enriched"):
        EnrichedScan.from_dict(make_scan().to_dict())
