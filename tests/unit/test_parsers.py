import pytest

from vuln_reports.parsers import PARSERS, detect_scanner, parse_file
from vuln_reports.parsers.util import add_cve_list, is_broad_cpe, is_ip, split_host


@pytest.mark.parametrize(
    "name, expected",
    [
        ("nmap.xml", "nmap_xml"),
        ("nessus.nessus", "nessus_xml"),
        ("nessus.csv", "nessus_csv"),
        ("qualys.xml", "qualys_xml"),
        ("qualys.csv", "qualys_csv"),
        ("cves_upload.csv", None),
    ],
)
def test_detect_scanner(scans, name, expected):
    assert detect_scanner(str(scans / name)) == expected


def test_detect_scanner_unknown_extension_and_missing_file(tmp_path):
    (tmp_path / "x.txt").write_text("<nmaprun>")
    assert detect_scanner(str(tmp_path / "x.txt")) is None
    assert detect_scanner(str(tmp_path / "missing.xml")) is None


@pytest.mark.parametrize(
    "value, expected", [("192.0.2.1", True), ("host.example.test", False), ("", False), (None, False)]
)
def test_is_ip(value, expected):
    assert is_ip(value) is expected


@pytest.mark.parametrize(
    "cpe, broad",
    [
        ("cpe:/a:openbsd:openssh:8.9p1", False),
        ("cpe:/a:apache:http_server", True),
        ("cpe:/o:linux:linux_kernel", True),
        ("cpe:/a:vendor:product:-", True),
        ("cpe:/a:vendor:product:*", True),
    ],
)
def test_is_broad_cpe(cpe, broad):
    assert is_broad_cpe(cpe) is broad


def test_split_host():
    assert split_host("192.0.2.1", "") == ("192.0.2.1", "")
    assert split_host("192.0.2.1", "a.example.test") == ("192.0.2.1", "a.example.test")
    assert split_host("a.example.test", "") == ("", "a.example.test")


def test_add_cve_list():
    target = set()
    add_cve_list(target, "CVE-1, ,CVE-2,")
    add_cve_list(target, None)
    assert target == {"CVE-1", "CVE-2"}


def test_nmap(scans):
    scan = parse_file(str(scans / "nmap.xml"), "nmap_xml")
    assert scan.scanner_type == "nmap_xml"
    assert list(scan.hosts) == ["192.0.2.10", "192.0.2.11", "app02.example.test", "192.0.2.12"]
    web = scan.hosts["192.0.2.10"]
    assert (web.ip, web.hostname) == ("192.0.2.10", "web01.example.test")
    # Port 8080 has no CPE and is skipped.
    assert [(s.port, s.name) for s in web.services] == [
        ("22", "OpenSSH 8.9p1"),
        ("80", "nginx 1.29.8"),
        ("443", "Apache httpd"),
    ]
    assert web.services[0].cpes == ["cpe:/a:openbsd:openssh:8.9p1", "cpe:/o:linux:linux_kernel"]
    assert all(s.cves == set() for s in web.services)
    assert scan.hosts["app02.example.test"].ip == ""
    assert scan.hosts["192.0.2.12"].services == []


def test_nessus_xml(scans):
    scan = parse_file(str(scans / "nessus.nessus"), "nessus_xml")
    mail = scan.hosts["192.0.2.20"]
    assert mail.hostname == "mail01.example.test"
    assert [(s.port, s.name, s.cves) for s in mail.services] == [
        ("22", "ssh", {"CVE-2023-48795", "CVE-2024-6387"}),
        ("443", "www", {"CVE-2021-44228", "CVE-2099-0001"}),
    ]
    assert (scan.hosts["db01.example.test"].ip, scan.hosts["db01.example.test"].hostname) == (
        "192.0.2.21",
        "db01.example.test",
    )
    # host-ip tag that is not an IP moves to hostname
    files = scan.hosts["files01.example.test"]
    assert (files.ip, files.hostname) == ("", "files01.example.test")


def test_nessus_csv(scans):
    scan = parse_file(str(scans / "nessus.csv"), "nessus_csv")
    vpn = scan.hosts["192.0.2.30"]
    assert vpn.hostname == "vpn01.example.test"
    assert vpn.services[0].cves == {"CVE-2023-48795", "CVE-2024-6387"}
    log4j = scan.hosts["192.0.2.31"]
    assert [(s.port, s.cves) for s in log4j.services] == [("8443", {"CVE-2021-44228", "CVE-2022-0001"})]
    assert scan.hosts["legacy01.example.test"].services[0].port_proto == "Host-level"


def test_qualys_xml(scans):
    scan = parse_file(str(scans / "qualys.xml"), "qualys_xml")
    erp = scan.hosts["192.0.2.40"]
    assert erp.hostname == "erp01.example.test"
    assert [s.cves for s in erp.services] == [
        {"CVE-2023-48795"},
        {"CVE-2024-6387"},
        {"CVE-2021-44228", "CVE-2022-0001"},
    ]
    assert scan.hosts["crm01.example.test"].ip == ""


def test_qualys_csv_skips_preamble_and_defaults(scans):
    scan = parse_file(str(scans / "qualys.csv"), "qualys_csv")
    assert scan.hosts["192.0.2.50"].hostname == "hr01.example.test"
    no_port = scan.hosts["192.0.2.51"].services
    assert [(s.port, s.proto, s.cves) for s in no_port] == [("0", "tcp", {"CVE-2021-44228", "CVE-2022-0001"})]


def test_qualys_csv_without_header(tmp_path, capsys):
    path = tmp_path / "q.csv"
    path.write_text('"Report"\n"nothing here"\n')
    scan = parse_file(str(path), "qualys_csv")
    assert scan.hosts == {}
    assert "Could not find header" in capsys.readouterr().out


@pytest.mark.parametrize("scanner_type", ["nmap_xml", "nessus_xml", "qualys_xml"])
def test_malformed_xml_reports_error(tmp_path, capsys, scanner_type):
    path = tmp_path / "bad.xml"
    path.write_text("<nmaprun><host>")
    assert parse_file(str(path), scanner_type).hosts == {}
    assert "Error parsing" in capsys.readouterr().out


@pytest.mark.parametrize("scanner_type", ["nmap_xml", "nessus_xml", "qualys_xml"])
def test_entity_expansion_is_rejected(tmp_path, capsys, scanner_type):
    """defusedxml refuses DTD entities (billion laughs / XXE) instead of expanding them."""
    path = tmp_path / "evil.xml"
    path.write_text(
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;">]>'
        '<nmaprun><host><address addr="&b;"/></host></nmaprun>'
    )
    assert parse_file(str(path), scanner_type).hosts == {}
    assert "Error parsing" in capsys.readouterr().out


def test_all_parsers_registered():
    assert set(PARSERS) == {"nmap_xml", "nessus_xml", "nessus_csv", "qualys_xml", "qualys_csv"}
