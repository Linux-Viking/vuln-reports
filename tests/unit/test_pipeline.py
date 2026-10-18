from vuln_reports.enrichment import pipeline
from vuln_reports.models import Host, ScanResult, Service
from vuln_reports.parsers import parse_file


def test_specific_cpes_reports_broad_ones(scans):
    scan = parse_file(str(scans / "nmap.xml"), "nmap_xml")
    broad = []
    cpes = pipeline.specific_cpes(scan, on_broad=broad.append)
    assert cpes == {
        "cpe:/a:openbsd:openssh:8.9p1",
        "cpe:/a:igor_sysoev:nginx:1.29.8",
        "cpe:/a:apache:http_server:2.4.49",
    }
    assert broad == ["cpe:/o:linux:linux_kernel", "cpe:/a:apache:http_server"]


def test_lookup_and_apply_cpes(net, scans):
    scan = parse_file(str(scans / "nmap.xml"), "nmap_xml")
    cpe_to_cves = pipeline.lookup_cpes(pipeline.specific_cpes(scan), None, max_workers=4)
    pipeline.apply_cpe_results(scan, cpe_to_cves)
    web = scan.hosts["192.0.2.10"].services
    assert web[0].cves == {"CVE-2023-48795", "CVE-2024-6387"}
    assert web[1].cves == {"CVE-2022-0001", "CVE-2026-42945"}
    assert web[2].cves == set()  # broad CPE never looked up


def test_apply_cpe_results_leaves_non_cpe_services_alone():
    scan = ScanResult("nessus_xml", "x", {"h": Host("192.0.2.1", "", [Service("22", "tcp", "ssh", {"CVE-1"})])})
    pipeline.apply_cpe_results(scan, {})
    assert scan.hosts["h"].services[0].cves == {"CVE-1"}


def test_enrich_cves_maps_failures_to_error_entries(net, capsys):
    result = pipeline.enrich_cves(["CVE-2021-44228", "CVE-2099-0001"], max_workers=2)
    assert result["CVE-2021-44228"]["cvss_score"] == 10.0
    assert set(result["CVE-2099-0001"]) == {"cve_id", "error"}
    out = capsys.readouterr().out
    assert "[*] Fetching enrichment data for 2 unique CVEs..." in out
    assert "[!] Error enriching CVE-2099-0001" in out
