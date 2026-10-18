import json
import subprocess
import sys

import pytest

from vuln_reports import cli

REPO_ROOT = __import__("pathlib").Path(__file__).resolve().parents[2]


def test_subcommands_registered():
    parser = cli.build_parser()
    for argv in (["parse", "x"], ["enrich", "x"], ["report", "x"], ["run", "x"]):
        assert parser.parse_args(argv).command == argv[0]
    with pytest.raises(SystemExit):
        parser.parse_args([])


def test_parse_writes_findings_json(scans, tmp_path):
    out = tmp_path / "f.json"
    with pytest.raises(SystemExit) as exc:
        cli.main(["parse", str(scans / "nessus.csv"), "-o", str(out)])
    assert exc.value.code == 0
    data = json.loads(out.read_text())
    assert data["kind"] == "scan" and data["scanner_type"] == "nessus_csv"
    assert data["hosts"]["192.0.2.30"]["services"][0]["cves"] == ["CVE-2023-48795", "CVE-2024-6387"]


@pytest.mark.parametrize("command", ["parse", "enrich", "report"])
def test_missing_input_exits_non_zero(tmp_path, capsys, command):
    with pytest.raises(SystemExit) as exc:
        cli.main([command, str(tmp_path / "missing.json")])
    assert exc.value.code == 1


def test_report_rejects_unenriched_findings(scans, tmp_path, capsys):
    findings = tmp_path / "f.json"
    with pytest.raises(SystemExit):
        cli.main(["parse", str(scans / "qualys.csv"), "-o", str(findings)])
    with pytest.raises(SystemExit) as exc:
        cli.main(["report", str(findings), "-C", str(tmp_path / "r.csv")])
    assert exc.value.code == 1
    assert "kind=enriched" in capsys.readouterr().out


def test_module_entry_point_version():
    proc = subprocess.run(
        [sys.executable, "-m", "vuln_reports", "--version"], cwd=REPO_ROOT, capture_output=True, text=True, check=False
    )
    assert proc.returncode == 0 and proc.stdout.startswith("vuln-reports ")


def test_cve_lookup_import_graph_stays_light():
    """The Tines Lambda may have stale site-packages: cve_lookup.py must not import report libraries."""
    code = (
        "import sys, cve_lookup; "
        "heavy = [m for m in ('jinja2','matplotlib','weasyprint','docx','openpyxl','defusedxml') if m in sys.modules]; "
        "print(heavy)"
    )
    proc = subprocess.run([sys.executable, "-c", code], cwd=REPO_ROOT, capture_output=True, text=True, check=True)
    assert proc.stdout.strip() == "[]"


def test_legacy_module_api_still_importable(scans):
    import requests

    import scan2cve

    parser = scan2cve.NmapParser(str(scans / "nmap.xml"), requests.Session(), use_colors=False)
    assert parser.parse() is None
    service = parser.hosts["192.0.2.10"]["services"][0]
    assert list(service) == ["port", "proto", "name", "cpes", "cves"]
    assert service["cves"] == set()
    assert hasattr(parser, "get_cves_for_cpe")

    nessus = scan2cve.NessusCSVParser(str(scans / "nessus.csv"))
    nessus.parse()
    assert nessus.hosts["192.0.2.30"]["hostname"] == "vpn01.example.test"

    import cve_lookup
    import vuln_report

    for name in ("get_cve_data", "get_keys", "validate_cve_id", "csv_safe", "get_output_path", "VERSION"):
        assert hasattr(cve_lookup, name)
    for name in (
        "generate_report",
        "get_detailed_cve_info",
        "get_severity",
        "save_html_report",
        "scan2cve",
        "cve_lookup",
    ):
        assert hasattr(vuln_report, name)
