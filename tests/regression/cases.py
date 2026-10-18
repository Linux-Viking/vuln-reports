"""Regression cases: CLI invocations whose outputs must match the reference release exactly.

``{work}`` in an argument expands to the absolute scratch directory the case
runs in (automation such as Tines passes absolute ``/tmp/...`` paths the same way).
``inputs`` are copied from tests/fixtures/scans; ``pre_files`` are created first.
"""

ALL_CVES = [
    "CVE-2021-44228",
    "CVE-2023-48795",
    "CVE-2024-6387",
    "CVE-2014-0160",
    "CVE-2022-0001",
    "CVE-2026-42945",
    "CVE-2021-41773",
    "CVE-2099-0001",
]

# Synthetic, obviously fake credentials; they only toggle code paths.
FAKE_KEYS = {
    "GITHUB_TOKEN": "test-github-token",
    "NVD_API_KEY": "test-nvd-key",
    "VULNERS_API_KEY": "test-vulners-key",
    "CIRCL_API_KEY": "test-circl-key",
}

SCANS = ["nmap.xml", "nessus.nessus", "nessus.csv", "qualys.xml", "qualys.csv"]


def _case(name, script, args, inputs=(), env=None, pre_files=None, python_min=None):
    return {
        "name": name,
        "script": script,
        "args": list(args),
        "inputs": list(inputs),
        "env": dict(env or {}),
        "pre_files": dict(pre_files or {}),
        "python_min": python_min,
    }


CASES = [
    # --- cve_lookup.py: the call shapes a Tines automation uses -------------
    _case(
        "lookup_tines_paste",
        "cve_lookup.py",
        [
            "-c",
            "{work}/results.csv",
            "CVE-2021-44228, cve-2023-48795\nCVE-2024-6387 junk CVE-2099-0001\nCVE-2021-44228",
        ],
    ),
    _case(
        "lookup_tines_file",
        "cve_lookup.py",
        ["-c", "{work}/results.csv", "-f", "{work}/cves_upload.csv"],
        inputs=["cves_upload.csv"],
    ),
    _case(
        "lookup_tines_keys",
        "cve_lookup.py",
        ["-c", "{work}/results.csv", ", ".join(ALL_CVES)],
        env=FAKE_KEYS,
    ),
    _case(
        "lookup_existing_results",
        "cve_lookup.py",
        ["-c", "results.csv", "CVE-2022-0001"],
        pre_files={"results.csv": "stale\n"},
    ),
    # --- cve_lookup.py: other flags -----------------------------------------
    _case("lookup_all_formats", "cve_lookup.py", ALL_CVES + ["-A", "out", "-n"]),
    _case("lookup_all_default_base", "cve_lookup.py", ["CVE-2022-0001", "-A"]),
    _case(
        "lookup_individual_formats",
        "cve_lookup.py",
        ["-t", "t", "-G", "g", "-x", "x.xml", "-j", "-c", "c", "CVE-2021-44228"],
    ),
    _case(
        "lookup_poc_mode", "cve_lookup.py", ["-p", "CVE-2021-44228", "CVE-2023-48795", "CVE-2022-0001", "CVE-2099-0001"]
    ),
    _case(
        "lookup_keys_json",
        "cve_lookup.py",
        ["-j", "keys", "CVE-2014-0160", "CVE-2024-6387", "CVE-2023-48795"],
        env=FAKE_KEYS,
    ),
    # argparse --help layout is stdlib formatting and changed in Python 3.13 (goldens use 3.13+).
    _case("lookup_no_args", "cve_lookup.py", [], python_min=(3, 13)),
    _case("lookup_version", "cve_lookup.py", ["--version"]),
    _case("lookup_missing_file", "cve_lookup.py", ["-f", "nope.txt"]),
    # --- scan2cve.py --------------------------------------------------------
    *[
        _case(f"scan2cve_{scan.replace('.', '_')}", "scan2cve.py", [scan, "-o", "cves.txt", "-n"], inputs=[scan])
        for scan in SCANS
    ],
    _case("scan2cve_forced_type", "scan2cve.py", ["nessus.csv", "-t", "nessus_csv"], inputs=["nessus.csv"]),
    _case("scan2cve_undetectable", "scan2cve.py", ["cves_upload.csv"], inputs=["cves_upload.csv"]),
    _case("scan2cve_missing", "scan2cve.py", ["missing.xml"]),
    # --- vuln_report.py -----------------------------------------------------
    *[
        _case(f"report_{scan.replace('.', '_')}_all", "vuln_report.py", [scan, "-A", "report"], inputs=[scan])
        for scan in SCANS
    ],
    _case(
        "report_severity_filter",
        "vuln_report.py",
        ["nessus.nessus", "-s", "Critical, high", "-C", "filtered.csv", "-H", "filtered.html"],
        inputs=["nessus.nessus"],
    ),
    _case("report_default_csv", "vuln_report.py", ["qualys.csv"], inputs=["qualys.csv"]),
    _case(
        "report_threads_md_xlsx",
        "vuln_report.py",
        ["nmap.xml", "-t", "2", "-M", "n.md", "-X", "n.xlsx"],
        inputs=["nmap.xml"],
    ),
    _case(
        "report_with_keys", "vuln_report.py", ["nessus.nessus", "-C", "k.csv"], inputs=["nessus.nessus"], env=FAKE_KEYS
    ),
    _case("report_missing", "vuln_report.py", ["missing.nessus"]),
    _case("report_undetectable", "vuln_report.py", ["cves_upload.csv"], inputs=["cves_upload.csv"]),
]
