"""Golden-master regression: today's CLI output must equal v1.0.0's on the same inputs.

Goldens live in tests/regression/golden and are produced only by
generate_goldens.py from a release tag. A failure here means user-visible
output changed; if that is intentional, regenerate from the new release tag
and call it out in the release notes.
"""

import difflib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cases import CASES  # noqa: E402
from harness import read_golden, run_case, run_staged  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.regression
@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_matches_v1_0_0(case):
    if case.get("python_min") and sys.version_info < case["python_min"]:
        pytest.skip(f"output owned by the stdlib differs before Python {'.'.join(map(str, case['python_min']))}")
    expected = read_golden(case["name"])
    actual = run_case(REPO_ROOT, case)

    assert sorted(actual) == sorted(expected), "set of output files changed"
    problems = []
    for name in sorted(expected):
        if actual[name] != expected[name]:
            diff = difflib.unified_diff(
                expected[name].decode("utf-8", "replace").splitlines(keepends=True),
                actual[name].decode("utf-8", "replace").splitlines(keepends=True),
                fromfile=f"golden/{case['name']}/{name}",
                tofile=f"actual/{name}",
                n=2,
            )
            problems.append("".join(list(diff)[:80]) or f"{name}: bytes differ (line endings?)")
    assert not problems, "\n".join(problems)


REPORT_CASES = [c for c in CASES if c["script"] == "vuln_report.py"]


@pytest.mark.regression
@pytest.mark.parametrize("case", REPORT_CASES, ids=[c["name"] for c in REPORT_CASES])
def test_cli_run_matches_vuln_report(case):
    """``python -m vuln_reports run ...`` must produce exactly what ``vuln_report.py ...`` did."""
    expected = read_golden(case["name"])
    actual = run_case(REPO_ROOT, {**case, "script": "-m vuln_reports", "args": ["run", *case["args"]]})
    # Usage errors name the program, which legitimately differs.
    expected.pop("_stderr.txt")
    actual.pop("_stderr.txt")
    assert actual == expected


STAGED_SCANS = ["nmap.xml", "nessus.csv", "qualys.xml", "qualys.csv"]


@pytest.mark.regression
@pytest.mark.parametrize("scan", STAGED_SCANS)
def test_staged_pipeline_csv_matches_vuln_report(scan):
    """parse -> enrich -> report yields the same CSV as the one-shot vuln_report.py run."""
    golden = read_golden(f"report_{scan.replace('.', '_')}_all")["report.csv"]
    work_case = {"script": "-m vuln_reports", "inputs": [scan], "env": {}, "pre_files": {}}

    outputs = run_staged(
        REPO_ROOT,
        work_case,
        [["parse", scan, "-o", "f.json"], ["enrich", "f.json", "-o", "e.json"], ["report", "e.json", "-C", "out.csv"]],
    )
    assert outputs["_exit_codes"] == [0, 0, 0], outputs["_log"]
    assert outputs["out.csv"] == golden
