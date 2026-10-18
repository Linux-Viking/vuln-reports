# Vuln-Reports Suite

A vulnerability management and reporting toolkit for security teams and pentesters. It parses Nmap, Nessus and Qualys output, enriches CVEs with CVSS, CISA KEV, EPSS and exploit intelligence, and produces professional reports or automation-ready CSV, for example from a Tines (SOAR) workflow.

[![CI](https://github.com/Linux-Viking/vuln-reports/actions/workflows/ci.yml/badge.svg)](https://github.com/Linux-Viking/vuln-reports/actions/workflows/ci.yml)

## 🎬 Demo

CVE lookup running as a Tines automation: paste CVE IDs, get enriched results (CVSS, KEV, EPSS, PoC links) as a table and CSV.

https://github.com/user-attachments/assets/19e618e9-4107-4454-bef4-8acccefd0872

## Tools in the Suite

1.  **`vuln_report.py` (The Orchestrator)**:
    - Automatically detects scan types (Nmap, Nessus, Qualys).
    - Extracts Host IPs and FQDNs with intelligent fallback.
    - Enriches findings with CVSS scores, CISA KEV status, EPSS, and exploit links.
    - **Visual Intelligence**: Generates severity distribution pie charts for HTML, PDF, and DOCX reports.
    - **Remediation Intelligence**: Extracts patching and upgrade advice from CVE records.
    - Generates professional reports in **CSV, HTML, PDF, Markdown, XLSX, and DOCX**.
2.  **`scan2cve.py` (The Parser)**:
    - Parses XML/CSV exports from major scanners.
    - **Multi-threaded Resolution**: Translates Nmap CPEs to CVEs via concurrent NVD API calls.
    - **False Positive Reduction**: Automatically filters out broad/generic CPEs (like unversioned Adobe Reader) to ensure high-fidelity results.
    - High-fidelity host identification (handles IP and FQDN-only environments).
3.  **`cve_lookup.py` (The Enricher)**:
    - Researches specific CVEs for intelligence and PoCs.
    - Sophisticated title generation for sparse records.
    - **Optimized Concurrency**: Concurrent enrichment with non-blocking rate limiting for maximum throughput.
4.  **`python3 -m vuln_reports` (Staged CLI)**: the same pipeline as separate `parse`, `enrich`, `report` and `run` steps that exchange JSON, so an expensive enrichment can be saved once and rendered many times. See [Staged pipeline](#staged-pipeline-python3--m-vuln_reports).

### Where the intelligence comes from

| Field | Source |
| :--- | :--- |
| Title, description, affected products, references, remediation | [CIRCL vulnerability-lookup](https://cve.circl.lu/) (CVE JSON 5 records) |
| CVSS | The CVE record (v4.0 → v3.1 → v3.0), falling back to the [NVD API](https://nvd.nist.gov/developers) (v3.1 → v3.0 → v2) |
| CPE → CVE (Nmap) | NVD API (`virtualMatchString`) |
| EPSS | [FIRST EPSS API](https://www.first.org/epss/api) |
| CISA KEV | *Inferred* from the CVE record: CISA ADP `kev` metric, KEV tags, or a link to the KEV catalogue. The CISA KEV feed itself is not downloaded. |
| Exploit / PoC | Exploit-DB, Packet Storm, Metasploit, … links in the record, then GitHub repository (and, with a token, code) search |
| Better titles / version ranges (optional) | [Vulners](https://vulners.com/) when a key is configured |

---

## ⚡ Performance & Scale

The suite is optimized for large datasets (1000s of CVEs) through deep multi-threading.

- **Concurrent CVE Discovery**: `scan2cve.py` resolves unique CPEs in parallel.
- **Concurrent Enrichment**: `vuln_report.py` fetches detailed intelligence for all unique CVEs simultaneously.
- **Configurable Threads**: Use the `-t` or `--threads` flag of `vuln_report.py` to set the worker count (default: 10).
- **Intelligent Rate Limiting**: CIRCL and NVD calls are spaced 6.5 s apart without an API key and 0.65 s apart with one, so keys make large runs roughly 10× faster.

---

## 🔍 Advanced Filtering & Grouping

### Severity Filtering (`-s` / `--severity`)
Filter the final report by one or more severity levels (comma-separated):
- `Critical`: CVSS 9.0 - 10.0 (Red)
- `High`: CVSS 7.0 - 8.9 (Orange)
- `Medium`: CVSS 4.0 - 6.9 (Amber)
- `Low`: CVSS 0.1 - 3.9 (Blue)
- `Info`: CVSS 0.0 or N/A (Green)

---

## 🔑 API Key Configuration

All keys are optional, but they raise rate limits and improve results.

| Key | Used for | How to get it | Environment variable |
| :--- | :--- | :--- | :--- |
| **GitHub token** | PoC discovery (repository and code search) | [GitHub Settings › Personal access tokens](https://github.com/settings/tokens) — no scopes needed | `GITHUB_TOKEN` |
| **NVD API key** | Faster CPE → CVE lookups and CVSS fallback | [NVD API key request](https://nvd.nist.gov/developers/request-an-api-key) | `NVD_API_KEY` |
| **Vulners API key** | Higher-quality titles, descriptions, and clean version ranges (e.g. resolving raw Linux kernel git hashes to semver) | Register at [Vulners](https://vulners.com/) and create a key in your profile | `VULNERS_API_KEY` |
| **CIRCL API key** | Faster CIRCL vulnerability-lookup queries | [CIRCL vulnerability-lookup](https://cve.circl.lu/) account | `CIRCL_API_KEY` |

Keys are read from the **environment variable** first, then from the **system keyring** (service `cve-lookup-tool`; entries `github-token`, `nvd-key`, `vulners-key`, `circl-key`).

When `cve_lookup.py` runs interactively (stdin is a terminal, not in `-p` mode) it prompts for each missing key and offers to save it to the keyring. In scripts, CI, and automation (stdin redirected or closed) it never prompts.

---

## 🚀 Installation

```bash
git clone https://github.com/Linux-Viking/vuln-reports.git
cd vuln-reports
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
```

Python 3.10 or newer (CI tests 3.10 through 3.14). For automation, download a pinned, checksum-verified release instead of cloning `master` — see [Pinned downloads](#-pinned-downloads-for-automation).

---

## 📖 Usage Guide

The three original commands work exactly as before (same flags, same output).

### End-to-End Reporting
```bash
# Generate all formats at once with a base filename
python3 vuln_report.py my_scan.nessus -A report

# Or specify individual formats
python3 vuln_report.py my_scan.nessus -C report.csv -H report.html -P report.pdf -M report.md -X report.xlsx -D report.docx

# Only Critical and High findings, 20 worker threads
python3 vuln_report.py my_scan.xml -s critical,high -t 20 -H report.html
```
With no output flag, `vuln_report.py` writes `vulnerability_report.csv`.

### Scanner Parsing Only
```bash
# Per-host/service CVE summary, plus a de-duplicated CVE list
python3 scan2cve.py my_scan.xml -o cves.txt

# Force the scanner type if auto-detection fails
python3 scan2cve.py export.csv -t qualys_csv
```
Types: `nmap_xml`, `nessus_xml`, `nessus_csv`, `qualys_xml`, `qualys_csv`.

### Standalone CVE Research
```bash
# Research a single CVE with PoC filtering
python3 cve_lookup.py CVE-2023-48795 -p

# Generate all research formats (JSON, CSV, TXT, grep, XML) for a list of CVEs
python3 cve_lookup.py CVE-2023-48795 CVE-2024-1234 -A results

# Pasted text or a file: every CVE ID found anywhere is used, de-duplicated
python3 cve_lookup.py -c results.csv "CVE-2021-44228, CVE-2022-0001 and CVE-2024-6387"
python3 cve_lookup.py -c results.csv -f cves.csv
```
`cve_lookup.py` never overwrites: if `results.csv` exists it writes `results_1.csv`, and so on.

### Staged pipeline (`python3 -m vuln_reports`)

```bash
python3 -m vuln_reports parse  my_scan.nessus -o findings.json   # hosts, services, CVEs (or CPEs for Nmap)
python3 -m vuln_reports enrich findings.json  -o enriched.json   # CPE -> CVE, CVE intelligence (slow, network)
python3 -m vuln_reports report enriched.json  -A report          # any of -C -H -M -P -X -D -A, plus -s
python3 -m vuln_reports run    my_scan.nessus -A report          # all three at once (same as vuln_report.py)
```
The JSON files follow the data model in `vuln_reports/models.py` (`schema_version: 1`). `report` can be rerun with different formats or severity filters without repeating the lookups. Unlike the original scripts, the staged commands exit with status 1 on errors.

---

## 📊 Supported Formats

| Format | Description | Command Flag |
| :--- | :--- | :--- |
| **All** | Generate all available formats using a base name | `-A` / `--all` |
| **CSV** | Professional spreadsheet for raw data (one row per host/service/CVE) | `-C` / `--csv` |
| **HTML** | Interactive dark-themed dashboard with severity charts | `-H` / `--html` |
| **PDF** | High-fidelity intelligence report with summary and charts | `-P` / `--pdf` |
| **DOCX** | Assessment-ready Word doc with technical workflow and charts | `-D` / `--docx` |
| **XLSX** | Multi-sheet workbook (summary plus one sheet per CVE) | `-X` / `--xlsx` |
| **Markdown**| Technical documentation and Wiki integration | `-M` / `--markdown` |

`cve_lookup.py` exports: JSON (`-j`), CSV (`-c`), text (`-t`), grep-friendly pipe-delimited (`-G`), XML (`-x`), or all (`-A`).

---

## 🛡️ Intelligence-Led Reporting
This suite is designed for large-scale technical assessments.

### 📈 Executive Summary (PDF & HTML)
The PDF and HTML reports feature a dedicated summary page:
- **HOSTS**: Total unique hosts identified across all findings.
- **Severity Distribution**: A professional pie chart visualizing risk levels.
- **Logical Flow**: PDF reports force a page break so the detailed findings always start on page 2.

### 📝 Technical Storytelling (Word DOCX)
The Word report is optimized for pentest deliverables with a logical section order:
1. **Executive Summary** (Metadata & Summary Table)
2. **Severity Chart** (Visual Risk Assessment)
3. **Detailed Findings** (Technical deep-dive on new page)

### 🎨 Custom Branding & Templates
- **Dark Theme**: HTML, PDF, and DOCX reports are fully synchronized with a professional dark aesthetic (Slate/Blue).
- **External Templates**: Drop your own branded Word file at `templates/report_template.docx` to preserve custom headers, footers, and logos. The tool will automatically detect it and append findings to your template. The HTML/PDF (`report_template.html`) and Markdown (`report_template.md`) Jinja2 templates live in the same folder.

### ⚙️ Scale & Fidelity
- **Host Limiting**: High-fidelity reports intelligently limit host displays to 5 items to maintain layout integrity, while CSV/XLSX preserve 100% of audit data.
- **FQDN Support**: Seamlessly handles environments where hosts are identified only by their DNS names, ensuring FQDNs are treated as primary identifiers when IPs are absent.
- **Safe parsing**: Scanner XML is parsed with `defusedxml`, so a malicious export cannot use XML entity expansion or external entities.

---

## 🗂️ Project Structure

```
vuln_report.py, scan2cve.py, cve_lookup.py   Original entry points (thin wrappers, unchanged CLI)
vuln_reports/
  models.py        Common data model shared by all stages: Service, Host, ScanResult,
                   CveIntel, AffectedProduct, Finding, EnrichedScan (+ JSON form)
  parsers/         Nmap, Nessus (XML/CSV), Qualys (XML/CSV) -> ScanResult; scanner detection
  enrichment/      circl (CVE records), nvd (CVSS fallback, CPE -> CVE), epss, kev, exploits
                   (references + GitHub), vulners, record (title/product/version heuristics),
                   keys, lookup (one CVE), pipeline (concurrency)
  reporting/       csv_report, html_report (HTML/Markdown/PDF), xlsx_report, docx_report,
                   chart, lookup_formats (cve_lookup terminal/JSON/CSV/text/grep/XML)
  commands/        Implementations behind the three scripts
  cli.py           python3 -m vuln_reports {parse,enrich,report,run}
templates/         Report templates (HTML, Markdown, optional branded DOCX)
tests/
  unit/            Offline unit tests per module
  regression/      Golden-master tests: today's output vs. the reference release on the same inputs
  fixtures/        Synthetic scans and API responses (RFC 5737 IPs, *.example.test hosts — no client data)
examples/          Pinned, checksum-verified Tines "Run Script" action
.github/workflows/ ci.yml (tests, lint, Bandit, Gitleaks, pip-audit), release.yml
```

`cve_lookup.py` deliberately imports none of the report libraries (Jinja2, WeasyPrint, matplotlib, openpyxl, python-docx), so it keeps working in environments that only have `requests` and `keyring`. CI enforces this.

---

## 🧪 Development & Testing

```bash
pip install -r requirements-dev.txt
python -m pytest                    # unit + regression (fully offline)
python -m pytest -m "not regression"   # unit tests only (~2 s)
black --check . && isort --check-only . && ruff check .
bandit --configfile pyproject.toml --recursive . --severity-level medium
pip-audit -r requirements.txt -r requirements-dev.txt
```

**Regression tests.** `tests/regression/` runs 31 command lines (including the way a Tines automation calls `cve_lookup.py`) against both the current code and the stored outputs of the **reference release** (v1.3.0, whose output is identical to the original v1.0.0 scripts). Every case runs in a fresh interpreter with the network mocked, the clock frozen, and thread pools serialized, so the output is deterministic. CSV, JSON, text, grep, XML, HTML, Markdown and terminal output must match byte for byte. XLSX is compared cell by cell, DOCX by its `document.xml`, and PDF by extracted text.

If an output change is intentional, cut a release first, then regenerate the goldens from that tag. Never regenerate them from the working tree:
```bash
python tests/regression/generate_goldens.py --ref v1.4.0
```

**CI** (`.github/workflows/ci.yml`) runs on every push and pull request:
- tests on Python 3.13 and 3.14
- a Tines-style `cve_lookup.py` smoke test with minimal dependencies
- black, isort and ruff
- Bandit (fails on medium severity and above)
- Gitleaks over the full git history
- pip-audit

---

## 📦 Releases

Pushing a `vX.Y.Z` tag runs `.github/workflows/release.yml`:
1. Runs the full CI suite on the tagged commit.
2. Builds `vuln-reports-vX.Y.Z.tar.gz` and `vuln-reports-vX.Y.Z.zip` with `git archive`. Each archive extracts to a `vuln-reports-vX.Y.Z/` folder.
3. Publishes `SHA256SUMS`, both as a release asset and in the release notes.
4. Records signed build provenance (verify it with `gh attestation verify`).
5. Creates the GitHub Release.

```bash
git tag --annotate v1.4.0 --message "v1.4.0"
git push origin v1.4.0
```
To publish a release for an existing tag (for example if a run failed), go to Actions › Release › **Run workflow** and enter the tag.

---

## 📌 Pinned Downloads for Automation

Anything that downloads this repo automatically, such as a Tines workflow, CI job or cron script, should **pin a specific release and verify its checksum**. It should never fetch `master` (or `main`). Fetching a branch means:
- every push to that branch reaches your automation unreviewed;
- a compromised or mistaken commit runs immediately;
- results can't be reproduced later.

### Option 1 — Release archive + SHA256 (recommended)

```bash
TAG=v1.3.0
BASE=https://github.com/Linux-Viking/vuln-reports/releases/download/$TAG
curl --fail --location --remote-name "$BASE/vuln-reports-$TAG.tar.gz"
curl --fail --location --remote-name "$BASE/SHA256SUMS"
sha256sum --check --ignore-missing SHA256SUMS      # must print: vuln-reports-v1.3.0.tar.gz: OK
tar --extract --gzip --file "vuln-reports-$TAG.tar.gz"
cd "vuln-reports-$TAG" && pip install -r requirements.txt
```
On macOS, use `shasum --algorithm 256 --check --ignore-missing SHA256SUMS`.

For real protection against tampering, **store the expected hash in your automation** instead of downloading `SHA256SUMS` alongside the archive. A checksum file served from the same place as the archive only proves the download isn't corrupted.
```bash
EXPECTED=3b5d...   # copied once from the release page when you reviewed it
echo "$EXPECTED  vuln-reports-$TAG.tar.gz" | sha256sum --check
```
You can also check that GitHub Actions built the archive from this repository:
```bash
gh attestation verify "vuln-reports-$TAG.tar.gz" --repo Linux-Viking/vuln-reports
```

**Tines:** [`examples/tines_execute_cve_lookup.py`](examples/tines_execute_cve_lookup.py) is a ready-to-use Tines **Run Script** action (Python 3.13) that runs `cve_lookup.py` from a pinned release. It expects inputs `cve_list` and/or `cve_file` (from a form), plus optional `GITHUB_TOKEN`, `NVD_API_KEY`, `VULNERS_API_KEY` and `CIRCL_API_KEY` credentials (set each credential's domain restriction to `run-script`). It:
- downloads the release zip for a fixed `TAG`;
- refuses to run if the zip's SHA256 doesn't match the hash stored in the script;
- caches the extracted code and dependencies under paths that include the version, so a cached sandbox can never keep running an older release after you change the pin;
- installs only what `cve_lookup.py` needs (`requests`, `keyring`): about 23 MB in seconds, instead of the full report stack;
- reports failures in the results table and CSV, instead of returning an empty table. A failed download or install, a timeout, or every lookup failing (for example when CIRCL is unavailable) each produce an `error` row explaining what happened.

To use it, set `TAG` and `SHA256` to a release you've reviewed (the example ships with v1.3.0's values). To upgrade, change both together.

### Option 2 — Pin a commit hash

If you need a commit that isn't released, pin the full 40-character commit SHA and let git verify the content:
```bash
git clone https://github.com/Linux-Viking/vuln-reports.git
cd vuln-reports
git checkout --detach 626bf9295c90d57f6ebbbb96cab98aef44b72853
test "$(git rev-parse HEAD)" = 626bf9295c90d57f6ebbbb96cab98aef44b72853
```
GitHub's automatic archives (`/archive/<sha>.tar.gz`, `/zipball/<ref>`) are fine for pinning *what* you download. However, GitHub doesn't guarantee their bytes stay the same over time, so **don't publish or check a SHA256 of those**. Use release assets when you need a checksum.

### Recommended repository settings
- **Settings › Rules › Rulesets**: add a tag ruleset for `v*` that blocks deletion and force-updates, so a tag can't be moved after you've pinned it.
- **Settings › General › Releases**: enable **immutable releases**, so published assets and their checksums can't be replaced.

---

## 🛠️ Troubleshooting (Windows)

### PDF Generation Error (`OSError: cannot load library 'libgobject-2.0-0'`)
If you see this error when generating PDFs, it means **WeasyPrint** cannot find its required C libraries (GTK+).
1.  Download the **GTK for Windows Runtime** (e.g., from [GTK-for-Windows-Runtime-Environment-Installer](https://github.com/tschoonj/GTK-for-Windows-Runtime-Environment-Installer/releases)).
2.  Install it and ensure you check the box to **add the GTK bin folder to your System PATH**.
3.  Restart your terminal/IDE.

*Note: The suite automatically suppresses noisy `GLib-GIO-WARNING` messages regarding UWP apps by forcing the local VFS backend on Windows.*

*Alternatively, you can skip PDF generation and use HTML, DOCX, or XLSX formats which do not have this dependency.*

---

## 📄 License

Released under the [MIT License](LICENSE).
