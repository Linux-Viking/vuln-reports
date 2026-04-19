# Vuln-Reports Suite

A unified vulnerability reporting toolkit for pentesters. This suite combines scanner output parsing, CVE intelligence, and exploit research into a professional reporting pipeline.

## Tools in the Suite

1.  **`vuln_report.py` (The Orchestrator)**:
    - Automatically detects scan types (Nmap, Nessus, Qualys).
    - Extracts Host IPs and FQDNs.
    - Enriches findings with CVSS scores, CISA KEV status, and exploit links.
    - Generates a professional CSV report.
2.  **`scan2cve.py` (The Parser)**:
    - Parses XML/CSV exports from major scanners.
    - Translates Nmap CPEs to CVEs via the NVD API.
    - Generates a simple text list of unique CVEs.
3.  **`cve_lookup.py` (The Enricher)**:
    - Researches specific CVEs for intelligence and PoCs.
    - Supports JSON, CSV, Text, Grep-able, and XML outputs.
    - Can be run standalone for quick vulnerability research.

---

## 🔑 API Key Configuration

To get the most out of the suite, you should configure API keys for **GitHub** (PoC discovery) and **NVD** (faster vulnerability lookups).

### 1. GitHub Token (PoC Research)
Used by `cve_lookup.py` to search for public exploits and Proof of Concepts.
- **Why:** Without a token, GitHub's API rate limits are extremely low, which may cause PoC lookups to fail or return incomplete results.
- **How to get:** Go to [GitHub Settings > Personal Access Tokens](https://github.com/settings/tokens). A "Fine-grained token" or "Classic token" with no extra permissions is sufficient for searching public repositories.

### 2. NVD API Key (Vulnerability Data)
Used to fetch detailed metadata, CVSS scores, and CPE information from the National Vulnerability Database.
- **Why:** NVD rate-limits requests strictly. An API key increases your limit from 5 requests per 30 seconds to 50 requests per 30 seconds, significantly speeding up large reports.
- **How to get:** Request a free key at [NVD API Request](https://nvd.nist.gov/developers/request-an-api-key).

### Configuration Methods
The tools check for keys in the following order of precedence:

| Method | GitHub Variable | NVD Variable |
| :--- | :--- | :--- |
| **Command Line** | `-T <token>` or `--token <token>` | `-N <key>` or `--nvd-key <key>` |
| **Environment** | `export GITHUB_TOKEN=...` | `export NVD_API_KEY=...` |
| **System Keyring** | Saved automatically via interactive prompt | Saved automatically via interactive prompt |
| **Config File** | `~/.config/cve-lookup/config.json` | `~/.config/cve-lookup/config.json` |

#### Interactive Setup
If keys are missing, `cve_lookup.py` will prompt you to enter them. You can then choose to save them securely:
- **Keyring (k):** Saves to your OS's secure credential store (e.g., Keychain, Windows Credential Manager).
- **Config File (f):** Saves to a plain-text JSON file in your home directory.

---

## 🚀 Installation

```bash
# Clone the repository
git clone <repo-url>
cd vuln-reports

# Install dependencies
pip install -r requirements.txt
```

---

## 📖 Usage Guide

### End-to-End Reporting
Generate comprehensive reports in multiple formats (CSV, HTML, PDF, Markdown) from a scan file:
```bash
python3 vuln_report.py my_scan.nessus -o report.csv -H report.html -P report.pdf -M report.md
```

### Standalone CVE Research
Look up detailed info and PoCs for specific CVEs:
```bash
# Single CVE with PoC filtering
python3 cve_lookup.py CVE-2023-48795 -p

# Multiple CVEs from a file, export to all formats
python3 cve_lookup.py -f cve_list.txt -A research_results
```

### Scanner Parsing
Convert a raw Nmap XML to a unique list of CVEs:
```bash
python3 scan2cve.py scan.xml -o unique_cves.txt
```

---

## 📊 Supported Formats

| Format | Description | Command Flag |
| :--- | :--- | :--- |
| **CSV** | Professional spreadsheet for clients | `--csv` (cve_lookup) or `-o` (vuln_report) |
| **HTML** | Interactive intelligence report with styling | `-H` (vuln_report) |
| **PDF** | High-fidelity intelligence report for delivery | `-P` (vuln_report) |
| **XLSX**| Multi-sheet workbook (one sheet per CVE) | `-X` (vuln_report) |
| **Markdown**| Technical documentation and Wiki integration | `-M` (vuln_report) |
| **JSON** | Machine-readable data for automation | `--json` |
| **Grep** | Pipe-delimited flat file for CLI wizards | `--grep` |
| **Text** | Human-readable terminal output | `--text` |
| **XML** | Structured XML data | `--xml` |
| **All** | Generate all the above at once | `-A` |

---

## Workflow Integration
This suite is designed to take you from a raw scanner export to a prioritized, intelligence-enriched vulnerability list in a single command. Use `vuln_report.py` for the full pipeline, or the standalone tools for modular tasks.
