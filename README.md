# Vuln-Reports Suite

A unified vulnerability reporting toolkit for pentesters. This suite combines scanner output parsing, CVE intelligence, and actionable remediation research into a professional reporting pipeline.

## Tools in the Suite

1.  **`vuln_report.py` (The Orchestrator)**:
    - Automatically detects scan types (Nmap, Nessus, Qualys).
    - Extracts Host IPs and FQDNs with intelligent fallback.
    - Enriches findings with CVSS scores, CISA KEV status, and exploit links.
    - **Remediation Intelligence**: Autonomously extracts patching and upgrade advice.
    - Generates professional reports in **CSV, HTML, PDF, Markdown, and XLSX**.
2.  **`scan2cve.py` (The Parser)**:
    - Parses XML/CSV exports from major scanners.
    - Translates Nmap CPEs to CVEs via the NVD API.
    - High-fidelity host identification (handles IP and FQDN-only environments).
3.  **`cve_lookup.py` (The Enricher)**:
    - Researches specific CVEs for intelligence and PoCs.
    - Sophisticated title generation for sparse records.
    - Concurrent enrichment with retry logic for high reliability.

---

## 🔑 API Key Configuration

To get the most out of the suite, you should configure API keys for **GitHub** (PoC discovery) and **NVD** (faster vulnerability lookups).

### 1. GitHub Token (PoC Research)
Used to search for public exploits and Proof of Concepts.
- **How to get:** Go to [GitHub Settings > Personal Access Tokens](https://github.com/settings/tokens). No special permissions required.

### 2. NVD API Key (Vulnerability Data)
Significantly increases rate limits for large-scale scan parsing.
- **How to get:** Request a free key at [NVD API Request](https://nvd.nist.gov/developers/request-an-api-key).

### Configuration Methods
| Method | GitHub Variable | NVD Variable |
| :--- | :--- | :--- |
| **Command Line** | `-T <token>` | `-N <key>` |
| **Environment** | `export GITHUB_TOKEN=...` | `export NVD_API_KEY=...` |
| **System Keyring** | Saved interactive prompt | Saved interactive prompt |
| **Config File** | `~/.config/cve-lookup/config.json` | `~/.config/cve-lookup/config.json` |

---

## 🚀 Installation

```bash
# Clone and install
git clone <repo-url>
cd vuln-reports
pip install -r requirements.txt
```

---

## 📖 Usage Guide

### End-to-End Reporting
Generate comprehensive reports in all supported formats:
```bash
python3 vuln_report.py my_scan.nessus -o report.csv -H report.html -P report.pdf -M report.md -X report.xlsx
```

### Standalone CVE Research
```bash
# Research a single CVE with PoC filtering
python3 cve_lookup.py CVE-2023-48795 -p
```

---

## 📊 Supported Formats

| Format | Description | Command Flag |
| :--- | :--- | :--- |
| **HTML** | Interactive dark-themed dashboard | `-H` (vuln_report) |
| **PDF** | High-fidelity intelligence report for delivery | `-P` (vuln_report) |
| **XLSX** | Multi-sheet workbook (one sheet per CVE) | `-X` (vuln_report) |
| **Markdown**| Technical documentation and Wiki integration | `-M` (vuln_report) |
| **CSV** | Professional spreadsheet for raw data | `-o` (vuln_report) |
| **JSON** | Machine-readable data for automation | `--json` (cve_lookup) |

---

## 🛡️ Intelligence-Led Reporting
This suite is designed for large-scale security assessments. 
- **Host Limiting**: High-fidelity reports (PDF/HTML) intelligently limit host displays to maintain layout integrity while preserving full data in CSV/XLSX.
- **Actionable Advice**: Every report includes a **Remediation Recommendation** section, providing a direct path to resolution for stakeholders.
- **FQDN Support**: Seamlessly handles environments where hosts are identified only by their DNS names.
