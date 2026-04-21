# Vuln-Reports Suite

A unified vulnerability reporting toolkit for pentesters. This suite combines scanner output parsing, CVE intelligence, and actionable remediation research into a professional reporting pipeline.

## Tools in the Suite

1.  **`vuln_report.py` (The Orchestrator)**:
    - Automatically detects scan types (Nmap, Nessus, Qualys).
    - Extracts Host IPs and FQDNs with intelligent fallback.
    - Enriches findings with CVSS scores, CISA KEV status, and exploit links.
    - **Visual Intelligence**: Generates severity distribution pie charts for HTML, PDF, and DOCX reports.
    - **Remediation Intelligence**: Autonomously extracts patching and upgrade advice.
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

---

## ⚡ Performance & Scale

The suite is optimized for large datasets (1000s of CVEs) through deep multi-threading.

- **Concurrent CVE Discovery**: `scan2cve.py` resolves unique CPEs in parallel.
- **Concurrent Enrichment**: `vuln_report.py` fetches detailed intelligence for all unique CVEs simultaneously.
- **Configurable Threads**: Use the `-t` or `--threads` flag to set the worker count (default: 10).
- **Intelligent Rate Limiting**: Automatically scales request timing based on the presence of an NVD API Key.

---

## 🔍 Advanced Filtering & Grouping

### Severity Filtering (`-s` / `--severity`)
Filter the final report by one or more severity levels (comma-separated):
- `Critical`: CVSS 9.0 - 10.0 (Red)
- `High`: CVSS 7.0 - 8.9 (Orange)
- `Medium`: CVSS 4.0 - 6.9 (Amber)
- `Low`: CVSS 0.1 - 3.9 (Blue)
- `Info`: CVSS 0.0 or N/A (Green)

### Output Grouping (`-g` / `--group-by`)
Customize the structure of your **XLSX** reports:
- `host`: Creates one sheet per Host, listing all associated CVEs (Default).
- `cve`: Creates one sheet per CVE, listing all affected hosts.

Example:
```bash
python3 vuln_report.py scan.xml -X report.xlsx -g host
```

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
# Generate all formats at once with a base filename
python3 vuln_report.py my_scan.nessus -A report

# Or specify individual formats
python3 vuln_report.py my_scan.nessus -C report.csv -H report.html -P report.pdf -M report.md -X report.xlsx -D report.docx
```

### Standalone CVE Research
```bash
# Research a single CVE with PoC filtering
python3 cve_lookup.py CVE-2023-48795 -p

# Generate all research formats for a list of CVEs
python3 cve_lookup.py CVE-2023-48795 CVE-2024-1234 -A results
```

---

## 📊 Supported Formats

| Format | Description | Command Flag |
| :--- | :--- | :--- |
| **All** | Generate all available formats using a base name | `-A` / `--all` |
| **CSV** | Professional spreadsheet for raw data | `-C` / `--csv` |
| **HTML** | Interactive dark-themed dashboard with severity charts | `-H` / `--html` |
| **PDF** | High-fidelity intelligence report with summary and charts | `-P` / `--pdf` |
| **DOCX** | Assessment-ready Word doc with टेक्निकल technical workflow and charts | `-D` / `--docx` |
| **XLSX** | Multi-sheet workbook (grouped by Host or CVE) | `-X` / `--xlsx` |
| **Markdown**| Technical documentation and Wiki integration | `-M` / `--markdown` |

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
- **External Templates**: Drop your own branded Word file at `templates/report_template.docx` to preserve custom headers, footers, and logos. The tool will automatically detect it and append findings to your template.

### ⚙️ Scale & Fidelity
- **Host Limiting**: High-fidelity reports intelligently limit host displays to 5 items to maintain layout integrity, while CSV/XLSX preserve 100% of audit data.
- **FQDN Support**: Seamlessly handles environments where hosts are identified only by their DNS names, ensuring FQDNs are treated as primary identifiers when IPs are absent.

---

## 🛠️ Troubleshooting (Windows)

### PDF Generation Error (`OSError: cannot load library 'libgobject-2.0-0'`)
If you see this error when generating PDFs, it means **WeasyPrint** cannot find its required C libraries (GTK+).
1.  Download the **GTK for Windows Runtime** (e.g., from [GTK-for-Windows-Runtime-Environment-Installer](https://github.com/tschoonj/GTK-for-Windows-Runtime-Environment-Installer/releases)).
2.  Install it and ensure you check the box to **add the GTK bin folder to your System PATH**.
3.  Restart your terminal/IDE.

*Note: The suite now automatically suppresses noisy `GLib-GIO-WARNING` messages regarding UWP apps by forcing the local VFS backend on Windows.*

*Alternatively, you can skip PDF generation and use HTML, DOCX, or XLSX formats which do not have this dependency.*
