#!/usr/bin/env python3
"""
VulnReport: Unified vulnerability report generator.
Combines Scan2CVE (parsing) and CVE-Lookup (enrichment) to produce detailed reports.

Thin entry point kept for backward compatibility. The implementation lives in
``vuln_reports``; this module re-exports the v1.0.0 public names.
"""

import os
import sys

# --- Aggressive GLib/GIO Warning Suppression ---
# These must be set BEFORE any GIO/GTK-based libraries are loaded.
os.environ["GIO_USE_VFS"] = "local"
os.environ["GIO_USE_DESKTOP_APP_INFO"] = "none"
os.environ["GIO_USE_VOLUME_MONITOR"] = "none"
os.environ["G_MESSAGES_DEBUG"] = "none"


def suppress_gio_noise():
    """Silence C-level stderr (persistent GLib warnings on Windows) during imports."""
    if os.name != "nt":
        return None
    try:
        null_fd = os.open(os.devnull, os.O_RDWR)
        old_stderr = os.dup(sys.stderr.fileno())
        os.dup2(null_fd, sys.stderr.fileno())
        os.close(null_fd)
        return old_stderr
    except Exception:
        return None


def restore_gio_noise(old_stderr):
    if old_stderr is not None:
        os.dup2(old_stderr, sys.stderr.fileno())
        os.close(old_stderr)


_gio_stderr = suppress_gio_noise()
try:
    import cve_lookup  # noqa: F401  (v1.0.0 exposed these as attributes)
    import scan2cve  # noqa: F401
    from vuln_reports.commands.report import build_parser, generate_report, run
    from vuln_reports.enrichment.pipeline import enrich_cves as get_detailed_cve_info
    from vuln_reports.reporting.chart import HAS_MATPLOTLIB, generate_severity_chart
    from vuln_reports.reporting.common import get_severity
    from vuln_reports.reporting.docx_report import HAS_DOCX, save_docx_report
    from vuln_reports.reporting.html_report import (
        HAS_JINJA,
        HAS_WEASYPRINT,
        save_html_report,
        save_markdown_report,
        save_pdf_report,
    )
    from vuln_reports.reporting.xlsx_report import HAS_OPENPYXL, save_xlsx_report
finally:
    restore_gio_noise(_gio_stderr)

__all__ = [
    "HAS_DOCX",
    "HAS_JINJA",
    "HAS_MATPLOTLIB",
    "HAS_OPENPYXL",
    "HAS_WEASYPRINT",
    "build_parser",
    "generate_report",
    "generate_severity_chart",
    "get_detailed_cve_info",
    "get_severity",
    "main",
    "save_docx_report",
    "save_html_report",
    "save_markdown_report",
    "save_pdf_report",
    "save_xlsx_report",
]


def main():
    run(sys.argv[1:])


if __name__ == "__main__":
    main()
