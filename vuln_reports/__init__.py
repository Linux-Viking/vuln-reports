"""Vuln-Reports: scanner parsing, CVE enrichment and report generation.

Kept import-free on purpose: ``cve_lookup.py`` runs in environments (the Tines
Lambda) whose cached site-packages may predate newer report dependencies, so
importing this package must never pull in jinja2, matplotlib, weasyprint, etc.
"""

__version__ = "1.1.0"
