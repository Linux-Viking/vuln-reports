#!/usr/bin/env python3
"""CVE Lookup: research CVE IDs for intelligence and PoCs.

Thin entry point kept for backward compatibility (automation such as Tines runs
this file directly). The implementation lives in ``vuln_reports``; this module also
re-exports the v1.0.0 public names so ``import cve_lookup`` keeps working.
"""

import os
import sys

# Suppress GLib-GIO warnings
os.environ["GIO_USE_VFS"] = "local"
if "G_MESSAGES_DEBUG" not in os.environ:
    os.environ["G_MESSAGES_DEBUG"] = "none"

from vuln_reports.commands.lookup import MAX_WORKERS, VERSION, build_parser, run  # noqa: E402
from vuln_reports.console import Colors, colorize, print_lock  # noqa: E402
from vuln_reports.enrichment.exploits import get_poc_from_github  # noqa: E402
from vuln_reports.enrichment.http import DEFAULT_TIMEOUT, USER_AGENT  # noqa: E402
from vuln_reports.enrichment.keys import get_keys  # noqa: E402
from vuln_reports.enrichment.lookup import CVE_REGEX, get_cve_data, validate_cve_id  # noqa: E402
from vuln_reports.enrichment.record import normalize_text  # noqa: E402
from vuln_reports.reporting.lookup_formats import (  # noqa: E402
    csv_safe,
    get_output_path,
    print_pretty,
    save_csv,
    save_text,
)

__all__ = [
    "CVE_REGEX",
    "DEFAULT_TIMEOUT",
    "MAX_WORKERS",
    "USER_AGENT",
    "VERSION",
    "Colors",
    "build_parser",
    "colorize",
    "csv_safe",
    "get_cve_data",
    "get_keys",
    "get_output_path",
    "get_poc_from_github",
    "main",
    "normalize_text",
    "print_lock",
    "print_pretty",
    "save_csv",
    "save_text",
    "validate_cve_id",
]


def main():
    run(sys.argv[1:], max_workers=MAX_WORKERS)


if __name__ == "__main__":
    main()
