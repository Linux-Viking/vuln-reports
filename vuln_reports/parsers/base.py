"""Base class for scanner parsers."""

from __future__ import annotations

from vuln_reports.models import Host, ScanResult


class BaseParser:
    """Parse one scanner export into a :class:`ScanResult`.

    Subclasses fill ``self.hosts`` (host id -> :class:`Host`) in ``parse()``.
    Parse errors are reported on stdout and leave whatever was parsed so far,
    matching v1.0.0 behaviour.
    """

    scanner_type = ""

    def __init__(self, file_path: str, use_colors: bool = True):
        self.file_path = file_path
        self.use_colors = use_colors
        self.hosts: dict[str, Host] = {}

    def parse(self) -> ScanResult:
        raise NotImplementedError("Subclasses must implement parse()")

    def result(self) -> ScanResult:
        return ScanResult(scanner_type=self.scanner_type, source_file=self.file_path, hosts=self.hosts)
