"""Helpers shared by the scanner parsers."""

from __future__ import annotations

import re


def is_ip(string: str) -> bool:
    """Check if a string is a valid IPv4 address."""
    if not string:
        return False
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", string))


def is_broad_cpe(cpe: str) -> bool:
    """
    Check if a CPE is too broad (lacks a specific version).
    E.g., 'cpe:/a:adobe:acrobat_reader' matches everything if not versioned.
    """
    parts = cpe.split(":")
    if len(parts) < 5:
        return True
    version = parts[4]
    if not version or version in ["-", "*"]:
        return True
    return False


def split_host(raw: str, hostname: str = "") -> tuple[str, str]:
    """Split a scanner host value into (ip, hostname).

    ``raw`` is used as the IP when it is one, otherwise as the hostname
    fallback. A non-IP that ended up in the IP slot is moved to hostname.
    """
    ip = raw if is_ip(raw) else ""
    if not hostname and not is_ip(raw):
        hostname = raw
    if ip and not is_ip(ip):
        if not hostname:
            hostname = ip
        ip = ""
    return ip, hostname


def add_cve_list(target: set, value: str | None) -> None:
    """Add every non-empty CVE from a comma-separated cell to ``target``."""
    if value:
        for c in value.split(","):
            c = c.strip()
            if c:
                target.add(c)
