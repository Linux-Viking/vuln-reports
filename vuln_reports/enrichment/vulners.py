"""Vulners: optional higher-quality titles, descriptions and affected-version ranges."""

from __future__ import annotations

import requests

from vuln_reports.enrichment.http import DEFAULT_TIMEOUT, USER_AGENT
from vuln_reports.enrichment.record import normalize_text

VULNERS_URL = "https://vulners.com/api/v3/search/lucene/"


def fetch_records(session: requests.Session, cve_id: str, vulners_key: str | None) -> list:
    """All ``_source`` documents Vulners holds for ``cve_id`` ([] without a key or on failure)."""
    records = []
    if not vulners_key:
        return records
    try:
        resp = session.post(
            VULNERS_URL,
            json={"query": f"id:{cve_id}"},
            headers={"User-Agent": USER_AGENT, "X-Api-Key": vulners_key},
            timeout=DEFAULT_TIMEOUT,
        )
        if resp.status_code == 200:
            body = resp.json()
            if body.get("result") == "OK":
                for res in body.get("data", {}).get("search", []):
                    records.append(res.get("_source", {}))
    # Vulners is optional enrichment; failures fall back to CIRCL data.
    except Exception:  # nosec B110
        pass
    return records


def _type_priority(record) -> int:
    t = record.get("type", "").lower()
    if t == "cisa_kev":
        return 0
    if t == "nvd":
        return 1
    if t == "osv":
        return 2
    return 3


def improve_text(records, cve_id, title, description, is_generic, is_commit_msg):
    """Prefer Vulners' title/description when ours is weak. Returns (title, description)."""
    for v in sorted(records, key=_type_priority):
        v_title = v.get("title")
        v_is_good = v_title and len(v_title) > len(cve_id)
        curr_is_weak = (
            "resolved" in str(title).lower()
            or "N/A" in str(title)
            or str(title) == cve_id
            or is_generic
            or is_commit_msg
        )
        if v_is_good and curr_is_weak:
            title = v_title

        v_desc = v.get("description")
        if v_desc and len(v_desc) > 20 and ("resolved" in description.lower() or "N/A" in description):
            description = normalize_text(v_desc)
            break
    return title, description


def affected_products(records) -> list:
    """Affected software across all records, de-duplicated, with readable version operators."""
    affected = []
    seen = set()
    for v in records:
        for sw in v.get("affectedSoftware") or []:
            product_name = sw.get("name", "Unknown")
            version_range = sw.get("version", "N/A")
            operator = sw.get("operator", "")
            key = (product_name, version_range, operator)
            if key in seen:
                continue
            seen.add(key)
            display_version = version_range
            if operator == "lt":
                display_version = f"before {version_range}"
            elif operator == "le":
                display_version = f"up to {version_range}"
            affected.append({"vendor": "Unknown", "product": product_name, "versions": [display_version]})
    return affected
