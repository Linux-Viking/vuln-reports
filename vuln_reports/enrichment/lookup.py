"""Enrich one CVE ID from every source and assemble the report fields."""

from __future__ import annotations

import re
from typing import Any

import requests

from vuln_reports.enrichment import circl, epss, exploits, kev, nvd, record, vulners

CVE_REGEX = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
CVE_SEARCH_REGEX = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def validate_cve_id(cve_id: str) -> bool:
    return bool(CVE_REGEX.match(cve_id))


def extract_cve_ids(texts, into: list | None = None) -> list:
    """Unique upper-cased CVE IDs found anywhere in ``texts``, in first-seen order."""
    found = into if into is not None else []
    for text in texts:
        for c in CVE_SEARCH_REGEX.findall(text):
            c_upper = c.upper()
            if c_upper not in found:
                found.append(c_upper)
    return found


def get_cve_data(
    session: requests.Session,
    cve_id: str,
    github_token: str | None,
    nvd_key: str | None = None,
    vulners_key: str | None = None,
    circl_key: str | None = None,
) -> dict[str, Any]:
    """Full intelligence for ``cve_id`` as a dict (see ``models.CveIntel``), or ``{"cve_id", "error"}``.

    Source order matters for rate limits and is unchanged from v1.0.0:
    Vulners (if keyed) -> CIRCL -> EPSS -> NVD CVSS fallback -> GitHub PoC search.
    """
    if not validate_cve_id(cve_id):
        return {"cve_id": cve_id, "error": f"Invalid format: {cve_id}"}

    vulners_records = vulners.fetch_records(session, cve_id, vulners_key)

    circl_data, error = circl.fetch_record(session, cve_id, circl_key)
    if error is not None:
        return {"cve_id": cve_id, "error": error}

    epss_data = epss.fetch_epss(session, cve_id)

    if not circl_data:
        return {"cve_id": cve_id, "error": "Not found"}

    containers = circl_data.get("containers", {})
    cna = containers.get("cna", {})
    adp_list = containers.get("adp", [])

    title = record.raw_title(cna, adp_list)
    description = record.normalize_text(cna.get("descriptions", [{}])[0].get("value", "N/A"))
    affected_raw = cna.get("affected", [])
    product, detected_products = record.derive_product(description, affected_raw)
    current_title, aka_title, is_generic, is_commit_msg = record.derive_title(
        title, description, product, cna, adp_list
    )

    if vulners_records:
        current_title, description = vulners.improve_text(
            vulners_records, cve_id, current_title, description, is_generic, is_commit_msg
        )

    affected = record.build_affected(affected_raw, description, product, detected_products)
    affected = record.prefer_vulners_affected(affected, vulners.affected_products(vulners_records))

    metrics = record.all_metrics(cna, adp_list)
    cvss_score, attack_complexity, user_interaction, threat_vector = record.extract_cvss(metrics)
    if cvss_score == "N/A":
        cvss_score, attack_complexity, user_interaction, threat_vector = nvd.fetch_cvss(cve_id, nvd_key)

    raw_refs = cna.get("references", [])
    references = record.combined_references(cve_id, raw_refs)
    poc_available, poc_link = exploits.poc_from_references(raw_refs, cve_id)
    cisa_kev = kev.kev_status(metrics, cna, adp_list, references)
    epss_score = epss.epss_score(epss_data)

    if poc_available == "No":
        aliases = exploits.poc_aliases(aka_title, current_title, is_generic, is_commit_msg)
        gh_poc = exploits.get_poc_from_github(session, cve_id, github_token, aliases=aliases)
        if gh_poc:
            poc_available = "Yes (GitHub)"
            poc_link = gh_poc
            references.append(gh_poc)

    if cisa_kev == "Yes":
        exploitability = "Exploited in the wild"
    elif poc_available != "No":
        exploitability = "PoC Available"
    else:
        exploitability = "Theoretical / Unknown"

    remediation = record.derive_remediation(cna, description, references)

    return {
        "cve_id": cve_id,
        "title": current_title,
        "description": description,
        "affected": affected,
        "cisa_kev": cisa_kev,
        "cvss_score": cvss_score,
        "exploitability": exploitability,
        "poc_available": poc_available,
        "poc_link": poc_link,
        "threat_vector": threat_vector,
        "user_interaction": user_interaction,
        "epss_score": epss_score,
        "attack_complexity": attack_complexity,
        "references": references,
        "remediation": remediation,
    }
