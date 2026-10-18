"""CISA Known Exploited Vulnerabilities status.

Note: this is inferred from the CVE record itself (CISA ADP "kev" metric, KEV
tags, or a link to the KEV catalogue), not downloaded from the CISA KEV feed.
"""

KEV_TAG_INDICATORS = ["known-exploited-vulnerability", "exploited-in-the-wild", "active-exploitation", "cisa-kev"]
KEV_CATALOG_URL = "cisa.gov/known-exploited-vulnerabilities-catalog"


def kev_status(metrics: list, cna: dict, adp_list: list, references: list) -> str:
    """Return "Yes" if any KEV signal is present in the record, else "No"."""
    for m in metrics:
        if m.get("other", {}).get("type") == "kev":
            return "Yes"

    all_tags = list(cna.get("tags", []))
    for adp in adp_list:
        all_tags.extend(adp.get("tags", []))
    if any(any(ki in str(t).lower() for ki in KEV_TAG_INDICATORS) for t in all_tags):
        return "Yes"

    for ref in references:
        if KEV_CATALOG_URL in ref.lower():
            return "Yes"
    return "No"
