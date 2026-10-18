"""FIRST EPSS exploit-prediction scores."""

import requests

from vuln_reports.enrichment.http import DEFAULT_TIMEOUT, USER_AGENT

EPSS_URL = "https://api.first.org/data/v1/epss"


def fetch_epss(session: requests.Session, cve_id: str) -> dict:
    """Raw EPSS API reply, or {} on any failure."""
    try:
        resp = session.get(
            EPSS_URL, headers={"User-Agent": USER_AGENT}, params={"cve": cve_id}, timeout=DEFAULT_TIMEOUT
        )
        if resp.status_code == 200:
            return resp.json()
    # EPSS is optional enrichment; any failure means "N/A".
    except Exception:  # nosec B110
        pass
    return {}


def epss_score(epss_data: dict):
    if epss_data.get("status") == "OK" and epss_data.get("data"):
        return epss_data["data"][0].get("epss", "N/A")
    return "N/A"
