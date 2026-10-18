"""CIRCL vulnerability-lookup: the primary source of CVE records (CVE JSON 5)."""

from __future__ import annotations

import time

import requests

from vuln_reports.enrichment.http import DEFAULT_TIMEOUT, USER_AGENT, api_delay, circl_limiter

CIRCL_URL = "https://cve.circl.lu/api/cve/{cve_id}"
MAX_RETRIES = 8


def fetch_record(session: requests.Session, cve_id: str, circl_key: str | None = None):
    """Return ``(record, error)``; exactly one is not None (record may be empty/None on odd replies)."""
    headers = {"User-Agent": USER_AGENT}
    if circl_key:
        # Some endpoints/instances use Authorization, some X-API-KEY; send both.
        headers["Authorization"] = f"Token {circl_key}"
        headers["X-API-KEY"] = circl_key

    for attempt in range(MAX_RETRIES):
        circl_limiter.wait(api_delay(circl_key))
        try:
            resp = session.get(CIRCL_URL.format(cve_id=cve_id), headers=headers, timeout=DEFAULT_TIMEOUT)
            if resp.status_code == 429:
                if attempt == MAX_RETRIES - 1:
                    return None, "HTTP 429: Too Many Requests"
                time.sleep(5 * (attempt + 1))
                continue
            resp.raise_for_status()
            return resp.json(), None
        except Exception as e:
            if attempt == MAX_RETRIES - 1:
                return None, str(e)
            time.sleep(2 * (attempt + 1))
    return None, None
