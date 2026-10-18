"""Shared HTTP settings and per-service rate limiters."""

import time
from threading import Lock

# Browser UA for CIRCL/EPSS/GitHub/Vulners/NVD CVE lookups (as in v1.0.0 cve_lookup.py).
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)
# Tool UA for NVD CPE -> CVE lookups (as in v1.0.0 scan2cve.py).
SCAN_USER_AGENT = "Scan2CVE-Tool/1.0 (Unified Parser)"
DEFAULT_TIMEOUT = 10


def api_delay(has_key) -> float:
    """Seconds between calls: CIRCL and NVD both allow ~10x the rate with an API key."""
    return 0.65 if has_key else 6.5


class RateLimiter:
    """Thread-safe minimum spacing between calls to one service."""

    def __init__(self):
        self._lock = Lock()
        self._last = 0.0

    def wait(self, delay: float) -> None:
        with self._lock:
            elapsed = time.time() - self._last
            if elapsed < delay:
                time.sleep(delay - elapsed)
            self._last = time.time()


# One limiter per call site, as in v1.0.0 (sharing them would slow lookups down).
circl_limiter = RateLimiter()
nvd_cve_limiter = RateLimiter()
nvd_cpe_limiter = RateLimiter()
