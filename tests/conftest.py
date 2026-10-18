import sys
from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent
SCANS = TESTS_DIR / "fixtures" / "scans"

for p in (str(REPO_ROOT), str(TESTS_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)


@pytest.fixture
def scans():
    return SCANS


@pytest.fixture
def no_sleep(monkeypatch):
    """Rate limiters and retry back-offs call time.sleep; make them instant."""
    import time

    monkeypatch.setattr(time, "sleep", lambda s: None)


@pytest.fixture
def net(no_sleep, monkeypatch):
    """All HTTP served from tests/fixtures/api; no keys from the host environment."""
    from mocknet import MockNet

    for var in ("GITHUB_TOKEN", "NVD_API_KEY", "VULNERS_API_KEY", "CIRCL_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    mock = MockNet().install()
    yield mock
    mock.uninstall()


@pytest.fixture
def session():
    import requests

    return requests.Session()
