"""Offline stand-ins for every external service the suite talks to.

All responses are served from the synthetic fixtures in ``tests/fixtures/api``.
``install()`` patches ``requests`` (via the ``responses`` library) and
``urllib.request.urlopen`` (used by the NVD CVSS fallback); anything not mocked
here raises a ConnectionError so no test can reach the real network.
"""

import io
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path

import responses

API_DIR = Path(__file__).parent / "fixtures" / "api"


def _load(name):
    return json.loads((API_DIR / name).read_text(encoding="utf-8"))


class MockNet:
    def __init__(self):
        self.circl = {p.stem: json.loads(p.read_text(encoding="utf-8")) for p in (API_DIR / "circl").glob("*.json")}
        self.circl_429 = _load("circl_429.json")
        self.epss = _load("epss.json")
        self.nvd_cve = _load("nvd_cve.json")
        self.nvd_cpe = _load("nvd_cpe.json")
        self.github = _load("github.json")
        self.vulners = _load("vulners.json")
        self.calls = Counter()
        self.requests_mock = None
        self._orig_urlopen = None

    # --- requests callbacks -------------------------------------------------
    def _circl(self, request):
        cve_id = request.path_url.rsplit("/", 1)[-1]
        self.calls[("circl", cve_id)] += 1
        if self.calls[("circl", cve_id)] <= self.circl_429.get(cve_id, 0):
            return 429, {}, json.dumps({"message": "rate limited"})
        if cve_id not in self.circl:
            return 404, {}, json.dumps({"message": "Not found"})
        return 200, {"Content-Type": "application/json"}, json.dumps(self.circl[cve_id])

    def _epss(self, request):
        cve_id = urllib.parse.parse_qs(urllib.parse.urlsplit(request.url).query).get("cve", [""])[0]
        self.calls[("epss", cve_id)] += 1
        data = [{"cve": cve_id, "epss": self.epss[cve_id], "percentile": "0.5"}] if cve_id in self.epss else []
        return 200, {}, json.dumps({"status": "OK", "data": data})

    def _nvd_cpe(self, request):
        cpe = urllib.parse.parse_qs(urllib.parse.urlsplit(request.url).query).get("virtualMatchString", [""])[0]
        self.calls[("nvd_cpe", cpe)] += 1
        vulns = [{"cve": {"id": c}} for c in self.nvd_cpe.get(cpe, [])]
        return 200, {}, json.dumps({"totalResults": len(vulns), "vulnerabilities": vulns})

    def _github(self, kind):
        def callback(request):
            q = urllib.parse.parse_qs(urllib.parse.urlsplit(request.url).query).get("q", [""])[0]
            self.calls[("github_" + kind, q)] += 1
            items = []
            for key, found in self.github[kind].items():
                if q.startswith(key):
                    items = found
                    break
            return 200, {}, json.dumps({"total_count": len(items), "items": items})

        return callback

    def _vulners(self, request):
        cve_id = json.loads(request.body)["query"].split(":", 1)[1]
        self.calls[("vulners", cve_id)] += 1
        hits = [{"_source": src} for src in self.vulners.get(cve_id, [])]
        return 200, {}, json.dumps({"result": "OK", "data": {"search": hits}})

    # --- urllib (NVD CVE fallback) -----------------------------------------
    def _urlopen(self, req, *args, **kwargs):
        url = req.full_url if isinstance(req, urllib.request.Request) else req
        match = re.match(r"https://services\.nvd\.nist\.gov/rest/json/cves/2\.0\?cveId=(.+)$", url)
        if not match:
            raise urllib.error.URLError(f"mocknet: unexpected urlopen {url}")
        cve_id = match.group(1)
        self.calls[("nvd_cve", cve_id)] += 1
        if cve_id not in self.nvd_cve:
            raise urllib.error.HTTPError(url, 404, "Not Found", {}, io.BytesIO(b""))
        body = {"vulnerabilities": [{"cve": {"id": cve_id, "metrics": self.nvd_cve[cve_id]}}]}
        return _FakeResponse(200, json.dumps(body).encode())

    # --- lifecycle ----------------------------------------------------------
    def install(self):
        rsps = responses.RequestsMock(assert_all_requests_are_fired=False)
        rsps.add_callback(responses.GET, re.compile(r"https://cve\.circl\.lu/api/cve/.+"), callback=self._circl)
        rsps.add_callback(responses.GET, re.compile(r"https://api\.first\.org/data/v1/epss.*"), callback=self._epss)
        rsps.add_callback(
            responses.GET, re.compile(r"https://services\.nvd\.nist\.gov/rest/json/cves/2\.0.*"), callback=self._nvd_cpe
        )
        rsps.add_callback(
            responses.GET,
            re.compile(r"https://api\.github\.com/search/repositories.*"),
            callback=self._github("repositories"),
        )
        rsps.add_callback(
            responses.GET, re.compile(r"https://api\.github\.com/search/code.*"), callback=self._github("code")
        )
        rsps.add_callback(
            responses.POST, re.compile(r"https://vulners\.com/api/v3/search/lucene/.*"), callback=self._vulners
        )
        rsps.start()
        self.requests_mock = rsps
        self._orig_urlopen = urllib.request.urlopen
        urllib.request.urlopen = self._urlopen
        return self

    def uninstall(self):
        if self.requests_mock is not None:
            self.requests_mock.stop()
            self.requests_mock.reset()
            self.requests_mock = None
        if self._orig_urlopen is not None:
            urllib.request.urlopen = self._orig_urlopen
            self._orig_urlopen = None


class _FakeResponse:
    def __init__(self, code, body):
        self._code = code
        self._body = body

    def getcode(self):
        return self._code

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False
