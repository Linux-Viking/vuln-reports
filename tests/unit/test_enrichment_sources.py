import pytest

from vuln_reports.enrichment import circl, epss, exploits, kev, keys, lookup, nvd, vulners


def test_circl_retries_after_429(net, session):
    data, error = circl.fetch_record(session, "CVE-2022-0001")
    assert error is None and data["cveMetadata"]["cveId"] == "CVE-2022-0001"
    assert net.calls[("circl", "CVE-2022-0001")] == 2


def test_circl_not_found_is_an_error_after_retries(net, session):
    data, error = circl.fetch_record(session, "CVE-2099-0001")
    assert data is None and "404" in error
    assert net.calls[("circl", "CVE-2099-0001")] == circl.MAX_RETRIES


def test_epss(net, session):
    assert epss.epss_score(epss.fetch_epss(session, "CVE-2021-44228")) == "0.944570000"
    assert epss.epss_score(epss.fetch_epss(session, "CVE-2014-0160")) == "N/A"


def test_nvd_cvss_fallback_v2_uses_access_fields(net):
    assert nvd.fetch_cvss("CVE-2014-0160") == (5.0, "LOW", "N/A", "NETWORK")
    assert nvd.fetch_cvss("CVE-2022-0001") == ("N/A", "N/A", "N/A", "N/A")


def test_cves_for_cpe_applies_overrides_and_aliases(net, session):
    cves = nvd.cves_for_cpe(session, "cpe:/a:igor_sysoev:nginx:1.29.8")
    assert sorted(cves) == ["CVE-2022-0001", "CVE-2026-42945"]
    assert net.calls[("nvd_cpe", "cpe:2.3:a:f5:nginx:1.29.8")] == 1
    assert net.calls[("nvd_cpe", "cpe:2.3:a:nginx:nginx:1.29.8")] == 1


def test_kev_status_signals():
    assert kev.kev_status([{"other": {"type": "kev"}}], {}, [], []) == "Yes"
    assert kev.kev_status([], {"tags": ["x_known-exploited-vulnerability"]}, [], []) == "Yes"
    assert kev.kev_status([], {}, [{"tags": ["cisa-kev"]}], []) == "Yes"
    assert kev.kev_status([], {}, [], ["https://www.cisa.gov/known-exploited-vulnerabilities-catalog"]) == "Yes"
    assert kev.kev_status([], {}, [], ["https://example.test"]) == "No"


def test_kev_status_does_not_mutate_record_tags():
    cna = {"tags": ["a"]}
    kev.kev_status([], cna, [{"tags": ["b"]}], [])
    assert cna["tags"] == ["a"]


def test_poc_from_references():
    refs = [{"url": "https://example.test"}, {"url": "https://www.exploit-db.com/exploits/1"}]
    assert exploits.poc_from_references(refs, "CVE-1") == ("Yes", "https://www.exploit-db.com/exploits/1")
    assert exploits.poc_from_references([{"url": "https://github.com/x/CVE-1-poc"}], "CVE-1")[0] == "Yes"
    assert exploits.poc_from_references([{"url": "https://github.com/x/other"}], "CVE-1") == ("No", "N/A")


def test_poc_aliases():
    assert exploits.poc_aliases("Terrapin", "OpenSSH: Terrapin", False, False) == ["Terrapin", "OpenSSH: Terrapin"]
    assert exploits.poc_aliases(None, "A very long descriptive title here", False, False) == []
    assert exploits.poc_aliases(None, "Short", True, False) == []


def test_github_poc_skips_scanners(net, session):
    url = exploits.get_poc_from_github(session, "CVE-2023-48795", None)
    assert url == "https://github.com/example-org/CVE-2023-48795-poc"


def test_github_code_search_needs_token_and_alias(net, session):
    assert exploits.get_poc_from_github(session, "CVE-2000-0001", None, aliases=["Terrapin"]) is None
    url = exploits.get_poc_from_github(session, "CVE-2000-0001", "test-token", aliases=["Terrapin"])
    assert url == "https://github.com/example-org/collection/tree/main/exploits/terrapin"


def test_vulners_records_require_key(net, session):
    assert vulners.fetch_records(session, "CVE-2014-0160", None) == []
    assert len(vulners.fetch_records(session, "CVE-2014-0160", "k")) == 2


def test_vulners_affected_products_dedupes_and_formats(net, session):
    records = vulners.fetch_records(session, "CVE-2014-0160", "k")
    assert vulners.affected_products(records) == [
        {"vendor": "Unknown", "product": "openssl", "versions": ["before 1.0.1g"]},
        {"vendor": "Unknown", "product": "openssl", "versions": ["up to 1.0.2-beta1"]},
    ]


def test_vulners_improve_text_prefers_kev_record():
    records = [
        {"type": "nvd", "title": "NVD title long enough"},
        {"type": "cisa_kev", "title": "KEV title long enough"},
    ]
    title, desc = vulners.improve_text(records, "CVE-1", "CVE-1", "Resolved: ...", False, False)
    assert title == "KEV title long enough"  # cisa_kev records are consulted first
    assert desc == "Resolved: ..."


def test_get_cve_data_full_record(net, session):
    data = lookup.get_cve_data(session, "CVE-2021-44228", None)
    assert data["title"].startswith("Apache Log4j2 JNDI")
    assert data["cvss_score"] == 10.0
    assert data["cisa_kev"] == "Yes"
    assert data["exploitability"] == "Exploited in the wild"
    assert data["poc_link"] == "https://www.exploit-db.com/exploits/00000"
    assert data["remediation"].startswith("Upgrade to Log4j 2.17.1")
    assert net.calls[("github_repositories", '"CVE-2021-44228" exploit OR poc')] == 0  # PoC already known


def test_get_cve_data_errors(net, session):
    assert lookup.get_cve_data(session, "not-a-cve", None) == {
        "cve_id": "not-a-cve",
        "error": "Invalid format: not-a-cve",
    }
    assert "404" in lookup.get_cve_data(session, "CVE-2099-0001", None)["error"]


@pytest.mark.parametrize(
    "texts, expected",
    [
        (["CVE-2021-44228, cve-2023-48795"], ["CVE-2021-44228", "CVE-2023-48795"]),
        (["junk CVE-2024-6387\nCVE-2024-6387 CVE-123-1"], ["CVE-2024-6387"]),
    ],
)
def test_extract_cve_ids(texts, expected):
    assert lookup.extract_cve_ids(texts) == expected


def test_get_keys_env_then_keyring(monkeypatch):
    for var in ("GITHUB_TOKEN", "NVD_API_KEY", "VULNERS_API_KEY", "CIRCL_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("NVD_API_KEY", "env-nvd")
    stored = {"github-token": "ring-gh"}
    monkeypatch.setattr(keys.keyring, "get_password", lambda service, name: stored.get(name))
    assert keys.get_keys() == ("ring-gh", "env-nvd", None, None)

    def broken(service, name):
        raise RuntimeError("no backend")

    monkeypatch.setattr(keys.keyring, "get_password", broken)
    assert keys.get_keys() == (None, "env-nvd", None, None)
