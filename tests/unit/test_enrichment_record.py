from vuln_reports.enrichment import record


def test_normalize_text():
    assert record.normalize_text("a  b\\n  c ") == "a b c"
    assert record.normalize_text(None) == "N/A"
    assert record.normalize_text(5) == "5"


def test_clean_noise_strips_repeated_prefixes():
    assert record.clean_noise("the vulnerability in OpenSSL") == "OpenSSL"
    assert record.clean_noise("") == ""


def test_derive_product_prefers_known_products():
    assert record.derive_product("Bug in OpenSSH sshd", []) == ("OpenSSH", ["OpenSSH"])
    assert record.derive_product("Apache HTTP Server 2.4.49 flaw", []) == ("Apache HTTP Server", ["Apache HTTP Server"])


def test_derive_product_from_affected_or_description():
    assert record.derive_product("text", [{"product": "Widget"}])[0] == "Widget"
    product, detected = record.derive_product("Foo Bar, Baz allow things", [{"product": "n/a"}])
    assert product == "Foo Bar"
    assert detected == ["Foo Bar", "Baz"]
    assert record.derive_product("a flaw discovered in Contoso Portal", [])[0] == "Contoso Portal"


def test_raw_title_skips_boilerplate_adp_titles():
    adp = [{"title": "CISA ADP Vulnrichment"}, {"title": "CVE Program Container"}, {"title": "Real Title"}]
    assert record.raw_title({}, adp) == "Real Title"
    assert record.raw_title({"title": "CNA"}, adp) == "CNA"
    assert record.raw_title({}, [{"title": "CISA ADP Vulnrichment"}]) is None


def test_derive_title_keeps_good_title():
    assert record.derive_title("Specific title", "desc", "P", {}, []) == ("Specific title", None, False, False)


def test_derive_title_from_aka_and_generic_flags():
    desc = "Something in OpenSSH, aka a Terrapin attack."
    title, aka, generic, commit = record.derive_title(None, desc, "OpenSSH", {}, [])
    assert (title, aka, generic, commit) == ("OpenSSH: Terrapin", "Terrapin", False, False)

    title, _, generic, commit = record.derive_title(
        "Openssh: regresshion - race condition", "x race condition", "OpenSSH", {}, []
    )
    assert (title, generic, commit) == ("OpenSSH: Race Condition", True, True)


def test_derive_title_falls_back_to_cwe():
    cna = {"problemTypes": [{"descriptions": [{"lang": "en", "description": "CWE-22 Path Traversal"}]}]}
    assert record.derive_title(None, "no hints here", "", cna, [])[0] == "Path Traversal"


def test_build_affected_semver_with_patched_versions():
    raw = [
        {
            "vendor": "V",
            "product": "P",
            "versions": [
                {"version": "1.0", "status": "affected", "versionType": "semver"},
                {"version": "2.0", "lessThan": "2.5", "status": "affected", "versionType": "semver"},
                {"version": "1.5", "status": "unaffected", "versionType": "semver"},
                {"version": "deadbeef" * 5, "status": "affected", "versionType": "git"},
            ],
        }
    ]
    assert record.build_affected(raw, "desc", "P", []) == [
        {"vendor": "V", "product": "P", "versions": ["1.0 and later (Patched in: 1.5)", "2.0 to <2.5"]}
    ]


def test_build_affected_from_description_when_record_is_empty():
    affected = record.build_affected([], "Widget 1.2 before 1.4 is bad", "Widget", ["Widget"])
    assert affected == [{"vendor": "Unknown", "product": "Widget", "versions": ["1.2 before 1.4"]}]
    assert record.build_affected([], "An SDK issue", "", ["Acme"])[0]["versions"] == ["SDK (All Versions)"]


def test_prefer_vulners_affected_replaces_git_hashes():
    ours = [{"vendor": "V", "product": "P", "versions": ["a" * 40]}]
    theirs = [{"vendor": "Unknown", "product": "p", "versions": ["before 1.0"]}]
    assert record.prefer_vulners_affected(ours, theirs) == theirs
    good = [{"vendor": "V", "product": "P", "versions": ["1.0"]}]
    assert record.prefer_vulners_affected(good, theirs) == good


def test_extract_cvss_priority():
    metrics = [
        {
            "cvssV3_1": {
                "baseScore": 7.5,
                "attackComplexity": "LOW",
                "userInteraction": "NONE",
                "attackVector": "NETWORK",
            }
        },
        {
            "cvssV4_0": {
                "baseScore": 9.3,
                "attackComplexity": "HIGH",
                "userInteraction": "PASSIVE",
                "attackVector": "LOCAL",
            }
        },
    ]
    assert record.extract_cvss(metrics) == (9.3, "HIGH", "PASSIVE", "LOCAL")
    assert record.extract_cvss([]) == ("N/A", "N/A", "N/A", "N/A")


def test_combined_references_dedupes_and_prefixes():
    refs = record.combined_references("CVE-1", [{"url": "https://a"}, {"url": "https://a"}, {"url": ""}])
    assert refs == ["https://nvd.nist.gov/vuln/detail/CVE-1", "https://www.cve.org/CVERecord?id=CVE-1", "https://a"]


def test_derive_remediation_paths():
    assert record.derive_remediation({"solutions": [{"value": "Do X"}]}, "", []) == "Do X"
    # Known v1.0.0 bug, preserved by the refactor: the pattern stops at the first "." so
    # dotted versions are truncated ("fixed in version 1.2.3" -> "Upgrade to 1 or later.").
    assert record.derive_remediation({}, "This is fixed in version 1.2.3.", []) == "Upgrade to 1 or later."
    assert record.derive_remediation({}, "Users are recommended to upgrade to v2, which fixes it", []) == (
        "Upgrade to v2 or later."
    )
    assert record.derive_remediation({}, "nothing", ["https://x/advisory/1"]) == (
        "Review vendor advisory and apply available patches: https://x/advisory/1"
    )
    assert record.derive_remediation({}, "nothing", ["https://x"]) == record.DEFAULT_REMEDIATION
