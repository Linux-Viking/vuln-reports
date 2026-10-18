"""Heuristics that turn a raw CVE JSON 5 record into readable report fields.

Titles, product names, affected-version ranges, CVSS and remediation advice are
derived here. The heuristics are carried over unchanged from v1.0.0; the
regression suite pins their output.
"""

import re
from typing import Any

GENERIC_VULNS = [
    "information disclosure",
    "remote code execution",
    "command injection",
    "cross-site scripting",
    "buffer overflow",
    "denial of service",
    "privilege escalation",
    "sql injection",
    "path traversal",
    "directory traversal",
    "authentication bypass",
    "incorrect authorization",
    "input validation",
    "cross-site request forgery",
    "csrf",
    "xss",
    "rce",
    "use-after-free",
    "user enumeration",
    "impersonation",
    "crlf injection",
    "side-channel",
    "race condition",
    "memory corruption",
]

# "allows ... to [action]", "mishandles [feature]", "is vulnerable to [type]", "due to [reason]", ...
ACTION_PATTERNS = [
    r"allows (?:remote )?attackers to ([^,\.\(;]+)",
    r"mishandles ([^,\.\(;]+)",
    r"is vulnerable to ([^,\.\(;]+)",
    r"could allow (?:remote )?attackers to ([^,\.\(;]+)",
    r"due to ([^,\.\(;]+)",
    r"lacks ([^,\.\(;]+)",
    r"provides ([^,\.\(;]+)",
    r"creates ([^,\.\(;]+)",
    r"triggering ([^,\.\(;]+)",
    r"allows ([^,\.\(;]+)",
]

NOISE_WORDS = ["issue", "use", "vulnerability", "multiple", "all", "certain", "use-after-free", "an", "the"]

DEFAULT_REMEDIATION = "Apply the latest security patches from the vendor."

REMEDIATION_PATTERNS = [
    r"recommended to upgrade to ([^,\.\(;]+)",
    r"fixed in (?:version )?([^,\.\(;]+)",
    r"update to (?:version )?([^,\.\(;]+)",
    r"mitigated by ([^,\.\(;]+)",
]

DESC_VERSION_PATTERNS = [
    r"(\d+(?:\.\d+)* (?:before|through|prior to) (?:build )?\d+(?:\.\d+)*)",
    r"v(?:ersion)?\s?(\d+(?:\.\d+)*)",
    r"(\d+(?:\.\d+)+)",
]


def normalize_text(text: Any) -> str:
    if not text or not isinstance(text, str):
        return str(text) if text is not None else "N/A"
    text = text.replace(" ", " ").replace("\\n", " ")
    return re.sub(r"\s+", " ", text).strip()


def clean_noise(text):
    """Strip leading filler ("the", "in", "vulnerability in", ...) from a product/detail phrase."""
    if not text:
        return ""
    prev = ""
    while text != prev:
        prev = text
        text = re.sub(
            r"^(?:the|in|an|a|at|of|on|issue was discovered in|multiple|use-after-free vulnerability in|vulnerability in)\s+",
            "",
            text,
            flags=re.IGNORECASE,
        ).strip()
    return text


def derive_product(description: str, affected_raw: list):
    """Best-guess product name plus every product named in the description.

    Returns ``(product, detected_products)``.
    """
    product = affected_raw[0].get("product", "") if affected_raw else ""
    if product.lower() in ["n/a", "unknown", "none", ""]:
        product = ""

    detected_products = []
    lowered = description.lower()

    # Pre-check for common high-value products
    if "openssh" in lowered:
        product = "OpenSSH"
        detected_products = ["OpenSSH"]
    elif "apache http server" in lowered or "httpd" in lowered:
        product = "Apache HTTP Server"
        detected_products = ["Apache HTTP Server"]

    if not product:
        # 1. Capitalised product list at the start of the description
        multi_match = re.match(
            r"^([A-Z][a-zA-Z0-9]+(?:\s+[A-Z][a-zA-Z0-9]+)*(?:,\s+[A-Z][a-zA-Z0-9]+(?:\s+[A-Z][a-zA-Z0-9]+)*)*)",
            description,
        )
        if multi_match:
            products_str = multi_match.group(1)
            detected_products = [p.strip() for p in re.split(r",| and ", products_str) if p.strip()]
            product = detected_products[0] if detected_products else ""

        # 2. "... in Product", "... of Product", ...
        if not product or product.lower() in ["the", "in", "an", "a"]:
            pm = re.search(
                r"(?:discovered in|\bin\b|\bat\b|\bof\b) ([A-Z][a-zA-Z0-9]+(?:\s+[A-Z][a-zA-Z0-9]+)*)", description
            )
            if pm:
                product = pm.group(1).strip()
                detected_products = [product]
            elif "owncloud" in lowered:
                product = "ownCloud"
                detected_products = [product]
            elif "log4j" in lowered:
                product = "Apache Log4j"
                detected_products = [product]

    product = clean_noise(product)
    if product.lower() in NOISE_WORDS:
        product = ""

    detected_products = [clean_noise(p) for p in detected_products if clean_noise(p)]
    detected_products = [p for p in detected_products if p.lower() not in NOISE_WORDS]

    if not product and detected_products:
        product = detected_products[0]
    return product, detected_products


def _vuln_type(description: str):
    lowered = description.lower()
    for gv in GENERIC_VULNS:
        if gv in lowered:
            vuln_type = gv.title()
            if len(vuln_type) <= 4:
                vuln_type = vuln_type.upper()  # CSRF, XSS, RCE
            return vuln_type
    for pattern in ACTION_PATTERNS:
        action_match = re.search(pattern, description, re.IGNORECASE)
        if action_match:
            return action_match.group(1).strip().capitalize()
    return None


def _cwe_title(cna: dict, adp_list: list):
    all_problem_types = cna.get("problemTypes", []) + [pt for adp in adp_list for pt in adp.get("problemTypes", [])]
    for pt in all_problem_types:
        for desc in pt.get("descriptions", []):
            if desc.get("lang") == "en" and desc.get("description") and desc.get("description").lower() != "n/a":
                return re.sub(r"^CWE-\d+\s+", "", desc.get("description"), flags=re.IGNORECASE)
    return None


def raw_title(cna: dict, adp_list: list):
    """The record's own title: CNA first, then a non-boilerplate ADP title."""
    title = cna.get("title")
    if not title:
        for adp in adp_list:
            adp_title = adp.get("title", "")
            if adp_title and "ADP" not in adp_title.upper() and "CVE Program" not in adp_title:
                return adp_title
    return title


def derive_title(title, description: str, product: str, cna: dict, adp_list: list):
    """Build a readable title when the record's is missing, generic, or a commit message.

    Returns ``(title, aka_title, is_generic, is_commit_msg)``; the flags describe
    the *original* title and later steps (Vulners, PoC search) depend on them.
    """
    aka_match = re.search(r"aka a? ([A-Z][a-zA-Z0-9\s\-]+?)(?:\s+attack|\.|$)", description, re.IGNORECASE)
    aka_title = aka_match.group(1).strip() if aka_match else None
    vuln_type = _vuln_type(description)
    cwe_title = _cwe_title(cna, adp_list)

    current_title = normalize_text(title)
    # Catch commit-message titles like "crypto: algif_aead - ..."
    is_commit_msg = ":" in current_title and " - " in current_title
    is_generic = (
        any(gv in current_title.lower() for gv in GENERIC_VULNS)
        or current_title.lower().startswith("vulnerability in")
        or current_title.endswith(": Privilege Escalation")
    )

    if not title or current_title == "N/A" or is_generic or is_commit_msg:
        if product:
            base = product
            detail = aka_title or vuln_type or (current_title if current_title != "N/A" else None) or cwe_title

            # If the description starts with "FILE.c in SERVICE", use that as the detail
            file_match = re.match(r"^([a-zA-Z0-9_\-\./]+\.[a-z]{1,4}(?:\s+in\s+[a-zA-Z0-9_\-]+)?)", description)
            if file_match and not aka_title:
                detail = file_match.group(1)

            if detail:
                detail = clean_noise(detail)
                current_title = base if detail.lower() in base.lower() else f"{base}: {detail}"
            else:
                current_title = f"Vulnerability in {base}"
        elif aka_title:
            current_title = aka_title
        elif vuln_type:
            current_title = vuln_type
        elif cwe_title:
            current_title = cwe_title
    return current_title, aka_title, is_generic, is_commit_msg


def _versions_from_description(description: str) -> list:
    for pattern in DESC_VERSION_PATTERNS:
        matches = re.findall(pattern, description)
        if matches:
            return list(matches)
    return []


def build_affected(affected_raw: list, description: str, product: str, detected_products: list) -> list:
    """Affected products with human-readable version ranges.

    Uses the record's ``affected`` block when it has real data (merging git and
    semver entries, noting patched versions), otherwise falls back to products
    and versions mentioned in the description.
    """
    versions_from_desc = _versions_from_description(description)
    affected = []
    if not affected_raw or (len(affected_raw) == 1 and affected_raw[0].get("product", "").lower() in ["n/a", ""]):
        if detected_products:
            for i in range(len(detected_products)):
                if detected_products[i].lower().startswith("in "):
                    detected_products[i] = detected_products[i][3:].strip()
            for p in detected_products:
                p_versions = ["N/A"]
                if versions_from_desc:
                    p_versions = versions_from_desc
                elif "SDK" in description or "software development kit" in description.lower():
                    p_versions = ["SDK (All Versions)"]
                affected.append({"vendor": "Unknown", "product": p, "versions": p_versions})
        elif product:
            affected.append(
                {
                    "vendor": "Unknown",
                    "product": product,
                    "versions": versions_from_desc if versions_from_desc else ["N/A"],
                }
            )

    if not affected:
        # Group by product to merge git and semver records
        product_map = {}
        for a in affected_raw:
            prod = a.get("product", "Unknown")
            if prod not in product_map:
                product_map[prod] = {"vendor": a.get("vendor", "Unknown"), "versions": [], "has_semver": False}

            for v in a.get("versions", []):
                v_type = v.get("versionType", "")
                status = v.get("status", "unknown")
                ver = v.get("version", "N/A")
                lt = v.get("lessThan")
                ltoe = v.get("lessThanOrEqual")

                looks_like_version = re.match(r"^\d+(\.\d+)*", str(ver))
                if v_type == "semver" or (not v_type and looks_like_version):
                    product_map[prod]["has_semver"] = True
                    item_type = "semver"
                else:
                    item_type = v_type

                if status == "affected":
                    if lt and lt != "n/a":
                        ver = f"{ver} to <{lt}"
                    elif ltoe and ltoe != "n/a":
                        ver = f"{ver} to {ltoe}"
                    if ver != "N/A":
                        product_map[prod]["versions"].append({"ver": ver, "type": item_type, "status": "affected"})
                elif status == "unaffected":
                    if ver and ver != "0" and ver != "N/A" and not str(ver).startswith("*"):
                        product_map[prod]["versions"].append({"ver": ver, "type": item_type, "status": "unaffected"})

        for prod, info in product_map.items():
            # With semver data available, drop git-hash entries for the same product
            all_vers = info["versions"]
            if info["has_semver"]:
                all_vers = [v for v in all_vers if v["type"] == "semver"]

            affected_display = []
            affected_items = [v["ver"] for v in all_vers if v["status"] == "affected"]
            unaffected_items = [v["ver"] for v in all_vers if v["status"] == "unaffected"]
            if affected_items:
                if unaffected_items:
                    patched_str = ", ".join(unaffected_items)
                    for a in affected_items:
                        if "to " not in a:
                            affected_display.append(f"{a} and later (Patched in: {patched_str})")
                        else:
                            affected_display.append(a)
                else:
                    affected_display.extend(affected_items)

            if not affected_display:
                affected_display = versions_from_desc if versions_from_desc else ["N/A"]

            affected.append({"vendor": info["vendor"], "product": prod, "versions": affected_display})
    return affected


def prefer_vulners_affected(affected: list, vulners_affected: list) -> list:
    """Use Vulners' ranges when ours are empty or contain raw git hashes."""
    has_git_hashes = any(any(len(v) > 30 for v in a["versions"]) for a in affected)
    if (not affected or has_git_hashes) and vulners_affected:
        return vulners_affected
    return affected


def all_metrics(cna: dict, adp_list: list) -> list:
    return cna.get("metrics", []) + [m for adp in adp_list for m in adp.get("metrics", [])]


def extract_cvss(metrics: list):
    """CVSS from the record: v4.0, then v3.1, then v3.0 (CNA before ADP).

    Returns ``(score, attack_complexity, user_interaction, attack_vector)``,
    all "N/A" when the record has no CVSS v3+/v4 data.
    """
    cvss_score, attack_complexity, user_interaction, threat_vector = "N/A", "N/A", "N/A", "N/A"
    for version in ["cvssV4_0", "cvssV3_1", "cvssV3_0"]:
        for m in metrics:
            v = m.get(version)
            if v and cvss_score == "N/A":
                cvss_score = v.get("baseScore", "N/A")
                attack_complexity = v.get("attackComplexity", "N/A")
                user_interaction = v.get("userInteraction", "N/A")
                threat_vector = v.get("attackVector", "N/A")
        if cvss_score != "N/A":
            break
    return cvss_score, attack_complexity, user_interaction, threat_vector


def combined_references(cve_id: str, raw_refs: list) -> list:
    refs = [f"https://nvd.nist.gov/vuln/detail/{cve_id}", f"https://www.cve.org/CVERecord?id={cve_id}"]
    for r in raw_refs:
        url = r.get("url", "")
        if url and url not in refs:
            refs.append(url)
    return refs


def derive_remediation(cna: dict, description: str, references: list) -> str:
    """Explicit solution field, else an upgrade hint from the description, else an advisory link."""
    remediation = DEFAULT_REMEDIATION

    solutions = cna.get("solutions", [])
    if solutions and isinstance(solutions, list) and solutions[0].get("value"):
        remediation = solutions[0]["value"]

    if remediation == DEFAULT_REMEDIATION:
        for pattern in REMEDIATION_PATTERNS:
            rem_match = re.search(pattern, description, re.IGNORECASE)
            if rem_match:
                remediation = f"Upgrade to {rem_match.group(1).strip()} or later."
                break

    if remediation == DEFAULT_REMEDIATION:
        for ref in references:
            if any(k in ref.lower() for k in ["advisory", "patch", "fix", "update"]):
                remediation = f"Review vendor advisory and apply available patches: {ref}"
                break
    return remediation
