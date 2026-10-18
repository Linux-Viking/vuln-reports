"""Helpers shared by the report formats: severity, statistics, ordering, templates."""

import os
from datetime import datetime

# Repository-level templates/ directory (users drop a branded report_template.docx here).
TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "templates")

SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]


def get_score(v) -> float:
    """CVSS as a float for sorting ("N/A" -> 0)."""
    s = v.get("cvss_score", 0)
    return float(s) if s != "N/A" else 0


def severity_bucket(score) -> str:
    """Chart/DOCX severity label from a numeric score (Low starts at 0.1)."""
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    elif score >= 0.1:
        return "Low"
    return "Info"


def get_severity(cvss_score) -> str:
    """Map CVSS score to the lower-case level used by ``--severity`` (Low starts above 0.0)."""
    if cvss_score == "N/A":
        return "info"
    try:
        score = float(cvss_score)
        if score >= 9.0:
            return "critical"
        elif score >= 7.0:
            return "high"
        elif score >= 4.0:
            return "medium"
        elif score > 0.0:
            return "low"
        else:
            return "info"
    except (ValueError, TypeError):
        return "info"


def _numeric(v):
    return isinstance(v.get("cvss_score"), (int, float))


def compute_stats(vulnerabilities: dict, cve_to_hosts: dict) -> dict:
    """Summary numbers for the HTML/PDF/Markdown executive summary."""
    vulns = vulnerabilities.values()
    return {
        "total_hosts": len(set(h[0] for hosts in cve_to_hosts.values() for h in hosts)),
        "total_cves": len(vulnerabilities),
        "critical_count": sum(1 for v in vulns if _numeric(v) and v["cvss_score"] >= 9),
        "high_count": sum(1 for v in vulns if _numeric(v) and 7 <= v["cvss_score"] < 9),
        "medium_count": sum(1 for v in vulns if _numeric(v) and 4 <= v["cvss_score"] < 7),
        "low_count": sum(1 for v in vulns if _numeric(v) and 0.1 <= v["cvss_score"] < 4),
        "info_count": sum(1 for v in vulns if not _numeric(v) or v["cvss_score"] < 0.1),
        "kev_count": sum(1 for v in vulns if v.get("cisa_kev") == "Yes"),
    }


def sorted_by_score(vulnerabilities: dict) -> dict:
    """Vulnerabilities ordered by CVSS, highest first (stable for ties)."""
    return dict(sorted(vulnerabilities.items(), key=lambda x: get_score(x[1]), reverse=True))


def report_timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M")


def render_context(vulnerabilities, cve_to_hosts, stats, chart_b64, scanner_type, target_file) -> dict:
    return {
        "vulnerabilities": sorted_by_score(vulnerabilities),
        "cve_to_hosts": cve_to_hosts,
        "stats": stats,
        "chart_b64": chart_b64,
        "date": report_timestamp(),
        "scanner_type": scanner_type,
        "target_file": os.path.basename(target_file),
    }


def affected_summary(affected) -> str:
    return "; ".join([f"{a['product']} ({', '.join(a['versions'])})" for a in affected])
