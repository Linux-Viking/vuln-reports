"""Severity distribution pie chart (matplotlib, dark theme)."""

from vuln_reports.reporting.common import severity_bucket

try:
    import base64
    import io

    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False

COLORS = {
    "Critical": "#dc2626",  # red-600
    "High": "#ea580c",  # orange-600
    "Medium": "#f59e0b",  # amber-500
    "Low": "#3b82f6",  # blue-500
    "Info": "#22c55e",  # green-500
}


def severity_counts(vulnerabilities: dict) -> dict:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for v in vulnerabilities.values():
        score = v.get("cvss_score")
        if not isinstance(score, (int, float)):
            try:
                score = 0 if score == "N/A" or score is None else float(score)
            except (ValueError, TypeError):
                score = 0
        counts[severity_bucket(score)] += 1
    return counts


def generate_severity_chart(vulnerabilities: dict, return_bytes: bool = False):
    """PNG pie chart as base64 text, or a BytesIO when ``return_bytes``; None if nothing to plot."""
    if not HAS_MATPLOTLIB:
        return None

    counts = severity_counts(vulnerabilities)
    labels = [k for k in counts if counts[k] > 0]
    sizes = [counts[k] for k in counts if counts[k] > 0]
    if not sizes:
        return None

    # Dark background to match the report theme
    plt.figure(figsize=(7, 5), facecolor="#0F172A")
    plt.rcParams["text.color"] = "white"
    patches, texts, autotexts = plt.pie(
        sizes,
        labels=labels,
        autopct="%1.1f%%",
        startangle=140,
        colors=[COLORS[label] for label in labels],
        textprops={"fontsize": 10, "weight": "bold"},
    )
    for text in texts:
        text.set_color("white")
    for autotext in autotexts:
        autotext.set_color("white")

    plt.title("Severity Distribution", color="white", fontsize=14, fontweight="bold", pad=10)
    plt.axis("equal")

    buf = io.BytesIO()
    plt.savefig(buf, format="png", bbox_inches="tight", facecolor="#0F172A", dpi=150)
    plt.close()
    buf.seek(0)

    if return_bytes:
        return buf
    return base64.b64encode(buf.read()).decode("utf-8")
