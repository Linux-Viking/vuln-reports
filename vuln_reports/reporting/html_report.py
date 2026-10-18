"""HTML dashboard, Markdown and PDF reports rendered from the Jinja2 templates."""

from vuln_reports.reporting.chart import generate_severity_chart
from vuln_reports.reporting.common import TEMPLATES_DIR, compute_stats, render_context

try:
    from jinja2 import Environment, FileSystemLoader

    HAS_JINJA = True
except Exception:
    HAS_JINJA = False

try:
    from weasyprint import HTML

    HAS_WEASYPRINT = True
except Exception:
    HAS_WEASYPRINT = False


def _prepare(vulnerabilities, cve_to_hosts):
    """Stats and chart are computed outside the error handler, as in v1.0.0."""
    return compute_stats(vulnerabilities, cve_to_hosts), generate_severity_chart(vulnerabilities)


def _render(template_name, prepared, vulnerabilities, cve_to_hosts, scanner_type, target_file) -> str:
    stats, chart_b64 = prepared
    # Autoescaping stays off to keep output identical to v1.0.0 (tracked as a follow-up).
    env = Environment(loader=FileSystemLoader(TEMPLATES_DIR))  # nosec B701
    template = env.get_template(template_name)
    return template.render(**render_context(vulnerabilities, cve_to_hosts, stats, chart_b64, scanner_type, target_file))


def save_html_report(vulnerabilities, cve_to_hosts, scanner_type, target_file, output_file):
    if not HAS_JINJA:
        print("[!] Jinja2 not installed. HTML report skipped.")
        return
    prepared = _prepare(vulnerabilities, cve_to_hosts)
    try:
        html_out = _render("report_template.html", prepared, vulnerabilities, cve_to_hosts, scanner_type, target_file)
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html_out)
        print(f"[+] HTML intelligence report saved to: {output_file}")
    except Exception as e:
        print(f"[!] Error generating HTML report: {e}")


def save_markdown_report(vulnerabilities, cve_to_hosts, scanner_type, target_file, output_file):
    if not HAS_JINJA:
        return
    prepared = _prepare(vulnerabilities, cve_to_hosts)
    try:
        md_out = _render("report_template.md", prepared, vulnerabilities, cve_to_hosts, scanner_type, target_file)
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(md_out)
        print(f"[+] Markdown report saved to: {output_file}")
    except Exception as e:
        print(f"[!] Error generating Markdown report: {e}")


def save_pdf_report(vulnerabilities, cve_to_hosts, scanner_type, target_file, output_file):
    if not HAS_WEASYPRINT or not HAS_JINJA:
        print("[!] PDF generation requires WeasyPrint and Jinja2.")
        print("[*] Note: On Windows, WeasyPrint also requires the GTK+ runtime installed and in your PATH.")
        print("[!] PDF report skipped.")
        return
    prepared = _prepare(vulnerabilities, cve_to_hosts)
    try:
        html_out = _render("report_template.html", prepared, vulnerabilities, cve_to_hosts, scanner_type, target_file)
        HTML(string=html_out).write_pdf(output_file)
        print(f"[+] PDF intelligence report saved to: {output_file}")
    except Exception as e:
        print(f"[!] Error generating PDF report: {e}")
