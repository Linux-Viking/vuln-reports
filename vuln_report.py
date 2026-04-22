#!/usr/bin/env python3
"""
VulnReport: Unified vulnerability report generator.
Combines Scan2CVE (parsing) and CVE-Lookup (enrichment) to produce a detailed CSV.
"""

import sys
import os

# --- Aggressive GLib/GIO Warning Suppression ---
# These must be set BEFORE any GIO/GTK-based libraries are loaded.
os.environ["GIO_USE_VFS"] = "local"
os.environ["GIO_USE_DESKTOP_APP_INFO"] = "none"
os.environ["GIO_USE_VOLUME_MONITOR"] = "none"
os.environ["G_MESSAGES_DEBUG"] = "none"

# Function to suppress C-level stderr (to catch persistent GLib warnings on Windows)
def suppress_gio_noise():
    if os.name != 'nt': return None
    try:
        null_fd = os.open(os.devnull, os.O_RDWR)
        old_stderr = os.dup(sys.stderr.fileno())
        os.dup2(null_fd, sys.stderr.fileno())
        os.close(null_fd)
        return old_stderr
    except: return None

def restore_gio_noise(old_stderr):
    if old_stderr is not None:
        os.dup2(old_stderr, sys.stderr.fileno())
        os.close(old_stderr)

# Suppress noise during initialization imports
_gio_stderr = suppress_gio_noise()
try:
    import csv
    import argparse
    import requests
    import time
    from typing import List, Dict, Any

    # Dynamic imports
    import scan2cve
    import cve_lookup

    from concurrent.futures import ThreadPoolExecutor, as_completed
    from datetime import datetime

    try:
        from jinja2 import Environment, FileSystemLoader
        HAS_JINJA = True
    except Exception:
        HAS_JINJA = False

    try:
        from weasyprint import HTML
        HAS_WEASYPRINT = True
    except Exception as e:
        HAS_WEASYPRINT = False

    try:
        import openpyxl
        from openpyxl.styles import Font, Alignment, PatternFill
        from openpyxl.utils import get_column_letter
        HAS_OPENPYXL = True
    except ImportError:
        HAS_OPENPYXL = False

    try:
        from docx import Document
        from docx.shared import Pt, RGBColor, Inches
        from docx.enum.text import WD_ALIGN_PARAGRAPH
        HAS_DOCX = True
    except ImportError:
        HAS_DOCX = False

    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import io
        import base64
        HAS_MATPLOTLIB = True
    except ImportError:
        HAS_MATPLOTLIB = False
finally:
    restore_gio_noise(_gio_stderr)

def get_detailed_cve_info(cve_ids: List[str], github_token: str = None, nvd_key: str = None, max_workers: int = 10) -> Dict[str, Dict[str, Any]]:
    """Fetch details for a list of CVEs using cve_lookup logic with concurrency."""
    session = requests.Session()
    cve_details = {}
    print(f"[*] Fetching enrichment data for {len(cve_ids)} unique CVEs...")
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(cve_lookup.get_cve_data, session, cve_id, github_token, nvd_key): cve_id for cve_id in cve_ids}
        for future in as_completed(futures):
            cve_id = futures[future]
            try:
                data = future.result()
                if "error" not in data:
                    cve_details[cve_id] = data
                else:
                    print(f"  [!] Error enriching {cve_id}: {data['error']}")
                    cve_details[cve_id] = {"cve_id": cve_id, "error": data["error"]}
            except Exception as e:
                print(f"  [!] Exception enriching {cve_id}: {e}")
                cve_details[cve_id] = {"cve_id": cve_id, "error": str(e)}
    return cve_details

def generate_severity_chart(vulnerabilities: Dict[str, Any], return_bytes: bool = False):
    """Generates a severity distribution pie chart and returns it as a base64 string or bytes."""
    if not HAS_MATPLOTLIB:
        return None

    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    
    for v in vulnerabilities.values():
        score = v.get('cvss_score')
        if not isinstance(score, (int, float)):
            try:
                if score == "N/A" or score is None:
                    score = 0
                else:
                    score = float(score)
            except (ValueError, TypeError):
                score = 0
        
        if score >= 9.0:
            counts["Critical"] += 1
        elif score >= 7.0:
            counts["High"] += 1
        elif score >= 4.0:
            counts["Medium"] += 1
        elif score >= 0.1:
            counts["Low"] += 1
        else:
            counts["Info"] += 1

    labels = [k for k in counts.keys() if counts[k] > 0]
    sizes = [counts[k] for k in counts.keys() if counts[k] > 0]
    
    if not sizes:
        return None

    colors = {
        "Critical": "#dc2626", # red-600
        "High": "#ea580c",     # orange-600
        "Medium": "#f59e0b",   # amber-500
        "Low": "#3b82f6",      # blue-500
        "Info": "#22c55e"      # green-500
    }
    chart_colors = [colors[l] for l in labels]

    # Create figure with dark background to match report theme
    plt.figure(figsize=(7, 5), facecolor='#0F172A')
    plt.rcParams['text.color'] = 'white'
    
    patches, texts, autotexts = plt.pie(
        sizes, 
        labels=labels, 
        autopct='%1.1f%%', 
        startangle=140, 
        colors=chart_colors,
        textprops={'fontsize': 10, 'weight': 'bold'}
    )
    
    for text in texts:
        text.set_color('white')
    for autotext in autotexts:
        autotext.set_color('white')

    plt.title("Severity Distribution", color='white', fontsize=14, fontweight='bold', pad=10)
    plt.axis('equal')
    
    buf = io.BytesIO()
    plt.savefig(buf, format='png', bbox_inches='tight', facecolor='#0F172A', dpi=150)
    plt.close()
    buf.seek(0)
    
    if return_bytes:
        return buf
    return base64.b64encode(buf.read()).decode('utf-8')

def save_docx_report(vulnerabilities, cve_to_hosts, scanner_type, target_file, output_file):
    if not HAS_DOCX:
        print("[!] python-docx not installed. DOCX report skipped.")
        return

    from docx.oxml.ns import nsdecls
    from docx.oxml import parse_xml
    from docx.oxml.shared import qn

    # --- TEMPLATE LOGIC ---
    template_path = os.path.join(os.path.dirname(__file__), 'templates', 'report_template.docx')
    if os.path.exists(template_path):
        doc = Document(template_path)
        print(f"[*] Using custom Word template: {template_path}")
    else:
        doc = Document()
    
    # --- GLOBAL DARK THEME (Fallback/Base) ---
    # 1. Set Page Background Color (#0F172A)
    shading_elm_2 = parse_xml(r'<w:background {} w:color="0F172A"/>'.format(nsdecls('w')))
    doc.element.insert(0, shading_elm_2)
    
    # 2. Enable background color display in Word settings
    section = doc.sections[0]
    settings = doc.settings.element
    display_bg = parse_xml(r'<w:displayBackgroundShape {}/>'.format(nsdecls('w')))
    settings.append(display_bg)

    # 3. Helper for light text by default
    def set_run_light(run, size=None, bold=False):
        run.font.color.rgb = RGBColor(248, 250, 252) # text-main
        if size: run.font.size = Pt(size)
        if bold: run.bold = True
        return run

    # Title
    title_p = doc.add_paragraph()
    title_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    title_run = title_p.add_run('Vulnerability Intelligence Report')
    title_run.font.size = Pt(24)
    title_run.font.color.rgb = RGBColor(59, 130, 246) # blue-500
    title_run.bold = True
    
    # Metadata
    meta = doc.add_paragraph()
    meta.alignment = WD_ALIGN_PARAGRAPH.CENTER
    m_run = meta.add_run(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M')} | ")
    set_run_light(m_run)
    m_run2 = meta.add_run(f"Scanner: {scanner_type} | Target: {os.path.basename(target_file)}")
    set_run_light(m_run2)
    m_run2.italic = True

    # --- Severity Chart ---
    chart_buf = generate_severity_chart(vulnerabilities, return_bytes=True)
    if chart_buf:
        doc.add_picture(chart_buf, width=Inches(5.5))
        last_p = doc.paragraphs[-1]
        last_p.alignment = WD_ALIGN_PARAGRAPH.CENTER

    # Summary Statistics
    doc.add_heading('Executive Summary', level=1)
    # Note: Headings need color fix too as they default to black
    for p in doc.paragraphs:
        if p.style.name.startswith('Heading'):
            for run in p.runs: run.font.color.rgb = RGBColor(248, 250, 252)

    stats = {
        "HOSTS": len(set(h[0] for hosts in cve_to_hosts.values() for h in hosts)),
        "Unique CVEs": len(vulnerabilities),
        "Critical Risks": sum(1 for v in vulnerabilities.values() if isinstance(v.get('cvss_score'), (int, float)) and v['cvss_score'] >= 9),
        "KEV Exploited": sum(1 for v in vulnerabilities.values() if v.get('cisa_kev') == 'Yes')
    }
    
    table = doc.add_table(rows=1, cols=4)
    table.style = 'Table Grid'
    hdr_cells = table.rows[0].cells
    for i, label in enumerate(stats.keys()):
        hdr_cells[i].text = label
        shading_elm = parse_xml(r'<w:shd {} w:fill="1E293B"/>'.format(nsdecls('w')))
        hdr_cells[i]._tc.get_or_add_tcPr().append(shading_elm)
        run = hdr_cells[i].paragraphs[0].runs[0]
        run.font.color.rgb = RGBColor(255, 255, 255)
        run.bold = True

    row_cells = table.add_row().cells
    for i, val in enumerate(stats.values()):
        row_cells[i].text = str(val)
        row_cells[i].paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
        # Dark card background for value cells too
        shading_elm = parse_xml(r'<w:shd {} w:fill="1E293B"/>'.format(nsdecls('w')))
        row_cells[i]._tc.get_or_add_tcPr().append(shading_elm)
        run = row_cells[i].paragraphs[0].runs[0]
        run.font.color.rgb = RGBColor(248, 250, 252)

    doc.add_page_break()

    # Detailed Findings
    doc.add_heading('Detailed Findings', level=1)
    
    def get_score(v):
        s = v.get('cvss_score', 0)
        return float(s) if s != 'N/A' else 0

    sorted_cves = sorted(vulnerabilities.keys(), key=lambda cid: get_score(vulnerabilities[cid]), reverse=True)

    for i, cve_id in enumerate(sorted_cves):
        d = vulnerabilities[cve_id]
        
        # CVE Header Card
        h_table = doc.add_table(rows=1, cols=1)
        h_table.style = 'Table Grid'
        cell = h_table.rows[0].cells[0]
        shading_elm = parse_xml(r'<w:shd {} w:fill="1E293B"/>'.format(nsdecls('w')))
        cell._tc.get_or_add_tcPr().append(shading_elm)
        
        p = cell.paragraphs[0]
        id_run = p.add_run(f"{cve_id}: ")
        id_run.bold = True
        id_run.font.color.rgb = RGBColor(59, 130, 246)
        id_run.font.size = Pt(14)
        
        title_run = p.add_run(d.get('title', 'N/A'))
        title_run.font.color.rgb = RGBColor(255, 255, 255)
        title_run.font.size = Pt(14)

        p2 = cell.add_paragraph()
        p2.add_run("CVSS: ").font.color.rgb = RGBColor(148, 163, 184)
        score = str(d.get('cvss_score', 'N/A'))
        s_run = p2.add_run(score)
        s_run.bold = True
        
        cvss_val = get_score(d)
        if cvss_val >= 9.0: s_run.font.color.rgb = RGBColor(220, 38, 38)   # Red (Critical)
        elif cvss_val >= 7.0: s_run.font.color.rgb = RGBColor(234, 88, 12) # Orange (High)
        elif cvss_val >= 4.0: s_run.font.color.rgb = RGBColor(245, 158, 11) # Amber (Medium)
        elif cvss_val >= 0.1: s_run.font.color.rgb = RGBColor(59, 130, 246) # Blue (Low)
        else: s_run.font.color.rgb = RGBColor(34, 197, 94)                # Green (Info/NA)
        
        p2.add_run(" | KEV: ").font.color.rgb = RGBColor(148, 163, 184)
        kev_run = p2.add_run(d.get('cisa_kev', 'N/A'))
        if d.get('cisa_kev') == 'Yes': kev_run.font.color.rgb = RGBColor(219, 39, 119)
        
        p2.add_run(" | Exploitability: ").font.color.rgb = RGBColor(148, 163, 184)
        p2.add_run(d.get('exploitability', 'N/A')).font.color.rgb = RGBColor(255, 255, 255)

        # Content - Manual color fix for every paragraph
        def add_themed_para(text, level=None, color=RGBColor(248, 250, 252), bold=False):
            if level:
                h = doc.add_heading(text, level=level)
                for run in h.runs: run.font.color.rgb = color
                return h
            else:
                p = doc.add_paragraph()
                r = p.add_run(text)
                r.font.color.rgb = color
                if bold: r.bold = True
                return p

        # --- NEW TECHNICAL FLOW ---

        # 1. Description
        add_themed_para('Description', level=3, color=RGBColor(59, 130, 246))
        add_themed_para(d.get('description', 'N/A'))

        # 2. Affected Products
        add_themed_para('Affected Products', level=3, color=RGBColor(59, 130, 246))
        for a in d.get('affected', []):
            p = doc.add_paragraph(style='List Bullet')
            r1 = p.add_run(f"{a['product']} ")
            r1.bold = True
            r1.font.color.rgb = RGBColor(248, 250, 252)
            r2 = p.add_run(f"({', '.join(a['versions'])})")
            r2.font.color.rgb = RGBColor(148, 163, 184)
        if not d.get('affected'): add_themed_para("N/A", color=RGBColor(148, 163, 184))

        # 3. Validation Evidence (Early Proof)
        add_themed_para('Validation Evidence', level=3, color=RGBColor(59, 130, 246))
        placeholder = doc.add_paragraph()
        placeholder.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = placeholder.add_run("\n[ INSERT VALIDATION SCREENSHOT HERE ]\n")
        run.font.color.rgb = RGBColor(150, 150, 150)
        run.italic = True

        caption = doc.add_paragraph()
        caption.alignment = WD_ALIGN_PARAGRAPH.CENTER
        cap_run = caption.add_run(f"Figure: Evidence of successful validation for {cve_id}")
        cap_run.font.size = Pt(9)
        cap_run.font.color.rgb = RGBColor(148, 163, 184)
        cap_run.italic = True

        # 4. Affected Hosts
        add_themed_para('Affected Hosts', level=3, color=RGBColor(59, 130, 246))
        hosts = cve_to_hosts.get(cve_id, [])
        hosts_str = ", ".join([f"{h[1] if h[1] else h[0]} ({h[2]})" for h in hosts[:5]])
        if len(hosts) > 5: hosts_str += f" (+{len(hosts)-5} more)"
        add_themed_para(hosts_str if hosts_str else "N/A")

        # 5. Remediation Recommendation
        add_themed_para('Remediation Recommendation', level=3, color=RGBColor(59, 130, 246))
        rem_p = doc.add_paragraph()
        rem_run = rem_p.add_run(d.get('remediation', 'N/A'))
        rem_run.font.color.rgb = RGBColor(59, 130, 246)
        rem_run.bold = True

        # 6. Intelligence & References
        add_themed_para('Intelligence & References', level=3, color=RGBColor(59, 130, 246))
        if d.get('poc_link') != 'N/A':
            p = doc.add_paragraph(style='List Bullet')
            r = p.add_run("Exploit PoC: ")
            r.bold = True
            r.font.color.rgb = RGBColor(248, 250, 252)
            r2 = p.add_run(d['poc_link'])
            r2.font.color.rgb = RGBColor(59, 130, 246)

        for ref in d.get('references', [])[:4]:
            p = doc.add_paragraph(ref, style='List Bullet')
            for run in p.runs: run.font.color.rgb = RGBColor(59, 130, 246)

        # Only add page break if there's another CVE after this one
        if i < len(sorted_cves) - 1:
            doc.add_page_break()


    # Fix all standard headings to be white
    for p in doc.paragraphs:
        if p.style.name.startswith('Heading'):
            for run in p.runs:
                if not run.font.color.rgb: # Don't override our manual blue/accent fixes
                    run.font.color.rgb = RGBColor(248, 250, 252)

    doc.save(output_file)
    print(f"[+] Word (DOCX) intelligence report saved to: {output_file}")

def save_xlsx_report(vulnerabilities, cve_to_hosts, output_file):
    if not HAS_OPENPYXL:
        print("[!] openpyxl not installed. XLSX report skipped.")
        return

    wb = openpyxl.Workbook()
    
    # 1. Summary Sheet
    ws_summary = wb.active
    ws_summary.title = "Summary"
    summary_headers = ["CVE ID", "Title", "CVSS Score", "CISA KEV", "Exploitability", "Hosts Affected"]
    ws_summary.append(summary_headers)
    
    # Header Styling
    header_fill = PatternFill(start_color="334155", end_color="334155", fill_type="solid")
    header_font = Font(color="FFFFFF", bold=True)
    for col in range(1, len(summary_headers) + 1):
        cell = ws_summary.cell(row=1, column=col)
        cell.fill = header_fill
        cell.font = header_font

    # Sort vulnerabilities by CVSS
    def get_score(v):
        s = v.get('cvss_score', 0)
        return float(s) if s != 'N/A' else 0
    
    sorted_cves = sorted(vulnerabilities.keys(), key=lambda cid: get_score(vulnerabilities[cid]), reverse=True)

    for cve_id in sorted_cves:
        d = vulnerabilities[cve_id]
        hosts_count = len(cve_to_hosts.get(cve_id, []))
        ws_summary.append([
            cve_id, d.get('title', 'N/A'), d.get('cvss_score', 'N/A'),
            d.get('cisa_kev', 'N/A'), d.get('exploitability', 'N/A'), hosts_count
        ])

    # 2. Individual CVE Sheets
    for cve_id in sorted_cves:
        d = vulnerabilities[cve_id]
        # Excel sheet names limited to 31 chars
        sheet_name = cve_id[:31]
        ws = wb.create_sheet(title=sheet_name)
        
        # CVE Metadata Table
        metadata = [
            ("CVE ID", cve_id),
            ("Title", d.get('title', 'N/A')),
            ("Description", d.get('description', 'N/A')),
            ("CVSS Score", d.get('cvss_score', 'N/A')),
            ("CISA KEV", d.get('cisa_kev', 'N/A')),
            ("Exploitability", d.get('exploitability', 'N/A')),
            ("EPSS Score", d.get('epss_score', 'N/A')),
            ("Remediation", d.get('remediation', 'N/A'))
        ]
        
        for i, (label, val) in enumerate(metadata, 1):
            ws.cell(row=i, column=1, value=label).font = Font(bold=True)
            ws.cell(row=i, column=2, value=str(val)).alignment = Alignment(wrap_text=True)
        
        # Affected Hosts Table
        start_row = len(metadata) + 2
        ws.cell(row=start_row, column=1, value="Affected Hosts").font = Font(bold=True, size=12)
        host_headers = ["IP Address", "Hostname", "Port/Proto", "Service Name"]
        for col, h_text in enumerate(host_headers, 1):
            cell = ws.cell(row=start_row+1, column=col, value=h_text)
            cell.fill = header_fill
            cell.font = header_font
            
        for i, (ip, host, port, svc) in enumerate(sorted(cve_to_hosts.get(cve_id, [])), 1):
            ws.append([ip, host, port, svc]) 

        # Adjust columns
        ws.column_dimensions['A'].width = 20
        ws.column_dimensions['B'].width = 80

    wb.save(output_file)
    print(f"[+] XLSX intelligence report saved to: {output_file}")

def save_markdown_report(vulnerabilities, cve_to_hosts, scanner_type, target_file, output_file):
    if not HAS_JINJA: return
    
    # Calculate statistics
    stats = {
        "total_hosts": len(set(h[0] for hosts in cve_to_hosts.values() for h in hosts)),
        "total_cves": len(vulnerabilities),
        "critical_count": sum(1 for v in vulnerabilities.values() if isinstance(v.get('cvss_score'), (int, float)) and v['cvss_score'] >= 9),
        "high_count": sum(1 for v in vulnerabilities.values() if isinstance(v.get('cvss_score'), (int, float)) and 7 <= v['cvss_score'] < 9),
        "medium_count": sum(1 for v in vulnerabilities.values() if isinstance(v.get('cvss_score'), (int, float)) and 4 <= v['cvss_score'] < 7),
        "low_count": sum(1 for v in vulnerabilities.values() if isinstance(v.get('cvss_score'), (int, float)) and 0.1 <= v['cvss_score'] < 4),
        "info_count": sum(1 for v in vulnerabilities.values() if not isinstance(v.get('cvss_score'), (int, float)) or v['cvss_score'] < 0.1),
        "kev_count": sum(1 for v in vulnerabilities.values() if v.get('cisa_kev') == 'Yes')
    }

    chart_b64 = generate_severity_chart(vulnerabilities)

    try:
        env = Environment(loader=FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')))
        template = env.get_template('report_template.md')

        # Sort vulnerabilities by CVSS score descending
        def get_score(v):
            s = v.get('cvss_score', 0)
            return float(s) if s != 'N/A' else 0

        sorted_vulns = dict(sorted(vulnerabilities.items(), key=lambda x: get_score(x[1]), reverse=True))

        md_out = template.render(
            vulnerabilities=sorted_vulns,
            cve_to_hosts=cve_to_hosts,
            stats=stats,
            chart_b64=chart_b64,
            date=datetime.now().strftime("%Y-%m-%d %H:%M"),
            scanner_type=scanner_type,
            target_file=os.path.basename(target_file)
        )
        with open(output_file, 'w', encoding='utf-8') as f:
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

    # Generate HTML first (temporarily or in memory)
    stats = {
        "total_hosts": len(set(h[0] for hosts in cve_to_hosts.values() for h in hosts)),
        "total_cves": len(vulnerabilities),
        "critical_count": sum(1 for v in vulnerabilities.values() if isinstance(v.get('cvss_score'), (int, float)) and v['cvss_score'] >= 9),
        "high_count": sum(1 for v in vulnerabilities.values() if isinstance(v.get('cvss_score'), (int, float)) and 7 <= v['cvss_score'] < 9),
        "medium_count": sum(1 for v in vulnerabilities.values() if isinstance(v.get('cvss_score'), (int, float)) and 4 <= v['cvss_score'] < 7),
        "low_count": sum(1 for v in vulnerabilities.values() if isinstance(v.get('cvss_score'), (int, float)) and 0.1 <= v['cvss_score'] < 4),
        "info_count": sum(1 for v in vulnerabilities.values() if not isinstance(v.get('cvss_score'), (int, float)) or v['cvss_score'] < 0.1),
        "kev_count": sum(1 for v in vulnerabilities.values() if v.get('cisa_kev') == 'Yes')
    }

    chart_b64 = generate_severity_chart(vulnerabilities)

    try:
        env = Environment(loader=FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')))
        template = env.get_template('report_template.html')

        def get_score(v):
            s = v.get('cvss_score', 0)
            return float(s) if s != 'N/A' else 0

        sorted_vulns = dict(sorted(vulnerabilities.items(), key=lambda x: get_score(x[1]), reverse=True))

        html_out = template.render(
            vulnerabilities=sorted_vulns,
            cve_to_hosts=cve_to_hosts,
            stats=stats,
            chart_b64=chart_b64,
            date=datetime.now().strftime("%Y-%m-%d %H:%M"),
            scanner_type=scanner_type,
            target_file=os.path.basename(target_file)
        )
        HTML(string=html_out).write_pdf(output_file)
        print(f"[+] PDF intelligence report saved to: {output_file}")
    except Exception as e:
        print(f"[!] Error generating PDF report: {e}")

def save_html_report(vulnerabilities, cve_to_hosts, scanner_type, target_file, output_file):
    if not HAS_JINJA:
        print("[!] Jinja2 not installed. HTML report skipped.")
        return

    # Calculate statistics
    stats = {
        "total_hosts": len(set(h[0] for hosts in cve_to_hosts.values() for h in hosts)),
        "total_cves": len(vulnerabilities),
        "critical_count": sum(1 for v in vulnerabilities.values() if isinstance(v.get('cvss_score'), (int, float)) and v['cvss_score'] >= 9),
        "high_count": sum(1 for v in vulnerabilities.values() if isinstance(v.get('cvss_score'), (int, float)) and 7 <= v['cvss_score'] < 9),
        "medium_count": sum(1 for v in vulnerabilities.values() if isinstance(v.get('cvss_score'), (int, float)) and 4 <= v['cvss_score'] < 7),
        "low_count": sum(1 for v in vulnerabilities.values() if isinstance(v.get('cvss_score'), (int, float)) and 0.1 <= v['cvss_score'] < 4),
        "info_count": sum(1 for v in vulnerabilities.values() if not isinstance(v.get('cvss_score'), (int, float)) or v['cvss_score'] < 0.1),
        "kev_count": sum(1 for v in vulnerabilities.values() if v.get('cisa_kev') == 'Yes')
    }

    chart_b64 = generate_severity_chart(vulnerabilities)

    try:
        env = Environment(loader=FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')))
        template = env.get_template('report_template.html')

        # Sort vulnerabilities by CVSS score descending
        def get_score(v):
            s = v.get('cvss_score', 0)
            return float(s) if s != 'N/A' else 0

        sorted_vulns = dict(sorted(vulnerabilities.items(), key=lambda x: get_score(x[1]), reverse=True))

        html_out = template.render(
            vulnerabilities=sorted_vulns,
            cve_to_hosts=cve_to_hosts,
            stats=stats,
            chart_b64=chart_b64,
            date=datetime.now().strftime("%Y-%m-%d %H:%M"),
            scanner_type=scanner_type,
            target_file=os.path.basename(target_file)
        )
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_out)
        print(f"[+] HTML intelligence report saved to: {output_file}")
    except Exception as e:
        print(f"[!] Error generating HTML report: {e}")

def get_severity(cvss_score) -> str:
    """Map CVSS score to severity level."""
    if cvss_score == "N/A": return "info"
    try:
        score = float(cvss_score)
        if score >= 9.0: return "critical"
        elif score >= 7.0: return "high"
        elif score >= 4.0: return "medium"
        elif score > 0.0: return "low"
        else: return "info"
    except (ValueError, TypeError):
        return "info"

def generate_report(scan_file: str, csv_file: str = None, github_token: str = None, nvd_key: str = None, html_file: str = None, md_file: str = None, pdf_file: str = None, xlsx_file: str = None, docx_file: str = None, all_base: str = None, threads: int = 10, severity: str = None):
    # Handle the --all (-A) logic
    if all_base:
        csv_file = f"{all_base}.csv"
        html_file = f"{all_base}.html"
        md_file = f"{all_base}.md"
        pdf_file = f"{all_base}.pdf"
        xlsx_file = f"{all_base}.xlsx"
        docx_file = f"{all_base}.docx"
    
    # Severity filter processing
    allowed_severities = [s.strip().lower() for s in severity.split(',')] if severity else None

    # Smart Fallback: If absolutely no output is specified, default to CSV
    if not any([csv_file, html_file, md_file, pdf_file, xlsx_file, docx_file]):
        csv_file = "vulnerability_report.csv"
        print(f"[*] No output format specified. Defaulting to CSV: {csv_file}")

    scanner_type = scan2cve.detect_scanner(scan_file)
    if not scanner_type: print(f"[!] Could not detect scanner type for {scan_file}"); return
    print(f"[*] Detected scanner type: {scanner_type}")
    session = requests.Session()
    if scanner_type == 'nmap_xml': parser = scan2cve.NmapParser(scan_file, session)
    elif scanner_type == 'nessus_xml': parser = scan2cve.NessusXMLParser(scan_file)
    elif scanner_type == 'nessus_csv': parser = scan2cve.NessusCSVParser(scan_file)
    elif scanner_type == 'qualys_xml': parser = scan2cve.QualysXMLParser(scan_file)
    elif scanner_type == 'qualys_csv': parser = scan2cve.QualysCSVParser(scan_file)
    else: print("[!] Unsupported scanner type."); return

    parser.parse()
    if not parser.hosts: print("[!] No scan data found."); return
    
    # Resolve CPEs to CVEs for Nmap (concurrently)
    if scanner_type == 'nmap_xml':
        unique_valid_cpes = set()
        for _, host_data in parser.hosts.items():
            for s in host_data["services"]:
                for cpe in s.get('cpes', []):
                    if not scan2cve.is_broad_cpe(cpe):
                        unique_valid_cpes.add(cpe)
                    else:
                        print(f"  [-] Skipping broad/generic CPE: {cpe}")
        
        if unique_valid_cpes:
            print(f"[*] Fetching CVEs for {len(unique_valid_cpes)} unique specific CPEs using {threads} threads...")
            cpe_to_cves = {}
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {executor.submit(parser.get_cves_for_cpe, cpe, nvd_key): cpe for cpe in unique_valid_cpes}
                for f in as_completed(futures):
                    cpe = futures[f]
                    try:
                        cpe_to_cves[cpe] = f.result()
                    except Exception as e:
                        print(f"  [!] Error fetching {cpe}: {e}")
                        cpe_to_cves[cpe] = []
            
            # Map resolved CVEs back to services
            for _, host_data in parser.hosts.items():
                for s in host_data["services"]:
                    service_cves = []
                    for cpe in s.get('cpes', []):
                        if cpe in cpe_to_cves:
                            service_cves.extend(cpe_to_cves[cpe])
                    s['cves'] = set(service_cves)

    all_cve_ids = set()
    for _, host_data in parser.hosts.items():
        for s in host_data["services"]:
            all_cve_ids.update(s['cves'])

    cve_enrichment = get_detailed_cve_info(list(all_cve_ids), github_token, nvd_key, max_workers=threads)
    
    # Apply Severity Filtering
    if allowed_severities:
        print(f"[*] Filtering results for severities: {', '.join(allowed_severities)}")
        filtered_cves = set()
        for cve_id, d in cve_enrichment.items():
            if get_severity(d.get('cvss_score', 'N/A')) in allowed_severities:
                filtered_cves.add(cve_id)
        
        # Prune services and enrichment
        for _, host_data in parser.hosts.items():
            for s in host_data["services"]:
                s['cves'] = {cid for cid in s['cves'] if cid in filtered_cves}
        
        cve_enrichment = {cid: data for cid, data in cve_enrichment.items() if cid in filtered_cves}
        all_cve_ids = filtered_cves

    headers = [
        "IP", "Hostname (FQDN)", "CVE ID", "Port", "Service",
        "Title", "Description", "CVSS Score", "CISA KEV", "EPSS Score",
        "Exploitability", "PoC Available", "PoC Link", "User Interaction", "Complexity", 
        "Affected Products", "Remediation", "References"
    ]

    # Prepare host mapping for reporting
    cve_to_hosts = {}
    for _, host_data in parser.hosts.items():
        ip, hostname = host_data.get('ip', ''), host_data.get('hostname', '')
        display_name = ip if ip else hostname
        for s in host_data["services"]:
            port_proto = f"{s['port']}/{s['proto']}" if s['port'] != "0" else "Host-level"
            for cve_id in s['cves']:
                if cve_id not in cve_to_hosts: cve_to_hosts[cve_id] = []
                # Avoid duplicate (display_name, hostname, port_proto, s['name']) for the same CVE
                host_entry = (display_name, hostname, port_proto, s['name'])
                if host_entry not in cve_to_hosts[cve_id]:
                    cve_to_hosts[cve_id].append(host_entry)

    if csv_file:
        try:
            with open(csv_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(headers)
                # CSV always defaults to host-based rows
                for _, host_data in sorted(parser.hosts.items()):
                    ip, hostname = host_data.get('ip', ''), host_data.get('hostname', '')
                    for s in host_data["services"]:
                        port_proto = f"{s['port']}/{s['proto']}" if s['port'] != "0" else "Host-level"
                        for cve_id in sorted(list(s['cves'])):
                            d = cve_enrichment.get(cve_id, {})
                            writer.writerow([
                                ip, hostname, cve_id, port_proto, s['name'],
                                d.get('title', 'N/A'), d.get('description', 'N/A'), d.get('cvss_score', 'N/A'),
                                d.get('cisa_kev', 'N/A'), d.get('epss_score', 'N/A'), d.get('exploitability', 'N/A'),
                                d.get('poc_available', 'N/A'), d.get('poc_link', 'N/A'), d.get('user_interaction', 'N/A'),
                                d.get('attack_complexity', 'N/A'),
                                "; ".join([f"{a['product']} ({', '.join(a['versions'])})" for a in d.get('affected', [])]),
                                d.get('remediation', 'N/A'),
                                "; ".join(d.get('references', []))
                            ])
            print(f"[+] Detailed CSV report saved to: {csv_file}")
        except Exception as e: print(f"[!] Error writing CSV: {e}")

    if html_file:
        save_html_report(cve_enrichment, cve_to_hosts, scanner_type, scan_file, html_file)
    if md_file:
        save_markdown_report(cve_enrichment, cve_to_hosts, scanner_type, scan_file, md_file)
    if pdf_file:
        save_pdf_report(cve_enrichment, cve_to_hosts, scanner_type, scan_file, pdf_file)
    if xlsx_file:
        save_xlsx_report(cve_enrichment, cve_to_hosts, xlsx_file)
    if docx_file:
        save_docx_report(cve_enrichment, cve_to_hosts, scanner_type, scan_file, docx_file)

def main():
    p = argparse.ArgumentParser(description="VulnReport - Unified Scan Reporting Tool")
    p.add_argument("file", help="Input scan file (Nmap/Nessus/Qualys)")
    p.add_argument("-C", "--csv", help="Output CSV filename")
    p.add_argument("-H", "--html", help="Output HTML report filename")
    p.add_argument("-M", "--markdown", help="Output Markdown report filename")
    p.add_argument("-P", "--pdf", help="Output PDF report filename")
    p.add_argument("-X", "--xlsx", help="Output XLSX report filename")
    p.add_argument("-D", "--docx", help="Output Word DOCX report filename")
    p.add_argument("-A", "--all", help="Generate ALL formats using this base filename")
    p.add_argument("-T", "--token", help="GitHub Token for PoC lookup")
    p.add_argument("-N", "--nvd-key", help="NVD API Key")
    p.add_argument("-t", "--threads", type=int, default=10, help="Number of concurrent threads (default: 10)")
    p.add_argument("-s", "--severity", help="Filter by severity: Info, Low, Medium, High, Critical (comma-separated)")
    args = p.parse_args()
    if not os.path.exists(args.file): print(f"[!] File not found: {args.file}"); return

    # Automatic key discovery
    github_token, nvd_key, _ = cve_lookup.get_keys(args.token, args.nvd_key)
    if nvd_key: print("[*] Using NVD API Key for accelerated lookups.")
    if github_token: print("[*] Using GitHub Token for PoC research.")

    generate_report(args.file, args.csv, github_token, nvd_key, args.html, args.markdown, args.pdf, args.xlsx, args.docx, args.all, args.threads, args.severity)

if __name__ == "__main__": main()
