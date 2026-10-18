"""Output formats for CVE lookups (``cve_lookup.py``): terminal, JSON, CSV, text, grep, XML.

The CSV columns and the formula-injection guard are a contract with the Tines
story, which turns this CSV straight into a results table.
"""

from __future__ import annotations

import csv
import json
import os

# Only used to *write* XML; untrusted input is parsed with defusedxml.
import xml.etree.ElementTree as ET  # nosec B405
from typing import Any

from vuln_reports.console import Colors, colorize, print_lock

CSV_HEADERS = [
    "CVE ID",
    "Title",
    "Description",
    "CVSS",
    "KEV",
    "EPSS",
    "Exploitability",
    "PoC Link",
    "Threat Vector",
    "User Interaction",
    "Complexity",
    "Affected",
    "References",
]


def csv_safe(value: Any) -> str:
    """Neutralise spreadsheet formula injection."""
    val = str(value)
    if val.startswith(("=", "+", "-", "@")):
        return f"'{val}"
    return val


def _affected(d, sep="; ") -> str:
    return sep.join([f"{a['product']} ({', '.join(a['versions'])})" for a in d["affected"]])


def get_output_path(base_name: str | None, extension: str) -> str:
    """``base.ext``, or ``base_N.ext`` if that already exists (never overwrites)."""
    if not base_name:
        base_name = "results"
    if base_name.endswith(f".{extension}"):
        base_name = base_name[: -(len(extension) + 1)]

    filename = f"{base_name}.{extension}"
    if not os.path.exists(filename):
        return filename

    counter = 1
    while os.path.exists(f"{base_name}_{counter}.{extension}"):
        counter += 1
    return f"{base_name}_{counter}.{extension}"


def print_pretty(data: dict[str, Any], use_colors: bool, minimal: bool = False):
    with print_lock:
        if "error" in data:
            if not minimal:
                c_id = data.get("cve_id", "Unknown")
                err = data.get("error", "Unknown error")
                print(f"\n[!] {colorize(f'Error for {c_id}: {err}', Colors.RED, use_colors)}")
            return

        if minimal:
            poc = data["poc_link"]
            if poc == "N/A":
                return  # Suppress if no PoC link found
            print(
                f"{colorize(data['cve_id'], Colors.BLUE + Colors.BOLD, use_colors)}: {colorize(poc, Colors.YELLOW, use_colors)}"
            )
            return

        cvss = data["cvss_score"]
        cvss_color = Colors.RED if (isinstance(cvss, (int, float)) and cvss >= 7) else Colors.END
        cvss_str = colorize(str(cvss), cvss_color, use_colors)
        kev_str = (
            colorize(data["cisa_kev"], Colors.RED + Colors.BOLD, use_colors)
            if data["cisa_kev"] == "Yes"
            else data["cisa_kev"]
        )

        aff_lines = []
        for a in data["affected"][:3]:
            # Limit versions per product for the terminal
            vers = ", ".join(a["versions"][:5])
            if len(a["versions"]) > 5:
                vers += ", ..."
            aff_lines.append(f"  - {a['product']} ({vers})")
        aff_str = "\n".join(aff_lines)
        if len(data["affected"]) > 3:
            aff_str += "\n  - ..."

        print(f"\n{'=' * 60}")
        print(f"CVE ID: {colorize(data['cve_id'], Colors.BLUE + Colors.BOLD, use_colors)}")
        print(f"Vulnerability Title: {data['title']}")
        print(f"Description: {data['description']}")
        print(f"Affected Products:\n{aff_str}")
        print(f"CISA KEV?: {kev_str}")
        print(f"CVSS Score: {cvss_str}")
        print(f"Exploitability: {data['exploitability']}")
        print(f"PoC Available: {data['poc_available']}")
        print(f"PoC Link: {colorize(data['poc_link'], Colors.YELLOW, use_colors)}")
        print(f"Threat Vector: {data.get('threat_vector', 'N/A')}")
        print(f"User Interaction: {data['user_interaction']}")
        print(f"EPSS Score: {data['epss_score']}")
        print(f"Attack Complexity: {data['attack_complexity']}")
        print("References:")
        for ref in data["references"][:5]:
            print(f"  - {ref}")
        print(f"{'=' * 60}")


def save_json(results: list[dict[str, Any]], filename: str):
    with open(filename, "w") as f:
        json.dump(results, f, indent=4)


def save_text(results: list[dict[str, Any]], filename: str):
    with open(filename, "w", encoding="utf-8") as f:
        for d in results:
            if "error" in d:
                continue
            f.write(f"{'=' * 60}\nCVE ID: {d['cve_id']}\nTitle: {d['title']}\nDescription: {d['description']}\n")
            f.write(f"CVSS: {d['cvss_score']} | KEV: {d['cisa_kev']} | EPSS: {d['epss_score']}\n")
            f.write(f"Exploitability: {d['exploitability']} | PoC: {d['poc_link']}\n")
            f.write(
                f"Threat Vector: {d['threat_vector']} | User Interaction: {d['user_interaction']} | Complexity: {d['attack_complexity']}\n"
            )
            f.write(f"Affected: {_affected(d, ' | ')}\nReferences: {', '.join(d['references'])}\n\n")


def save_csv(results: list[dict[str, Any]], filename: str):
    with open(filename, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(CSV_HEADERS)
        for d in results:
            if "error" in d:
                continue
            w.writerow(
                [
                    csv_safe(d["cve_id"]),
                    csv_safe(d["title"]),
                    csv_safe(d["description"]),
                    d["cvss_score"],
                    d["cisa_kev"],
                    d["epss_score"],
                    d["exploitability"],
                    d["poc_link"],
                    d["threat_vector"],
                    d["user_interaction"],
                    d["attack_complexity"],
                    csv_safe(_affected(d)),
                    csv_safe("; ".join(d["references"])),
                ]
            )


def _grep_field(val) -> str:
    """Strip newlines and pipes so each record stays on one pipe-delimited line."""
    return str(val).replace("\n", " ").replace("\r", " ").replace("|", " ").strip()


def save_grep(results: list[dict[str, Any]], filename: str):
    # Fields: 1.ID 2.Title 3.Description 4.CVSS 5.KEV 6.EPSS 7.Exploitability 8.PoC
    #         9.Threat Vector 10.Interaction 11.Complexity 12.Affected 13.References 14.PoC_Link
    with open(filename, "w") as f:
        for d in results:
            if "error" in d:
                continue
            line = [
                d["cve_id"],
                d["title"],
                d["description"],
                d["cvss_score"],
                d["cisa_kev"],
                d["epss_score"],
                d["exploitability"],
                d["poc_available"],
                d["threat_vector"],
                d["user_interaction"],
                d["attack_complexity"],
                _affected(d),
                "; ".join(d["references"]),
                d["poc_link"],
            ]
            f.write(f"{'|'.join(_grep_field(v) for v in line)}\n")


def save_xml(results: list[dict[str, Any]], filename: str):
    root = ET.Element("CVEList")
    for d in results:
        if "error" in d:
            continue
        c = ET.SubElement(root, "CVE")
        for k, v in d.items():
            ET.SubElement(c, k).text = str(v)
    ET.ElementTree(root).write(filename, encoding="utf-8", xml_declaration=True)
