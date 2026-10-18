"""Run regression cases against a checkout and normalise the outputs for comparison.

Normalisation only removes what legitimately varies between machines:
absolute paths, and rendered chart/image bytes (matplotlib/freetype versions).
Text formats (CSV, JSON, TXT, grep, XML, HTML, Markdown, stdout) are otherwise
compared byte for byte. Binary formats are reduced to their content:
XLSX -> cell values and header styling, DOCX -> document.xml, PDF -> text
(whitespace removed).
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parents[1]
SCANS_DIR = TESTS_DIR / "fixtures" / "scans"
RUNNER = Path(__file__).resolve().parent / "run_case.py"
GOLDEN_DIR = Path(__file__).resolve().parent / "golden"

# Environment variables the suite reads; always cleared so the host's real keys never leak in.
SUITE_ENV = ["GITHUB_TOKEN", "NVD_API_KEY", "VULNERS_API_KEY", "CIRCL_API_KEY"]

CHART_RE = re.compile(r"data:image/png;base64,[A-Za-z0-9+/=]+")


def run_case(impl_dir, case):
    """Run ``case`` against the checkout at ``impl_dir``; return {name: normalised bytes}."""
    impl_dir = Path(impl_dir).resolve()
    with tempfile.TemporaryDirectory(prefix="vr-regression-") as tmp:
        work = Path(tmp).resolve()
        for name in case["inputs"]:
            shutil.copy(SCANS_DIR / name, work / name)
        for name, content in case["pre_files"].items():
            (work / name).write_text(content, encoding="utf-8")
        before = {p.name for p in work.iterdir()}

        env = {k: v for k, v in os.environ.items() if k not in SUITE_ENV}
        env.update(case["env"])
        env["PYTHONHASHSEED"] = "0"
        env.pop("PYTHONPATH", None)
        args = [a.replace("{work}", str(work)) for a in case["args"]]
        proc = subprocess.run(
            [sys.executable, str(RUNNER), str(impl_dir), case["script"], *args],
            cwd=work,
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=600,
        )

        def scrub(data: bytes) -> bytes:
            return data.replace(str(impl_dir).encode(), b"<ROOT>").replace(str(work).encode(), b"<WORK>")

        outputs = {
            "_stdout.txt": scrub(proc.stdout),
            "_stderr.txt": scrub(_strip_noise(proc.stderr)),
            "_exit_code.txt": f"{proc.returncode}\n".encode(),
        }
        for path in sorted(work.iterdir()):
            if path.name in before and path.name not in case["pre_files"]:
                continue
            if path.name in case["pre_files"] and path.read_text(encoding="utf-8") == case["pre_files"][path.name]:
                continue
            name, data = normalise_file(path)
            outputs[name] = scrub(data)
        return outputs


def _strip_noise(stderr: bytes) -> bytes:
    """Reduce stderr to what our code controls.

    * INFO/WARNING records come from WeasyPrint/fontTools via the root logger that
      scan2cve configures at import; their wording depends on library versions.
    * Traceback frames carry file names and line numbers, which a refactor changes
      by definition; only the final exception line is compared.
    """
    keep, in_traceback = [], False
    for line in stderr.decode("utf-8", "replace").splitlines(keepends=True):
        if re.match(r"(INFO|WARNING|DEBUG): ", line) or "Fontconfig" in line or "GLib" in line:
            continue
        if line.startswith("Traceback (most recent call last):"):
            keep.append(line)
            keep.append("  <frames>\n")
            in_traceback = True
            continue
        if in_traceback:
            if line.startswith((" ", "\t")):
                continue
            in_traceback = False
        keep.append(line)
    return "".join(keep).encode()


def normalise_file(path: Path):
    suffix = path.suffix.lower()
    if suffix in (".html", ".md"):
        return path.name, CHART_RE.sub("data:image/png;base64,<CHART_PNG>", path.read_text(encoding="utf-8")).encode()
    if suffix == ".xlsx":
        return path.name + ".json", _dump_xlsx(path)
    if suffix == ".docx":
        return path.name + ".xml", _dump_docx(path)
    if suffix == ".pdf":
        return path.name + ".txt", _dump_pdf(path)
    return path.name, path.read_bytes()


def _dump_xlsx(path):
    import openpyxl

    wb = openpyxl.load_workbook(path)
    dump = {}
    for ws in wb.worksheets:
        rows = []
        for row in ws.iter_rows():
            rows.append(
                [
                    {
                        "v": c.value,
                        "bold": bool(c.font and c.font.bold),
                        "fill": c.fill.fgColor.rgb if c.fill and c.fill.fill_type else None,
                    }
                    for c in row
                ]
            )
        dump[ws.title] = {"rows": rows, "widths": {k: v.width for k, v in sorted(ws.column_dimensions.items())}}
    return (json.dumps(dump, indent=1, ensure_ascii=False, default=str) + "\n").encode()


def _dump_docx(path):
    with zipfile.ZipFile(path) as z:
        parts = []
        for name in ("word/document.xml", "word/settings.xml"):
            xml = z.read(name).decode("utf-8")
            parts.append(f"<!-- {name} -->\n" + re.sub(r">\s*<", ">\n<", xml))
        media = sorted(n for n in z.namelist() if n.startswith("word/media/"))
        parts.append("<!-- media -->\n" + "\n".join(media))
    return ("\n".join(parts) + "\n").encode()


def _dump_pdf(path):
    from pypdf import PdfReader

    text = "".join(page.extract_text() or "" for page in PdfReader(path).pages)
    # Glyph spacing, kerning and line wrapping depend on the installed fonts (pypdf may
    # extract "Target" as "T arget"), so compare the character stream without whitespace.
    return ("".join(text.split()) + "\n").encode()


def write_golden(case_name, outputs):
    target = GOLDEN_DIR / case_name
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True)
    for name, data in outputs.items():
        (target / name).write_bytes(data)


def read_golden(case_name):
    target = GOLDEN_DIR / case_name
    return {p.name: p.read_bytes() for p in sorted(target.iterdir())}


def run_staged(impl_dir, case, steps):
    """Run several invocations in one shared work dir (for parse -> enrich -> report)."""
    impl_dir = Path(impl_dir).resolve()
    with tempfile.TemporaryDirectory(prefix="vr-staged-") as tmp:
        work = Path(tmp).resolve()
        for name in case["inputs"]:
            shutil.copy(SCANS_DIR / name, work / name)
        env = {k: v for k, v in os.environ.items() if k not in SUITE_ENV}
        env.update(case["env"])
        env["PYTHONHASHSEED"] = "0"
        env.pop("PYTHONPATH", None)
        codes, log = [], []
        for args in steps:
            proc = subprocess.run(
                [sys.executable, str(RUNNER), str(impl_dir), case["script"], *args],
                cwd=work,
                env=env,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=600,
            )
            codes.append(proc.returncode)
            log.append(proc.stdout.decode() + proc.stderr.decode())
        outputs = {p.name: p.read_bytes() for p in work.iterdir() if p.is_file()}
        outputs["_exit_codes"] = codes
        outputs["_log"] = "\n".join(log)
        return outputs
