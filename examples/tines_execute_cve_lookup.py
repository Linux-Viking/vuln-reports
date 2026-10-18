# Tines "Run Script" action (python_3_13) that runs cve_lookup.py from a pinned, verified release.
# Inputs: cve_list (pasted text) and/or cve_file (form upload), plus optional GITHUB_TOKEN,
# NVD_API_KEY, VULNERS_API_KEY, CIRCL_API_KEY (credentials with domain restriction "run-script").
# Outputs: csv_content, csv_base64, stdout, stderr, returncode, version (and error on failure).
#
# To upgrade: change TAG and SHA256 together. Copy SHA256 from the release's SHA256SUMS
# (the line for vuln-reports-<TAG>.zip) — never fetch it at runtime from the same place
# as the archive, or the check only proves the download wasn't corrupted, not that it's
# the release you reviewed.


def main(input):
    import base64
    import csv
    import hashlib
    import io
    import os
    import shutil
    import subprocess
    import sys
    import zipfile

    import requests

    TAG = "v1.1.0"
    SHA256 = "8348152db144a7c9715b6d7b949f79e3bb78ebc46c93f5074ea57d587646050c"

    def failure(message, stdout="", stderr=""):
        # Put the error in the CSV too, so the results page shows it instead of an empty table.
        buf = io.StringIO()
        csv.writer(buf).writerows([["error"], [message]])
        text = buf.getvalue()
        return {
            "error": message,
            "csv_content": text,
            "csv_base64": base64.b64encode(text.encode()).decode(),
            "stdout": stdout,
            "stderr": stderr,
            "version": TAG,
        }

    cve_list = input.get("cve_list", "")
    cve_file = input.get("cve_file")
    if not cve_file and not cve_list:
        return failure("No CVE input provided.")

    # /tmp is the only writable location in the Tines (AWS Lambda) sandbox, which is single-tenant.
    tmp = "/tmp"  # nosec B108
    # Version-specific paths: a cached sandbox can never run a different release than TAG.
    repo_path = f"{tmp}/vuln-reports-{TAG}"
    # cve_lookup.py only needs requests + keyring (~23 MB, seconds), not the full report stack.
    packages_dir = f"{tmp}/site-packages-{TAG}-lookup"
    packages_ready = os.path.join(packages_dir, ".install-complete")

    if not os.path.isfile(os.path.join(repo_path, "cve_lookup.py")):
        url = f"https://github.com/Linux-Viking/vuln-reports/releases/download/{TAG}/vuln-reports-{TAG}.zip"
        r = requests.get(url, timeout=30)
        if r.status_code != 200:
            return failure(f"Could not download {url} (HTTP {r.status_code}).")
        digest = hashlib.sha256(r.content).hexdigest()
        if digest != SHA256:
            return failure(
                f"Checksum mismatch for vuln-reports {TAG}: expected {SHA256}, got {digest}. Not running it."
            )
        # Extract beside the target and rename, so an interrupted run never leaves a half-extracted tree.
        staging = f"{tmp}/.vuln-reports-{TAG}-staging"
        shutil.rmtree(staging, ignore_errors=True)
        with zipfile.ZipFile(io.BytesIO(r.content)) as z:
            z.extractall(staging)  # zipfile strips absolute paths and ".." components
        shutil.rmtree(repo_path, ignore_errors=True)
        os.replace(os.path.join(staging, f"vuln-reports-{TAG}"), repo_path)
        shutil.rmtree(staging, ignore_errors=True)

    os.chdir(repo_path)

    # The marker is written only after a successful install, so a run killed mid-install is retried.
    if not os.path.isfile(packages_ready):
        shutil.rmtree(packages_dir, ignore_errors=True)
        try:
            pip = subprocess.run(
                [sys.executable, "-m", "pip", "install", "-q", "--target", packages_dir, "requests", "keyring"],
                capture_output=True,
                text=True,
                timeout=60,
            )
        except subprocess.TimeoutExpired:
            shutil.rmtree(packages_dir, ignore_errors=True)
            return failure("Dependency install timed out after 60 s. Please run it again.")
        if pip.returncode != 0:
            shutil.rmtree(packages_dir, ignore_errors=True)
            return failure("Dependency install failed.", pip.stdout[-3000:], pip.stderr[-3000:])
        open(packages_ready, "w").close()

    env = os.environ.copy()
    env["PYTHONPATH"] = packages_dir + ":" + env.get("PYTHONPATH", "")
    for key in ("GITHUB_TOKEN", "NVD_API_KEY", "VULNERS_API_KEY", "CIRCL_API_KEY"):
        if input.get(key):
            env[key] = input[key]

    results_path = f"{tmp}/results.csv"
    # Remove stale results so cve_lookup.py writes to results.csv (it never overwrites).
    for f in os.listdir(tmp):
        if f.startswith("results") and f.endswith(".csv"):
            os.remove(os.path.join(tmp, f))

    # File upload takes priority over pasted text
    if cve_file and isinstance(cve_file, dict) and cve_file.get("contents"):
        upload_path = f"{tmp}/uploaded_cves.txt"
        with open(upload_path, "wb") as f:
            f.write(base64.b64decode(cve_file["contents"]))
        cmd = [sys.executable, "cve_lookup.py", "-c", results_path, "-f", upload_path]
    else:
        cmd = [sys.executable, "cve_lookup.py", "-c", results_path, cve_list]

    try:
        result = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=95, env=env)
    except subprocess.TimeoutExpired as e:
        partial = e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
        return failure("CVE lookup timed out after 95 s. Try fewer CVEs per run.", partial[-3000:])

    try:
        with open(results_path) as f:
            csv_content = f.read()
    except FileNotFoundError:
        csv_content = f"No results file generated.\nStdout: {result.stdout}\nStderr: {result.stderr}"

    # A header-only CSV means every lookup failed; surface cve_lookup's error lines instead of a blank table.
    if len(csv_content.strip().splitlines()) <= 1:
        errors = [line.strip() for line in (result.stdout or "").splitlines() if line.strip().startswith("[!]")]
        detail = "; ".join(errors[:5]) if errors else "no error details were printed"
        return failure(f"No results. {detail}", result.stdout[-3000:], result.stderr[-3000:])

    return {
        "csv_content": csv_content,
        "csv_base64": base64.b64encode(csv_content.encode()).decode(),
        "stdout": result.stdout[-3000:] if result.stdout else "",
        "stderr": result.stderr[-3000:] if result.stderr else "",
        "returncode": result.returncode,
        "version": TAG,
    }
