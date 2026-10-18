"""Regenerate golden outputs from a known-good release (default: v1.0.0).

    python tests/regression/generate_goldens.py [--ref v1.0.0] [case ...]

The ref is exported with ``git archive`` into a temp dir and every case in
cases.py is run against it. Goldens must only ever come from a released tag,
never from the working tree, or the regression suite stops proving anything.
"""

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cases import CASES  # noqa: E402
from harness import run_case, write_golden  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]


def export_ref(ref, dest):
    archive = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "archive", "--format=tar", ref], check=True, capture_output=True
    ).stdout
    subprocess.run(["tar", "--extract", "--directory", str(dest)], input=archive, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--ref", default="v1.0.0", help="git tag/commit to treat as the reference (default: v1.0.0)")
    parser.add_argument("cases", nargs="*", help="only regenerate these case names")
    args = parser.parse_args()

    selected = [c for c in CASES if not args.cases or c["name"] in args.cases]
    with tempfile.TemporaryDirectory(prefix="vr-golden-") as tmp:
        export_ref(args.ref, Path(tmp))
        for case in selected:
            outputs = run_case(tmp, case)
            write_golden(case["name"], outputs)
            print(f"[+] {case['name']}: {len(outputs)} files (exit {outputs['_exit_code.txt'].decode().strip()})")


if __name__ == "__main__":
    main()
