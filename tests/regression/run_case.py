"""Run one CLI invocation of a vuln-reports checkout in a hermetic sandbox.

Usage: python run_case.py <impl_dir> <script | '-m package'> [args...]

Invoked in a fresh interpreter (PYTHONHASHSEED=0, cwd = scratch work dir) by
``harness.run_case``. Before the target script is imported it:
  * serves all HTTP from tests/fixtures/api (no real network),
  * freezes the clock and turns time.sleep into a no-op (rate limiter delays),
  * makes thread pools run tasks serially in submission order (deterministic output),
  * makes keyring unavailable, as in the Tines Lambda.
The script then runs exactly as ``python <script> args...`` would.
"""

import concurrent.futures
import runpy
import sys
import time
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TESTS_DIR))

import freezegun  # noqa: E402
import keyring  # noqa: E402
from mocknet import MockNet  # noqa: E402

FROZEN_NOW = "2026-10-17 12:00:00"


class SerialExecutor(concurrent.futures.Executor):
    """ThreadPoolExecutor stand-in that runs each task immediately on submit."""

    def __init__(self, *args, **kwargs):
        pass

    def submit(self, fn, /, *args, **kwargs):
        future = concurrent.futures.Future()
        try:
            future.set_result(fn(*args, **kwargs))
        except BaseException as exc:  # mirror ThreadPoolExecutor: errors surface via result()
            future.set_exception(exc)
        return future


def serial_as_completed(fs, timeout=None):
    return iter(list(fs))


def _no_keyring(*args, **kwargs):
    raise keyring.errors.NoKeyringError("no keyring in sandbox")


def main():
    impl_dir = Path(sys.argv[1]).resolve()
    script = sys.argv[2]
    args = sys.argv[3:]

    concurrent.futures.ThreadPoolExecutor = SerialExecutor
    concurrent.futures.as_completed = serial_as_completed
    time.sleep = lambda seconds: None
    keyring.get_password = _no_keyring
    keyring.set_password = _no_keyring

    net = MockNet().install()
    freezer = freezegun.freeze_time(FROZEN_NOW)
    freezer.start()

    sys.path.insert(0, str(impl_dir))
    sys.argv = [script] + args
    code = 0
    try:
        if script.startswith("-m "):  # python -m <package>
            runpy.run_module(script[3:], run_name="__main__", alter_sys=True)
        else:
            runpy.run_path(str(impl_dir / script), run_name="__main__")
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 1)
        if not isinstance(exc.code, (int, type(None))):
            print(exc.code, file=sys.stderr)
    finally:
        sys.stdout.flush()
        freezer.stop()
        net.uninstall()
    sys.exit(code)


if __name__ == "__main__":
    main()
