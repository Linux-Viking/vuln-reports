"""API key discovery: environment variables first, then the system keyring."""

import getpass
import os

import keyring

KEYRING_SERVICE = "cve-lookup-tool"

# (environment variable, keyring entry, prompt label, saved message noun)
KEY_SPECS = [
    ("GITHUB_TOKEN", "github-token", "GitHub Token", "Token"),
    ("NVD_API_KEY", "nvd-key", "NVD API Key", "Key"),
    ("VULNERS_API_KEY", "vulners-key", "Vulners API Key", "Key"),
    ("CIRCL_API_KEY", "circl-key", "CIRCL API Key", "Key"),
]


def _lookup(env_var: str, keyring_name: str):
    value = os.getenv(env_var)
    if not value:
        try:
            value = keyring.get_password(KEYRING_SERVICE, keyring_name)
        except Exception:
            value = None
    return value


def get_keys():
    """Retrieve GitHub, NVD, Vulners, and CIRCL keys from env or keyring."""
    return tuple(_lookup(env_var, name) for env_var, name, _, _ in KEY_SPECS)


def prompt_for_missing_keys(keys):
    """Interactively ask for each missing key and offer to save it. Only call when stdin is a TTY."""
    keys = list(keys)
    for i, (_, keyring_name, label, noun) in enumerate(KEY_SPECS):
        if keys[i]:
            continue
        value = getpass.getpass(f"[?] {label} not found. Enter {noun} (optional, press Enter to skip): ").strip()
        keys[i] = value
        if value:
            save = input(f"[?] Save this {noun.lower()} to keyring/credential manager? (y/N): ").lower().strip()
            if save == "y":
                try:
                    keyring.set_password(KEYRING_SERVICE, keyring_name, value)
                    print(f"[+] {noun} saved to keyring.")
                except Exception as e:
                    print(f"[!] Failed: {e}")
    return tuple(keys)
