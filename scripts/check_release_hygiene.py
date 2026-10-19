#!/usr/bin/env python3
"""Sweep tracked text files for real identifiers before they reach the public repo.

    python scripts/check_release_hygiene.py          # every tracked text file
    python scripts/check_release_hygiene.py path ...  # just these files

BridgeLab runs only against a throwaway sandbox (Keycloak + LocalStack) or a
caller's own disposable Entra/Azure test tenant, so the tree should contain no
real tenant data at all -- only documented placeholders. This gate keeps it that
way: the realistic failure is someone pasting live `az` / `aws` output into a doc
while writing an example.

Philosophy, borrowed from CyderesInc/MeridianCS: high-signal patterns only (a
noisy check is one people learn to skip), a *documented* allowlist of sanctioned
placeholders, and refuse-with-a-precise-list rather than guess. There is no real
identifier denylist here because, unlike that project, BridgeLab was never
developed against a real tenant -- so this whole script is publishable as-is.

Exit status: 0 clean, 1 findings, 2 misuse. Intended for CI and pre-commit.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# Binary, vendored, or hash-bearing files where the patterns are either
# meaningless or guaranteed to false-positive (lockfile and SBOM carry long
# hashes; fonts/licences are third-party text).
SKIP_SUFFIXES = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".pdf",
    ".ttf", ".otf", ".woff", ".woff2", ".zip", ".gz",
)
SKIP_FILES = {
    "requirements.lock",
    "sbom.cdx.json",
    "scripts/check_release_hygiene.py",  # spells out the patterns and placeholders
}

# --- Patterns -------------------------------------------------------------
# Each is high-signal: a hit is almost always a real identifier, not prose.
PATTERNS = {
    "AWS access key id":  r"\bAKIA[0-9A-Z]{16}\b",
    "AWS secret-ish":     r"\baws_secret_access_key\s*[=:]\s*[\"']?[A-Za-z0-9/+]{40}\b",
    "Entra/Azure GUID":   r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
    "onmicrosoft tenant": r"\b[a-z0-9][a-z0-9-]*\.onmicrosoft\.com\b",
    "email address":      r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)*\.[A-Za-z]{2,}\b",
    "IPv4 literal":       r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
}

# --- Allowlists (sanctioned placeholders) ---------------------------------
# AWS's own documented example key. Shipped in boto examples the world over.
ALLOWED_AWS_KEYS = {"AKIAIOSFODNN7EXAMPLE"}

# Documented example domains (RFC 2606) plus Cyderes' own address, which is
# legitimate in LICENSE/NOTICE/SECURITY contact lines.
ALLOWED_EMAIL_DOMAINS = ("example.com", "example.org", "example.net", "cyderes.com")

# Non-routable / documentation ranges. A real public address outside these fails.
ALLOWED_IP_PREFIXES = (
    "0.", "10.", "127.", "169.254.", "192.168.", "255.",
    "192.0.2.", "198.51.100.", "203.0.113.",            # RFC 5737 TEST-NET
)


def _allowed_ip(ip: str) -> bool:
    octets = ip.split(".")
    if len(octets) != 4 or any(not o.isdigit() or int(o) > 255 for o in octets):
        return True  # malformed quad -> not an address, ignore (e.g. a version string)
    if 172 == int(octets[0]) and 16 <= int(octets[1]) <= 31:
        return True  # 172.16/12
    return any(ip.startswith(p) for p in ALLOWED_IP_PREFIXES)


def _placeholder_guid(guid: str) -> bool:
    """True for an obviously fake GUID: a sequential/placeholder, not a random one.

    Real GUIDs are high-entropy. Placeholders in this tree are things like
    11111111-2222-...-555555555555, aaaaaaaa-bbbb-...-eeeeeeeeeeee, and the all-zero
    GUID. Heuristic: each hyphen-group is a single repeated character. That catches
    every placeholder style used here without allowlisting each one, and a genuine
    random GUID practically never looks like this.
    """
    groups = guid.lower().split("-")
    return all(len(set(g)) == 1 for g in groups)


def known_azure_guids() -> set[str]:
    # Well-known first-party Microsoft app ids are public constants, not secrets.
    return {
        "00000003-0000-0000-c000-000000000000",  # Microsoft Graph
        "00000002-0000-0000-c000-000000000000",  # Azure AD Graph (legacy)
    }


def scan_text(text: str):
    findings = []
    azure_ok = known_azure_guids()
    for label, rx in PATTERNS.items():
        for m in re.finditer(rx, text):
            hit = m.group(0)
            if label == "AWS access key id" and hit in ALLOWED_AWS_KEYS:
                continue
            if label == "Entra/Azure GUID" and (_placeholder_guid(hit) or hit.lower() in azure_ok):
                continue
            if label == "email address" and hit.lower().endswith(ALLOWED_EMAIL_DOMAINS):
                continue
            if label == "IPv4 literal" and _allowed_ip(hit):
                continue
            findings.append((label, hit))
    return findings


def tracked_text_files():
    out = subprocess.run(
        ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.splitlines()
    for rel in out:
        if rel in SKIP_FILES or rel.lower().endswith(SKIP_SUFFIXES):
            continue
        yield rel


def read(path: str) -> str:
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


def main(argv):
    rels = argv[1:] or list(tracked_text_files())
    problems = []
    for rel in rels:
        path = os.path.join(ROOT, rel)
        if not os.path.isfile(path):
            continue
        for label, hit in scan_text(read(path)):
            problems.append((rel, label, hit))

    if problems:
        print("NOT RELEASE-CLEAN -- %d finding(s):" % len(problems))
        for rel, label, hit in problems:
            print("   %s: %s -> %s" % (rel, label, hit))
        print("\nIf a hit is a sanctioned placeholder, add it to the allowlist in this script")
        print("with a comment saying why. Do not disable the pattern.")
        return 1

    print("Release hygiene clean: no real identifiers in %d tracked file(s)." % len(rels))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
