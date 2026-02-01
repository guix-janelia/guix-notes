#!/usr/bin/env python3
"""
bump-kicad-guix.py

Bump the KiCad version in a Guix .scm file and refresh the sha256/base32 hashes
for KiCad and all companion packages that use (package-version kicad).

This is intended for package definitions like the ones in GNU Guix:

  (define-public kicad
    (package
      (version "9.0.6")
      (source (origin (method git-fetch) ... (commit version) ... (sha256 (base32 "..."))))))

and companion packages such as kicad-symbols/kicad-footprints/... that have:

  (version (package-version kicad))
  (source (origin (method git-fetch) ... (commit version) ... (sha256 (base32 "..."))))

What it does:
  1) Updates (version "...") in the 'kicad' package to the requested version.
  2) Computes new content hashes for:
       - kicad
       - every (define-public ...) form whose (version (package-version kicad))
     by cloning the upstream git repository at that tag and running:
       guix hash -rx <checkout-dir>
  3) Rewrites each package's (sha256 (base32 "...")) with the new value.
  4) Writes the file in-place (with a timestamped backup, unless --no-backup).

Requirements:
  - git
  - guix (for `guix hash`)
  - network access

Usage examples:
  ./bump-kicad-guix.py 9.0.7 -f engineering.scm
  ./bump-kicad-guix.py 9.0.7 -f engineering.scm --skip kicad-packages3d
  ./bump-kicad-guix.py 9.0.7 -f engineering.scm --dry-run

Notes:
  - If a repo uses tags like "v9.0.7" instead of "9.0.7", the script will try
    both forms automatically.
  - kicad-packages3D is large; use --skip kicad-packages3d if you want to avoid
    downloading it (but then you'll have to update that hash separately).
"""

from __future__ import annotations

import argparse
import datetime as _dt
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple


@dataclass
class DefinePublic:
    symbol: str
    start: int
    end: int
    text: str


class ParseError(RuntimeError):
    pass


def _run(cmd: List[str], *, cwd: str | None = None, capture: bool = True) -> str:
    """Run command and return stdout (stripped). Raise on non-zero exit."""
    try:
        if capture:
            out = subprocess.check_output(cmd, cwd=cwd, stderr=subprocess.STDOUT, text=True)
            return out.strip()
        subprocess.check_call(cmd, cwd=cwd)
        return ""
    except subprocess.CalledProcessError as e:
        msg = e.output if isinstance(e.output, str) else ""
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\n{msg}") from e


def _find_sexpr_end(s: str, start: int) -> int:
    """
    Return index (exclusive) of the end of the s-expression that starts at s[start] == '('.
    Handles strings, line comments ';', and block comments '#| ... |#'.
    """
    if start < 0 or start >= len(s) or s[start] != "(":
        raise ParseError(f"Expected '(' at index {start}")

    depth = 0
    i = start
    in_string = False
    escape = False
    in_line_comment = False
    in_block_comment = False

    while i < len(s):
        ch = s[i]

        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
        elif in_block_comment:
            if s.startswith("|#", i):
                in_block_comment = False
                i += 1  # skip '#'
        elif in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
        else:
            if s.startswith("#|", i):
                in_block_comment = True
                i += 1  # skip '|'
            elif ch == ";":
                in_line_comment = True
            elif ch == '"':
                in_string = True
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    return i + 1

        i += 1

    raise ParseError("Unbalanced parentheses while scanning s-expression")


_DEFINE_PUBLIC_RE = re.compile(r"\(define-public\s+([^\s\)]+)", re.M)


def parse_define_public_forms(text: str) -> Dict[str, DefinePublic]:
    """Parse all top-level (define-public <symbol> ...) forms."""
    forms: Dict[str, DefinePublic] = {}
    for m in _DEFINE_PUBLIC_RE.finditer(text):
        symbol = m.group(1)
        start = m.start()
        end = _find_sexpr_end(text, start)
        block = text[start:end]
        # If a symbol is defined multiple times, keep the first and warn.
        if symbol in forms:
            # Avoid noisy warning unless running verbose; just keep first.
            continue
        forms[symbol] = DefinePublic(symbol=symbol, start=start, end=end, text=block)
    return forms


def extract_git_url(block: str) -> str:
    """
    Extract the (url "…") string inside a (git-reference (url "…") …) form.
    """
    m = re.search(r"\(git-reference\s*\(\s*url\s*\"([^\"]+)\"\s*\)", block, re.S)
    if not m:
        raise ParseError("Could not find (git-reference (url \"…\") ...) in block")
    return m.group(1)


def replace_kicad_version(block: str, new_version: str) -> Tuple[str, str]:
    """
    Replace (version "OLD") with (version "NEW") in the kicad package block.
    Returns (new_block, old_version).
    """
    m = re.search(r"\(version\s*\"([^\"]+)\"\s*\)", block)
    if not m:
        raise ParseError("Could not find (version \"…\") in kicad block")
    old_version = m.group(1)
    new_block = block[:m.start(1)] + new_version + block[m.end(1):]
    return new_block, old_version


_SHA256_BASE32_RE = re.compile(r'(\(sha256\s*\(base32\s*")([^"]+)("\s*\)\s*\))', re.S)


def extract_sha256_base32(block: str) -> str:
    m = _SHA256_BASE32_RE.search(block)
    if not m:
        raise ParseError('Could not find (sha256 (base32 "...")) in block')
    return m.group(2)


def replace_sha256_base32(block: str, new_hash: str) -> Tuple[str, str]:
    """Replace the first sha256/base32 hash string in the block. Returns (new_block, old_hash)."""
    m = _SHA256_BASE32_RE.search(block)
    if not m:
        raise ParseError('Could not find (sha256 (base32 "...")) in block')
    old_hash = m.group(2)
    new_block = block[:m.start(2)] + new_hash + block[m.end(2):]
    return new_block, old_hash


def compute_git_checkout_hash(url: str, version: str, *, workdir: Path) -> str:
    """
    Clone URL at tag/branch `version` into a temporary dir and return:
      guix hash -rx <dir>

    If cloning version fails, also try "v<version>".
    """
    candidates = [version, f"v{version}"] if not version.startswith("v") else [version, version[1:]]
    last_error: str | None = None

    for tag in candidates:
        checkout = workdir / f"checkout-{sanitize_filename(tag)}"
        if checkout.exists():
            shutil.rmtree(checkout)

        # Use --depth 1 for speed; tags work with --branch.
        cmd = ["git", "clone", "--quiet", "--depth", "1", "--branch", tag, url, str(checkout)]
        try:
            _run(cmd, capture=True)
        except Exception as e:
            last_error = str(e)
            continue

        # Compute Guix content hash (same style used in (base32 "...") for git-fetch sources).
        try:
            h = _run(["guix", "hash", "-rx", str(checkout)], capture=True)
        except Exception as e:
            raise RuntimeError(
                f"Cloned {url} at {tag} but failed to run 'guix hash -rx'. "
                f"Is 'guix' installed and in PATH?\n{e}"
            ) from e
        return h.strip()

    raise RuntimeError(
        f"Failed to clone {url} at tag '{version}' (also tried '{candidates[-1]}').\n{last_error or ''}"
    )


def sanitize_filename(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s)


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(
        prog="bump-kicad-guix.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=__doc__,
    )
    ap.add_argument("version", help="New KiCad version/tag, e.g. 9.0.7")
    ap.add_argument(
        "-f",
        "--file",
        default="engineering.scm",
        help="Path to the .scm file that contains the KiCad package definitions (default: engineering.scm)",
    )
    ap.add_argument(
        "--skip",
        action="append",
        default=[],
        help="Package symbol(s) to skip (repeatable), e.g. --skip kicad-packages3d",
    )
    ap.add_argument("--dry-run", action="store_true", help="Compute hashes and show changes, but do not write the file.")
    ap.add_argument("--no-backup", action="store_true", help="Do not create a timestamped .bak file.")
    ap.add_argument(
        "--verbose", action="store_true", help="Print extra info (git URLs, temp dirs, etc.)"
    )

    args = ap.parse_args(argv)

    scm_path = Path(args.file)
    if not scm_path.exists():
        print(f"ERROR: file not found: {scm_path}", file=sys.stderr)
        return 2

    text = scm_path.read_text(encoding="utf-8")
    forms = parse_define_public_forms(text)

    if "kicad" not in forms:
        print("ERROR: did not find (define-public kicad ...) in the file.", file=sys.stderr)
        return 2

    # Identify companion packages that use (package-version kicad)
    dependents: List[str] = []
    for sym, form in forms.items():
        if sym == "kicad":
            continue
        if re.search(r"\(version\s*\(package-version\s+kicad\s*\)\)", form.text, re.S):
            dependents.append(sym)

    # Only keep the ones that look like git-fetch sources (since we compute via git).
    def is_git_fetch(form_text: str) -> bool:
        return "(method git-fetch)" in form_text and "(git-reference" in form_text

    targets = ["kicad"] + sorted(dependents)
    targets = [t for t in targets if is_git_fetch(forms[t].text)]

    # Apply skip list
    skip = set(args.skip)
    targets = [t for t in targets if t not in skip]

    if args.verbose:
        print(f"Targets to update: {', '.join(targets) or '(none)'}")

    # First: update kicad version in-memory
    updated_blocks: Dict[str, str] = {}
    kicad_block, old_version = replace_kicad_version(forms["kicad"].text, args.version)
    updated_blocks["kicad"] = kicad_block

    # Now compute hashes
    new_hashes: Dict[str, str] = {}
    old_hashes: Dict[str, str] = {}

    with tempfile.TemporaryDirectory(prefix="guix-kicad-bump-") as td:
        workdir = Path(td)
        if args.verbose:
            print(f"Working directory: {workdir}")

        for sym in targets:
            block = updated_blocks.get(sym, forms[sym].text)

            url = extract_git_url(block)
            if args.verbose:
                print(f"[{sym}] git url: {url}")

            old_hashes[sym] = extract_sha256_base32(block)

            print(f"[{sym}] hashing {url} @ {args.version} ...", flush=True)
            h = compute_git_checkout_hash(url, args.version, workdir=workdir)
            new_hashes[sym] = h

            # Update block with new hash
            new_block, _old = replace_sha256_base32(block, h)
            updated_blocks[sym] = new_block

    # If any dependents were not in targets because they weren't git-fetch, warn.
    skipped_non_git = [s for s in dependents if s not in targets and s not in skip]
    if skipped_non_git:
        print(
            "NOTE: these (package-version kicad) packages were found but not updated because they don't look like git-fetch sources:\n"
            + "  " + ", ".join(skipped_non_git),
            file=sys.stderr,
        )

    # Print summary
    print("\nSummary:")
    print(f"  kicad version: {old_version} -> {args.version}")
    for sym in targets:
        oh = old_hashes.get(sym, "<unknown>")
        nh = new_hashes.get(sym, "<unknown>")
        if oh == nh:
            print(f"  {sym}: hash unchanged ({nh})")
        else:
            print(f"  {sym}: {oh} -> {nh}")

    # Rewrite the file text by replacing blocks, from bottom to top to keep offsets valid.
    modifications: List[Tuple[int, int, str]] = []
    for sym, new_block in updated_blocks.items():
        if sym not in forms:
            continue
        form = forms[sym]
        modifications.append((form.start, form.end, new_block))

    modifications.sort(key=lambda t: t[0], reverse=True)
    new_text = text
    for start, end, new_block in modifications:
        new_text = new_text[:start] + new_block + new_text[end:]

    if args.dry_run:
        print("\nDry-run: not writing any files.")
        return 0

    if not args.no_backup:
        ts = _dt.datetime.now().strftime("%Y%m%d%H%M%S")
        backup = scm_path.with_suffix(scm_path.suffix + f".bak-{ts}")
        shutil.copy2(scm_path, backup)
        print(f"\nBackup written to: {backup}")

    scm_path.write_text(new_text, encoding="utf-8")
    print(f"Updated: {scm_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
