#!/usr/bin/env python3
# Copyright (C) 2026 Mike Sauh
#
# This file is part of ExposedObserve, a modified fork of OpenObserve.
# OpenObserve is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# Original project: https://github.com/openobserve/openobserve
#
# This file was created independently to audit and normalize AGPL attribution headers.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

"""Normalize and audit AGPL attribution headers across every file the fork changed.

    python3 scripts/check-license-headers.py v1.1.2            # audit only
    python3 scripts/check-license-headers.py v1.1.2 --fix      # audit and repair
    python3 scripts/check-license-headers.py v1.1.2 --worktree # include uncommitted changes

Rules (see .claude/skills/fork-rebrand/SKILL.md section 5):
  - Fork-authored code files carry the canonical fork copyright header and must
    not claim upstream authorship.
  - Modified upstream files carry a `Modifications Copyright` line directly
    beneath the untouched upstream copyright line.
  - The year is derived, never hardcoded: the calendar year of the commit that
    last touched the file.
  - Deleted, generated and lock files need no header.

Exit code is 1 when violations remain, so the script can gate a commit.
"""

from __future__ import annotations

import argparse
import datetime
import re
import subprocess
import sys
from pathlib import Path

CODE_SUFFIXES = {".rs", ".ts", ".tsx", ".vue", ".js", ".jsx", ".mjs", ".cjs"}
EXCLUDED_NAMES = {"Cargo.lock", "package-lock.json", "pnpm-lock.yaml"}
EXCLUDED_DIRS = {".git", "node_modules", "target", "dist", "coverage", ".claude"}

UPSTREAM_COPYRIGHT_RE = re.compile(r"Copyright\s+(?P<year>\d{4})\s+OpenObserve Inc\.")
FORK_COPYRIGHT_RE = re.compile(r"Copyright\s+\(C\)\s+(?P<year>\d{4})\s+Mike Sauh")
MODIFICATIONS_RE = re.compile(r"Modifications Copyright\s+\(C\)\s+(?P<year>\d{4})\s+Mike Sauh")

LINE_COMMENT = "//"
BLOCK_COMMENT_OPEN = "<!--"
BLOCK_COMMENT_CLOSE = "-->"

FORK_PURPOSE = "This file was created independently to make the product brand configurable."


def run_git(*args: str) -> str:
    result = subprocess.run(["git", *args], capture_output=True, text=True, check=True)
    return result.stdout


def current_year() -> int:
    return datetime.date.today().year


def fork_header_lines(comment: str, year: int) -> list[str]:
    return [
        f"{comment} Copyright (C) {year} Mike Sauh",
        comment,
        f"{comment} This file is part of ExposedObserve, a modified fork of OpenObserve.",
        f"{comment} OpenObserve is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).",
        f"{comment} Original project: https://github.com/openobserve/openobserve",
        comment,
        f"{comment} {FORK_PURPOSE}",
    ]



def changes(base: str, include_worktree: bool) -> list[tuple[str, str]]:
    entries = run_git("diff", "--name-status", "-z", f"{base}..HEAD").split("\0")
    result: list[tuple[str, str]] = []
    index = 0
    while index < len(entries):
        status = entries[index]
        if not status:
            index += 1
            continue
        path = entries[index + 1]
        index += 2
        result.append((status[0], path))

    if include_worktree:
        for raw in (
            run_git("diff", "--name-status", "-z", "--cached").split("\0"),
            run_git("diff", "--name-status", "-z").split("\0"),
        ):
            index = 0
            while index < len(raw):
                status = raw[index]
                if not status:
                    index += 1
                    continue
                path = raw[index + 1]
                index += 2
                result.append((status[0], path))

    return result


def is_excluded(path: str) -> bool:
    if Path(path).name in EXCLUDED_NAMES:
        return True
    return any(part in EXCLUDED_DIRS for part in Path(path).parts)


def last_commit_year(path: str) -> int:
    stamp = run_git("log", "-1", "--format=%ct", "--", path).strip()
    if not stamp:
        return current_year()
    return datetime.datetime.fromtimestamp(int(stamp)).year


def comment_syntax(path: Path) -> str:
    return BLOCK_COMMENT_OPEN if path.suffix == ".vue" else LINE_COMMENT


def read_lines(path: Path) -> list[str]:
    try:
        return path.read_text(encoding="utf-8").splitlines()
    except (UnicodeDecodeError, OSError):
        return []


def write_lines(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def upstream_exists(base: str, path: str) -> bool:
    return subprocess.run(
        ["git", "cat-file", "-e", f"{base}:{path}"], capture_output=True
    ).returncode == 0


def fix_fork_file(path: Path, year: int) -> bool:
    lines = read_lines(path)
    if not lines:
        return False
    comment = comment_syntax(path)
    if comment == BLOCK_COMMENT_OPEN:
        insertion = [
            f"{BLOCK_COMMENT_OPEN} {line[len(comment) + 1:]}{BLOCK_COMMENT_CLOSE}"
            for line in fork_header_lines(comment, year)
        ]
    else:
        insertion = fork_header_lines(comment, year)
    write_lines(path, insertion + [""] + lines)
    return True


def fix_modified_file(path: Path, year: int) -> bool:
    lines = read_lines(path)
    if not lines:
        return False
    for index, line in enumerate(lines):
        if UPSTREAM_COPYRIGHT_RE.search(line):
            notice = f"{comment_syntax(path)} Modifications Copyright (C) {year} Mike Sauh"
            lines.insert(index + 1, notice)
            write_lines(path, lines)
            return True
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base", help="upstream tag or commit to diff against")
    parser.add_argument("--fix", action="store_true", help="insert missing headers")
    parser.add_argument(
        "--worktree",
        action="store_true",
        help="also audit uncommitted staged and unstaged changes",
    )
    args = parser.parse_args()

    violations: list[str] = []
    counts = {"fork-new": 0, "modified": 0, "deleted": 0, "other": 0}

    for status, path_str in changes(args.base, args.worktree):
        if is_excluded(path_str):
            continue
        path = Path(path_str)
        if status == "D":
            counts["deleted"] += 1
            continue
        if not path.exists() or path.suffix not in CODE_SUFFIXES:
            counts["other"] += 1
            continue

        year = last_commit_year(path_str)
        header = read_lines(path)[:4]
        joined = "\n".join(header)

        if not upstream_exists(args.base, path_str):
            counts["fork-new"] += 1
            if not FORK_COPYRIGHT_RE.search(joined):
                if args.fix and fix_fork_file(path, year):
                    continue
                violations.append(f"fork file lacks the fork copyright header: {path_str}")
            elif UPSTREAM_COPYRIGHT_RE.search(joined):
                violations.append(f"fork file claims upstream authorship: {path_str}")
            continue

        counts["modified"] += 1
        if UPSTREAM_COPYRIGHT_RE.search(joined) and not MODIFICATIONS_RE.search(joined):
            if args.fix and fix_modified_file(path, year):
                continue
            violations.append(
                f"modified upstream file lacks a Modifications Copyright line: {path_str}"
            )

    print(f"audited against {args.base}")
    for key, value in counts.items():
        print(f"  {key}: {value}")

    if violations:
        print(f"\n{len(violations)} violation(s):", file=sys.stderr)
        for violation in violations:
            print(f"  - {violation}", file=sys.stderr)
        return 1

    print("\nOK - every changed code file carries the correct attribution.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
