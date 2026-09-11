#!/usr/bin/env python3
# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Answer "what is this file, and what happens if I break it?" in one command.

The knowledge debt in this project is not that the code is unknown - it is that
it cannot be *held*. `git grep` answers "where is this string"; this answers the
three questions you actually have when you open an unfamiliar module:

  1. What does it expose?
  2. Who depends on it, and what does it depend on?
  3. Which tests would go red if I broke it - and is that number reassuring?

Question 3 is the load-bearing one. A module with no test context is a module
you can silently break, and this prints that fact in red rather than leaving you
to infer it from a coverage percentage.

Usage:
    make explain FILE=ttp/state.py
    make explain FILE=ttp/state.py REFRESH=1     # re-measure per-test coverage
"""

from __future__ import annotations

import ast
import sqlite3
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
COVERAGE_DB = REPO / ".coverage"

BOLD, DIM, RED, GREEN, YELLOW, CYAN, RESET = (
    "\033[1m",
    "\033[2m",
    "\033[31m",
    "\033[32m",
    "\033[33m",
    "\033[36m",
    "\033[0m",
)


def is_definitions_only(path: Path) -> bool:
    """
    True when the module contains no runnable body - only class and constant
    definitions, like an exception hierarchy.

    Such a module's lines execute at *import* time, before any test context
    exists, so coverage attributes them to nothing. Reporting that as "no test
    guards this file" would be a confident falsehood, and a tool that lies in
    red is worse than no tool.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        body = list(node.body)
        # Drop only the docstring and the placeholder forms. Dropping every
        # ast.Expr - as a first attempt did - also drops a body that is a single
        # bare call, so `def print_error(...): console.print(...)` looked empty
        # and the whole module was wrongly excluded from the ranking.
        if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
            body = body[1:]
        body = [
            b
            for b in body
            if not isinstance(b, ast.Pass) and not (isinstance(b, ast.Expr) and isinstance(b.value, ast.Constant))
        ]
        if body:
            return False
    return True


def public_api(path: Path) -> list[str]:
    """Every public class and top-level function, with its first docstring line."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    out: list[str] = []
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if node.name.startswith("_"):
            continue
        doc = (ast.get_docstring(node) or "").strip().split("\n")[0]
        kind = "class" if isinstance(node, ast.ClassDef) else "def"
        out.append(f"{kind} {node.name} - {doc}" if doc else f"{kind} {node.name}")
    return out


def imports_of(path: Path) -> list[str]:
    """First-party modules this file imports."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("ttp"):
            found.add(node.module)
        elif isinstance(node, ast.Import):
            found.update(a.name for a in node.names if a.name.startswith("ttp"))
    return sorted(found)


def importers_of(module: str) -> list[str]:
    """
    First-party files that import *module*.

    Matches all three spellings Python allows, because missing one makes the
    blast radius look smaller than it is - which is the opposite of useful here:
    `from ttp.state import x`, `import ttp.state`, and `from ttp import state`.
    """
    leaf = module.rsplit(".", 1)[-1]
    parent = module.rsplit(".", 1)[0] if "." in module else ""
    patterns = [rf"from {module} import", rf"import {module}\b"]
    if parent:
        patterns.append(rf"from {parent} import .*\b{leaf}\b")
    result = subprocess.run(
        ["git", "grep", "-l", "-E", "|".join(patterns), "--", "ttp", "tests"],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=False,
    )
    return sorted(x for x in result.stdout.split() if x)


def measure_contexts() -> None:
    """Re-run the suite recording which test touched which line."""
    print(f"{DIM}Measuring per-test coverage (this takes a few seconds)...{RESET}")
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "tests",
            "-q",
            "--cov=ttp",
            "--cov-context=test",
            "--cov-report=",
            "-p",
            "no:cacheprovider",
        ],
        cwd=REPO,
        check=False,
        stdout=subprocess.DEVNULL,
    )


def covering_tests(rel: str) -> list[str] | None:
    """Test files whose execution reached this file. None if not measured."""
    if not COVERAGE_DB.exists():
        return None
    con = sqlite3.connect(COVERAGE_DB)
    try:
        # A .coverage written without --cov-context=test has exactly one
        # context: the empty string. Reporting "no tests guard this" from that
        # would be a confident lie, which is the one thing this tool must not do.
        contexts = con.execute("SELECT COUNT(*) FROM context WHERE context != ''").fetchone()
        if not contexts or contexts[0] == 0:
            return None
        rows = con.execute(
            """
            SELECT DISTINCT c.context FROM context c
            JOIN line_bits l ON l.context_id = c.id
            JOIN file f ON f.id = l.file_id
            WHERE f.path LIKE ? AND c.context != ''
            """,
            (f"%{rel}",),
        ).fetchall()
    except sqlite3.OperationalError:
        return None
    finally:
        con.close()
    # "tests/test_state.py::test_write_lock|run" -> "tests/test_state.py"
    return sorted({r[0].split("::")[0] for r in rows if r[0]})


def rank_debt() -> int:
    """
    Rank modules by exposure: many dependents, few guarding suites.

    This is the point of the whole script. "I have a knowledge debt" is not
    actionable; "state.py is imported by 15 modules and executed by 2 test
    suites" is. The top of this list is where a change is most likely to break
    something far away without anything going red.
    """
    measured = covering_tests("ttp/__init__.py") is not None
    if not measured:
        print(f"{YELLOW}Per-test coverage not measured yet. Run: make debt REFRESH=1{RESET}")
        return 1

    rows = []
    for path in sorted((REPO / "ttp").rglob("*.py")):
        rel = str(path.relative_to(REPO))
        if path.name == "__init__.py":
            continue
        module = rel.removesuffix(".py").replace("/", ".")
        if is_definitions_only(path):
            continue  # cannot be attributed; see is_definitions_only
        users = [u for u in importers_of(module) if u != rel and not u.startswith("tests/")]
        tests = covering_tests(rel) or []
        rows.append((len(users), len(tests), rel))

    # Sort by dependents descending, then by guarding suites ascending: the most
    # depended-upon, least guarded module first.
    rows.sort(key=lambda r: (-r[0], r[1]))

    print(f"\n{BOLD}Exposure: depended upon, thinly guarded{RESET}\n")
    print(f"  {DIM}{'dependents':>10}  {'suites':>6}  module{RESET}")
    for users, tests, rel in rows[:15]:
        colour = RED if tests == 0 else (YELLOW if users >= 5 and tests <= 2 else "")
        print(f"  {colour}{users:>10}  {tests:>6}  {rel}{RESET}")
    print(f"\n  {DIM}Red: nothing executes it. Yellow: wide blast radius, thin guard.")
    print(f"  `make explain FILE=<module>` for the detail.{RESET}\n")
    return 0


def main() -> int:
    if len(sys.argv) >= 2 and sys.argv[1] == "--debt":
        if "--refresh" in sys.argv:
            measure_contexts()
        return rank_debt()

    if len(sys.argv) < 2:
        print("usage: explain.py <path-to-source-file> [--refresh] | --debt", file=sys.stderr)
        return 2

    rel = sys.argv[1]
    path = REPO / rel
    if not path.exists():
        print(f"{RED}no such file: {rel}{RESET}", file=sys.stderr)
        return 1

    if "--refresh" in sys.argv:
        measure_contexts()

    module = rel.removesuffix(".py").replace("/", ".")
    print(f"\n{BOLD}{rel}{RESET}  {DIM}({len(path.read_text().splitlines())} lines){RESET}\n")

    api = public_api(path)
    print(f"{BOLD}Exposes{RESET}")
    if api:
        for item in api:
            print(f"  {item}")
    else:
        print(f"  {DIM}nothing public - internal to its package{RESET}")

    deps = imports_of(path)
    print(f"\n{BOLD}Depends on{RESET}")
    print("  " + (", ".join(deps) if deps else f"{DIM}nothing first-party{RESET}"))

    users = [u for u in importers_of(module) if u != rel]
    src_users = [u for u in users if not u.startswith("tests/")]
    print(f"\n{BOLD}Depended on by{RESET}")
    if src_users:
        for u in src_users:
            print(f"  {u}")
        print(f"  {DIM}-> {len(src_users)} first-party module(s) break if this one does{RESET}")
    else:
        print(f"  {DIM}nothing - it is a leaf, or reached only dynamically{RESET}")

    tests = covering_tests(rel)
    print(f"\n{BOLD}Guarded by{RESET}")
    if is_definitions_only(path):
        print(f"  {DIM}n/a - definitions only. Its lines run at import, before any")
        print(f"  test context exists, so coverage cannot attribute them.{RESET}")
    elif tests is None:
        print(f"  {YELLOW}not measured. Run: make explain FILE={rel} REFRESH=1{RESET}")
    elif tests:
        for t in tests:
            print(f"  {GREEN}{t}{RESET}")
        print(f"\n  {DIM}Break this file and those {len(tests)} suites should go red.")
        print(f"  If you can predict which, you do not have a debt here.{RESET}")
    else:
        print(f"  {RED}NOTHING.{RESET}")
        print(f"  {RED}You can break this file silently. That is the debt, located.{RESET}")

    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
