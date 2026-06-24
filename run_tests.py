#!/usr/bin/env python3
"""
Dependency-free test runner for PLEXUS.

The test files are written as ordinary pytest test functions, so in a normal
environment you can simply run `pytest`.  This runner exists so the full suite
also runs with *zero third-party dependencies* (handy for an offline or
minimal CI box): it discovers every top-level `test_*` function in
`tests/test_*.py`, runs it, and reports pass/fail counts.

Usage:
    python run_tests.py            # run everything
    python run_tests.py field      # run only tests/test_field.py

Author: Ideatrino <ideatrino@proton.me>
Copyright (c) 2026 Ideatrino <ideatrino@proton.me>. All Rights Reserved. Proprietary — see LICENSE.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import traceback
import types

ROOT = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(ROOT, "src")
TESTS = os.path.join(ROOT, "tests")

if SRC not in sys.path:
    sys.path.insert(0, SRC)


def _load(path: str) -> types.ModuleType:
    name = os.path.splitext(os.path.basename(path))[0]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main(argv: list[str]) -> int:
    selectors = argv[1:]
    files = sorted(
        f for f in os.listdir(TESTS)
        if f.startswith("test_") and f.endswith(".py")
    )
    if selectors:
        files = [f for f in files if any(s in f for s in selectors)]

    total = passed = failed = 0
    failures: list[tuple[str, str]] = []

    for fname in files:
        mod = _load(os.path.join(TESTS, fname))
        tests = sorted(
            n for n in dir(mod)
            if n.startswith("test_") and callable(getattr(mod, n))
        )
        print(f"\n{fname}")
        for tname in tests:
            total += 1
            try:
                getattr(mod, tname)()
                passed += 1
                print(f"  PASS  {tname}")
            except Exception:
                failed += 1
                tb = traceback.format_exc()
                failures.append((f"{fname}::{tname}", tb))
                print(f"  FAIL  {tname}")

    print("\n" + "=" * 60)
    print(f"  {passed}/{total} passed, {failed} failed")
    print("=" * 60)

    for name, tb in failures:
        print(f"\n--- {name} ---\n{tb}")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
