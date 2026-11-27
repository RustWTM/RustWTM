#!/usr/bin/env python3
"""Validate RustWTM GUI locale JSON files for syntax and key coverage."""

from __future__ import annotations

import json
import sys
from pathlib import Path

LOCALES_DIR = Path(__file__).resolve().parents[2] / "crates" / "wtm-gui" / "locales"
REFERENCE_FILE = LOCALES_DIR / "tr.json"


def main() -> int:
    files = sorted(LOCALES_DIR.glob("*.json"))
    if not files:
        print(f"No locale files found in {LOCALES_DIR}", file=sys.stderr)
        return 1

    ref_keys: set[str] | None = None
    if REFERENCE_FILE.is_file():
        ref_data = json.loads(REFERENCE_FILE.read_text(encoding="utf-8"))
        if isinstance(ref_data, dict):
            ref_keys = set(ref_data.keys())

    errors = 0
    for path in files:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            print(f"INVALID JSON: {path.name}: {exc}", file=sys.stderr)
            errors += 1
            continue

        if not isinstance(data, dict):
            print(f"INVALID STRUCTURE (expected object): {path.name}", file=sys.stderr)
            errors += 1
            continue

        if ref_keys is not None and path.name != "messages.json":
            missing = len(ref_keys - set(data.keys()))
            extra = len(set(data.keys()) - ref_keys)
            if missing or extra:
                print(f"{path.name}: {missing} missing, {extra} extra keys vs {REFERENCE_FILE.name}")

    print(f"Checked {len(files)} locale file(s) with {errors} error(s).")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
