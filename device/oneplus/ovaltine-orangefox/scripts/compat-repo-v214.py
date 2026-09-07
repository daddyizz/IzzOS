#!/usr/bin/env python3
"""Add legacy repo-compatible names to path-only remove-project entries."""

from __future__ import annotations

import re
import sys
from pathlib import Path
import xml.etree.ElementTree as ET


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: compat-repo-v214.py /path/to/.repo/manifests", file=sys.stderr)
        return 2

    manifest_dir = Path(sys.argv[1]).resolve()
    if not manifest_dir.is_dir():
        print(f"manifest directory not found: {manifest_dir}", file=sys.stderr)
        return 1

    path_to_name: dict[str, str] = {}
    xml_files = sorted(manifest_dir.glob("*.xml"))
    for xml_file in xml_files:
        root = ET.parse(xml_file).getroot()
        for project in root.iter("project"):
            path = project.get("path")
            name = project.get("name")
            if path and name:
                path_to_name[path] = name

    remove_re = re.compile(r'<remove-project\s+path="([^"]+)"\s*/>')
    changed = 0
    for xml_file in xml_files:
        text = xml_file.read_text(encoding="utf-8")

        def replace(match: re.Match[str]) -> str:
            nonlocal changed
            path = match.group(1)
            name = path_to_name.get(path)
            if not name:
                raise RuntimeError(f"no project name mapping for remove path: {path}")
            changed += 1
            return f'<remove-project name="{name}" path="{path}" />'

        updated = remove_re.sub(replace, text)
        if updated != text:
            xml_file.write_text(updated, encoding="utf-8")

    print(f"Added legacy names to {changed} remove-project entries.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ET.ParseError, OSError, RuntimeError) as exc:
        print(f"repo v2.14 manifest compatibility failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
