#!/usr/bin/env python3
"""Compatibility hook for repo v2.14; manifest edits are intentionally explicit."""
import sys
from pathlib import Path
if len(sys.argv) != 2 or not Path(sys.argv[1]).is_dir():
    raise SystemExit("usage: compat-repo-v214.py MANIFEST_DIR")
