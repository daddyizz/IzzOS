#!/usr/bin/env python3
import hashlib
import re
import sys
from pathlib import Path


if len(sys.argv) != 3:
    raise SystemExit(f"Usage: {sys.argv[0]} <LinuxLoader.efi> <report.txt>")

SOURCE = Path(sys.argv[1])
OUT = Path(sys.argv[2])
if not SOURCE.is_file():
    raise SystemExit(f"ERROR: LinuxLoader input not found: {SOURCE}")
if SOURCE.resolve() == OUT.resolve():
    raise SystemExit("ERROR: output must not overwrite LinuxLoader input")

data = SOURCE.read_bytes()
keywords = (
    "fastboot", "getvar", "download", "continue", "reboot", "set_active",
    "set-active", "boot", "flash", "erase",
)


def interesting(value):
    lowered = value.lower()
    return any(keyword in lowered for keyword in keywords)


records = []
for match in re.finditer(rb"[\x20-\x7e]{4,}", data):
    value = match.group().decode("ascii", errors="replace")
    if interesting(value):
        records.append((match.start(), "ASCII", value))

for alignment in (0, 1):
    pattern = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
    for match in pattern.finditer(data, alignment):
        if match.start() % 2 != alignment:
            continue
        value = match.group().decode("utf-16le", errors="replace")
        if interesting(value):
            records.append((match.start(), "UTF16LE", value))

unique = []
seen = set()
for offset, encoding, value in sorted(records):
    key = (offset, encoding, value)
    if key not in seen:
        seen.add(key)
        unique.append(key)

lines = [
    "IzzOS exact stock LinuxLoader fastboot/boot string inventory",
    "Analyzer mode: READ_ONLY_HOST_SIDE_STATIC_STRINGS_ONLY",
    "Device commands executed: NONE",
    "Device writes executed: NONE",
    "Launch commands executed: NONE",
    f"input: {SOURCE}",
    f"byte-size: {len(data)}",
    f"sha256: {hashlib.sha256(data).hexdigest()}",
    f"matching-string-count: {len(unique)}",
    "",
    "matching strings:",
]
for offset, encoding, value in unique:
    safe = value.replace("\r", "\\r").replace("\n", "\\n")
    lines.append(f"0x{offset:08X}|{encoding}|{safe}")

if unique:
    lines += [
        "",
        "classification: LINUXLOADER_FASTBOOT_BOOT_STRINGS_ENUMERATED",
        "decision: exact-binary command-related strings were enumerated host-side. String presence does not prove a reachable command handler, exact bootloader acceptance, non-persistent behavior or safe payload execution; no fastboot boot, flash, erase or slot change is authorized.",
    ]
else:
    lines += [
        "",
        "classification: LINUXLOADER_FASTBOOT_BOOT_STRINGS_NOT_FOUND",
        "decision: no selected command-related strings were found. This cannot be treated as proof that a route is absent or safe; device launch remains unauthorized.",
    ]

rendered = "\n".join(lines) + "\n"
OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(rendered, newline="\n")
print(rendered, end="")
