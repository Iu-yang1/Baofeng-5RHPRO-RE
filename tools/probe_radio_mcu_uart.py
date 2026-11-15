#!/usr/bin/env python3
"""Passive receiver for the experimental UV-5RH Pro ID UART diagnostic.

This tool only reads serial data. It does not send firmware, handshakes,
commands, writes, erases, changes protection, or read any MCU on its own.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

PATTERN = re.compile(
    r"^UV5RHPRO-ID/1(?:,(?:CPUID|FSIZE_RAW|DBG_ID|AT_PROJECT|AIR_UID0_MASK)=0x[0-9A-F]+X?)+$",
    re.ASCII,
)
FIELDS = {"CPUID": 8, "FSIZE_RAW": 4, "DBG_ID": 8,
          "AT_PROJECT": 2, "AIR_UID0_MASK": 8}


def parse_line(line: str) -> dict | None:
    """Return decoded fields only for known, well-formed diagnostic frames."""
    text = line.strip()
    if not PATTERN.fullmatch(text):
        return None
    pairs = [part.split("=", 1) for part in text.split(",")[1:]]
    keys = [key for key, _ in pairs]
    if len(set(keys)) != len(keys) or "CPUID" not in keys:
        return None
    values = {}
    for field, value in pairs:
        expected = FIELDS.get(field)
        if expected is None or len(value) != expected + 2:
            return None
        if field == "AIR_UID0_MASK":
            if not value.endswith("X"):
                return None
            values[field] = value
        else:
            if value.endswith("X"):
                return None
            values[field] = int(value, 16)
    from mcu_readonly_id_evidence import interpret
    uid0 = (int(values["AIR_UID0_MASK"][2:-1], 16) << 4
            if "AIR_UID0_MASK" in values else None)
    evidence = interpret(
        cpuid=values["CPUID"],
        flash_size_halfword=values.get("FSIZE_RAW"),
        debug_id=values.get("DBG_ID"),
        project_byte=values.get("AT_PROJECT"),
        uid_first_word=uid0,
    )
    return {
        "source": "unverified firmware UART output (not SWD)",
        "raw_registers": {key: value for key, value in values.items()
                          if key != "AIR_UID0_MASK"},
        "masked_uid0_class": values.get("AIR_UID0_MASK"),
        "interpretation": evidence,
    }


def collect_file(path: Path) -> list[dict]:
    return [decoded for line in path.read_text(encoding="ascii").splitlines()
            if (decoded := parse_line(line)) is not None]


def listen(port: str, baud: int, seconds: float) -> list[dict]:
    import time
    try:
        import serial
    except ImportError as exc:
        raise RuntimeError("pyserial missing: install with python -m pip install pyserial") from exc
    outputs = []
    seen = set()
    with serial.Serial(port=port, baudrate=baud, timeout=0.25,
                       rtscts=False, dsrdtr=False, xonxoff=False) as device:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            line = device.readline(320).decode("ascii", errors="ignore")
            record = parse_line(line)
            if record is not None:
                fingerprint = tuple(sorted(record["raw_registers"].items()))
                if fingerprint not in seen:
                    outputs.append(record)
                    seen.add(fingerprint)
    return outputs


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--port", help="Listen on UART (e.g. COM5), read-only")
    src.add_argument("--file", type=Path, help="Parse a saved diagnostic text stream")
    parser.add_argument("--baud", type=int, default=9600)
    parser.add_argument("--seconds", type=float, default=12.0)
    args = parser.parse_args(argv)
    reports = collect_file(args.file) if args.file else listen(args.port, args.baud, args.seconds)
    print(json.dumps({"reports": reports, "received": len(reports)}, ensure_ascii=False, indent=2))
    return 0 if reports else 2


if __name__ == "__main__":
    raise SystemExit(main())
