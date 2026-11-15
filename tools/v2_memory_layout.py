#!/usr/bin/env python3
"""Check candidate V2 stock-image RAM boundaries against scatterload records.

Reports linker/startup invariants, not the MCU's physically implemented RAM.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import struct

from mcu_fingerprint import decoded_payload
from v2_scatterload_regions import REGION_START
from thumb_window import BASE


def analyze(payload: bytes) -> dict:
    vectors_sp = struct.unpack_from("<I", payload, 0)[0]
    records = []
    for pc in (REGION_START, REGION_START+16):
        source, destination, size, handler = struct.unpack_from(
            "<IIII", payload, pc-BASE
        )
        records.append({
            "source": f"0x{source:08X}",
            "destination": f"0x{destination:08X}",
            "length": size,
            "exclusive_end": f"0x{destination + size:08X}",
            "handler": f"0x{handler:08X}",
        })
    data_end = int(records[0]["exclusive_end"], 16)
    bss_start = int(records[1]["destination"], 16)
    bss_end = int(records[1]["exclusive_end"], 16)
    return {
        "initial_msp_candidate": f"0x{vectors_sp:08X}",
        "data_region": records[0],
        "zero_region": records[1],
        "data_then_zero_contiguous": data_end == bss_start,
        "last_region_end_equals_initial_msp": bss_end == vectors_sp,
        "total_init_bytes": records[0]["length"]+records[1]["length"],
        "limits": [
            "The image's initial MSP and initialization regions do not establish physical RAM capacity.",
            "Some zeroed region may be reserved for a runtime stack or other ARM runtime use.",
            "This is based on a decoded upgrade payload at assumed load base 0x08001000.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("firmware", type=Path)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    report = analyze(decoded_payload(args.firmware.read_bytes()))
    print(json.dumps(report, indent=2) if args.json else
          f"MSP={report['initial_msp_candidate']} DATA={report['data_region']} "
          f"ZERO={report['zero_region']} contiguous={report['data_then_zero_contiguous']} "
          f"last_end_is_MSP={report['last_region_end_equals_initial_msp']}")


if __name__ == "__main__":
    raise SystemExit(main())
