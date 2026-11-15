#!/usr/bin/env python3
"""Recover the V2 ROM-initialized SRAM prescaler tables from ARM scatterload.

Derived strictly from Thumb 0x08001F06..0x08001F5A and the actual descriptor:
tag bits0..2 literal length (extended if 0), bits4..7 run length
(extended if 0), bit3 selects zero-run or backward-reference.
Only extracted clock-table bytes and a digest are reported. No firmware dump.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct

from mcu_fingerprint import decoded_payload
from thumb_window import BASE
from v2_scatterload_regions import REGION_START

SRAM_BASE = 0x20000000
TABLE_CLOCK_APB = 0x20000018
TABLE_CLOCK_ADC = 0x20000014


def decompress_region(blob: bytes, output_length: int) -> tuple[bytes, int]:
    if output_length < 0:
        raise ValueError("negative output length")
    output = bytearray()
    cursor = 0

    def take() -> int:
        nonlocal cursor
        if cursor >= len(blob):
            raise ValueError("compressed scatterload stream truncated")
        byte = blob[cursor]
        cursor += 1
        return byte

    while len(output) < output_length:
        tag = take()
        literal_count = tag & 0x07
        if literal_count == 0:
            literal_count = take()
        run_count = tag >> 4
        if run_count == 0:
            run_count = take()

        for _ in range(literal_count):
            if len(output) >= output_length:
                raise ValueError("literal would overrun declared SRAM region")
            output.append(take())

        if tag & 0x08:
            distance = take()
            if not 0 < distance <= len(output):
                raise ValueError("invalid scatterload backward-reference distance")
            for _ in range(run_count + 2):
                if len(output) >= output_length:
                    raise ValueError("back-reference overruns declared SRAM region")
                output.append(output[-distance])
        else:
            if len(output) + run_count > output_length:
                raise ValueError("zero run would overrun declared SRAM region")
            output.extend(b"\x00" * run_count)
    return bytes(output), cursor


def inspect_tables(payload: bytes) -> dict:
    offset = REGION_START - BASE
    load, run, size, handler = struct.unpack_from("<IIII", payload, offset)
    next_load = struct.unpack_from("<I", payload, offset+16)[0]
    if run != SRAM_BASE or (handler & ~1) != 0x08001F06:
        raise ValueError("unexpected V2 scatterload descriptor/handler")
    if not (BASE <= load < next_load <= BASE+len(payload)):
        raise ValueError("invalid compressed source address")
    compressed = payload[load-BASE:next_load-BASE]
    expanded, consumed = decompress_region(compressed, size)
    if consumed != len(compressed):
        # The next region could be aligned; report rather than assume exact.
        trailing = len(compressed) - consumed
    else:
        trailing = 0

    # 0x20000014..0x2000001F: the 4-byte ADC divisor lookup and first 8
    # AHB/APB shift values actually used by clock getter 0x08030C30.
    adc = tuple(expanded[TABLE_CLOCK_ADC-SRAM_BASE:TABLE_CLOCK_APB-SRAM_BASE])
    clock = tuple(expanded[TABLE_CLOCK_APB-SRAM_BASE:TABLE_CLOCK_APB-SRAM_BASE+16])
    return {
        "region_destination": f"0x{run:08X}",
        "region_size": size,
        "source_address": f"0x{load:08X}",
        "compressed_bytes_available": len(compressed),
        "compressed_bytes_consumed": consumed,
        "unused_trailing_source_bytes": trailing,
        "decompressed_sha256": hashlib.sha256(expanded).hexdigest(),
        "adc_prescaler_table_4": list(adc),
        "clock_prescaler_table_first16": list(clock),
        "apb_shift_first8": list(clock[:8]),
        "lookup_explanation": (
            "Original decoded firmware writes the table to SRAM using a "
            "Thumb-defined scatterload decompression routine; these bytes "
            "are copied from restored image, not an SDK default assumption."
        ),
        "limits": [
            "The recovered SRAM image represents reset initialization only; runtime may mutate tables.",
            "A clock register map still requires MCU vendor/part verification.",
            "No physical oscillator or live RAM read was performed.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("image", type=Path)
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    r = inspect_tables(decoded_payload(args.image.read_bytes()))
    print(json.dumps(r, indent=2) if args.json else
          f"ADC divisor table {r['adc_prescaler_table_4']} ; "
          f"clock shift table {r['clock_prescaler_table_first16']} ; "
          f"decompressed SHA256 {r['decompressed_sha256']}")


if __name__ == "__main__":
    raise SystemExit(main())
