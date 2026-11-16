#!/usr/bin/env python3
"""Survey static AIR32-style boot-ROM code evidence across stock firmware files.

Report only image bytes and documented offsets; neither prove live MCU
identity nor assume that every stock image has an identical code layout.
"""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct

from mcu_fingerprint import decoded_payload

IMAGE_BASE = 0x08001000
BOOT_HELPER_WINDOW_START = 0x08001280
BOOT_HELPER_WINDOW_SIZE = 0xD8
LITERALS = {
    0x1FFFF7E8: "UID0 pointer used by AIR32 SDK-compatible branch",
    0x1FFFD000: "system ROM function pointer table",
    0x400210F0: "system CFG clock gate",
    0x40016C00: "three-key configuration interface",
    0x40016C18: "temporary SRAM window configuration",
    0x4002228C: "QSPI / flash extension control",
    0xA7D93A86: "unlock key 1",
    0xAB12DFCD: "unlock key 2",
    0xCDED3526: "unlock key 3",
    0xA5A5A5A5: "QSPI unlock marker",
    0x5A5A5A5A: "QSPI lock marker",
    0x200183FF: "temporary SRAM window marker",
}
DEFAULT_IMAGES = (
    "BF_5RH_501_v1_0_92.dat",
    "BF_5RH_501_v1_0_97.dat",
    "BF_5RH_501_v1_1_00.dat",
    "BF_5RH_501_v1_1_04.dat",
    "BF_5RH_501_v2_0_7.dat",
    "BF_5RH_501_v2_0_9.dat",
)


def count_aligned_words(payload: bytes) -> dict[str, int]:
    words = Counter(
        struct.unpack_from("<I", payload, off)[0]
        for off in range(0, len(payload) - 3, 4)
    )
    return {f"0x{k:08X}": words[k] for k in LITERALS}


def stock_window(payload: bytes) -> bytes:
    offset = BOOT_HELPER_WINDOW_START - IMAGE_BASE
    return payload[offset:offset + BOOT_HELPER_WINDOW_SIZE]


def assess(payload: bytes, reference: bytes) -> dict:
    window = stock_window(payload)
    ref = stock_window(reference)
    if len(window) != BOOT_HELPER_WINDOW_SIZE or len(ref) != BOOT_HELPER_WINDOW_SIZE:
        raise ValueError("decoded stock image lacks the shared boot-ROM helper window")
    matches = sum(a == b for a, b in zip(window, ref))
    magic_counts = count_aligned_words(payload)
    return {
        "decoded_payload_bytes": len(payload),
        "helper_pc": f"0x{BOOT_HELPER_WINDOW_START:08X}",
        "helper_window_bytes": len(window),
        "helper_window_sha256": hashlib.sha256(window).hexdigest(),
        "helper_matching_bytes_vs_v2_0_9": matches,
        "helper_exactly_same_as_v2_0_9": window == ref,
        "aligned_literal_counts": magic_counts,
        "aligned_magic_constant_words_present": sum(
            magic_counts[f"0x{value:08X}"] > 0 for value in LITERALS
        ),
        "nonliteral_or_unreferenced_constant_words": [
            f"0x{value:08X}" for value in LITERALS
            if magic_counts[f"0x{value:08X}"] == 0
        ],
        "interpretation": (
            "Matching the official AIR32 SDK-style constants and helper "
            "supports code lineage, not live chip identification. "
            "Aligned word counts are not verified control-flow references."
        ),
    }


def analyze(images: dict[str, bytes]) -> dict:
    ref_name = "BF_5RH_501_v2_0_9.dat"
    if ref_name not in images:
        raise ValueError("V2.0.09 reference stock firmware missing")
    ref = images[ref_name]
    return {
        "reference": ref_name,
        "versions": {name: assess(payload, ref)
                     for name, payload in sorted(images.items())},
        "limits": [
            "No physical registers, actual UID, CPUID or MCU PID were read.",
            "Matching boot-ROM helper bytes identify firmware lineage, not silicon supplier.",
            "Aligned word presence is a weak clue; a missing literal may be encoded as an immediate or an offset rather than absent from code.",
            "Code-referenced behavior is separately verified in V1.1.04/V2.0.09.",
            "No chip Flash/SRAM or OEM custom marking is inferred from the SDK signature.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--firmware-dir", type=Path, default=Path("firmware"))
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    images = {
        name: decoded_payload((args.firmware_dir / name).read_bytes())
        for name in DEFAULT_IMAGES
    }
    output = analyze(images)
    if args.json:
        print(json.dumps(output, indent=2, ensure_ascii=False))
    else:
        for name, row in output["versions"].items():
            print(name, "payload", row["decoded_payload_bytes"],
                  "helper bytes matching", row["helper_matching_bytes_vs_v2_0_9"],
                  "of", row["helper_window_bytes"],
                  "aligned magic words",
                  row["aligned_magic_constant_words_present"],
                  "of", len(LITERALS))
            print("  key counts:", row["aligned_literal_counts"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
