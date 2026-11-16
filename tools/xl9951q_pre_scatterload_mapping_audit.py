#!/usr/bin/env python3
"""Read-only stock V1/V2 boot-stage audit of high Flash scatterload vs QSPI helper.

All evidence is extracted from decoded original upgrade packages and public
AIR32 SDK call semantics. This does not know the OEM XL9951Q silicon mapping.
No device, serial port, debugger, or Flash writer is accessed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from mcu_fingerprint import decoded_payload
from thumb_callsites import find_calls
from v2_bootrom_dispatch import analyze as verify_rom_helper
from v2_air32_sdk_fingerprint import ROM_HELPER_LITERALS, literal
from v2_pll_runtime_order import V1, V2, verify_reset_to_main
from v2_scatterload_decode import inspect_tables
from v2_scatterload_regions import inspect as inspect_regions

IMAGE_BASE = 0x08001000
CORTEX_FLASH_REGION_BASE = 0x08000000
ROM_HELPER = 0x08001260
# Both are instruction-verified in v2_bootrom_dispatch.analyze(), which also
# validates the ROM call and AIR32-style special MMIO register addresses.
QSPI_UNLOCK_SITE = 0x0800129E
QSPI_RELOCK_SITE = 0x0800133A
EXPECTED_ROM_CALLS = {
    "v1": "0x08026252",
    "v2": "0x08032386",
}


def describe_source_span(image_size: int, address: int, consumed_bytes: int) -> dict:
    """Report how much of a runtime flash-address source exists in the package."""
    if consumed_bytes < 1 or image_size < 1 or address < IMAGE_BASE:
        raise ValueError("invalid source coordinates or consumed byte count")
    offset = address - IMAGE_BASE
    end = offset + consumed_bytes
    if end > image_size:
        raise ValueError("startup compressed source is outside decoded package")
    window_last = address + consumed_bytes - 1
    return {
        "image_load_base_hypothesis": f"0x{IMAGE_BASE:08X}",
        "package_size_bytes": image_size,
        "source_address": f"0x{address:08X}",
        "source_package_offset_bytes": offset,
        "source_end_exclusive": f"0x{address + consumed_bytes:08X}",
        "bytes_consumed_from_package": consumed_bytes,
        "bytes_from_high_source_to_package_end": image_size - offset,
        "last_compressed_source_address": f"0x{window_last:08X}",
        "minimum_linear_window_kib_from_0x08000000": (
            (window_last - CORTEX_FLASH_REGION_BASE + 1024) // 1024
        ),
        "source_is_contained_in_original_package": True,
    }


def _rom_bl_sites(payload: bytes, edition: str) -> list[str]:
    rows = find_calls(payload, [ROM_HELPER])[f"0x{ROM_HELPER:08X}"]
    sites = sorted({r["call_pc"] for r in rows})
    if sites != [EXPECTED_ROM_CALLS[edition]]:
        raise ValueError(f"{edition} ROM helper direct BL sites changed: {sites}")
    return sites


def _audit_v2(v2: bytes, v1: bytes | None) -> tuple[dict, dict]:
    stage = verify_reset_to_main(v2, V2, True)
    helper = verify_rom_helper(v2, v1)
    # The instruction audit does not check every word in the helper literal
    # pool; validate the ten AIR32 SDK-specific MMIO/ROM/UID pointers as well.
    for pc, expected in ROM_HELPER_LITERALS.items():
        if literal(v2, pc) != expected:
            raise ValueError(
                f"original AIR32-style helper literal changed at 0x{pc:08X}"
            )
    all_regions = inspect_regions(v2)
    data = inspect_tables(v2)
    if data["source_address"] != "0x08061A54":
        raise ValueError("V2 original high scatterload source has changed")
    if data["region_size"] != 7084:
        raise ValueError("V2 decompressed SRAM region size has changed")
    if data["decompressed_sha256"] != (
        "78b4cd40871079ecc1ceacf33f1379a8c76ea84a2b3b7155b98c4753d5ae7627"
    ):
        raise ValueError("V2 original compressed SRAM data no longer matches")
    source_address = int(data["source_address"], 16)
    consumed = data["compressed_bytes_consumed"]
    source = describe_source_span(len(v2), source_address, consumed)
    first_region = all_regions["descriptors"][0]
    if first_region["load_address"] != data["source_address"]:
        raise ValueError("scatterload table and compressed data disagree")

    start = source["source_package_offset_bytes"]
    source["compressed_source_sha256"] = hashlib.sha256(
        v2[start:start+consumed]
    ).hexdigest()
    v2_callers = _rom_bl_sites(v2, "v2")
    return {
        "reset_to_main": stage,
        "scatterload_source": source,
        "scatterload_region_count": len(all_regions["descriptors"]),
        "sram_restore": {
            "size_bytes": data["region_size"],
            "compressed_bytes_available": data["compressed_bytes_available"],
            "compressed_bytes_consumed": consumed,
            "unused_trailing_source_bytes": data["unused_trailing_source_bytes"],
            "decompressed_sha256": data["decompressed_sha256"],
        },
        "rom_helper_bl_sites": v2_callers,
        "air32_sdk_qspi_control_sites": {
            "helper_entry": f"0x{ROM_HELPER:08X}",
            "unlock_store_pc": f"0x{QSPI_UNLOCK_SITE:08X}",
            "restore_store_pc": f"0x{QSPI_RELOCK_SITE:08X}",
            "control_mmio": "0x4002228C",
            "sdk_name": "QSPI unlock / restore; not evidence of GT25Q16A XIP",
        },
    }, helper


def _audit_v1(v1: bytes, helper: dict) -> dict:
    v1_stage = verify_reset_to_main(v1, V1, False)
    result = {
        "verified_reset_to_main": v1_stage,
        "rom_helper_direct_bl_sites": _rom_bl_sites(v1, "v1"),
        "same_216_byte_rom_helper_as_v2": bool(
            helper["v1_v2_window_comparison"]["byte_for_byte_identical"]
        ),
    }
    if not result["same_216_byte_rom_helper_as_v2"]:
        raise ValueError("V1/V2 shared ROM helper code changed")
    return result


def analyze(v2: bytes, v1: bytes | None = None) -> dict:
    v2_report, helper = _audit_v2(v2, v1)
    v1_audit = _audit_v1(v1, helper) if v1 is not None else None
    return {
        "method": "decoded original firmware; static call sequence, no runtime execution",
        "v2": v2_report,
        "v1": v1_audit,
        "stage_order": [
            "0. Prior bootloader or mask ROM behavior unknown (not in .dat application)",
            "1. Reset veneer -> early clock-init routine",
            "2. ARM scatterload reads original compressed source at 0x08061A54 into SRAM",
            "3. Scatterload transfers to application main at 0x080340E0",
            "4. Main calls PLL wrapper -> AIR32-compatible helper at 0x08001260",
            "5. Helper uses 0x4002228C QSPI-labelled unlock and optional ROM callback",
        ],
        "hypotheses": {
            "ordinary_contiguous_program_flash": (
                "consistent with compressed source being part of the original upgrade payload; "
                "native on-chip capacity still not measured"
            ),
            "gt25q16a_external_nor_xip_alias": (
                "not established: no confirmed external chip-select, memory-mapping window, "
                "pre-scatterload mapper, bus trace or on-chip ROM implementation"
            ),
            "rom_or_bootloader_pre_mapped_flash_alias": (
                "possible but unverified: bootloader / mask-ROM source is not available"
            ),
            "air32_sdk_qspi_unlock_as_external_spi_nor_mapper": (
                "unsupported: the verified application-level unlock is reached only "
                "after the already completed scatterload on the known startup path"
            ),
        },
        "limitations": [
            "Direct BL xrefs use a halfword sweep: checked specific stock call sites but indirect calls may exist.",
            "The stage order assumes the verified Reset/scatterload/main path completes and does not prove actual boot completion.",
            "We have not identified the chip's hardware Flash mapping or internal Flash capacity.",
            "No negative result about other code paths, ROM-internal mapping or external NOR activity is claimed.",
            "The JLCPCB XL9951Q catalogue lists QFN64 marking/package only, not CPU/Flash/ROM.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("v2", type=Path)
    p.add_argument("--v1", type=Path)
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    report = analyze(
        decoded_payload(args.v2.read_bytes()),
        decoded_payload(args.v1.read_bytes()) if args.v1 else None,
    )
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        v = report["v2"]
        print("V2 scatterload source:", v["scatterload_source"])
        print("V2 ROM helper BL callsites:", v["rom_helper_bl_sites"])
        if report["v1"]:
            print("V1 ROM helper BL callsites:", report["v1"]["rom_helper_direct_bl_sites"])
        print("Conclusions:", report["hypotheses"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
