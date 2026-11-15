#!/usr/bin/env python3
"""Offline-only decoder of manufacturer-published Cortex/MCU identification fields.

Accepts independently obtained read-only register values. Never connects to
hardware, reads memory, sends SWD commands, prints a full UID word, or writes
Flash/option bytes. A pattern match is identification *evidence*, not proof.
"""

from __future__ import annotations

import argparse
import json
from at32_readonly_id_decode import PART_IDS, PROJECT_TYPES

AIR32_UID_LOW_PATTERNS = {
    0x1A5A5BB: "AIR32F103CBT6",
    0x1A5A5CC: "AIR32F103CCT6",
    0x1A6A5CD: "AIR32F103RPT6",
    0x1A8A6DD: "AIR32F103VET6",
    0x1A8A6ED: "AIR32F103VGT6",
    0x1A9A6DD: "AIR32F103ZET6",
}
ARM_PARTS = {
    0xC20: "Cortex-M0",
    0xC60: "Cortex-M0+",
    0xC23: "Cortex-M3",
    0xC24: "Cortex-M4",
    0xC27: "Cortex-M7",
}
MIN_USED_FLASH_ADDRESS = 0x08061A54
FLASH_BASE = 0x08000000
FLASH_REQUIRED_KIB = (MIN_USED_FLASH_ADDRESS - FLASH_BASE + 4 + 1023) // 1024


def fmt32(value: int | None) -> str | None:
    return f"0x{value:08X}" if value is not None else None


def require_unsigned(name: str, value: int | None, width: int = 32) -> None:
    if value is not None and not (0 <= value < (1 << width)):
        raise ValueError(f"{name} must be an unsigned {width}-bit value")


def decode_air32_uid(uid_first_word: int | None) -> dict:
    uid_pattern = (uid_first_word >> 4) if uid_first_word is not None else None
    air_model = AIR32_UID_LOW_PATTERNS.get(uid_pattern)
    # Only report bits that classify the family, never the unique 32-bit UID.
    air = {
        "uid_first_word_provided": uid_first_word is not None,
        "uid_high_byte": (f"0x{uid_first_word >> 24:02X}"
                          if uid_first_word is not None else None),
        "matches_documented_air32_uid_pattern": air_model,
        "interpretation": (
            "Only the six LuatOS-documented 0x1A... patterns are recognized. "
            "A match supports an AIR32-compatible ID scheme; custom markings "
            "and other chips are not ruled out. Unknown does not mean non-AIR32."
        ),
    }
    return air


def decode_flash_size(flash_size_halfword: int | None) -> dict:
    size = flash_size_halfword
    flash = {
        "reported_flash_size_kib": size if size not in (None, 0, 0xFFFF) else None,
        "required_readable_address": fmt32(MIN_USED_FLASH_ADDRESS),
        "minimum_contiguous_flash_window_kib": FLASH_REQUIRED_KIB,
        "meets_firmware_address_requirement": (
            size >= FLASH_REQUIRED_KIB if size not in (None, 0, 0xFFFF) else None
        ),
        "meaning": (
            "Lower 16 bits interpreted as KiB under ST/Artery F_SIZE layout; "
            "readable address range may be mapped or aliased and does not, "
            "alone, prove native internal Flash capacity."
        ),
    }
    return flash


def decode_arm_cpuid(cpuid: int | None) -> dict:
    core_part = (cpuid >> 4) & 0xFFF if cpuid is not None else None
    core = {
        "cpuid": fmt32(cpuid),
        "implementer": (f"0x{cpuid >> 24:02X}" if cpuid is not None else None),
        "partno": (f"0x{core_part:03X}" if core_part is not None else None),
        "core_name": ARM_PARTS.get(core_part),
        "variant": (cpuid >> 20) & 0xF if cpuid is not None else None,
        "revision": cpuid & 0xF if cpuid is not None else None,
        "not_the_silicon_vendor": True,
    }
    return core


def decode_artery_ids(debug_id: int | None, project_byte: int | None) -> dict:
    at_part = PART_IDS.get(debug_id)
    project = PROJECT_TYPES.get(project_byte)
    expected_project = (
        0x07 if at_part and "F403A" in at_part[0] else
        0x08 if at_part and "F407" in at_part[0] else None
    )
    artery = {
        "debug_idcode": fmt32(debug_id),
        "pid_table_match": ({"model": at_part[0], "flash_kib": at_part[1],
                             "package": at_part[2]} if at_part else None),
        "project_id_byte": (f"0x{project_byte:02X}" if project_byte is not None else None),
        "project_family": project,
        "pid_and_project_consistent": (
            expected_project == project_byte
            if expected_project is not None and project_byte is not None else None
        ),
        "interpretation": (
            "Only selected AT32F403A/407 LQFP64 PIDs from Artery's official "
            "DEBUG_IDCODE table are mapped; unmatched PID is inconclusive. "
            "0x1FFFF7F3, not UID[31:24], carries the Artery series ID."
        ),
    }
    return artery


def decode_swd_dpidr(dpidr: int | None) -> dict:
    dp = {
        "dpidr": fmt32(dpidr),
        "manufacturer_jedec_11bit": (f"0x{(dpidr >> 1) & 0x7FF:03X}"
                                    if dpidr is not None else None),
        "manufacturer_is_arm": (((dpidr >> 1) & 0x7FF) == 0x23B
                                if dpidr is not None else None),
        "debug_port_partno": (f"0x{(dpidr >> 20) & 0xFF:02X}"
                              if dpidr is not None else None),
        "dp_architecture_version": (dpidr >> 12) & 0xF if dpidr is not None else None,
        "is_swd_dp_register_not_mem32": True,
        "meaning": "The SW-DP designer is not the manufacturer of the target MCU.",
    }
    return dp


def interpret(
    *, uid_first_word: int | None = None,
    flash_size_halfword: int | None = None,
    cpuid: int | None = None,
    debug_id: int | None = None,
    project_byte: int | None = None,
    dpidr: int | None = None,
) -> dict:
    """Interpret independent observations without fabricating any live read."""
    for name, value, bits in (
        ("uid_first_word", uid_first_word, 32),
        ("flash_size_halfword", flash_size_halfword, 16),
        ("cpuid", cpuid, 32),
        ("debug_id", debug_id, 32),
        ("project_byte", project_byte, 8),
        ("dpidr", dpidr, 32),
    ):
        require_unsigned(name, value, bits)

    air = decode_air32_uid(uid_first_word)
    flash = decode_flash_size(flash_size_halfword)
    core = decode_arm_cpuid(cpuid)
    artery = decode_artery_ids(debug_id, project_byte)
    dp = decode_swd_dpidr(dpidr)

    limits = [
        "No device was accessed and no actual register values were collected.",
        "A matching UID pattern is vendor-defined identification evidence, not a cryptographic proof.",
        "CPUID and SW-DP DPIDR identify ARM IP, not the MCU brand.",
        "Do not interpret a missing address read or all-ones/all-zeros as an actual valid chip ID.",
        "No external Flash, ROM function body, UID, SWD access protection, or on-board data was dumped.",
    ]
    if core["core_name"] == "Cortex-M3" and at_part:
        limits.append("An AT32F403A/407 PID with Cortex-M3 conflicts with its published Cortex-M4F core.")
    if core["core_name"] == "Cortex-M4" and air_model:
        limits.append("An AIR32F103 UID pattern with Cortex-M4 conflicts with the published Cortex-M3 core.")
    if flash["meets_firmware_address_requirement"] is False:
        limits.append("Reported capacity is smaller than the stock startup-readable high Flash address; verify mapping, aliases and that the read is genuine.")
    return {
        "air32_uid_family_pattern": air,
        "flash_capacity": flash,
        "arm_cpuid": core,
        "artery_device_id": artery,
        "swd_dp_id": dp,
        "limits": limits,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--uid-first-word", type=lambda s: int(s, 0),
                   help="32-bit word read at 0x1FFFF7E8; full UID is NEVER echoed")
    p.add_argument("--flash-size-halfword", type=lambda s: int(s, 0),
                   help="16-bit value read at 0x1FFFF7E0")
    p.add_argument("--cpuid", type=lambda s: int(s, 0), help="SCB CPUID at 0xE000ED00")
    p.add_argument("--debug-id", type=lambda s: int(s, 0),
                   help="vendor-specific DEBUG_IDCODE at 0xE0042000")
    p.add_argument("--project-byte", type=lambda s: int(s, 0),
                   help="Artery Series/Project ID at 0x1FFFF7F3")
    p.add_argument("--dpidr", type=lambda s: int(s, 0),
                   help="DP read via SWD protocol, NOT a CPU-mapped mem32 address")
    a = p.parse_args(argv)
    if all(value is None for value in vars(a).values()):
        p.error("provide one or more actual read-only register values")
    print(json.dumps(interpret(
        uid_first_word=a.uid_first_word,
        flash_size_halfword=a.flash_size_halfword,
        cpuid=a.cpuid,
        debug_id=a.debug_id,
        project_byte=a.project_byte,
        dpidr=a.dpidr,
    ), indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
