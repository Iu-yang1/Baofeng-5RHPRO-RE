#!/usr/bin/env python3
"""Interpret read-only ARM/Artery debug IDs using official AT32F403A/407 PID table.

Input values must be obtained separately from an actual SWD read. No hardware,
SWD, bootloader, GPIO, or Flash write capability exists in this tool.

Do not use the UID registers as a public report: unique per-device identifiers
are unnecessary for the model identification.
"""

from __future__ import annotations

import argparse
import json

# PID -> (model, known Flash KiB, package). Source:
# RM_AT32F403A_407_EN_V2.02, section 27.4.1, table DEBUG device ID.
PART_IDS = {
    0x700502CE: ("AT32F403ARET7", 512, "LQFP64"),
    0x70050345: ("AT32F403ARGT7", 1024, "LQFP64"),
    0x700502D2: ("AT32F407RET7", 512, "LQFP64"),
    0x7005034C: ("AT32F407RGT7", 1024, "LQFP64"),
}
PROJECT_TYPES = {
    0x02: "AT32F403",
    0x04: "AT32F413",
    0x05: "AT32F415",
    0x07: "AT32F403A",
    0x08: "AT32F407",
    0x09: "AT32F421",
}
PART_CORE_IDS = {
    0xC20: "Cortex-M0",
    0xC23: "Cortex-M3",
    0xC24: "Cortex-M4",
    0xC27: "Cortex-M7",
}


def inspect(cpuid: int | None, debug_id: int | None,
            project_code: int | None) -> dict:
    if any(x is not None and not 0 <= x <= 0xFFFFFFFF
           for x in (cpuid, debug_id, project_code)):
        raise ValueError("expected unsigned 32-bit values")
    core = PART_CORE_IDS.get((cpuid >> 4) & 0xFFF, "unknown") if cpuid is not None else None
    part = PART_IDS.get(debug_id) if debug_id is not None else None
    project = (PROJECT_TYPES.get(project_code & 0xFF)
               if project_code is not None else None)
    family = part[0].split("R")[0] if part else None
    consistent = None
    if part is not None and project is not None:
        consistent = family == project
    return {
        "cpuid": f"0x{cpuid:08X}" if cpuid is not None else None,
        "core_by_cpuid": core,
        "at32_debug_idcode": f"0x{debug_id:08X}" if debug_id is not None else None,
        "match_in_official_pid_table": (
            {"part": part[0], "flash_kib": part[1], "package": part[2]}
            if part else None
        ),
        "artery_project_code_byte": (
            f"0x{project_code & 0xFF:02X}" if project_code is not None else None
        ),
        "artery_project_family_hint": project,
        "pid_project_family_consistent": consistent,
        "interpretation": (
            "Unknown PID must NOT be interpreted as non-Artery or counterfeit. "
            "The official table here covers only selected AT32F403A/407 LQFP64 parts. "
            "CPUID alone identifies the ARM core, not the MCU. "
            "No hardware access was performed."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cpuid", type=lambda x: int(x, 0))
    parser.add_argument("--debug-id", type=lambda x: int(x, 0))
    parser.add_argument("--project-byte", type=lambda x: int(x, 0))
    args = parser.parse_args(argv)
    if all(x is None for x in (args.cpuid, args.debug_id, args.project_byte)):
        parser.error("pass at least one actual device ID value")
    print(json.dumps(
        inspect(args.cpuid, args.debug_id, args.project_byte), indent=2
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
