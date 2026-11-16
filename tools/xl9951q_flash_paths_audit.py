#!/usr/bin/env python3
"""Read-only XL9951Q stock application Flash-driver and host-upgrade audit.

Observes OEM firmware Thumb instructions, updater source and archived PE
metadata only. Never executes the updater or touches a serial device.
"""
from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
import struct

from mcu_fingerprint import decoded_payload
from thumb_callsites import find_calls
from thumb_window import inspect_window

BASE = 0x08001000
FLASH_BASE = 0x40022000
SCRATCH_ADDRESS = 0x0807F800
CLUSTER_SIZE = 0xDC
V1_DRIVER = 0x08002E70
V2_DRIVER = 0x08006980

STOCK = {
    "v1": {"path": "firmware/BF_5RH_501_v1_1_04.dat",
           "base": V1_DRIVER,
           "callers": {
               0x08002E70: ("0x08007C70", "0x08012DB6"),
               0x08002EE4: ("0x08012DE4", "0x08012E72"),
               0x08002F34: ("0x08007C6A", "0x08012DB0")},
           "scratch_literals": (0x08007C7C, 0x0800AF7C, 0x08012E80)},
    "v2": {"path": "firmware/BF_5RH_501_v2_0_9.dat",
           "base": V2_DRIVER,
           "callers": {
               0x08006980: ("0x0800D310", "0x080190FE"),
               0x080069F4: ("0x0801912C", "0x080191BA"),
               0x08006A44: ("0x0800D30A", "0x080190F8")},
           "scratch_literals": (0x0800D31C, 0x08010810, 0x080191C8)},
}


def word(payload: bytes, address: int) -> int:
    offset = address - BASE
    if offset < 0 or offset + 4 > len(payload):
        raise ValueError(f"address out of package: 0x{address:08X}")
    return struct.unpack_from("<I", payload, offset)[0]


def _require(rows: list[dict], address: int, mnemonic: str,
             operands_contain: str = "") -> dict:
    row = next((r for r in rows if r["pc"] == f"0x{address:08X}"), None)
    if (row is None or row["mnemonic"].split(".")[0] != mnemonic
            or operands_contain not in row["operands"]):
        raise ValueError(f"Thumb evidence mismatch at 0x{address:08X}: {row}")
    return row


def audit_flash_driver(payload: bytes, edition: str) -> dict:
    spec = STOCK[edition]
    base = spec["base"]
    rows = inspect_window(payload, base, base + CLUSTER_SIZE)
    # PC-relative literals must still be referenced by actual instructions.
    pool_offsets = (0x38, 0x60, 0x70, 0xC0, 0xD4)
    for offset in pool_offsets:
        if word(payload, base + offset) != FLASH_BASE:
            raise ValueError(f"{edition}: FLASH literal pool changed at +0x{offset:X}")
    points = (
        (0x12, "ldr", "r4, [pc"),   # flash base from +0x38
        (0x16, "ldr", "r0, [r4, #0x10]"),
        (0x1A, "str", "r0, [r4, #0x10]"),
        (0x1C, "str", "r5, [r4, #0x14]"),
        (0x24, "str", "r0, [r4, #0x10]"),
        (0x3C, "ldr", "r1, [pc"),   # FLASH_SR reader
        (0x44, "ldr", "r2, [r1, #0xc]"),
        (0x66, "ldr", "r1, [r0, #0x10]"),
        (0x6C, "str", "r1, [r0, #0x10]"),
        (0x8E, "ldr", "r4, [pc"),   # PG programming
        (0x96, "str", "r0, [r4, #0x10]"),
        (0x98, "strh", "r5, [r6]"),
        (0xAE, "strh", "r0, [r6]"),
        (0xBA, "str", "r1, [r4, #0x10]"),
        (0xC4, "ldr", "r0, [pc"),
        (0xC8, "str", "r1, [r0, #4]"),
        (0xCC, "str", "r1, [r0, #4]"),
    )
    verified = [_require(rows, base + offset, name, operands)
                for offset, name, operands in points]
    # Under STM32F1 register conventions, PER=bit1, STRT=bit6,
    # PG=bit0, LOCK=bit7. Do not promote them to XL9951Q measurements.
    for offset, mnemonic, fragment in (
        (0x16, "ldr", "#0x10"),
        (0x16 + 2, "orr", "#2"),
        (0x20, "orr", "#0x40"),
        (0x92, "orr", "#1"),
        (0x64, "ldr", "[pc"),
        (0x68, "orr", "#0x80"),
    ):
        # Flash byte-identical code in both generations is additionally
        # checked by analyze(). Some points overlap preceding checks.
        _require(rows, base + offset, mnemonic, fragment)
    if word(payload, base + 0xD0) != 0x45670123:
        raise ValueError("FLASH key 1 literal changed")
    if word(payload, base + 0xD8) != 0xCDEF89AB:
        raise ValueError("FLASH key 2 literal changed")
    callers = find_calls(payload, list(spec["callers"]))
    for target, expected in spec["callers"].items():
        actual = tuple(sorted(x["call_pc"] for x in callers[f"0x{target:08X}"]))
        if actual != expected:
            raise ValueError(f"{edition}: unexpected direct calls to 0x{target:08X}: {actual}")
    for pc in spec["scratch_literals"]:
        if word(payload, pc) != SCRATCH_ADDRESS:
            raise ValueError(f"{edition}: high Flash scratch candidate changed at 0x{pc:08X}")
    return {
        "cluster_range": [f"0x{base:08X}", f"0x{base + CLUSTER_SIZE:08X}"],
        "validated_thumb_instructions": len(verified) + 6,
        "flash_controller_literals": [f"0x{base + off:08X}" for off in pool_offsets],
        "flash_controller_base": f"0x{FLASH_BASE:08X}",
        "firmware_functions": {
            "erase_candidate": f"0x{base:08X}",
            "status_wait_candidate": f"0x{base + 0x3C:08X}",
            "program_two_halfwords": f"0x{base + 0x74:08X}",
            "unlock_key_writer": f"0x{base + 0xC4:08X}",
        },
        "direct_bl_callsites": callers,
        "scratch_address_literals": [f"0x{x:08X}" for x in spec["scratch_literals"]],
        "candidate_flash_operation_target": f"0x{SCRATCH_ADDRESS:08X}",
    }


def _literal_assignments(source: str) -> dict:
    result = {}
    for statement in ast.parse(source).body:
        if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
            continue
        targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
        if len(targets) != 1 or not isinstance(targets[0], ast.Name):
            continue
        name = targets[0].id
        value = statement.value
        if isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id == "bytes":
            if len(value.args) == 1:
                try:
                    result[name] = bytes(ast.literal_eval(value.args[0]))
                except (TypeError, ValueError):
                    pass
        else:
            try:
                result[name] = ast.literal_eval(value)
            except (TypeError, ValueError):
                pass
    return result


def audit_updater(source: str) -> dict:
    values = _literal_assignments(source)
    expected = {
        "EXPECTED_FLASH_SIZE": 524288, "BLOCK_SIZE": 1024, "HEADER_SIZE": 80,
        "CMD_DOWNLOAD": b"DOWNLOAD", "CMD_UPDATE": b"#UPDATE?",
        "CMD_NEW_HARDWARE": b"V2_00_00", "CMD_PRG": b"PROGRAM1",
        "CMD_ACK": b"ACK",
    }
    for name, value in expected.items():
        if values.get(name) != value:
            raise ValueError(f"host updater constant changed: {name}")
    commands = values.get("CMD_FLASH")
    if not isinstance(commands, list) or len(commands) < 2:
        raise ValueError("host updater FLASH command list unavailable")
    # List elements are bytes([...]) calls; evaluate these data-only AST nodes.
    tree = ast.parse(source)
    nodes = [s.value for s in tree.body if isinstance(s, ast.Assign)
             and len(s.targets) == 1 and isinstance(s.targets[0], ast.Name)
             and s.targets[0].id == "CMD_FLASH"]
    if len(nodes) != 1 or not isinstance(nodes[0], ast.List):
        raise ValueError("FLASH command table not a list literal")
    commands = [bytes(ast.literal_eval(item.args[0]))
                for item in nodes[0].elts if isinstance(item, ast.Call)
                and isinstance(item.func, ast.Name) and item.func.id == "bytes"]
    if len(commands) != 7 or commands[1] != b"F-ERASE\xff":
        raise ValueError("FLASH command opcode table changed")
    # Require observed frame-assembly and checksum expressions to remain in
    # the source, rather than reporting inferred byte ordering unconditionally.
    anchors = (
        "data[8:16] = bytes([40, 6, 136, 25, 19, 3, 24, 32])",
        "data = FLASH[curTimes:curTimes+realLen]",
        "realData[0] = (dataAddr >> 24) & 0xFF",
        "realData[3] = dataAddr & 0xFF",
        "realData[4] = 0",
        "ser.write(realData[:5])",
        "ser.write(realData[5:])",
        "check_sum += sum(data)",
        "data[0:3] = b'END'",
        "data[3:5] = b'\\xFF\\xFF'",
    )
    for line in anchors:
        if line not in source:
            raise ValueError(f"host updater frame construction changed: {line}")
    return {
        "source": "fw_updater.py (static source AST/expressions; not executed)",
        "handshake": {
            "request_ascii": "DOWNLOAD",
            "v1_response_ascii": "#UPDATE?",
            "v2_response_ascii": "V2_00_00",
            "ack_bytes_used": "41 (single ASCII 'A', not full 'ACK')",
        },
        "erase_command_hex": (commands[1] + bytes([40, 6, 136, 25, 19, 3, 24, 32])).hex(),
        "erase_trailer_meaning": "unknown opaque eight-byte sequence, not a verified sector size",
        "program_command_ascii": "PROGRAM1",
        "data": {
            "block_size_bytes": values["BLOCK_SIZE"],
            "wire_block_header": "4-byte big-endian relative dataAddr + one 0x00 byte",
            "wire_payload": "original .dat bytes after 0x50-byte package header; XOR not removed by host",
            "per_block_response": "one ASCII 'A' byte",
            "footer": "END + FFFF + four-byte big-endian additive sum of transmitted payload",
        },
        "host_declared_max_bytes": values["EXPECTED_FLASH_SIZE"],
        "host_limit_is_physical_flash_size": False,
        "absolute_mcu_destination_from_host_source": "not specified; bootloader controls mapping",
    }


def analyze(firmware: dict[str, bytes], updater_source: str,
            upgrade_tool: bytes | None = None) -> dict:
    v1 = firmware["v1"]
    v2 = firmware["v2"]
    a = v1[V1_DRIVER - BASE:V1_DRIVER - BASE + CLUSTER_SIZE]
    b = v2[V2_DRIVER - BASE:V2_DRIVER - BASE + CLUSTER_SIZE]
    if len(a) != CLUSTER_SIZE or a != b:
        raise ValueError("V1/V2 original Flash-driver code differs")
    versions = {}
    for edition, payload in firmware.items():
        evidence = audit_flash_driver(payload, edition)
        evidence["package_payload_bytes"] = len(payload)
        evidence["hypothetical_load_end_exclusive"] = f"0x{BASE + len(payload):08X}"
        evidence["host_block_count"] = (len(payload) + 1023) // 1024
        versions[edition] = evidence
    # V2 application caller uses 0x1000 as a copy/iteration unit. This is not
    # a proof that the underlying physical Flash has 4KiB erase pages.
    caller_rows = inspect_window(v2, 0x080190E0, 0x080191C6)
    for pc, mnemonic, operand in (
        (0x080190F4, "lsr", "#0xc"),
        (0x08019102, "mov", "#0x1000"),
        (0x08019106, "lsl", "#0xc"),
        (0x0801910E, "mov", "r0, r4"),
        (0x0801912C, "bl", "#0x80069f4"),
    ):
        _require(caller_rows, pc, mnemonic, operand)
    pe = None
    if upgrade_tool is not None:
        markers = ("CMD_DOWNLOAD", "CMD_FLASH", "CMD_FLASH_CO",
                   "START_ADDR", "UpdateFirmware")
        pe = {
            "file": "UpgradeTool/bin/Release/net20/Radio.exe",
            "length_bytes": len(upgrade_tool),
            "ascii_metadata_token_offsets": {
                name: upgrade_tool.index(name.encode("ascii"))
                for name in markers if name.encode("ascii") in upgrade_tool
            },
            "limitations": "PE metadata names are not proof of command semantics; IL not audited",
        }
    return {
        "mode": "read-only archived stock binaries + static host Python/PE metadata",
        "verified_v1_v2_flash_driver_identical_bytes": CLUSTER_SIZE,
        "versions": versions,
        "v2_high_flash_application_caller": {
            "entry": "0x080190E0",
            "copy_or_iteration_unit_bytes": 0x1000,
            "high_address_scratch_candidate": "0x0807F800",
            "physical_page_size_confirmed": False,
        },
        "host_protocol": audit_updater(updater_source),
        "oem_upgrader_pe": pe,
        "limits": [
            "The .dat decoded payload is modeled at 0x08001000; it does not contain the preceding 0x08000000..0x08000FFF bootloader.",
            "The identified erase/program code is in the *application* image, not the unobserved ROM bootloader.",
            "The high 0x0807F800 Flash address is a code reference, not a hardware readback or measured capacity.",
            "A 4KiB transfer/iteration unit cannot by itself establish the physical Flash erase page size.",
            "Disassembly and literal searches cannot prove runtime execution of a path or identify the silicon vendor.",
            "No serial port, SWD device, firmware upload, Flash erase or write was attempted.",
        ],
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--json", action="store_true")
    p.add_argument("--updater", type=Path, default=Path("fw_updater.py"))
    p.add_argument("--upgrade-tool", type=Path,
                   default=Path("UpgradeTool/bin/Release/net20/Radio.exe"))
    args = p.parse_args()
    firmware = {k: decoded_payload(Path(spec["path"]).read_bytes())
                for k, spec in STOCK.items()}
    report = analyze(firmware, args.updater.read_text(encoding="utf-8"),
                     args.upgrade_tool.read_bytes())
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print("V1/V2 Flash driver code identical:", CLUSTER_SIZE, "bytes")
        for k, v in report["versions"].items():
            print(k, "Flash functions:", v["firmware_functions"],
                  "high scratch references:", v["scratch_address_literals"])
        print("Host command:", report["host_protocol"]["erase_command_hex"])
        print("Physical Flash size and bootloader erase geometry: UNKNOWN")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
