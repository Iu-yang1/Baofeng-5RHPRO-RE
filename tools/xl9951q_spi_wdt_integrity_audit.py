#!/usr/bin/env python3
"""Offline OEM SPI3 timeout, IWDG startup and NOR journal integrity audit.

This checks actual V1/V2 stock Thumb instruction sites, without connecting to
hardware, executing firmware, or claiming physical reset/write correctness.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from mcu_fingerprint import decoded_payload
from thumb_window import inspect_window
from thumb_callsites import find_calls
from xl9951q_journal_recovery_audit import STOCK, verify_recovery
from xl9951q_reset_nor_error_audit import audit_one as verify_reset_nor

BASE = 0x08001000
SPI3 = 0x40003C00
IWDG = 0x40003000

# Each record: Thumb PC, exact mnemonic, distinguishing operand string,
# optional literal pool value. Sites are verified from original disassembly.
SITES = {
    "v1": {
        "spi": (
            (0x080257A6,"ldr","r5, [pc",SPI3),
            (0x080257AE,"cmp","r4, #0xc8"),
            (0x080257B0,"bhi","#0x80257d2"),
            (0x080257B6,"bl","#0x8025752"),
            (0x080257C2,"bl","#0x8025764"),
            (0x080257CE,"cmp","r4, #0xc8"),
            (0x080257D0,"bls","#0x80257d6"),
            (0x080257D2,"movs","r0, #0"),
            (0x080257DA,"bl","#0x8025752"),
            (0x080257E4,"bl","#0x8025760"),
            (0x080257E8,"uxtb","r0, r0"),
            (0x080257EA,"pop","{r4, r5, r6, pc}"),
        ),
        "status": (
            (0x080030D6,"movs","r0, #5"),
            (0x080030D8,"bl","#0x80257a0"),
            (0x080030DC,"movs","r0, #0xff"),
            (0x080030DE,"bl","#0x80257a0"),
            (0x080030EA,"lsls","r0, r0, #0x1f"),
            (0x080030EC,"bne","#0x80030ce"),
            (0x080030EE,"pop","{r4, r5, r6, pc}"),
        ),
        "watchdog_driver": (
            (0x0800387C,"ldr","r1, [pc",IWDG),
            (0x0800387E,"movw","r0, #0xcccc"),
            (0x08003882,"str","r0, [r1]"),
            (0x0800388C,"ldr","r1, [pc",IWDG),
            (0x0800388E,"movw","r0, #0xaaaa"),
            (0x08003892,"str","r0, [r1]"),
            (0x0800389C,"ldr","r1, [pc",IWDG),
            (0x0800389E,"str","r0, [r1, #4]"),
            (0x080038A8,"ldr","r1, [pc",IWDG),
            (0x080038AA,"str","r0, [r1, #8]"),
            (0x080038B4,"ldr","r1, [pc",IWDG),
            (0x080038B6,"str","r0, [r1]"),
        ),
        "watchdog_setup": (
            (0x0800AB44,"movw","r0, #0x5555"),
            (0x0800AB48,"bl","#0x80038b4"),
            (0x0800AB4C,"cbz","r4, #0x800ab5a"),
            (0x0800AB4E,"movs","r0, #4"),
            (0x0800AB50,"bl","#0x800389c"),
            (0x0800AB54,"movw","r0, #0x7ff"),
            (0x0800AB5A,"movs","r0, #6"),
            (0x0800AB5C,"bl","#0x800389c"),
            (0x0800AB60,"movw","r0, #0xffff"),
            (0x0800AB64,"bl","#0x80038a8"),
            (0x0800AB68,"bl","#0x800388c"),
            (0x0800AB70,"b.w","#0x800387c"),
            (0x080130A4,"movs","r0, #1"),
            (0x080130A6,"bl","#0x800ab40"),
            (0x080111FE,"b.w","#0x80130a0"),
            (0x08027BF2,"bl","#0x80111f0"),
            (0x08027BFC,"bl","#0x800ab74"),
            (0x0800E07A,"bl","#0x800388c"),
        ),
        "spi_entry": 0x080257A0,
        "spi_end": 0x080257EC,
        "status_entry": 0x080030C8,
        "status_end": 0x080030F0,
        "watchdog_reload_helper": 0x0800388C,
        "watchdog_reload_callers": (0x0800AB68, 0x0800E07A),
        "watchdog_entry": 0x0800AB40,
        "watchdog_setup_call": 0x080130A6,
        "watchdog_feed_elsewhere": 0x0800E07A,
        "recovery_call": 0x08027BFC,
    },
    "v2": {
        "spi": (
            (0x0803181A,"ldr","r5, [pc",SPI3),
            (0x08031822,"cmp","r4, #0xc8"),
            (0x08031824,"bhi","#0x8031846"),
            (0x0803182A,"bl","#0x80317c6"),
            (0x08031836,"bl","#0x80317d8"),
            (0x08031842,"cmp","r4, #0xc8"),
            (0x08031844,"bls","#0x803184a"),
            (0x08031846,"movs","r0, #0"),
            (0x0803184E,"bl","#0x80317c6"),
            (0x08031858,"bl","#0x80317d4"),
            (0x0803185C,"uxtb","r0, r0"),
            (0x0803185E,"pop","{r4, r5, r6, pc}"),
        ),
        "status": (
            (0x08006BE6,"movs","r0, #5"),
            (0x08006BE8,"bl","#0x8031814"),
            (0x08006BEC,"movs","r0, #0xff"),
            (0x08006BEE,"bl","#0x8031814"),
            (0x08006BFA,"lsls","r0, r0, #0x1f"),
            (0x08006BFC,"bne","#0x8006bde"),
            (0x08006BFE,"pop","{r4, r5, r6, pc}"),
        ),
        "watchdog_driver": (
            (0x0800738C,"ldr","r1, [pc",IWDG),
            (0x0800738E,"movw","r0, #0xcccc"),
            (0x08007392,"str","r0, [r1]"),
            (0x0800739C,"ldr","r1, [pc",IWDG),
            (0x0800739E,"movw","r0, #0xaaaa"),
            (0x080073A2,"str","r0, [r1]"),
            (0x080073AC,"ldr","r1, [pc",IWDG),
            (0x080073AE,"str","r0, [r1, #4]"),
            (0x080073B8,"ldr","r1, [pc",IWDG),
            (0x080073BA,"str","r0, [r1, #8]"),
            (0x080073C4,"ldr","r1, [pc",IWDG),
            (0x080073C6,"str","r0, [r1]"),
        ),
        "watchdog_setup": (
            (0x080103D0,"movw","r0, #0x5555"),
            (0x080103D4,"bl","#0x80073c4"),
            (0x080103D8,"cbz","r4, #0x80103e6"),
            (0x080103DA,"movs","r0, #4"),
            (0x080103DC,"bl","#0x80073ac"),
            (0x080103E0,"movw","r0, #0x7ff"),
            (0x080103E6,"movs","r0, #6"),
            (0x080103E8,"bl","#0x80073ac"),
            (0x080103EC,"movw","r0, #0xffff"),
            (0x080103F0,"bl","#0x80073b8"),
            (0x080103F4,"bl","#0x800739c"),
            (0x080103FC,"b.w","#0x800738c"),
            (0x080193EC,"movs","r0, #1"),
            (0x080193EE,"bl","#0x80103cc"),
            (0x080173EA,"b.w","#0x80193e8"),
            (0x080340EA,"bl","#0x80173dc"),
            (0x080340F4,"bl","#0x8010400"),
            (0x08013C36,"bl","#0x800739c"),
        ),
        "spi_entry": 0x08031814,
        "spi_end": 0x08031860,
        "status_entry": 0x08006BD8,
        "status_end": 0x08006C00,
        "watchdog_reload_helper": 0x0800739C,
        "watchdog_reload_callers": (0x080103F4, 0x08013C36),
        "watchdog_entry": 0x080103CC,
        "watchdog_setup_call": 0x080193EE,
        "watchdog_feed_elsewhere": 0x08013C36,
        "recovery_call": 0x080340F4,
    },
}


def check_sites(payload: bytes, edition: str) -> dict:
    evidence = SITES[edition]
    counts = {}
    for name in ("spi", "status", "watchdog_driver", "watchdog_setup"):
        for row in evidence[name]:
            pc, mnemonic, operand, *literal = row
            items = inspect_window(payload, pc, pc + 4)
            actual = items[0] if items else None
            if (actual is None or actual["mnemonic"] != mnemonic
                    or operand not in actual["operands"]):
                raise ValueError(f"{edition}/{name} incorrect Thumb at 0x{pc:08X}: {actual}")
            if literal and actual.get("literal_value") != f"0x{literal[0]:08X}":
                raise ValueError(f"{edition}/{name} unexpected literal at 0x{pc:08X}")
        counts[name] = len(evidence[name])
    return counts



def check_callers(payload: bytes, edition: str) -> dict:
    info = SITES[edition]
    lookup = find_calls(
        payload, [info["spi_entry"], info["watchdog_reload_helper"]]
    )
    spi = lookup[f"0x{info['spi_entry']:08X}"]
    wdt = lookup[f"0x{info['watchdog_reload_helper']:08X}"]
    expected_wdt = [f"0x{x:08X}" for x in info["watchdog_reload_callers"]]
    actual_wdt = sorted(r["call_pc"] for r in wdt)
    if actual_wdt != sorted(expected_wdt):
        raise ValueError(f"{edition}: watchdog reload caller list changed: {actual_wdt}")
    if len(spi) != 26:
        raise ValueError(f"{edition}: SPI byte exchange call inventory changed: {len(spi)}")

    nor = inspect_window(payload, info["status_entry"], info["status_end"])
    status_bls = [r["pc"] for r in nor if r["mnemonic"] == "bl"]
    expected_spi_status = [
        f"0x{row[0]:08X}" for row in info["status"] if row[1] == "bl"
    ]
    if status_bls != expected_spi_status:
        raise ValueError(f"{edition}: NOR RDSR calls unexpected target code")
    return {
        "spi_byte_exchange_direct_calls_in_stock": len(spi),
        "watchdog_reload_direct_calls": actual_wdt,
        "rdsr_only_calls_spi_byte_exchange": True,
    }


def rdsr_outcome(status_byte: int, transfer_timed_out: bool = False) -> dict:
    """Apply observed RDSR bit0 branch to a single byte exchange result."""
    if not 0 <= status_byte <= 255:
        raise ValueError("RDSR byte must be 8-bit")
    received = 0 if transfer_timed_out else status_byte
    return {
        "spi_result_byte": received,
        "busy_branch_taken": (received & 1) != 0,
        "will_leave_busy_wait": (received & 1) == 0,
        "communication_failure_indistinguishable_from_idle": transfer_timed_out,
    }


def analyze_one(payload: bytes, edition: str) -> dict:
    site_counts = check_sites(payload, edition)
    callers = check_callers(payload, edition)
    reset = verify_reset_nor(payload, edition)
    journal = verify_recovery(payload, edition)
    info = SITES[edition]
    return {
        "reset_vector": reset["reset"],
        "watchdog_config_is_on_main_pre_recovery_path": True,
        "watchdog_mode_one": {
            "wrapper_entry": f"0x{info['watchdog_entry']:08X}",
            "callsite": f"0x{info['watchdog_setup_call']:08X}",
            "prescaler_register_write": 4,
            "reload_register_write": "0x07FF",
            "unlock_key": "0x5555",
            "reload_key": "0xAAAA",
            "start_key": "0xCCCC",
        },
        "watchdog_mode_zero": {
            "prescaler_register_write": 6,
            "reload_register_write": "0xFFFF",
            "effective_reload_width_unknown_for_XL9951Q": True,
        },
        "spi3_exchange": {
            "entry": f"0x{info['spi_entry']:08X}",
            "spi_register_base": f"0x{SPI3:08X}",
            "poll_counter_compare": 200,
            "returns_zero_on_tx_or_rx_poll_timeout": True,
            "returns_received_byte_on_success": True,
            "timeout_result_ambiguous_with_valid_zero_byte": True,
        },
        "nor_rdsr": {
            "entry": f"0x{info['status_entry']:08X}",
            "opcode": "0x05",
            "busy_mask": 1,
            "status_exchange_timeout_can_look_like_wip_clear": True,
            "separate_watchdog_feed_in_status_loop": False,
            "no_whole_sector_post_restore_compare": True,
        },
        "recovery": {
            "entry": journal["recovery_entry"],
            "main_direct_call": f"0x{info['recovery_call']:08X}",
            "backup_address": journal["recovery_backup"]["nor_offset"],
            "journal_address": journal["journal_metadata_read"]["address"],
            "restore_then_clear_without_confirmed_writeback": True,
            "local_backup_crc_verified": False,
        },
        "additional_watchdog_feed_site": f"0x{info['watchdog_feed_elsewhere']:08X}",
        "verified_sites": site_counts,
        "call_inventory": callers,
        "limitations": [
            "Startup path assumes successful return from earlier functions, not observed hardware boot.",
            "IWDG write sequence is proven, not actual LSI frequency, timeout seconds, option bytes or reset result.",
            "No watchdog reload call occurs inside the inspected RDSR busy-loop body.",
            "No exhaustive global search for every other possible checksum or unobserved ROM implementation.",
            "No real device, proprietary bootloader, flash program, power-cut, or hardware SPI trace.",
        ],
    }


def analyze(v1: bytes, v2: bytes) -> dict:
    r1, r2 = analyze_one(v1, "v1"), analyze_one(v2, "v2")
    a = SITES["v1"]
    b = SITES["v2"]
    raw1 = v1[a["spi_entry"]-BASE:a["spi_end"]-BASE]
    raw2 = v2[b["spi_entry"]-BASE:b["spi_end"]-BASE]
    return {
        "method": "read-only original binary Thumb disassembly and known verified callsites",
        "versions": {"v1": r1, "v2": r2},
        "spi_exchange_window_byte_identical": raw1 == raw2,
        "spi_exchange_window_sha256": {
            "v1": hashlib.sha256(raw1).hexdigest(),
            "v2": hashlib.sha256(raw2).hexdigest(),
        },
        "emulated_hardware": False,
        "conclusion": (
            "SPI3 byte-transfer timeout returns a zero indistinguishable from a valid status byte; "
            "the RDSR WIP loop may accept that error as idle. Both applications configure IWDG "
            "before journal replay under normal startup call returns, but power-loss behavior "
            "and watchdog timing have not been hardware validated."
        ),
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--json", action="store_true")
    args = p.parse_args()
    images = {
        version: decoded_payload(Path(info["file"]).read_bytes())
        for version, info in STOCK.items()
    }
    result = analyze(images["v1"], images["v2"])
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        for version, row in result["versions"].items():
            print(version, row["spi3_exchange"]["entry"],
                  row["watchdog_mode_one"]["callsite"],
                  row["nor_rdsr"]["entry"],
                  row["verified_sites"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
