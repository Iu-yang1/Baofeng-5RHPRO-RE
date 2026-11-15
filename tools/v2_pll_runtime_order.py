#!/usr/bin/env python3
"""Reconstruct V1/V2 Reset -> main -> PLL -> USART/TIM paths from original bytes.

This is an offline *control-flow evidence* graph, not an execution trace.
Branches, ROM outcome, and peripheral register state are not measured.
"""

from __future__ import annotations

import argparse
from collections import deque
import json
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN, CS_GRP_JUMP
from capstone.arm import ARM_OP_IMM
from mcu_fingerprint import decoded_payload
from thumb_window import inspect_window
from v2_bootrom_dispatch import require as assert_ins
from v2_clock_tree_model import analyze as clock_analyze
from usart_clock_callers import analyze_callers as usart_analyze, predict_brr16
from timer_clock_callers import analyze_callers as timer_analyze

BASE = 0x08001000
V1 = {
    "reset": 0x0800123C, "clock_reset": 0x080262A8, # reset implementation tested separately
    "main": 0x08027BE8, "main_pll_call": 0x08027BF2,
    "pll_wrapper": 0x080111F0, "pll_driver": 0x0802622A,
}
V2 = {
    "reset": 0x0800123C, "clock_reset": 0x080323DC,
    "main": 0x080340E0, "main_pll_call": 0x080340EA,
    "pll_wrapper": 0x080173DC, "pll_driver": 0x0803235E,
}
USART_CALLS = {
    0x0800CA2A: ("USART3", 19200),
    0x08010306: ("USART2", 9600),
    0x08018C20: ("USART1", 115200),
}
TIM3_CLOCK_QUERY = 0x080193FC
TIM3_SETUP = 0x08019426
CLOCK_GETTER = 0x08030C30
USART_INIT = 0x08032CDC
TIM_INIT = 0x080324F8


def hexpc(pc: int) -> str:
    return f"0x{pc:08X}"


def word(payload: bytes, pc: int) -> int:
    offset = pc - BASE
    if offset < 0 or offset + 4 > len(payload):
        raise ValueError(f"outside stock payload: {hexpc(pc)}")
    return struct.unpack_from("<I", payload, offset)[0]


def verify_reset_to_main(payload: bytes, spec: dict, v2: bool) -> dict:
    """Check resolved startup literal and direct instructions, no execution."""
    assert_ins(payload, 0x08001228, "ldr", "r0, [pc, #0]", spec["main"] | 1)
    assert_ins(payload, 0x0800122A, "bx", "r0")
    assert_ins(payload, spec["main_pll_call"], "bl", f"#{spec['pll_wrapper']:#x}")
    first_call = spec["main_pll_call"] - 4
    row = inspect_window(payload, first_call, first_call + 4)[0]
    if row["mnemonic"] != "bl":
        raise ValueError(f"unexpected preceding main call at {hexpc(first_call)}")
    if v2:
        assert_ins(payload, 0x0800123C, "ldr", "r0, [pc, #0x18]", 0x080323DD)
        assert_ins(payload, 0x0800123E, "blx", "r0")
        assert_ins(payload, 0x08001240, "ldr", "r0, [pc, #0x18]", 0x08001221)
        assert_ins(payload, 0x08001242, "bx", "r0")
        assert_ins(payload, 0x080340E6, "bl", "#0x80309bc")
        assert_ins(payload, 0x080173DE, "bl", "#0x803235e")
        assert_ins(payload, 0x080173E2, "bl", "#0x80194b4")
        assert_ins(payload, 0x080173EA, "b.w", "#0x80193e8")
        assert_ins(payload, 0x080193FC, "bl", "#0x8030c30")
        assert_ins(payload, 0x08019426, "bl", "#0x80324f8")
        assert_ins(payload, 0x08032386, "bl", "#0x8001260")
        assert_ins(payload, 0x080323AA, "bl", "#0x8030d64")
        assert_ins(payload, 0x08032D18, "bl", "#0x8030c30")
    else:
        assert_ins(payload, 0x080111F2, "bl", "#0x802622a")
        assert_ins(payload, 0x080111F6, "bl", "#0x8013170")
        assert_ins(payload, 0x080111FE, "b.w", "#0x80130a0")
    return {
        "reset_vector": hexpc(word(payload, BASE+4)),
        "reset_software_path": hexpc(spec["reset"]),
        "post_scatterload_main_pointer_at_0x0800122C": hexpc(word(payload, 0x0800122C)),
        "main_entry": hexpc(spec["main"]),
        "main_pre_pll_call": row["operands"],
        "main_pll_call": hexpc(spec["main_pll_call"]),
        "main_pll_wrapper": hexpc(spec["pll_wrapper"]),
        "pll_driver": hexpc(spec["pll_driver"]),
        "precondition": (
            "Literal-indirect startup entry after scatterload; successful returns "
            "and actual clock-switch hardware status are not proved"
        ),
    }


def _direct_target(ins) -> int | None:
    for op in ins.operands:
        if op.type == ARM_OP_IMM:
            return op.imm & ~1
    return None


def reachable_calls(payload: bytes, entry: int, cap: int = 6000) -> list[tuple[int, int]]:
    """CFG walk inside a function; follows conditional branches and tail jumps.

    Direct BL/BLX targets are *collected*, never inlined. A register-only BLX
    is unresolved. This traversal does not claim dynamic reachability.
    """
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    work = [entry]
    visited: set[int] = set()
    calls: set[tuple[int, int]] = set()
    last = BASE + len(payload)
    while work:
        pc = work.pop()
        if pc in visited or not (BASE <= pc <= last-4):
            continue
        if len(visited) >= cap:
            raise ValueError(f"CFG budget exceeded from {hexpc(entry)}")
        inst = next(md.disasm(payload[pc-BASE:pc-BASE+4], pc, count=1), None)
        if inst is None:
            continue
        visited.add(pc)
        name = inst.mnemonic
        nxt = pc + inst.size
        if name in ("bl", "blx"):
            target = _direct_target(inst)
            if target is not None and BASE <= target < last:
                calls.add((pc, target))
            work.append(nxt)
            continue
        if name in ("bx", "bxj", "tbb", "tbh", "udf", "svc", "bkpt"):
            continue
        if name.startswith("pop") and "pc" in inst.op_str:
            continue
        if name.startswith("ldr") and inst.op_str.split(",")[0] == "pc":
            continue
        is_jump = inst.group(CS_GRP_JUMP) or name.startswith(("cbz", "cbnz"))
        if is_jump:
            target = _direct_target(inst)
            if target is not None and BASE <= target < last:
                work.append(target)
            if name not in ("b", "b.w"):
                work.append(nxt)
            continue
        work.append(nxt)
    return sorted(calls)


def find_main_call_paths(
    payload: bytes, main_entry: int, callsites: set[int],
    max_depth: int = 4, max_functions: int = 850
) -> dict[str, list[dict]]:
    """Find interprocedural direct-BL paths from main to target callsites.

    Every path edge is disassembled at the actual call address. May be
    incomplete for function pointers, virtual dispatch, or ignored tailcalls.
    """
    q = deque([(main_entry, [])])
    seen: set[int] = set()
    results: dict[str, list[dict]] = {}
    while q and len(seen) < max_functions:
        fn, path = q.popleft()
        if fn in seen:
            continue
        seen.add(fn)
        for call_pc, callee in reachable_calls(payload, fn):
            edge = {"call": hexpc(call_pc), "callee": hexpc(callee)}
            if call_pc in callsites:
                results.setdefault(hexpc(call_pc), []).append({
                    "path": path + [edge],
                    "length": len(path)+1,
                })
            if len(path) < max_depth:
                q.append((callee, path + [edge]))
    return results


def clock_brr_timing(payload: bytes) -> dict:
    """Compare 48 MHz reset path to the conditional 128 MHz AIR32 PLL request."""
    reset_model = clock_analyze(payload)["reset_default_software_profile"]
    serial = usart_analyze(payload)
    timers = timer_analyze(payload)
    if len(serial["callers"]) != 3 or timers["matched_timer_call_chains"] != 5:
        raise ValueError("original USART/TIM call fingerprints changed")
    # Request from AIR_RCC_PLLConfig, conditional on 8MHz HSE and ROM dispatch.
    pll_requested_hz = 8_000_000 * 16
    pclk1, pclk2 = pll_requested_hz//2, pll_requested_hz
    rows = []
    for row in serial["callers"]:
        name = row["peripheral_candidate"]
        bus = row["clock_bus_candidate"]
        pclk = pclk2 if bus == "PCLK2" else pclk1
        baud = row["baud"]
        rows.append({
            "name": name, "baud": baud, "init_callsite": row["call_pc"],
            "bus": bus,
            "reset_48mhz_brr16": row["brr16_default_hypothesis"],
            "post_128mhz_brr16_hypothesis": f"0x{predict_brr16(pclk, baud):04X}",
            "post_128mhz_pclk_hz": pclk,
        })
    psc = pclk1//1_000_000-1
    tick = (pclk1*2)//(psc+1)
    return {
        "early_reset_sysclk_hz": reset_model["sysclk_hz"],
        "post_rom_pll_request_sysclk_hz": pll_requested_hz,
        "clock_request_caveat": (
            "128MHz requires HSE=8MHz, a matching UID-dispatched ROM clock "
            "operation, PLL lock, SWS switch and subsequent unchanged bus divisors"
        ),
        "post_128mhz_hypothesis": {
            "hclk_hz": pll_requested_hz,
            "pclk1_hz": pclk1,
            "pclk2_hz": pclk2,
            "tim_apb1_input_hz": pclk1*2,
            "tim3_psc_if_live_pclk1": psc,
            "tim3_arr": 1999,
            "tim3_counter_hz": tick,
            "tim3_update_us": round(1e6*2000/tick, 4),
        },
        "usart_brr16_comparison": sorted(rows, key=lambda row: row["name"]),
        "read_live_clock_evidence": {
            "USART_Init_clock_getter_call": hexpc(0x08032D18),
            "TIM3_clock_getter_call": hexpc(0x080193FC),
        },
        "uart_instructions": serial["callers"],
        "tim3_instructions": [
            r for r in timers["callers"]
            if r["clock_getter_call"] == hexpc(TIM3_CLOCK_QUERY)
        ],
    }


def analyze(v2: bytes, v1: bytes | None = None) -> dict:
    stage = verify_reset_to_main(v2, V2, True)
    next_calls = reachable_calls(v2, V2["main"])
    main_early = [dict(call=hexpc(pc), callee=hexpc(dst))
                  for pc, dst in next_calls if 0x080340E6 <= pc <= 0x08034158]
    sites = set(USART_CALLS) | {TIM3_CLOCK_QUERY, TIM3_SETUP}
    paths = find_main_call_paths(v2, V2["main"], sites)
    report = {
        "image": "UV-5RH Pro V2.0.09 original decoded Thumb",
        "reset_to_main": stage,
        "initialization_sequence": [
            "Reset 0x0800123C executes 48MHz-compatible early clock setup",
            "0x08001220 performs scatterload and literal BX to 0x080340E0",
            "0x080340E6 early helper precedes the 0x080340EA PLL call",
            "0x080173DC calls 0x0803235E (AIR32-style HSE/1, PLL x16, Flash divider 2)",
            "0x080173EA tail-jumps to 0x080193E8, querying live clock then initializing TIM3",
            "Upon return, main continues the ordered peripheral/application initialization calls",
        ],
        "main_early_calls": main_early,
        "main_to_peripheral_callsite_paths": paths,
        "clock_and_peripheral_hypotheses": clock_brr_timing(v2),
        "runtime_trigger_assessment": (
            "Reset->scatterload->main contains the PLL call without a local "
            "operating-mode or firmware-version branch. The ROM callback "
            "inside the helper remains conditional on UID byte 1A/1B/1C."
        ),
        "limits": [
            "Static CFG includes both sides of conditional branches, never proves execution.",
            "Direct BL paths can miss indirect calls; no negative claim is made from an absent path.",
            "128MHz is an SDK-requested clock, not a measured MCU frequency.",
            "USART BRR values assume 16x oversampling and STM32/AIR32 compatible format.",
            "TIM3 calculations assume APB1 /2 and timer clock doubling under the proposed PLL state.",
            "No real device, UART pins, clocks, SWD, ROM body, or UID were accessed.",
        ],
    }
    if v1 is not None:
        report["v1_cross_version"] = verify_reset_to_main(v1, V1, False)
        report["v1_cross_version"]["assessment"] = (
            "V1 uses the same startup->main->clock helper ordering, but with "
            "relocated application functions and a shared ROM helper."
        )
    return report


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("v2", type=Path)
    p.add_argument("--v1", type=Path)
    p.add_argument("--json", action="store_true")
    a = p.parse_args(argv)
    r = analyze(decoded_payload(a.v2.read_bytes()),
                decoded_payload(a.v1.read_bytes()) if a.v1 else None)
    if a.json:
        print(json.dumps(r, indent=2, ensure_ascii=False))
    else:
        print("V2 Reset->main:", r["reset_to_main"])
        print("First main init calls:", r["main_early_calls"][:12])
        print("Nested USART/TIM call paths:", r["main_to_peripheral_callsite_paths"])
        print("48 vs conditional 128 clock/USART/TIM:", r["clock_and_peripheral_hypotheses"])
        if a.v1:
            print("V1 Reset->main:", r["v1_cross_version"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
