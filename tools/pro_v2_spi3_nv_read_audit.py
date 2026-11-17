#!/usr/bin/env python3
"""Read-only evidence audit of the original V2 SPI3 NOR NV read transaction.

The OEM 0x080141DC routine sends 0x03, a 24-bit address and FF dummy
bytes through 0x08031814, using GPIOA15 BRR/BSRR software CS. These
observations do not identify the XL9951Q QFN64 pad or physical NOR chip.
"""
from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path
from mcu_fingerprint import decoded_payload

BASE = 0x08001000
V2 = Path("firmware/BF_5RH_501_v2_0_9.dat")
READ_ROUTINE = 0x080141DC
TRANSFER_ENTRY = 0x08031814
OEM_TRIM_NV_CALL = 0x08012BBC

# Exact V2 halfword signatures at positions already recovered from the
# original application. Checked rather than inferred from package strings.
HALFWORDS = {
    0x080141DC: 0xB570,  # push callee-saved registers
    0x080141E0: 0x4812,  # literal -> GPIOA BRR 0x40010814
    0x080141E8: 0xF441,  # ORR immediate, GPIOA bit15 set in BRR
    0x080141EA: 0x4100,
    0x080141EC: 0x6001,
    0x080141EE: 0x2003,  # SPI NOR READ opcode
    0x080141F4: 0xF3C4,  # first 8 bits of 24-bit address
    0x080141F6: 0x4007,
    0x080141FC: 0xF3C4,  # second 8 bits
    0x080141FE: 0x2007,
    0x08014204: 0xB2E0,  # final low 8 bits (UXTB)
    0x0801420E: 0x20FF,  # receive clock (MOSI dummy FF)
    0x08014214: 0x5528,  # byte received into caller-provided buffer
    0x0801421A: 0x42B4,  # remaining length condition
    0x0801421C: 0xD3F7,
    0x08014220: 0x1F00,  # 0x40010814 -> 0x40010810 BSRR
    0x08014224: 0xF441,
    0x08014226: 0x4100,
    0x08014228: 0x6001,
    0x0801422A: 0xBD70,
}

BL_TARGETS = {
    OEM_TRIM_NV_CALL: READ_ROUTINE,
    0x080141F0: TRANSFER_ENTRY,  # opcode
    0x080141F8: TRANSFER_ENTRY,  # address[23:16]
    0x08014200: TRANSFER_ENTRY,  # address[15:8]
    0x08014206: TRANSFER_ENTRY,  # address[7:0]
    0x08014210: TRANSFER_ENTRY,  # FF dummy -> received byte
}


def halfword(payload: bytes, pc: int) -> int:
    offset = pc - BASE
    if offset < 0 or offset + 2 > len(payload):
        raise ValueError(f"V2 PC outside decoded image: 0x{pc:08X}")
    return struct.unpack_from("<H", payload, offset)[0]


def decode_thumb_bl(payload: bytes, pc: int) -> int:
    high, low = halfword(payload, pc), halfword(payload, pc + 2)
    if high & 0xF800 != 0xF000 or low & 0xD000 != 0xD000:
        raise ValueError(f"not a Thumb BL instruction at 0x{pc:08X}")
    s = (high >> 10) & 1
    j1 = (low >> 13) & 1
    j2 = (low >> 11) & 1
    i1 = 1 ^ (j1 ^ s)
    i2 = 1 ^ (j2 ^ s)
    displacement = (s << 24) | (i1 << 23) | (i2 << 22)
    displacement |= (high & 0x03FF) << 12
    displacement |= (low & 0x07FF) << 1
    if s:
        displacement -= 1 << 25
    return (pc + 4 + displacement) & 0xFFFFFFFF


def verify_original(payload: bytes) -> dict:
    for pc, expected in HALFWORDS.items():
        found = halfword(payload, pc)
        if found != expected:
            raise ValueError(
                f"V2 SPI3 NV instruction 0x{pc:08X}: "
                f"expected 0x{expected:04X}, got 0x{found:04X}"
            )
    literal_offset = 0x0801422C - BASE
    cs_brr_base = struct.unpack_from("<I", payload, literal_offset)[0]
    if cs_brr_base != 0x40010814:
        raise ValueError(f"wrong software CS BRR address: 0x{cs_brr_base:08X}")
    for pc, expected in BL_TARGETS.items():
        target = decode_thumb_bl(payload, pc)
        if target != expected:
            raise ValueError(
                f"V2 SPI3 NV callsite 0x{pc:08X}: "
                f"expected 0x{expected:08X}, got 0x{target:08X}"
            )
    return {
        "read_routine": "0x080141DC",
        "calibration_caller": "0x08012BBC",
        "spi3_transfer_entry": "0x08031814",
        "verified_transfer_calls": len(BL_TARGETS) - 1,
        "opcode": "0x03",
        "address_width_bits": 24,
        "dummy_tx": "0xFF",
        "cs_software_port": "GPIOA15",
        "cs_assert_mmio_brr": "0x40010814",
        "cs_deassert_mmio_bsrr": "0x40010810",
        "read_only": True,
        "nor_part_electrically_confirmed": False,
        "mcu_qfn_pad_number_confirmed": False,
        "original_spi3_timeout_is_distinguishable_from_zero": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    evidence = verify_original(decoded_payload(V2.read_bytes()))
    if args.json:
        print(json.dumps(evidence, indent=2))
    else:
        print("Verified OEM SPI3 NV read:", evidence)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
