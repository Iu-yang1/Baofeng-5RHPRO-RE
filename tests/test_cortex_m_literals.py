"""Synthetic-code test of Thumb LDR-literal trace extraction."""

from __future__ import annotations

import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from cortex_m_literals import profile  # noqa: E402


def image():
    header = bytearray(b"\xff" * 80)
    header[0:7] = b"BaoFeng"
    header[16:22] = b"BF_5RH"
    header[32:40] = b"V1.0.0.0"
    header[48:56] = b"V2.0.0.0"
    data = bytearray(512)
    struct.pack_into(">I", header, 0x40, len(data))
    struct.pack_into("<I", data, 0, 0x20002000)
    struct.pack_into("<I", data, 4, 0x08001101)
    # At 0x08001100: LDR r0, [pc, #0] -> word at 0x08001104.
    struct.pack_into("<H", data, 0x100, 0x4800)
    struct.pack_into("<H", data, 0x102, 0x4770)  # BX LR
    struct.pack_into("<I", data, 0x104, 0x40023800)
    return bytes(header) + bytes(b ^ 0xC8 for b in data)


class CortexLiteralTests(unittest.TestCase):
    def test_extracts_real_pc_relative_literal(self):
        report = profile(image())
        self.assertEqual(report["vector_roots"], 1)
        self.assertFalse(report["budget_exhausted"])
        self.assertIn({"address": "0x40023800", "load_sites": 1},
                      report["literal_values"])
        self.assertEqual(report["literal_loads_peripheral"], 1)


if __name__ == "__main__":
    unittest.main()
