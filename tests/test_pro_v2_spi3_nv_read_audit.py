"""Cross-check original V2 SPI3 NV read entry and the new read-only core."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from mcu_fingerprint import decoded_payload
from pro_v2_spi3_nv_read_audit import (
    BASE, BL_TARGETS, HALFWORDS, decode_thumb_bl, verify_original,
)


class OriginalSpi3NvReaderEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = ROOT / "firmware/BF_5RH_501_v2_0_9.dat"
        cls.payload = decoded_payload(path.read_bytes())

    def test_calibration_reader_reaches_original_spi3_transport(self):
        report = verify_original(self.payload)
        self.assertEqual(report["calibration_caller"], "0x08012BBC")
        self.assertEqual(report["spi3_transfer_entry"], "0x08031814")
        self.assertEqual(report["verified_transfer_calls"], 5)
        self.assertEqual(report["opcode"], "0x03")
        self.assertEqual(report["address_width_bits"], 24)
        self.assertEqual(report["cs_software_port"], "GPIOA15")
        self.assertFalse(report["mcu_qfn_pad_number_confirmed"])
        self.assertFalse(report["nor_part_electrically_confirmed"])

    def test_all_direct_thumb_bl_calls_resolve(self):
        for pc, target in BL_TARGETS.items():
            with self.subTest(pc=hex(pc)):
                self.assertEqual(decode_thumb_bl(self.payload, pc), target)

    def test_mutated_instruction_or_literal_is_rejected(self):
        important = [
            0x080141EE, 0x080141F4, 0x080141FC, 0x08014204,
            0x0801420E, 0x08014214, 0x08014220, 0x0801422C,
        ]
        for pc in important:
            with self.subTest(pc=hex(pc)):
                changed = bytearray(self.payload)
                changed[pc-BASE] ^= 1
                with self.assertRaises(ValueError):
                    verify_original(bytes(changed))

    def test_mutated_bl_targets_are_rejected(self):
        for pc in BL_TARGETS:
            with self.subTest(pc=hex(pc)):
                changed = bytearray(self.payload)
                changed[pc-BASE+2] ^= 1
                with self.assertRaises(ValueError):
                    verify_original(bytes(changed))

    def test_rust_transport_does_not_conflate_spi3_timeout_with_zero(self):
        src = (ROOT / "firmware-pro/core/src/spi3_nv.rs").read_text(encoding="utf-8")
        for item in (
            "pub trait SpiByteTransfer", "OemSpi3NvReader",
            "OEM_NOR_READ_OPCODE: u8 = 0x03",
            "OEM_NOR_READ_DUMMY: u8 = 0xFF",
            "OemSpi3NvReadError::Transfer",
            "TransferAndDeselect",
        ):
            self.assertIn(item, src)
        board = (ROOT / "firmware-pro/core/src/board_v2.rs").read_text(encoding="utf-8")
        self.assertIn(
            "OEM_SPI3_NV_CS_SOFTWARE: Pin = Pin { port: Port::A, bit: 15 }",
            board,
        )


if __name__ == "__main__":
    unittest.main()
