"""Actual original V1/V2 NOR and internal Flash journal evidence tests."""
from __future__ import annotations
import sys
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from mcu_fingerprint import decoded_payload
from xl9951q_high_flash_nor_audit import MAP, analyze, verify_one, SCRATCH_FLASH


class HighFlashNorAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v1 = decoded_payload((ROOT / MAP["v1"]["path"]).read_bytes())
        cls.v2 = decoded_payload((ROOT / MAP["v2"]["path"]).read_bytes())

    def test_both_original_images_support_the_opcodes_and_call_graph(self):
        report = analyze(self.v1, self.v2)
        for key in ("v1", "v2"):
            with self.subTest(version=key):
                r = report["versions"][key]
                self.assertEqual(r["nor_opcodes"]["erase_4k"], "0x20")
                self.assertEqual(r["external_nor_backup_offset"], "0x001FE000")
                self.assertEqual(r["internal_flash_journal_candidate"], "0x0807F800")
        self.assertFalse(report["physical_storage_inference"]["external_nor_xip_verified"])
        self.assertFalse(report["physical_storage_inference"]["crash_recovery_behavior_verified"])

    def test_v2_spi_read_instruction_mutation_fails(self):
        raw = bytearray(self.v2)
        address = 0x08006B06 - 0x08001000
        raw[address] = 0
        with self.assertRaises(ValueError):
            verify_one(bytes(raw), "v2")

    def test_v1_spare_sector_literal_mutation_fails(self):
        raw = bytearray(self.v1)
        address = 0x08012DCE - 0x08001000
        raw[address] ^= 0xFF
        with self.assertRaises(ValueError):
            verify_one(bytes(raw), "v1")

    def test_v2_internal_flash_journal_literal_mutation_fails(self):
        raw = bytearray(self.v2)
        address = 0x080191C8 - 0x08001000
        raw[address] ^= 0x01
        with self.assertRaises(ValueError):
            verify_one(bytes(raw), "v2")

    def test_journal_not_contained_in_upload_payload(self):
        for raw in (self.v1, self.v2):
            self.assertLess(0x08001000 + len(raw), SCRATCH_FLASH)


if __name__ == "__main__":
    unittest.main()
