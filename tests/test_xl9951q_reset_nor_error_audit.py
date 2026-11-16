"""Cross-version Reset-to-recovery and error-path static regression tests."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from mcu_fingerprint import decoded_payload
from xl9951q_reset_nor_error_audit import audit_one, analyze
from xl9951q_journal_recovery_audit import STOCK


class ResetNorErrorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.images = {v: decoded_payload((ROOT / s["file"]).read_bytes())
                      for v,s in STOCK.items()}

    def test_both_stock_images_have_reset_main_recovery_path(self):
        out = analyze(self.images["v1"], self.images["v2"])
        for v in ("v1","v2"):
            with self.subTest(v=v):
                d = out[v]
                self.assertEqual(d["reset"], "0x0800123D")
                self.assertEqual(d["scatterload_handoff"], "0x08001220")
                self.assertTrue(d["nor_status_poll"]["loop_until_zero"])
                self.assertFalse(d["nor_status_poll"]["retry_timeout_observed"])
                self.assertFalse(d["nor_status_poll"]["separate_program_verify_observed"])
                self.assertEqual(d["nor_program"]["page_unit"], 256)
                self.assertEqual(d["nor_erase"]["opcode"], "0x20")
                self.assertFalse(d["restore_then_clear"]["conditional_status_branch_between"])
        self.assertFalse(out["hardware_verified"])

    def changed(self, v: str, addr: int) -> bytes:
        out = bytearray(self.images[v])
        out[addr - 0x08001000] ^= 1
        return bytes(out)

    def test_v1_main_recovery_bl_mutation_fails(self):
        with self.assertRaises(ValueError):
            audit_one(self.changed("v1", 0x08027BFC), "v1")

    def test_v2_main_recovery_bl_mutation_fails(self):
        with self.assertRaises(ValueError):
            audit_one(self.changed("v2", 0x080340F4), "v2")

    def test_v1_status_poll_conditional_mutation_fails(self):
        with self.assertRaises(ValueError):
            audit_one(self.changed("v1", 0x080030EC), "v1")

    def test_v2_status_poll_conditional_mutation_fails(self):
        with self.assertRaises(ValueError):
            audit_one(self.changed("v2", 0x08006BFC), "v2")

    def test_v1_restore_tail_call_mutation_fails(self):
        with self.assertRaises(ValueError):
            audit_one(self.changed("v1", 0x0800ED66), "v1")

    def test_v2_restore_tail_call_mutation_fails(self):
        with self.assertRaises(ValueError):
            audit_one(self.changed("v2", 0x08014A3E), "v2")

    def test_v1_journal_clear_call_mutation_fails(self):
        with self.assertRaises(ValueError):
            audit_one(self.changed("v1", 0x0800AC0C), "v1")

    def test_v2_journal_clear_call_mutation_fails(self):
        with self.assertRaises(ValueError):
            audit_one(self.changed("v2", 0x08010498), "v2")

    def test_v1_flash_erase_status_branch_mutation_fails(self):
        with self.assertRaises(ValueError):
            audit_one(self.changed("v1", 0x08002E80), "v1")

    def test_v2_flash_erase_status_branch_mutation_fails(self):
        with self.assertRaises(ValueError):
            audit_one(self.changed("v2", 0x08006990), "v2")


if __name__ == "__main__":
    unittest.main()
