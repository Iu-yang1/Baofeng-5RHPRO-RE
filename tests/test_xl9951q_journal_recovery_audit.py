"""Read-only OEM V1/V2 journal recovery control-flow and negative tests."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from mcu_fingerprint import decoded_payload
from xl9951q_journal_recovery_audit import (
    SCRATCH, STOCK, SECTOR_BYTES, classify_recovery, analyze, verify_recovery,
)
from xl9951q_high_flash_nor_audit import analyze as audit_nor


class OriginalRecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.images = {key: decoded_payload((ROOT / spec["file"]).read_bytes())
                      for key, spec in STOCK.items()}

    def test_both_original_versions_have_38_verified_sites(self):
        audit = analyze(self.images["v1"], self.images["v2"])
        for edition in STOCK:
            with self.subTest(edition=edition):
                report = audit["versions"][edition]
                self.assertEqual(report["verified_instruction_count"], 38)
                self.assertEqual(report["journal_metadata_read"]["target_offset_endian"], "little")
                self.assertEqual(report["journal_metadata_read"]["address"], f"0x{SCRATCH:08X}")
                self.assertEqual(report["recovery_backup"]["bytes"], SECTOR_BYTES)
                self.assertEqual(report["mismatch_scan"]["chunk_bytes"], 64)
                self.assertTrue(report["journal_cleanup"]["performed_after_equal_or_recovery"])
        self.assertFalse(audit["proven"]["physical_powerloss_atomicity"])
        self.assertFalse(audit["proven"]["full_reset_to_init_callgraph"])

    def test_cross_version_matches_known_nor_driver(self):
        journal = analyze(self.images["v1"], self.images["v2"])
        nor = audit_nor(self.images["v1"], self.images["v2"])
        for edition in STOCK:
            self.assertEqual(journal["versions"][edition]["recovery_backup"]["nor_offset"],
                             nor["versions"][edition]["external_nor_backup_offset"])

    def _corrupt(self, edition, address, xor=1):
        blob = bytearray(self.images[edition])
        blob[address-0x08001000] ^= xor
        return bytes(blob)

    def test_v1_completion_cmp_mutation_is_rejected(self):
        with self.assertRaises(ValueError):
            verify_recovery(self._corrupt("v1", 0x0800ABB4), "v1")

    def test_v2_completion_branch_mutation_is_rejected(self):
        with self.assertRaises(ValueError):
            verify_recovery(self._corrupt("v2", 0x08010442), "v2")

    def test_v1_backup_offset_mutation_is_rejected(self):
        with self.assertRaises(ValueError):
            verify_recovery(self._corrupt("v1", 0x0800ABC0), "v1")

    def test_v2_boot_call_mutation_is_rejected(self):
        with self.assertRaises(ValueError):
            verify_recovery(self._corrupt("v2", 0x080340F4), "v2")

    def test_v2_journal_literal_mutation_is_rejected(self):
        with self.assertRaises(ValueError):
            verify_recovery(self._corrupt("v2", 0x08010810), "v2")

    def test_v1_restore_branch_mutation_is_rejected(self):
        with self.assertRaises(ValueError):
            verify_recovery(self._corrupt("v1", 0x0800AC08), "v1")

    def test_v2_commit_flag_mutation_is_rejected(self):
        with self.assertRaises(ValueError):
            verify_recovery(self._corrupt("v2", 0x080191B6), "v2")


class RecoveryBranchModelTests(unittest.TestCase):
    def test_erased_journal_skips_recovery(self):
        result = classify_recovery(b"\xff" * 8)
        self.assertEqual(result["target_nor_offset"], 0xFFFFFFFF)
        self.assertEqual(result["action"], "skip_empty")

    def test_committed_journal_clears_without_replay(self):
        result = classify_recovery((0x123000).to_bytes(4,"little") + b"\x01\x00\x00\x00")
        self.assertEqual(result["action"], "skip_committed_then_clear")

    def test_pending_journal_reads_backup(self):
        result = classify_recovery((0x123000).to_bytes(4,"little") + bytes(4))
        self.assertEqual(result["action"], "pending_compare")

    def test_pending_matching_sector_clears_without_replay(self):
        header = (0x123000).to_bytes(4,"little") + bytes(4)
        sector = b"\x77" * SECTOR_BYTES
        result = classify_recovery(header, sector, sector)
        self.assertEqual(result["action"], "equal_then_clear")

    def test_pending_mismatched_sector_replays_entire_sector(self):
        header = (0x123000).to_bytes(4,"little") + bytes(4)
        expected = bytes(range(256))*16
        actual = bytearray(expected)
        actual[4095] ^= 0x3F
        result = classify_recovery(header, expected, bytes(actual))
        self.assertEqual(result["action"], "restore_then_clear")

    def test_header_is_little_endian(self):
        result = classify_recovery(bytes([0x78,0x56,0x34,0x12,0,0,0,0]))
        self.assertEqual(result["target_nor_offset"], 0x12345678)

    def test_short_header_is_not_a_model_input(self):
        with self.assertRaises(ValueError):
            classify_recovery(bytes(7))


if __name__ == "__main__":
    unittest.main()
