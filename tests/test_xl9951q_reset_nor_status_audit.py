"""Original OEM Reset-to-journal and NOR status error propagation regression."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from mcu_fingerprint import decoded_payload
from xl9951q_reset_nor_status_audit import (
    VERSIONS, analyze, verify_version, classify_status_result,
)


class StockNorErrorPathTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = {
            edition: decoded_payload((ROOT / spec["package"]).read_bytes())
            for edition, spec in VERSIONS.items()
        }

    def test_both_oem_versions_verify_reset_and_nor_failure_path(self):
        report = analyze(self.data["v1"], self.data["v2"])
        for edition in VERSIONS:
            with self.subTest(version=edition):
                r = report["versions"][edition]
                self.assertEqual(r["reset_vector"], "0x0800123D")
                self.assertTrue(r["nor_status_poll"]["spi_timeout_zero_treated_as_ready"])
                self.assertEqual(r["spi_byte_exchange"]["tx_poll_limit_immediate"], "0xC8")
                self.assertEqual(r["spi_byte_exchange"]["rx_poll_limit_immediate"], "0xC8")
                self.assertFalse(r["nor_write_and_replay"]["restore_result_checked_before_journal_clear"])
                self.assertFalse(r["nor_status_poll"]["total_timeout_present_in_bounded_function"])
                self.assertGreaterEqual(r["validated_thumb_sites"], 24)
        self.assertFalse(report["cross_version"]["actual_board_behavior_verified"])

    def _mutation(self, edition: str, address: int):
        raw = bytearray(self.data[edition])
        raw[address - 0x08001000] ^= 0x01
        return bytes(raw)

    def test_v1_reset_to_main_vector_mutation_fails(self):
        with self.assertRaises(ValueError):
            verify_version(self._mutation("v1", 0x08001004), "v1")

    def test_v2_main_recovery_call_mutation_fails(self):
        with self.assertRaises(ValueError):
            verify_version(self._mutation("v2", 0x080340F4), "v2")

    def test_v1_spi_tx_timeout_limit_mutation_fails(self):
        with self.assertRaises(ValueError):
            verify_version(self._mutation("v1", 0x080257AE), "v1")

    def test_v2_spi_failure_zero_return_mutation_fails(self):
        with self.assertRaises(ValueError):
            verify_version(self._mutation("v2", 0x08031846), "v2")

    def test_v1_status_wip_poll_mutation_fails(self):
        with self.assertRaises(ValueError):
            verify_version(self._mutation("v1", 0x080030EA), "v1")

    def test_v2_nor_status_busy_backedge_mutation_fails(self):
        with self.assertRaises(ValueError):
            verify_version(self._mutation("v2", 0x08006BFC), "v2")

    def test_v1_page_program_ignores_status_mutation_fails(self):
        with self.assertRaises(ValueError):
            verify_version(self._mutation("v1", 0x08003186), "v1")

    def test_v2_restore_before_clear_mutation_fails(self):
        with self.assertRaises(ValueError):
            verify_version(self._mutation("v2", 0x08010498), "v2")

    def test_v1_nor_erase_status_tail_mutation_fails(self):
        with self.assertRaises(ValueError):
            verify_version(self._mutation("v1", 0x08007CD6), "v1")


class NorStatusModelTests(unittest.TestCase):
    def test_spi_timeout_is_interpreted_as_ready(self):
        result = classify_status_result(spi_timed_out=True, actual_status=0x01)
        self.assertEqual(result["byte_returned_by_spi_exchange"], 0)
        self.assertEqual(result["journal_driver_interpretation"], "ready")

    def test_actual_busy_nor_status_retries(self):
        result = classify_status_result(spi_timed_out=False, actual_status=0x01)
        self.assertEqual(result["journal_driver_interpretation"], "busy")

    def test_valid_zero_and_timeout_zero_are_indistinguishable(self):
        valid = classify_status_result(spi_timed_out=False, actual_status=0)
        failed = classify_status_result(spi_timed_out=True, actual_status=0xFF)
        self.assertEqual(valid["byte_returned_by_spi_exchange"],
                         failed["byte_returned_by_spi_exchange"])
        self.assertFalse(valid["timeout_is_distinguishable_from_valid_zero_status"])

    def test_non_wip_bits_do_not_block_ready_interpretation(self):
        result = classify_status_result(spi_timed_out=False, actual_status=0x20)
        self.assertEqual(result["journal_driver_interpretation"], "ready")

    def test_invalid_status_byte_rejected_by_pure_model(self):
        with self.assertRaises(ValueError):
            classify_status_result(False, 256)


if __name__ == "__main__":
    unittest.main()
