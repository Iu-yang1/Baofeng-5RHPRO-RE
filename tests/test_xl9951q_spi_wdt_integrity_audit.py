"""V1/V2 OEM SPI timeout and watchdog startup evidence regression tests."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from mcu_fingerprint import decoded_payload
from xl9951q_journal_recovery_audit import STOCK
from xl9951q_spi_wdt_integrity_audit import (
    SPI3, IWDG, SITES, analyze, check_sites, rdsr_outcome,
)


class OriginalSpiWatchdogEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.payloads = {v: decoded_payload((ROOT / info["file"]).read_bytes())
                        for v, info in STOCK.items()}

    def test_both_original_versions_validate_spi_and_iwdg(self):
        report = analyze(self.payloads["v1"], self.payloads["v2"])
        for version in ("v1", "v2"):
            with self.subTest(version=version):
                row = report["versions"][version]
                self.assertEqual(row["spi3_exchange"]["spi_register_base"], f"0x{SPI3:08X}")
                self.assertEqual(row["spi3_exchange"]["poll_counter_compare"], 200)
                self.assertEqual(row["watchdog_mode_one"]["reload_register_write"], "0x07FF")
                self.assertEqual(row["watchdog_mode_one"]["start_key"], "0xCCCC")
                self.assertTrue(row["watchdog_config_is_on_main_pre_recovery_path"])
                self.assertFalse(row["nor_rdsr"]["separate_watchdog_feed_in_status_loop"])
                self.assertTrue(row["nor_rdsr"]["status_exchange_timeout_can_look_like_wip_clear"])
                self.assertFalse(row["recovery"]["local_backup_crc_verified"])
                self.assertGreaterEqual(sum(row["verified_sites"].values()), 50)
        self.assertFalse(report["emulated_hardware"])

    def altered(self, version: str, pc: int) -> bytes:
        blob = bytearray(self.payloads[version])
        blob[pc-0x08001000] ^= 1
        return bytes(blob)

    def test_v1_spi_timeout_return_mutation_detected(self):
        with self.assertRaises(ValueError):
            check_sites(self.altered("v1", 0x080257D2), "v1")

    def test_v2_spi_timeout_return_mutation_detected(self):
        with self.assertRaises(ValueError):
            check_sites(self.altered("v2", 0x08031846), "v2")

    def test_v1_spi3_base_mutation_detected(self):
        # LDR PC-relative pool used by the low-level byte exchange.
        with self.assertRaises(ValueError):
            check_sites(self.altered("v1", 0x080257EC), "v1")

    def test_v2_spi3_base_mutation_detected(self):
        with self.assertRaises(ValueError):
            check_sites(self.altered("v2", 0x08031860), "v2")

    def test_v1_busy_status_branch_mutation_detected(self):
        with self.assertRaises(ValueError):
            check_sites(self.altered("v1", 0x080030EC), "v1")

    def test_v2_busy_status_branch_mutation_detected(self):
        with self.assertRaises(ValueError):
            check_sites(self.altered("v2", 0x08006BFC), "v2")

    def test_v1_watchdog_start_key_mutation_detected(self):
        with self.assertRaises(ValueError):
            check_sites(self.altered("v1", 0x0800387E), "v1")

    def test_v2_watchdog_start_key_mutation_detected(self):
        with self.assertRaises(ValueError):
            check_sites(self.altered("v2", 0x0800738E), "v2")

    def test_v1_watchdog_startup_call_mutation_detected(self):
        with self.assertRaises(ValueError):
            check_sites(self.altered("v1", 0x080130A6), "v1")

    def test_v2_watchdog_startup_call_mutation_detected(self):
        with self.assertRaises(ValueError):
            check_sites(self.altered("v2", 0x080193EE), "v2")

    def test_v1_watchdog_reload_register_mutation_detected(self):
        with self.assertRaises(ValueError):
            check_sites(self.altered("v1", 0x080038AA), "v1")

    def test_v2_watchdog_reload_register_mutation_detected(self):
        with self.assertRaises(ValueError):
            check_sites(self.altered("v2", 0x080073BA), "v2")


class RdsrBranchTests(unittest.TestCase):
    def test_busy_bit_retries(self):
        self.assertTrue(rdsr_outcome(1)["busy_branch_taken"])
        self.assertFalse(rdsr_outcome(1)["will_leave_busy_wait"])

    def test_idle_bit_returns(self):
        self.assertFalse(rdsr_outcome(0)["busy_branch_taken"])
        self.assertTrue(rdsr_outcome(0)["will_leave_busy_wait"])

    def test_busy_with_timeout_is_falsely_idle(self):
        row = rdsr_outcome(1, transfer_timed_out=True)
        self.assertEqual(row["spi_result_byte"], 0)
        self.assertTrue(row["will_leave_busy_wait"])
        self.assertTrue(row["communication_failure_indistinguishable_from_idle"])

    def test_alternate_status_bits_do_not_change_bit_zero(self):
        self.assertTrue(rdsr_outcome(0xFF)["busy_branch_taken"])
        self.assertFalse(rdsr_outcome(0xFE)["busy_branch_taken"])

    def test_invalid_status_input_rejected(self):
        with self.assertRaises(ValueError):
            rdsr_outcome(256)
        with self.assertRaises(ValueError):
            rdsr_outcome(-1)


if __name__ == "__main__":
    unittest.main()
