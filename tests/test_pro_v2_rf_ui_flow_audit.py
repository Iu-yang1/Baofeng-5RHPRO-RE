"""V2 original tuning-table, register-prefix and key-state read-only proof."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
from mcu_fingerprint import decoded_payload
from pro_v2_rf_ui_flow_audit import (
    SITES, analyze, original_r37_setup_word, original_tuning_word, verify_sites
)


class OemRfUiFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v1=decoded_payload((ROOT/"firmware/BF_5RH_501_v1_1_04.dat").read_bytes())
        cls.v2=decoded_payload((ROOT/"firmware/BF_5RH_501_v2_0_9.dat").read_bytes())

    def test_all_original_v2_instruction_sites(self):
        report=analyze(self.v2,self.v1)
        self.assertGreaterEqual(sum(report["verified_v2_thumb_sites"].values()),45)
        self.assertFalse(report["tuning_table"]["frequency_hz_to_pll_formula_known"])
        self.assertFalse(report["fd6818"]["ptt_pa_complete_hardware_sequence_proved"])
        self.assertTrue(report["keypad"]["scanned_index_0x13_and_0x14_in_ui_event"])

    def changed(self,addr):
        b=bytearray(self.v2)
        b[addr-0x08001000]^=1
        return bytes(b)

    def test_sram_frequency_table_literal_mutation(self):
        with self.assertRaises(ValueError):
            verify_sites(self.changed(0x0800DDD0))

    def test_frequency_correction_add_mutation(self):
        with self.assertRaises(ValueError):
            verify_sites(self.changed(0x0800AFF0))

    def test_high_tuning_register_mutation(self):
        with self.assertRaises(ValueError):
            verify_sites(self.changed(0x08005ECC))

    def test_initial_rf_reg51_mutation(self):
        with self.assertRaises(ValueError):
            verify_sites(self.changed(0x0800A436))

    def test_rf_reg37_state_bitmask_mutation(self):
        with self.assertRaises(ValueError):
            verify_sites(self.changed(0x0800A446))

    def test_rf_reg30_second_state_mutation(self):
        with self.assertRaises(ValueError):
            verify_sites(self.changed(0x0800A46A))

    def test_oem_key_index_compare_mutation(self):
        with self.assertRaises(ValueError):
            verify_sites(self.changed(0x08010B46))

    def test_raw_word_correction_is_32bit_wrap_not_hz(self):
        self.assertEqual(original_tuning_word(0xFFFF_FFF0,0x30),0x20)
        self.assertEqual(original_tuning_word(0x10203040,0),0x10203040)
        with self.assertRaises(ValueError):
            original_tuning_word(0x100000000,0)

    def test_reg37_masks_match_verified_thumb(self):
        self.assertEqual(original_r37_setup_word(0),0x020F)
        self.assertEqual(original_r37_setup_word(0xFFFF),0xFFFF)
        self.assertEqual(original_r37_setup_word(0x1234),0x123F)
        with self.assertRaises(ValueError):
            original_r37_setup_word(-1)

    def test_rust_core_contract_has_correct_raw_operations(self):
        s=(ROOT/"firmware-pro/core/src/fd6818.rs").read_text(encoding="utf-8")
        for token in ["OEM_SETUP_DELAY_ARGUMENT: u32 = 0x0190",
                      "self.write_register(0x51, 0x0300)",
                      "self.write_register(0x37, oem_setup_reg37(cached_reg37))",
                      "self.write_register(REG_STATE, 0x0000)",
                      "self.write_register(REG_STATE, 0xBFF1)",
                      "raw_table_word.wrapping_add(correction_word)"]:
            self.assertIn(token,s)

if __name__=="__main__":
    unittest.main()
