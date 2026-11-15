"""Clock tree model tests against the archived, decoded V2.0.09 image."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from mcu_fingerprint import decoded_payload  # noqa: E402
from v2_clock_tree_model import (  # noqa: E402
    analyze, extract_config, simulate_configuration,
)


class ClockTreeModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        p = ROOT / "firmware/BF_5RH_501_v2_0_9.dat"
        cls.payload = decoded_payload(p.read_bytes())
        cls.config = extract_config(cls.payload)

    def test_instructions_and_literal_evidence(self):
        constants = self.config["constants"]
        self.assertEqual(constants["crm_base"], 0x40021000)
        self.assertEqual(constants["hick_hz"], 8_000_000)
        self.assertEqual(constants["half_clock_hz"], 4_000_000)
        instr = self.config["instructions"]
        self.assertEqual(instr["set_pll_source_multiplier"], 0x00110000)
        self.assertEqual(instr["apb1_div2"], 0x400)
        self.assertEqual(instr["clear_pll_low"], 0x3F0000)
        self.assertEqual(instr["reset_pll_bits"], 0x7F0000)

    def test_reset_default_clock_tree(self):
        x = simulate_configuration(self.config, 0)
        self.assertEqual(x["cfg_register_model"], "0x00110402")
        self.assertEqual(x["pll_multiplier"], 6)
        self.assertEqual(x["pll_input_hz"], 8_000_000)
        self.assertEqual(x["sysclk_hz"], 48_000_000)
        self.assertEqual(x["hclk_hz"], 48_000_000)
        self.assertEqual(x["pclk1_hz"], 24_000_000)
        self.assertEqual(x["pclk2_hz"], 48_000_000)
        self.assertEqual(x["apb1_timer_clock_hz"], 48_000_000)
        self.assertEqual(x["adc_divisor"], 2)
        self.assertEqual(x["adcclk_hz"], 24_000_000)

    def test_prior_bit28_can_change_multiplier(self):
        x = simulate_configuration(self.config, 1 << 28)
        self.assertEqual(x["pll_multiplier"], 21)
        self.assertEqual(x["sysclk_hz"], 168_000_000)
        self.assertEqual(x["pclk1_hz"], 84_000_000)

    def test_source_change_is_not_hidden(self):
        altered = {
            "instructions": dict(self.config["instructions"]),
            "constants": dict(self.config["constants"]),
            "sram_tables": self.config["sram_tables"],
        }
        altered["instructions"]["set_pll_source_multiplier"] = 0x100000
        x = simulate_configuration(altered)
        self.assertEqual(x["pll_input_hz"], 4_000_000)
        self.assertEqual(x["sysclk_hz"], 24_000_000)

    def test_rejects_binary_that_changed_clock_constants(self):
        p = bytearray(self.payload)
        # E.g. a firmware from another board: do not silently use old assumptions.
        p[0x08030CC4 - 0x08001000] ^= 0x1
        with self.assertRaisesRegex(ValueError, "unexpected CRM base"):
            extract_config(bytes(p))

    def test_provides_original_source_evidence_in_report(self):
        r = analyze(self.payload)
        self.assertEqual(r["original_literal_words"]["hick_hz"], "0x007A1200")
        self.assertEqual(
            r["reset_default_software_profile"]["pclk2_hz"], 48_000_000
        )
        self.assertEqual(r["restored_sram_table_evidence"]["apb_shift_first8"],
                         [0, 0, 0, 0, 1, 2, 3, 4])


if __name__ == "__main__":
    unittest.main()
