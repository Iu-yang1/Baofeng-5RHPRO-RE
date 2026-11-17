"""Verify OEM V2 calibration, GPIO, AF and full LCD initialization bytes."""
from __future__ import annotations
import sys
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
from mcu_fingerprint import decoded_payload
from pro_v2_full_board_audit import (
    FIXED,GAMMA_POS_SITES,GAMMA_NEG_SITES,LCD_COMMAND_SITES,
    analyze,original_trim_word,verify_original,
)


class FullBoardOriginalEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v2=decoded_payload((ROOT/"firmware/BF_5RH_501_v2_0_9.dat").read_bytes())
        cls.v1=decoded_payload((ROOT/"firmware/BF_5RH_501_v1_1_04.dat").read_bytes())

    def test_original_thumb_calibration_gpio_audio_lcd(self):
        r=analyze(self.v2,self.v1)
        self.assertGreaterEqual(sum(r["verified_thumb"].values()),130)
        self.assertEqual(r["frequency_trim"]["storage_logical_offset"],"0xC5C0")
        self.assertEqual(r["frequency_trim"]["effective_hz_step"],50)
        self.assertEqual(r["nv_record"]["halfword_values_per_bank"],64)
        self.assertTrue(r["nv_record"]["second_bank_present"])
        self.assertEqual(r["lcd"]["gpio_port_bit_reset"],"PA8")
        self.assertTrue(r["lcd"]["display_on_only_after_first_frame"])
        self.assertFalse(r["board_gpio_software_only"]["ptt_physical_button_proven"])
        self.assertFalse(r["board_gpio_software_only"]["rf_pa_external_gpio_proven"])
        self.assertTrue(r["board_gpio_software_only"]["pb1_low_then_high_in_one_routine"])
        self.assertEqual(r["ui_key_config_bridge"]["input_scan_indices_compared"],
                         ["0x13","0x14"])
        self.assertEqual(r["ui_key_config_bridge"]["config_parameter_ids"],
                         ["0x13","0x14","0x15","0x16"])
        self.assertFalse(r["ui_key_config_bridge"]["physical_key_legends_known"])
        self.assertFalse(r["mcu"]["silicon_vendor_confirmed"])

    def tamper(self,pc):
        b=bytearray(self.v2)
        b[pc-0x08001000]^=1
        return bytes(b)

    def test_mutation_detectors(self):
        sites=[
            0x08012BB8, # OEM calibration NV logical address 0xC5C0
            0x08012BEE, # four-word trim table store
            0x08012BEA, # signed trim multiplier
            0x08012CBE, # NV profile SRAM bank base literal
            0x08012D4A, # second 64-element halfword bank store
            0x0800A316, # audio mode 9 special
            0x0800A33C, # raw audio mode 0x6740
            0x0801501E, # GPIOA panel reset MMIO
            0x08015032, # reset GPIO bit8
            0x08015132, # orientation conditional jump
            0x0801524C, # orientation 0x60
            0x080153A4, # display-on command
            0x08009A92, # GPIOB bit1 reset (BRR)
            0x08009BB4, # GPIOB bit1 set (BSRR)
            0x08010B48, # key 0x13 to first conditional setting pair
            0x08010B4C, # key 0x14 to second conditional setting pair
            0x08010BB4, # OEM config ID 0x15, not a keypad index
            0x0800DA38, # GPIOB6 output set
            0x08011EC6, # GPIOB8 output set
            0x080138D2, # GPIOB14 output set
            0x0801720A, # GPIOD2 power-on set
        ]
        for pc in sites:
            with self.subTest(pc=hex(pc)),self.assertRaises(ValueError):
                verify_original(self.tamper(pc))

    def test_positive_and_negative_gamma_mutations(self):
        for pc in [GAMMA_POS_SITES[0][0],GAMMA_NEG_SITES[-1][0]]:
            with self.subTest(pc=hex(pc)),self.assertRaises(ValueError):
                verify_original(self.tamper(pc))
        self.assertEqual(len(GAMMA_POS_SITES),16)
        self.assertEqual(len(GAMMA_NEG_SITES),16)
        self.assertEqual(len(LCD_COMMAND_SITES),15)

    def test_trim_formula_matches_signed_original_word_cases(self):
        cases={0: -200,39:-5,40:0,41:5,96:280,97:0,255:0}
        for raw,signed in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(original_trim_word(raw),signed & 0xFFFFFFFF)
        for raw in (-1,256):
            with self.assertRaises(ValueError):original_trim_word(raw)

    def test_rust_core_uses_oem_trim_init_and_gpio_sw_pins(self):
        src={
            k:(ROOT/"firmware-pro/core/src"/(k+".rs")).read_text(encoding="utf-8")
            for k in ("nv_rf","lcd","audio","board_v2","fd6818")
        }
        for x in ("0xC5C0","0x28","0x60","original_trim_word",
                  "OEM_FREQUENCY_TRIM_UNITS_PER_BYTE: i32 = 5"):
            self.assertIn(x,src["nv_rf"])
        for x in ("OEM_GAMMA_POSITIVE","OEM_GAMMA_NEGATIVE",
                  "FirstFrameDisplayOn","reset_oem_panel","initialize_oem_registers"):
            self.assertIn(x,src["lcd"])
        for x in ("0x6740","0xB3AA","0x3028","0x4048"):
            self.assertIn(x,src["audio"])
        self.assertIn("OEM_SWITCH_PB1: Pin = Pin { port: Port::B, bit: 1 }",
                      src["board_v2"])
        key=(ROOT/"firmware-pro/core/src/keypad.rs").read_text(encoding="utf-8")
        self.assertIn("pub const fn conditional_oem_settings_pair",key)
        self.assertIn("0x14 => Some([0x15, 0x16])",key)
        self.assertIn("PANEL_RESET: Pin = Pin { port: Port::A, bit: 8 }",
                      src["board_v2"])
        self.assertIn("write_frequency_hz_with_oem_trim",src["fd6818"])


if __name__=="__main__":
    unittest.main()
