"""Read-only original V1/V2 keypad, FD6818 and FM I2C regression."""
from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from mcu_fingerprint import decoded_payload
from pro_v2_board_io_audit import (
    EXPECTED_KEYMAP, STOCK_SITES, KEY_COUNT,
    analyze, original_v2_key_table, verify_version,
)


class ProBoardOriginalCodeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v1 = decoded_payload((ROOT / "firmware/BF_5RH_501_v1_1_04.dat").read_bytes())
        cls.v2 = decoded_payload((ROOT / "firmware/BF_5RH_501_v2_0_9.dat").read_bytes())

    def test_cross_version_gpio_and_device_address_instruction_sites(self):
        result = analyze(self.v1, self.v2)
        self.assertGreaterEqual(result["v1_instruction_check"]["total"], 39)
        self.assertGreaterEqual(result["v2_instruction_check"]["total"], 60)
        self.assertEqual(result["interface_candidates"]["fd6818"]["write_byte"], "0xE2")
        self.assertEqual(result["interface_candidates"]["rda5807m"]["write_byte"], "0x22")
        self.assertEqual(result["interface_candidates"]["fd6818"]["gpio_software_sda"], "PC15")
        self.assertFalse(result["interface_candidates"]["fd6818"]["physical_qfn64_pad_mapping_proved"])

    def test_original_compressed_keymap_has_22_unambiguous_codes(self):
        report = original_v2_key_table(self.v2)
        self.assertEqual(report["entry_count"], 22)
        self.assertEqual(report["entry_stride_bytes"], 4)
        self.assertEqual(report["sram_address"], "0x200000A6")
        self.assertEqual(tuple(int(v, 16) for v in report["normalized_codes"]), EXPECTED_KEYMAP)
        self.assertEqual(len(set(EXPECTED_KEYMAP)), KEY_COUNT)

    def test_rust_core_table_uses_actual_original_decompressed_values(self):
        source = (ROOT / "firmware-pro/core/src/keypad.rs").read_text(encoding="utf-8")
        table = source.split("pub const ORIGINAL_SCAN_CODES:", 1)[1].split("];", 1)[0]
        values = tuple(int(v, 16) for v in re.findall(r"0x[0-9A-Fa-f]+", table))
        self.assertEqual(values, EXPECTED_KEYMAP)

    def corrupt(self, payload: bytes, pc: int) -> bytes:
        data = bytearray(payload)
        data[pc - 0x08001000] ^= 1
        return bytes(data)

    def test_keypad_gpio_literal_mutation_detected_in_v2(self):
        with self.assertRaises(ValueError):
            verify_version(self.corrupt(self.v2, 0x08010A50), "v2")

    def test_keypad_direction_config_mutation_detected_in_v1(self):
        with self.assertRaises(ValueError):
            verify_version(self.corrupt(self.v1, 0x0800B126), "v1")

    def test_keypad_lookup_stride_mutation_detected(self):
        with self.assertRaises(ValueError):
            verify_version(self.corrupt(self.v2, 0x08010A2A), "v2")

    def test_fm_i2c_index_address_mutation_detected(self):
        with self.assertRaises(ValueError):
            verify_version(self.corrupt(self.v2, 0x08030DF8), "v2")

    def test_rfic_i2c_write_address_mutation_detected(self):
        with self.assertRaises(ValueError):
            verify_version(self.corrupt(self.v1, 0x08002382), "v1")

    def test_rfic_gpio_data_pin_mutation_detected(self):
        with self.assertRaises(ValueError):
            verify_version(self.corrupt(self.v2, 0x08005F94), "v2")

    def test_rfic_split_frequency_register_mutation_detected(self):
        with self.assertRaises(ValueError):
            verify_version(self.corrupt(self.v2, 0x08005ECC), "v2")

    def test_fm_gpio_clock_pin_mutation_detected(self):
        with self.assertRaises(ValueError):
            verify_version(self.corrupt(self.v2, 0x08030F92), "v2")

    def test_lcd_spi2_window_and_rgb565_scanout_evidence(self):
        result = analyze(self.v1, self.v2)
        lcd = result["lcd"]
        self.assertEqual(lcd["spi_compatible_register_base"], "0x40003800")
        self.assertEqual(lcd["software_width_px"], 160)
        self.assertEqual(lcd["software_height_px"], 128)
        self.assertEqual(lcd["software_row_stride_bytes"], 320)
        self.assertEqual(lcd["software_framebuffer_end_exclusive"], "0x2000EB76")
        self.assertEqual(lcd["between_buffer_gap_bytes"], 18)
        self.assertTrue(lcd["rgb565_big_endian_on_wire"])
        self.assertTrue(lcd["physical_panel_rotation_unverified"])

    def test_spi2_command_literal_mutation_detected(self):
        with self.assertRaises(ValueError):
            verify_version(self.corrupt(self.v2, 0x08007554), "v2")

    def test_spi2_data_gpio_literal_mutation_detected(self):
        with self.assertRaises(ValueError):
            verify_version(self.corrupt(self.v2, 0x08007588), "v2")

    def test_lcd_buffer_literal_mutation_detected(self):
        with self.assertRaises(ValueError):
            verify_version(self.corrupt(self.v2, 0x080153B0), "v2")

    def test_lcd_rgb565_stride_mutation_detected(self):
        with self.assertRaises(ValueError):
            verify_version(self.corrupt(self.v2, 0x0801527E), "v2")

    def test_lcd_window_command_mutation_detected(self):
        with self.assertRaises(ValueError):
            verify_version(self.corrupt(self.v2, 0x0801535A), "v2")

    def test_documented_keypad_evidence_is_measurable_not_labeled(self):
        evidence = analyze(self.v1, self.v2)
        self.assertFalse(evidence["keypad"]["physical_key_labels_known"])
        self.assertEqual(evidence["interface_candidates"]["keypad"]["unknown_key_code"], "0xFF")


if __name__ == "__main__":
    unittest.main()
