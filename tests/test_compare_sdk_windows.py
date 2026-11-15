"""Pure window-comparison tests for relocated firmware functions."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from compare_sdk_windows import BASE, compare_window  # noqa: E402


class SdkWindowTests(unittest.TestCase):
    def test_identical_region_shifted_address(self):
        old = bytes(range(64))
        new = b"\x00" * 10 + old
        result = compare_window(old, new, BASE+8, BASE+18, 16)
        self.assertTrue(result["exact_bytes"])
        self.assertEqual(result["relocation_delta"], "0xA")
        self.assertEqual(result["equal_prefix_bytes"], 16)

    def test_patches_are_reported_without_exporting_bytes(self):
        old = bytes(range(64))
        new = bytearray(old)
        new[10] ^= 0x3
        result = compare_window(old, bytes(new), BASE+4, BASE+4, 20)
        self.assertFalse(result["exact_bytes"])
        self.assertEqual(result["matching_bytes"], 19)
        self.assertEqual(result["mismatch_offsets_sample"], [6])
        self.assertEqual(result["equal_prefix_bytes"], 6)
        self.assertNotIn("firmware_bytes", result)

    def test_rejects_outside_range(self):
        with self.assertRaises(ValueError):
            compare_window(bytes(10), bytes(10), BASE+9, BASE, 2)
        with self.assertRaises(ValueError):
            compare_window(bytes(10), bytes(10), BASE, BASE, 0)


if __name__ == "__main__":
    unittest.main()
