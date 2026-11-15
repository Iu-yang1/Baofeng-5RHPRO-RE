"""Check archive-specific clock getter identity without assuming fixed relocation."""

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from compare_sdk_windows import compare_window  # noqa: E402
from mcu_fingerprint import decoded_payload  # noqa: E402


class ClockGetterCrossVersionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.old = decoded_payload(
            (ROOT / "firmware/BF_5RH_501_v1_1_04.dat").read_bytes()
        )
        cls.new = decoded_payload(
            (ROOT / "firmware/BF_5RH_501_v2_0_9.dat").read_bytes()
        )

    def test_actual_getter_is_identical_across_versions(self):
        r = compare_window(self.old, self.new, 0x08024BBC, 0x08030C30, 0x94)
        self.assertTrue(r["exact_bytes"])
        self.assertEqual(r["matching_bytes"], 148)
        self.assertEqual(r["relocation_delta"], "0xC074")

    def test_wrong_uart_relocation_is_not_clock_getter_relocation(self):
        r = compare_window(self.old, self.new, 0x08024AFC, 0x08030C30, 0x94)
        self.assertFalse(r["exact_bytes"])
        self.assertLess(r["matching_percent"], 10)


if __name__ == "__main__":
    unittest.main()
