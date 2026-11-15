"""Check V2 memory sections are internally consistent without asserting chip RAM size."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from mcu_fingerprint import decoded_payload  # noqa: E402
from v2_memory_layout import analyze  # noqa: E402


class V2MemoryLayoutTests(unittest.TestCase):
    def test_original_image_linker_boundaries(self):
        data = decoded_payload(
            (ROOT / "firmware/BF_5RH_501_v2_0_9.dat").read_bytes()
        )
        r = analyze(data)
        self.assertEqual(r["initial_msp_candidate"], "0x20011308")
        self.assertEqual(r["data_region"]["destination"], "0x20000000")
        self.assertEqual(r["data_region"]["length"], 7084)
        self.assertEqual(r["zero_region"]["length"], 63324)
        self.assertEqual(r["zero_region"]["destination"], "0x20001BAC")
        self.assertEqual(r["total_init_bytes"], 70408)
        self.assertTrue(r["data_then_zero_contiguous"])
        self.assertTrue(r["last_region_end_equals_initial_msp"])


if __name__ == "__main__":
    unittest.main()
