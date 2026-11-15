"""Known direct-callsite evidence in the V2.0.09 decoded image."""

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from mcu_fingerprint import decoded_payload  # noqa: E402
from thumb_callsites import find_calls, scan_nearby_target  # noqa: E402


class ThumbCallsiteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.payload = decoded_payload(
            (ROOT / "firmware/BF_5RH_501_v2_0_9.dat").read_bytes()
        )

    def test_known_startup_and_clock_getter_calls(self):
        results = find_calls(self.payload, [0x08031BF4, 0x08030C30])
        self.assertIn(
            "0x0803240E",
            {x["call_pc"] for x in results["0x08031BF4"]},
        )
        self.assertIn(
            "0x08032D18",
            {x["call_pc"] for x in results["0x08030C30"]},
        )

    def test_absent_target_and_empty_image(self):
        self.assertEqual(find_calls(self.payload, [0x0807FFFF])["0x0807FFFE"], [])
        self.assertEqual(scan_nearby_target(b"\x00" * 128, 0x08001100, 0x08001200), [])


if __name__ == "__main__":
    unittest.main()
