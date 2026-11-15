"""Verify original ARM scatterload decompression and restored SRAM tables."""

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from mcu_fingerprint import decoded_payload  # noqa: E402
from v2_scatterload_decode import decompress_region, inspect_tables  # noqa: E402


class ScatterloadDecodeTests(unittest.TestCase):
    def test_literal_and_zero_run_with_predecrement(self):
        # Low 3-bit literal count encodes N+1, high nibble zero-run count.
        value, consumed = decompress_region(b"\x23AB", 4)
        self.assertEqual(value, b"AB\x00\x00")
        self.assertEqual(consumed, 3)

    def test_overlap_backward_reference(self):
        value, consumed = decompress_region(b"\x2cABC\x03", 7)
        self.assertEqual(value, b"ABCABCA")
        self.assertEqual(consumed, 5)

    def test_extended_literal_count(self):
        value, consumed = decompress_region(b"\x20\x02X", 3)
        self.assertEqual(value, b"X\x00\x00")
        self.assertEqual(consumed, 3)

    def test_real_v2_sram_prescaler_table(self):
        package = (ROOT / "firmware/BF_5RH_501_v2_0_9.dat").read_bytes()
        r = inspect_tables(decoded_payload(package))
        self.assertEqual(r["region_size"], 7084)
        self.assertEqual(r["source_address"], "0x08061A54")
        self.assertEqual(r["adc_prescaler_table_4"], [2, 4, 6, 8])
        self.assertEqual(
            r["clock_prescaler_table_first16"],
            [0, 0, 0, 0, 1, 2, 3, 4, 1, 2, 3, 4, 6, 7, 8, 9],
        )
        self.assertEqual(
            r["decompressed_sha256"],
            "78b4cd40871079ecc1ceacf33f1379a8c76ea84a2b3b7155b98c4753d5ae7627",
        )

    def test_incomplete_or_invalid_reference(self):
        with self.assertRaisesRegex(ValueError, "truncated"):
            decompress_region(b"\x2cABC", 7)
        with self.assertRaisesRegex(ValueError, "backward-reference"):
            decompress_region(b"\x2cABC\x09", 7)


if __name__ == "__main__":
    unittest.main()
