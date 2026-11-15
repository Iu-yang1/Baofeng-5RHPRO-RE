"""Reproducible V2 UART literal/IRQ vectors and SDK entrypoint assertions."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from mcu_fingerprint import decoded_payload  # noqa: E402
from v2_uart_irq_evidence import analyze, vector_evidence, literal_references  # noqa: E402


class V2UartIrqEvidenceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.payload = decoded_payload((ROOT / "firmware/BF_5RH_501_v2_0_9.dat").read_bytes())

    def test_original_firmware_uart_initializers_present(self):
        result = analyze(self.payload)
        self.assertGreaterEqual(
            result["sdk_candidate_direct_caller_counts"]["USART_Init_candidate"], 3
        )
        for name in ("USART1", "USART2", "USART3"):
            self.assertGreater(
                result["register_literal_site_counts"].get(name, 0), 0,
                name,
            )

    def test_irq_candidates_are_indexed_not_claimed_live(self):
        rows = vector_evidence(self.payload)
        self.assertEqual(rows["USART1"]["vector_index"], 53)
        self.assertEqual(rows["USART2"]["vector_index"], 54)
        self.assertEqual(rows["USART3"]["vector_index"], 55)
        self.assertEqual(rows["DMA1_Channel4"]["vector_index"], 30)

    def test_cannot_forge_xref_from_arbitrary_alignment(self):
        self.assertEqual(literal_references(bytes(400)), [])

    def test_requires_full_candidate_vector_window(self):
        with self.assertRaisesRegex(ValueError, "vector"):
            vector_evidence(b"\x00" * 40)


if __name__ == "__main__":
    unittest.main()
