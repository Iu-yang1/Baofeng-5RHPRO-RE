"""V2.0.09 UART RX/TX protocol fingerprints are tied to actual image instructions."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from mcu_fingerprint import decoded_payload  # noqa: E402
from v2_uart_protocol_evidence import analyze  # noqa: E402


class V2UartProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.payload = decoded_payload(
            (ROOT / "firmware/BF_5RH_501_v2_0_9.dat").read_bytes()
        )
        cls.report = analyze(cls.payload)

    def test_nmea_dma_uart2_original_evidence(self):
        row = self.report["gnss_nmea_rx"]
        self.assertEqual((row["uart"], row["baud"]), ("USART2", 9600))
        self.assertEqual(row["dma_transfer_length"], 1280)
        self.assertEqual(row["destination_buffer_sram"], "0x2000EB88")
        self.assertTrue(any("r0, #0x24" in x["instruction"] for x in row["instruction_evidence"]))

    def test_xor_tx_uart3_not_mislabeled_gnss(self):
        row = self.report["private_serial_protocol_candidate"]
        self.assertEqual(row["uart"], "USART3")
        self.assertEqual(row["baud"], 19200)
        self.assertEqual(row["dma_transfer_length"], 200)
        self.assertTrue(any(x["instruction"].startswith("eors")
                            for x in row["instruction_evidence"]))
        self.assertIn("not yet established", row["role"])

    def test_irq_buffer_uart1(self):
        row = self.report["usart1_irq_ring"]
        self.assertEqual(row["rx_ring_sram"], "0x200045A7")
        self.assertEqual(row["ring_capacity_bytes"], 20)

    def test_fingerprint_fail_closed_for_modified_source_instruction(self):
        payload = bytearray(self.payload)
        payload[0x0800F22A - 0x08001000] ^= 0x80
        with self.assertRaisesRegex(ValueError, "fingerprint mismatch"):
            analyze(bytes(payload))


if __name__ == "__main__":
    unittest.main()
