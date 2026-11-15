"""Tests for read-only MCU fingerprinting."""

from __future__ import annotations

import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from mcu_fingerprint import analyze, decoded_payload  # noqa: E402

KEY = 0xC8


def package(peripheral: int = 0x40023800, encrypted: bool = True) -> bytes:
    body = bytearray(256)
    struct.pack_into("<I", body, 0, 0x20002000)
    struct.pack_into("<I", body, 4, 0x0800123D)
    for index in range(64, 96, 4):
        struct.pack_into("<I", body, index, peripheral)
    header = bytearray(b"\xff" * 80)
    header[:7] = b"BaoFeng"
    header[16:22] = b"BF_5RH"
    header[32:40] = b"V1.0.0.0"
    header[48:56] = b"V2.0.0.0"
    struct.pack_into(">I", header, 64, len(body))
    encoded = bytes(x ^ KEY for x in body) if encrypted else bytes(body)
    return bytes(header) + encoded


class McufingerprintTests(unittest.TestCase):
    def test_encrypted_and_decrypted_same_result(self):
        left = analyze(package())
        right = analyze(package(encrypted=False))
        self.assertEqual(left["peripheral_top_words"], right["peripheral_top_words"])
        self.assertEqual(left["initial_sp_candidate"], "0x20002000")
        self.assertEqual(left["reset_handler_candidate"], "0x0800123D")
        self.assertEqual(decoded_payload(package()), decoded_payload(package(encrypted=False)))

    def test_peripheral_word_counts(self):
        report = analyze(package())
        self.assertEqual(report["peripheral_top_words"][0],
                         {"address": "0x40023800", "count": 8})
        self.assertEqual(report["peripheral_4k_bank_counts"][0],
                         {"bank": "0x40023000", "count": 8})

    def test_reject_malformed_header(self):
        image = bytearray(package())
        image[0] = 0
        with self.assertRaises(ValueError):
            analyze(bytes(image))

    def test_reject_unknown_xor_state(self):
        image = bytearray(package())
        image[0x53] = 0xAA
        with self.assertRaises(ValueError):
            analyze(bytes(image))


if __name__ == "__main__":
    unittest.main()
