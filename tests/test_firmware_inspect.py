"""Tests for the read-only firmware inspection tool."""

from __future__ import annotations

import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from firmware_inspect import HEADER_SIZE, XOR_KEY, inspect_bytes, inspect_file  # noqa: E402


def fixture(*, obfuscated: bool = True, payload_size: int = 32) -> bytes:
    header = bytearray(b"\xff" * HEADER_SIZE)
    header[0:7] = b"BaoFeng"
    header[0x10:0x16] = b"BF_5RH"
    header[0x20:0x28] = b"V1.0.0.0"
    header[0x30:0x38] = b"V2.0.0.0"
    struct.pack_into(">I", header, 0x40, payload_size)
    payload = struct.pack("<II", 0x20001000, 0x08000101)
    payload += bytes(payload_size - len(payload))
    if obfuscated:
        payload = bytes(byte ^ XOR_KEY for byte in payload)
    return bytes(header) + payload


class FirmwareInspectorTests(unittest.TestCase):
    def test_obfuscated_package_and_vector_hint(self):
        image = fixture()
        before = bytes(image)
        report = inspect_bytes(image)
        self.assertEqual(report["errors"], [])
        self.assertEqual(report["header"]["field_0x30"], "V2.0.0.0")
        self.assertEqual(report["payload"]["xor_state_hint"], "xor-obfuscated")
        self.assertEqual(report["payload"]["vector_hint"]["initial_sp"], "0x20001000")
        self.assertTrue(report["payload"]["vector_hint"]["thumb_reset_hint"])
        self.assertEqual(image, before)

    def test_deobfuscated_package(self):
        report = inspect_bytes(fixture(obfuscated=False))
        self.assertEqual(report["errors"], [])
        self.assertEqual(report["payload"]["xor_state_hint"], "deobfuscated")

    def test_mismatched_length(self):
        report = inspect_bytes(fixture()[:-1])
        self.assertTrue(any("length mismatch" in msg for msg in report["errors"]))

    def test_missing_signature(self):
        image = bytearray(fixture())
        image[:7] = b"Invalid"
        report = inspect_bytes(bytes(image))
        self.assertTrue(any("brand signature" in msg for msg in report["errors"]))

    def test_truncated_header(self):
        report = inspect_bytes(b"BaoFeng")
        self.assertTrue(report["errors"])
        self.assertIsNone(report["header"])

    def test_unknown_marker_not_assumed_encrypted(self):
        image = bytearray(fixture())
        image[0x53] = 0xFF
        report = inspect_bytes(bytes(image))
        self.assertEqual(report["payload"]["xor_state_hint"], "unknown")
        self.assertIsNone(report["payload"]["vector_hint"])

    def test_checked_in_firmware_packages(self):
        firmware_dir = ROOT / "firmware"
        paths = sorted(firmware_dir.glob("*.dat"))
        self.assertEqual(len(paths), 6, "upstream baseline should contain six packages")
        for path in paths:
            with self.subTest(image=path.name):
                report = inspect_file(path)
                self.assertEqual(report["errors"], [])
                self.assertEqual(
                    report["header"]["declared_payload_length"],
                    report["payload"]["actual_length"],
                )


if __name__ == "__main__":
    unittest.main()
