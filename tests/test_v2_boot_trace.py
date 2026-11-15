"""Synthetic-data tests for V2 boot-trace analysis (no radio access)."""

from __future__ import annotations

import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from mcu_fingerprint import decoded_payload  # noqa: E402
from v2_boot_trace import compare, trace  # noqa: E402


def fixture(peripheral=0x40013800, reset=0x08001101) -> bytes:
    header = bytearray(b"\xff" * 0x50)
    header[:7] = b"BaoFeng"
    header[0x10:0x16] = b"BF_5RH"
    header[0x20:0x28] = b"V1.0.0.0"
    header[0x30:0x38] = b"V2.0.0.0"
    data = bytearray(1024)
    struct.pack_into(">I", header, 0x40, len(data))
    struct.pack_into("<I", data, 0, 0x20011308)
    struct.pack_into("<I", data, 4, reset)
    # LDR r0, [PC, #0], then BX LR. The literal word is peripheral address.
    struct.pack_into("<H", data, 0x100, 0x4800)
    struct.pack_into("<H", data, 0x102, 0x4770)
    struct.pack_into("<I", data, 0x104, peripheral)
    return bytes(header) + bytes(b ^ 0xC8 for b in data)


class V2BootTraceTests(unittest.TestCase):
    def test_reset_and_peripheral_xref(self):
        image = fixture()
        report = trace(decoded_payload(image))
        self.assertEqual(report["initial_stack_pointer_candidate"], "0x20011308")
        self.assertEqual(report["reset_candidate"], "0x08001101")
        self.assertEqual(report["vector_unique_entry_points"], 1)
        self.assertEqual(report["vector_valid_thumb_entries"], 1)
        self.assertEqual(report["reachable_instruction_candidates"], 2)
        self.assertIn({"address": "0x40013800", "load_sites": 1},
                      report["peripheral_addresses"])
        self.assertEqual(report["literal_cross_reference_sample"][0]["load_pc"],
                         "0x08001100")
        self.assertEqual(len(report["thumb2_m3_plus_clues"]), 0)

    def test_reports_real_changes_only(self):
        first = trace(decoded_payload(fixture(0x40013800)))
        second = trace(decoded_payload(fixture(0x40012400)))
        diff = compare(first, second)
        self.assertEqual(diff["vector_entries_changed"], [])
        self.assertEqual(diff["old_only_peripheral_addresses"], ["0x40013800"])
        self.assertEqual(diff["new_only_peripheral_addresses"], ["0x40012400"])
        self.assertTrue(diff["identical_reset_candidates"])

    def test_different_reset_vectors(self):
        first = trace(decoded_payload(fixture()))
        second = trace(decoded_payload(fixture(reset=0x08001105)))
        diff = compare(first, second)
        self.assertEqual(diff["vector_entries_changed"][0]["index"], 1)
        self.assertFalse(diff["identical_reset_candidates"])

    def test_literal_fed_blx_follows_startup_veneer(self):
        package = bytearray(fixture())
        decoded = bytearray(decoded_payload(bytes(package)))
        # Reset: ldr r0,[pc,#4] -> 0x08001108, blx r0, bx lr.
        struct.pack_into("<H", decoded, 0x100, 0x4801)
        struct.pack_into("<H", decoded, 0x102, 0x4780)
        struct.pack_into("<H", decoded, 0x104, 0x4770)
        struct.pack_into("<I", decoded, 0x108, 0x08001121)
        struct.pack_into("<H", decoded, 0x120, 0x4770)
        report = trace(bytes(decoded))
        self.assertIn(
            {"target": "0x08001120", "sites": 1},
            report["resolved_indirect_branch_targets"],
        )
        self.assertIn(
            {"branch_site": "0x08001102", "resolved_target": "0x08001121"},
            report["indirect_branch_sample"],
        )
        self.assertGreaterEqual(report["reachable_instruction_candidates"], 4)

    def test_rejects_invalid_package(self):
        image = bytearray(fixture())
        image[0] = 0
        with self.assertRaises(ValueError):
            decoded_payload(bytes(image))


if __name__ == "__main__":
    unittest.main()
