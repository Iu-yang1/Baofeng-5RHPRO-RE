"""Synthetic instruction tests for read-only firmware clock-register tracing."""

from __future__ import annotations

import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from clock_register_trace import analyze  # noqa: E402
from mcu_fingerprint import decoded_payload  # noqa: E402

BASE = 0x08001000


def image(veneer: bool = False) -> bytes:
    data = bytearray(0x400)
    struct.pack_into("<II", data, 0, 0x20011308, BASE + 0x101)
    if veneer:
        # LDR r0, [PC, #4] -> 0x08001108; BLX r0; BX LR.
        struct.pack_into("<HHH", data, 0x100, 0x4801, 0x4780, 0x4770)
        struct.pack_into("<I", data, 0x108, BASE + 0x121)
        offset, target, value = 0x120, 0x40022000, 5
    else:
        offset, target, value = 0x100, 0x40021000, 3
    # LDR r0, [PC, #8]; MOVS r1,#value; STR r1,[r0];
    # LDR r2,[r0]; BX LR; NOP; then 32-bit literal.
    struct.pack_into("<HHHHHHI", data, offset,
                     0x4802, 0x2100 + value, 0x6001, 0x6802,
                     0x4770, 0xBF00, target)
    # Misleading aligned literal in unreachable data: must not be counted.
    struct.pack_into("<I", data, 0x300, 0x40021000)
    header = bytearray(b"\xff" * 0x50)
    header[:7] = b"BaoFeng"
    header[0x10:0x16] = b"BF_5RH"
    header[0x20:0x28] = b"V1.0.0.0"
    header[0x30:0x38] = b"V2.0.0.0"
    struct.pack_into(">I", header, 0x40, len(data))
    return bytes(header) + bytes(x ^ 0xC8 for x in data)


class ClockRegisterTraceTests(unittest.TestCase):
    def test_register_read_write_and_known_value(self):
        r = analyze(decoded_payload(image()))
        self.assertEqual(r["scope"], "reset")
        self.assertEqual(r["reset_vector"], "0x08001101")
        writes = [x for x in r["register_accesses"] if x["type"] == "write"]
        reads = [x for x in r["register_accesses"] if x["type"] == "read"]
        self.assertEqual(len(writes), 1)
        self.assertEqual(len(reads), 1)
        self.assertEqual(writes[0]["address"], "0x40021000")
        self.assertEqual(writes[0]["write_constant"], "0x00000003")
        self.assertEqual(reads[0]["address"], "0x40021000")
        self.assertEqual(r["unique_instruction_candidates"], 5)
        self.assertEqual(len(r["register_literals"]), 1)

    def test_indirect_startup_veneer_reaches_flash_setup(self):
        r = analyze(decoded_payload(image(veneer=True)))
        self.assertIn(
            {"pc": "0x08001102", "kind": "blx", "target": "0x08001120"},
            r["resolved_indirect_control_transfers"],
        )
        writes = [x for x in r["register_accesses"] if x["type"] == "write"]
        self.assertEqual(writes[0]["bank"], "FLASH")
        self.assertEqual(writes[0]["write_constant"], "0x00000005")

    def test_unreachable_fake_constant_not_a_register_access(self):
        r = analyze(decoded_payload(image(veneer=True)))
        self.assertNotIn("CRM/RCC:write", r["crm_related_access_counts"])
        self.assertFalse(any(x["address"] == "0x40021000" for x in r["register_accesses"]))

    def test_invalid_scope_vector_size(self):
        with self.assertRaisesRegex(ValueError, "vector window"):
            analyze(b"\x00" * 12)

    def test_both_seed_scopes_are_supported(self):
        payload = decoded_payload(image())
        self.assertEqual(analyze(payload, scope="vectors")["root_count"], 1)
        self.assertEqual(analyze(payload, scope="reset")["root_count"], 1)


if __name__ == "__main__":
    unittest.main()
