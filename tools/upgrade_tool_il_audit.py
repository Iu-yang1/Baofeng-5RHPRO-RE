#!/usr/bin/env python3
"""Static .NET IL evidence capture for the archived Baofeng UpgradeTool.

Never load or execute the managed assembly, call serial ports or emit upload data.
Reads only its metadata tables, user strings and managed-method IL.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import dnfile
from dnfile.enums import MetadataTables
from dncil.cil.body import CilMethodBody
from dncil.cil.body.reader import CilMethodBodyReaderBase
from dncil.cil.error import MethodBodyFormatError
from dncil.clr.token import Token, StringToken

TABLE_NAMES = {table.value: table.name for table in MetadataTables}
INTEREST = ("update", "flash", "download", "write", "read", "com", "check", "baud", "send", "progress", "form", "start", "size", "data")
DATA_PATH = Path("UpgradeTool/bin/Release/net20/Radio.exe")


class MethodReader(CilMethodBodyReaderBase):
    def __init__(self, pe, rva):
        self.pe = pe
        self.offset = pe.get_offset_from_rva(rva)

    def read(self, n):
        data = self.pe.get_data(self.pe.get_rva_from_offset(self.offset), n)
        self.offset += len(data)
        return data

    def tell(self):
        return self.offset

    def seek(self, offset):
        self.offset = offset
        return offset


def describe(pe, operand):
    if isinstance(operand, StringToken):
        us = pe.net.user_strings.get(operand.rid)
        return {"token": f"0x{operand.value:08X}",
                "value": us.value if us is not None and us.value is not None else None}
    if isinstance(operand, Token):
        table = TABLE_NAMES.get(operand.table)
        rows = getattr(pe.net.mdtables, table, None) if table else None
        row = rows.rows[operand.rid - 1] if rows and 0 < operand.rid <= len(rows.rows) else None
        name = str(getattr(row, "Name", getattr(row, "TypeName", ""))) if row else None
        return {"token": f"0x{operand.value:08X}", "table": table, "name": name}
    if isinstance(operand, (int, float, str, list)):
        return operand
    return str(operand) if operand is not None else None


def collect(path: Path, include_all: bool = False) -> dict:
    data = path.read_bytes()
    pe = dnfile.dnPE(data=data)
    if not pe.net or not pe.net.mdtables.MethodDef:
        raise ValueError("missing .NET MethodDef metadata")
    records = []
    selected = []
    failures = []
    for rid, row in enumerate(pe.net.mdtables.MethodDef.rows, 1):
        label = str(row.Name)
        method = {"rid": rid, "token": f"0x{0x06000000 | rid:08X}",
                  "name": label, "rva": f"0x{row.Rva:08X}"}
        if not row.Rva:
            continue
        try:
            body = CilMethodBody(MethodReader(pe, row.Rva))
        except (MethodBodyFormatError, ValueError) as e:
            failures.append({"method": label, "error": str(e)})
            continue
        method["il_code_size"] = body.code_size
        method["instruction_count"] = len(body.instructions)
        records.append(method)
        if include_all or any(s in label.lower() for s in INTEREST):
            selected.append({
                **method,
                "instructions": [
                    {
                        "pe_offset": f"0x{instruction.offset:08X}",
                        "il_offset": f"IL_{instruction.offset - body.offset - body.header_size:04X}",
                        "opcode": instruction.mnemonic,
                        "operand": describe(pe, instruction.operand),
                        "bytes": instruction.get_bytes().hex(),
                    }
                    for instruction in body.instructions
                ],
            })
    return {
        "source": str(path),
        "sha256": hashlib.sha256(data).hexdigest(),
        "pe_bytes": len(data),
        "method_count": len(records),
        "methods": records,
        "selected": selected,
        "parse_failures": failures,
        "limit": "Read-only IL; no managed code execution, no hardware or serial access",
    }



RELEASE_SHA256 = "782ea95bc3b6bbb8100b2f80e65eefc59fedf1ea007c2ed393136b3caa62ae19"

def verify_upgrade_il(snapshot: dict) -> dict:
    """Require source-stable MethodDef tokens and real IL instruction operands."""
    if snapshot["sha256"] != RELEASE_SHA256 or snapshot["method_count"] != 482 or snapshot["parse_failures"]:
        raise ValueError("unexpected OEM Release binary or metadata inventory")
    methods = {m["token"]: m for m in snapshot["selected"]}
    for token, name in (("0x0600018C", "UpdateFirmware"),
                        ("0x0600018D", "DoReadData"),
                        ("0x0600018E", "DoWriteData")):
        if token not in methods or methods[token]["name"] != name:
            raise ValueError(f"missing {token} / {name}")
    read = methods["0x0600018D"]
    if read["il_code_size"] != 1 or [i["opcode"] for i in read["instructions"]] != ["ret"]:
        raise ValueError("DoReadData is no longer a one-instruction stub")
    dispatch = methods["0x0600018C"]
    delegates = {i["operand"].get("token") for i in dispatch["instructions"]
                 if i["opcode"] == "ldftn" and isinstance(i["operand"], dict)}
    if not {"0x0600018D", "0x0600018E"} <= delegates:
        raise ValueError("UpdateFirmware no longer selects read/write delegates")
    write = methods["0x0600018E"]
    if write["il_code_size"] != 1667:
        raise ValueError("DoWriteData method size changed")
    actual = {int(i["pe_offset"], 16): i for i in write["instructions"]}
    checks = {
        0x91F6: ("ldc.i4", 1024),
        0x93DF: ("ldsfld", "CMD_FLASH"),
        0x93FB: ("ldc.i4.s", 40),
        0x9435: ("ldc.i4.s", 16),
        0x9498: ("ldsfld", "CMD_PRG"),
        0x94B1: ("ldc.i4.8", None),
        0x94FC: ("ldc.i4.s", 80),
        0x9558: ("ldc.i4", 1024),
        0x959E: ("ldc.i4.s", 24),
        0x95A8: ("ldc.i4.s", 16),
        0x95B2: ("ldc.i4.8", None),
        0x9605: ("ldc.i4.5", None),
        0x9606: ("callvirt", "Write"),
        0x9612: ("callvirt", "Write"),
        0x976D: ("ldstr", "Communication success"),
    }
    for pc, (opcode, target) in checks.items():
        inst = actual.get(pc)
        if inst is None or inst["opcode"] != opcode:
            raise ValueError(f"IL opcode mismatch at PE offset 0x{pc:04X}: {inst}")
        value = inst["operand"]
        if isinstance(value, dict):
            value = value.get("name", value.get("value"))
        if target is not None and value != target:
            raise ValueError(f"IL operand mismatch at PE offset 0x{pc:04X}: {value}")
    consts = [i["operand"] for i in write["instructions"]
              if i["opcode"].startswith("ldc.i4") and isinstance(i["operand"], int)]
    return {
        "sha256": snapshot["sha256"],
        "method_body_count": snapshot["method_count"],
        "read_entry": {"method": "0x0600018D", "body": "ret", "flash_backup_implemented": False},
        "dispatch": {"method": "0x0600018C", "read": "0x0600018D", "write": "0x0600018E"},
        "write_entry": {
            "method": "0x0600018E",
            "size_bytes": write["il_code_size"],
            "verified_pe_offsets": [f"0x{pc:04X}" for pc in checks],
            "wire_chunk_bytes": 1024,
            "wire_offset_bytes": 4,
            "wire_offset_endianness": "big",
            "file_header_skipped_bytes": 80,
            "end_ack_followed_by_success_message": True,
            "hardcoded_cpu_flash_addresses": [
                f"0x{v:08X}" for v in consts if 0x08000000 <= v < 0x08200000
            ],
        },
        "limitations": [
            "PE file offsets are distinct from method-relative IL offsets.",
            "No target-side Bootloader or memory controller examined.",
            "No executed code, UART communication or device flashing.",
        ],
    }

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--file", type=Path, default=DATA_PATH)
    p.add_argument("--json", action="store_true")
    p.add_argument("--all-methods", action="store_true")
    p.add_argument("--verify", action="store_true")
    args = p.parse_args()
    r = collect(args.file, args.all_methods)
    if args.verify:
        print(json.dumps(verify_upgrade_il(r), indent=2, ensure_ascii=False))
    elif args.json:
        print(json.dumps(r, indent=2, ensure_ascii=False))
    else:
        print("UpgradeTool IL:", r["method_count"], "methods;", len(r["selected"]), "selected")
        print("SHA-256:", r["sha256"])
        for m in r["methods"]:
            print(m["token"], m["name"], m["il_code_size"], "bytes")
        for m in r["selected"]:
            if not any(s in m["name"].lower() for s in ("update", "flash", "download", "write", "read")):
                continue
            print("METHOD", m["token"], m["name"])
            for i in m["instructions"]:
                print(i["pe_offset"], i["il_offset"], i["opcode"], i["operand"])
        print("parse failures:", len(r["parse_failures"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
