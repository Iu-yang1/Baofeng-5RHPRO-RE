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
                        "offset": f"IL_{instruction.offset:04X}",
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


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--file", type=Path, default=DATA_PATH)
    p.add_argument("--json", action="store_true")
    p.add_argument("--all-methods", action="store_true")
    args = p.parse_args()
    r = collect(args.file, args.all_methods)
    if args.json:
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
                print(i["offset"], i["opcode"], i["operand"])
        print("parse failures:", len(r["parse_failures"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
