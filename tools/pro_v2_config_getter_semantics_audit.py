#!/usr/bin/env python3
"""Check original V2 0x0800E454 67-case getter at instruction/field level.

The 67 entries are working-SRAM configuration *reads*, not 67 visible
menu labels. Several reads repair invalid SRAM byte values in-place.
No radio access, disassembly of jump table bytes as code, or NV writes.
"""
from __future__ import annotations
import argparse
import json
import re
from pathlib import Path

from mcu_fingerprint import decoded_payload
from thumb_window import inspect_window
from pro_v2_mode_ui_contract_audit import MENU_OFFSETS, TBB_BASE, check_sites

IMAGE=Path("firmware/BF_5RH_501_v2_0_9.dat")
CONFIG_BASE=0x20004580
GETTER_ENTRY=0x0800E454
FIRST_OPCODES=[
    "ldrb","ldrb","ldrb","ldrb","lsr.w","and","ldrb","ldrb",
    "ldrb","ldrb","ldrb","ldrb","ldrb","ldrb","ldrb","ldrb",
    "ldrb","ldrb","ldrb","ldrb","ldrb","ldrb","ldrb","ldrb.w",
    "lsrs","ubfx","ubfx","ubfx","ubfx","and","mov","mov",
    "pop.w","mov","ubfx","lsrs","ubfx","ubfx","ubfx","ldrb",
    "pop.w","pop.w","lsrs","ubfx","ubfx","ubfx","and","lsrs",
    "ubfx","ubfx","ubfx","and","ldrb.w","ldrb","ldrb.w","ldrb",
    "ldrb","movs","mov","movs","ldrb.w","lsrs","ubfx","ubfx",
    "ubfx","ubfx","ubfx",
]

# One source byte per register loaded in the original function prologue.
PRELOADS={
    "fp":(0x0800E45E,4),
    "r3":(0x0800E462,21),
    "sl":(0x0800E464,22),
    "sb":(0x0800E468,23),
    "r6":(0x0800E46C,24),
    "r5":(0x0800E46E,26),
    "r4":(0x0800E470,27),
    "lr":(0x0800E472,35),
    "r2":(0x0800E476,37),
}
LIMITED={
    0:(0,2,0),
    1:(1,2,0),
    2:(2,10,0),
    3:(3,10,0),
    7:(6,1,0),
    8:(7,10,5),
    18:(20,4,0),
}
READ_LITERAL_SITES=[
    (0x0800E458,"ldr","r1, [pc",CONFIG_BASE),
    (0x0800E45A,"mov","ip, r0",None),
    (0x0800E45C,"movs","r0, #0",None),
    (0x0800E47C,"cmp.w","ip, #0x43",None),
    (0x0800E480,"bhs","#0x800e4d4",None),
    (0x0800E482,"tbb","[pc, ip]",None),
]

def _instructions(payload,pc,count=5):
    return inspect_window(payload,pc,pc+20)[:count]

def verify_original(payload:bytes)->dict:
    assert len(FIRST_OPCODES)==67
    check_sites(payload,READ_LITERAL_SITES)
    for register,(pc,offset) in PRELOADS.items():
        row=_instructions(payload,pc,1)[0]
        if not row["mnemonic"].startswith("ldrb") or register not in row["operands"]:
            raise ValueError(f"original configuration preload changed {register}: {row}")
        token=f"#0x{offset:x}" if offset>=10 else f"#{offset}"
        if token not in row["operands"]:
            raise ValueError(f"original field offset changed {register}: {row}")

    handler_types={}
    for id_,relative in enumerate(MENU_OFFSETS):
        pc=TBB_BASE+relative*2
        ins=_instructions(payload,pc)
        if not ins or ins[0]["mnemonic"] != FIRST_OPCODES[id_]:
            raise ValueError(f"case {id_} 0x{pc:08X}: unexpected first Thumb opcode {ins[:1]}")
        if id_ in LIMITED:
            offset,max_value,replacement=LIMITED[id_]
            expected_cmp=(f"#{max_value}" if max_value<10 else f"#0x{max_value:x}")
            if ins[1]["mnemonic"]!="cmp" or expected_cmp not in ins[1]["operands"]:
                raise ValueError(f"case {id_} changed bounds check: {ins[1]}")
            # Within this branch the original case writes to the same byte.
            upcoming=_instructions(payload,pc,7)
            if not any(x["mnemonic"].startswith("strb") for x in upcoming):
                raise ValueError(f"case {id_} no longer repairs stored SRAM byte")
            if replacement==5 and not any(x["mnemonic"]=="movs" and "#5" in x["operands"]
                                           for x in upcoming):
                raise ValueError("case 8 no longer repairs to 5")
        handler_types[id_]=ins[0]["mnemonic"]

    # Explicit source register/bitfield pathways that use shared handlers.
    source_shared=[
        (0x0800E58E,"mov","r0, sl"),
        (0x0800E590,"b","#0x800e5b8"),
        (0x0800E592,"mov","r0, sl"),
        (0x0800E594,"b","#0x800e60e"),
        (0x0800E596,"mov","r0, sb"),
        (0x0800E598,"b","#0x800e5b8"),
        (0x0800E5B8,"lsrs","r0, r0, #7"),
        (0x0800E60C,"mov","r0, lr"),
        (0x0800E60E,"ubfx","r0, r0, #6, #1"),
        (0x0800E614,"movs","r0, #1"),
    ]
    check_sites(payload,source_shared)
    for idx in [32,40,41]:
        if TBB_BASE+MENU_OFFSETS[idx]*2 != 0x0800E4D4:
            raise ValueError("original config default-zero branch changed")
    for idx in [57,59]:
        if TBB_BASE+MENU_OFFSETS[idx]*2 != 0x0800E614:
            raise ValueError("original const-one config case changed")
    return {
        "oem_getter_entry":"0x0800E454",
        "oem_working_sram_base":"0x20004580",
        "config_ids":len(handler_types),
        "highest_direct_byte_offset":37,
        "observed_getter_minimum_working_span_bytes":38,
        "preloaded_registers_and_offsets":{r:o for r,(_,o) in PRELOADS.items()},
        "side_effectful_bounds_repairs": [
            {"config_id":i,"byte_offset":off,"inclusive_max":max_v,"invalid_replacement":rep}
            for i,(off,max_v,rep) in LIMITED.items()
        ],
        "constant_zero_config_ids":[32,40,41],
        "constant_one_config_ids":[57,59],
        "full_visible_menu_state_machine_recovered":False,
        "physical_keycap_names_known":False,
        "original_nv_save_format_inferred":False,
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--json",action="store_true")
    a=p.parse_args()
    report=verify_original(decoded_payload(IMAGE.read_bytes()))
    print(json.dumps(report,indent=2) if a.json else report)

if __name__=="__main__":
    main()
