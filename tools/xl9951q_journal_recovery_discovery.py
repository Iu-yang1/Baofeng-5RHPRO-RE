#!/usr/bin/env python3
"""Non-executing branch reconnaissance of the archived V1/V2 recovery journal."""
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_MEM, ARM_REG_PC
from mcu_fingerprint import decoded_payload
from thumb_callsites import find_calls
from thumb_window import inspect_window

BASE=0x08001000
LITERALS={0x0807F800,0x0807F804,0x001FE000,0x001FF000}
IMAGES={
 "v1":"firmware/BF_5RH_501_v1_1_04.dat",
 "v2":"firmware/BF_5RH_501_v2_0_9.dat",
}
WINDOWS={
 "v1":[(0x0800AAE0,0x0800AD95),(0x0800AD90,0x0800B000)],
 "v2":[(0x080102C0,0x08010470),(0x08010470,0x08010655)],
}

def get_word(b, pc):
    return struct.unpack_from("<I",b,pc-BASE)[0]

def xrefs(p):
    md=Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    md.detail=True
    raw=[]
    for i in range(0,len(p)-3,4):
        value=get_word(p,BASE+i)
        if value in LITERALS:
            raw.append({"literal_pc":BASE+i,"value":value})
    for o in raw:
        refs=[]
        loc=o["literal_pc"]
        for pc in range(max(BASE,loc-0x1000),loc,2):
            ins=next(md.disasm(p[pc-BASE:pc-BASE+4],pc,count=1),None)
            if not ins or not ins.mnemonic.startswith("ldr"):
                continue
            for arg in ins.operands:
                if arg.type==ARM_OP_MEM and arg.mem.base==ARM_REG_PC and not arg.mem.index:
                    target=((pc+4)&~3)+arg.mem.disp
                    if target==loc:
                        refs.append((pc,ins.mnemonic,ins.op_str))
        o["refs"]=refs
    return raw

for edition,path in IMAGES.items():
    p=decoded_payload(Path(path).read_bytes())
    print("\n==========",edition,"decoded",len(p),"bytes ==========")
    for o in xrefs(p):
        print("LITERAL",hex(o["literal_pc"]),hex(o["value"]),"LDR_XREFS",[(hex(pc),mn,ops) for pc,mn,ops in o["refs"]][:50])
    for start,end in WINDOWS[edition]:
        print("\n--------- WINDOW",hex(start),hex(end),"---------")
        for r in inspect_window(p,start,end):
            print(r["pc"],r["mnemonic"],r["operands"],"pool="+r.get("literal_value",""))
    targets=[0x08007C64,0x08007C94,0x08012D98] if edition=="v1" else [0x0800D304,0x0800D334,0x080190E0]
    print("\n== CALLS TO CANDIDATES ==")
    refs=find_calls(p,targets)
    for k,v in refs.items():
        print(k,len(v),[a["call_pc"] for a in v][:100])
