#!/usr/bin/env python3
"""Read-only exploratory SPI byte transfer and watchdog MMIO cross-references."""
from __future__ import annotations
import struct
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_MEM, ARM_REG_PC
from mcu_fingerprint import decoded_payload
from thumb_window import inspect_window
from thumb_callsites import find_calls

BASE=0x08001000
VERSION={
 "v1":{"file":"firmware/BF_5RH_501_v1_1_04.dat","spi":0x080257A0,"start":0x08025770,"stop":0x080258BC,"watchdog":(0x08003860,0x080038CC),"spi_helper":(0x08025748,0x0802576C),"wd_targets":[0x0800387C,0x0800388C,0x0800389C,0x080038A8,0x080038B4]},
 "v2":{"file":"firmware/BF_5RH_501_v2_0_9.dat","spi":0x08031814,"start":0x080317D0,"stop":0x08031918,"watchdog":(0x08007370,0x080073DC),"spi_helper":(0x080317BC,0x080317E0),"wd_targets":[0x0800738C,0x0800739C,0x080073AC,0x080073B8,0x080073C4]},
}
WATCHDOG_ADDRESSES={
 0x40003000:"IWDG_KR",
 0x40003004:"IWDG_PR",
 0x40003008:"IWDG_RLR",
 0x4000300C:"IWDG_SR",
 0x40002C00:"WWDG_CR",
 0x40002C04:"WWDG_CFR",
 0x40002C08:"WWDG_SR",
 0xE000E010:"SYST_CSR",
 0xE000ED0C:"SCB_AIRCR",
}
SPI_ADDRESSES={0x40003C00:"SPI3_CR1",0x40003C04:"SPI3_CR2",0x40003C08:"SPI3_SR",0x40003C0C:"SPI3_DR"}
def direct_pool_xrefs(p, loc):
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN);md.detail=True
    refs=[]
    for pc in range(max(BASE,loc-0x1000),loc,2):
        ins=next(md.disasm(p[pc-BASE:pc-BASE+4],pc,count=1),None)
        if ins is None or not ins.mnemonic.startswith("ldr"):continue
        for op in ins.operands:
            if op.type==ARM_OP_MEM and op.mem.base==ARM_REG_PC and not op.mem.index:
                target=((pc+4)&~3)+op.mem.disp
                if target==loc:refs.append(f"0x{pc:08X} {ins.mnemonic} {ins.op_str}")
    return refs
def main():
    for edition,info in VERSION.items():
        p=decoded_payload(Path(info["file"]).read_bytes())
        print("====",edition,len(p),"====")
        for row in inspect_window(p,info["start"],info["stop"]):
            print("SPI_TRANSFER_WINDOW",row["pc"],row["mnemonic"],row["operands"],row.get("literal_value",""))
        for lookup in (WATCHDOG_ADDRESSES,SPI_ADDRESSES):
            for word,meaning in lookup.items():
                hits=[]
                for i in range(0,len(p)-3,4):
                    if struct.unpack_from("<I",p,i)[0]==word:
                        loc=BASE+i
                        hits.append({"literal":f"0x{loc:08X}","refs":direct_pool_xrefs(p,loc)[:40]})
                print("MMIO",meaning,f"0x{word:08X}","COUNT",len(hits),"XREFS",hits[:50])
        for label,region in (("WATCHDOG_WINDOW",info["watchdog"]),("SPI_HELPERS",info["spi_helper"])):
            for row in inspect_window(p,*region):
                print(label,row["pc"],row["mnemonic"],row["operands"],row.get("literal_value",""))
        wd_calls=find_calls(p,info["wd_targets"])
        for t,refs in wd_calls.items():
            target=int(t,16)
            pointer=(target|1).to_bytes(4,"little")
            raw=[f"0x{BASE+i:08X}" for i in range(0,len(p)-3,4) if p[i:i+4]==pointer]
            print("WDT_CALLERS",t,len(refs),[x["call_pc"] for x in refs][:80],"THUMB_POINTER_REFS",raw[:60])
        calls=find_calls(p,[info["spi"]])
        key=f"0x{info['spi']:08X}"
        print("TRANSFER_CALLERS",key,len(calls[key]),[r["call_pc"] for r in calls[key]][:180])
if __name__=="__main__":main()
