#!/usr/bin/env python3
"""Find actual Thumb PC-relative references to working-SRAM/global addresses.

LDR-literal halfword sweep yields *candidates*: only direct callsite and
reachable CFG validation can establish ownership. No physical GPIO inference.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import struct
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_MEM, ARM_REG_PC
from mcu_fingerprint import decoded_payload
from thumb_window import BASE, inspect_window
from thumb_callsites import find_calls

IMAGE=Path("firmware/BF_5RH_501_v2_0_9.dat")
TARGETS={
  0x20004580:"menu working RAM 38+ bytes",
  0x200046E0:"menu UI scratch text",
  0x200017FC:"PB6 software state byte",
  0x20001B84:"FD6818 register cache",
  0x40010C10:"GPIOB BSRR",
  0x40010C14:"GPIOB BRR",
}
CALL_TARGETS={
   "nor_write":0x08006C28,"nor_erase":0x08006AA8,
   "flash_journal":0x080190E0,"oem_config_getter":0x0800E454,
   "pb6_control":0x0800DA10,"audio_mode":0x0800A310,
}

def ldr_refs(payload:bytes):
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN);md.detail=True
    found={t:[] for t in TARGETS}
    for ofs in range(0,len(payload)-3,2):
        h=struct.unpack_from("<H",payload,ofs)[0]
        if (h & 0xF800)!=0x4800 and (h & 0xFFF0) not in (0xF8DF,0xF85F):
            continue
        pc=BASE+ofs
        ins=next(md.disasm(payload[ofs:ofs+4],pc,count=1),None)
        if not ins or not ins.mnemonic.startswith("ldr"):continue
        for arg in ins.operands[1:]:
            if arg.type != ARM_OP_MEM or arg.mem.base != ARM_REG_PC or arg.mem.index:continue
            addr=((pc+4)&~3)+arg.mem.disp
            if addr%4 or not BASE<=addr<=BASE+len(payload)-4:continue
            value=struct.unpack_from("<I",payload,addr-BASE)[0]
            if value in found:
                found[value].append((pc,ins.mnemonic,ins.op_str))
    return found

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--kind",choices=["refs","nor-callers","mode-callers"],default="refs")
    p.add_argument("--max-each",type=int,default=80)
    args=p.parse_args()
    payload=decoded_payload(IMAGE.read_bytes())
    if args.kind=="refs":
        refs=ldr_refs(payload)
        for addr,rows in refs.items():
            print("REF_GROUP",hex(addr),TARGETS[addr],"TOTAL",len(rows))
            for pc,mnem,ops in rows[:args.max_each]:
                print("REF",f"0x{pc:08X}",mnem,ops)
    else:
        labels = (["nor_write","nor_erase","flash_journal"] if args.kind=="nor-callers"
                  else ["pb6_control","audio_mode"])
        entries=find_calls(payload,[CALL_TARGETS[k] for k in labels])
        for name in labels:
            t=CALL_TARGETS[name];rows=entries[f"0x{t:08X}"]
            print("CALLEE",name,f"0x{t:08X}","CANDIDATES",len(rows))
            for call in rows[:args.max_each]:
                pc=int(call["call_pc"],16)
                print("CALL",call["call_pc"],call["instruction"])
                for ins in inspect_window(payload,pc-24,pc+30):
                    print("NEAR",ins["pc"],ins["mnemonic"],ins["operands"],ins.get("literal_value",""))
if __name__=="__main__":
    main()
