#!/usr/bin/env python3
"""One-off read-only OEM GPIO/serial bus/RF/UI function reconnaissance.

All outputs are candidate static Thumb code, not real MCU pin assignments.
"""
from __future__ import annotations
import struct
import sys
from collections import Counter
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_MEM,ARM_REG_PC
from mcu_fingerprint import decoded_payload
from thumb_window import inspect_window

BASE=0x08001000
MMIO={
 0x40010000:"AFIO",0x40010400:"EXTI",0x40010800:"GPIOA",
 0x40010C00:"GPIOB",0x40011000:"GPIOC",0x40011400:"GPIOD",
 0x40011800:"GPIOE",0x40011C00:"GPIOF",0x40012000:"GPIOG",
 0x40012C00:"TIM1",0x40013000:"SPI1",0x40013400:"TIM8",
 0x40005400:"I2C1",0x40005800:"I2C2",0x40003800:"SPI2",
 0x40003C00:"SPI3",0x40004400:"USART2",0x40004800:"USART3",
 0x40013800:"USART1",0x40021000:"RCC"
}
def scan(payload:bytes):
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN);md.detail=True
    refs={}
    for off in range(0,len(payload)-3,2):
        half=struct.unpack_from("<H",payload,off)[0]
        if (half & 0xF800)!=0x4800 and (half&0xFFF0) not in (0xF85F,0xF8DF):
            continue
        pc=BASE+off
        inst=next(md.disasm(payload[off:off+4],pc,count=1),None)
        if not inst or not inst.mnemonic.startswith("ldr"):continue
        for op in inst.operands[1:]:
            if op.type!=ARM_OP_MEM or op.mem.base!=ARM_REG_PC or op.mem.index:continue
            loc=((pc+4)&~3)+op.mem.disp
            if loc<BASE or loc+4>BASE+len(payload) or loc%4:continue
            val=struct.unpack_from("<I",payload,loc-BASE)[0]
            if val not in MMIO:continue
            refs[pc]=(MMIO[val],val,loc)
    return refs

def context(payload,pc,lo=32,hi=68):
    st=max(BASE,(pc-lo)&~1);en=min(BASE+len(payload),(pc+hi)&~1)
    # Misaligned linear disassembly often yields false code; print from the
    # candidate LDR itself and a bounded surrounding aligned segment.
    rows=inspect_window(payload,pc,min(en,pc+hi))
    return " ; ".join(f"{r['pc']}:{r['mnemonic']} {r['operands']}" for r in rows[:28])

def main():
    for version,src in [("v1","firmware/BF_5RH_501_v1_1_04.dat"),("v2","firmware/BF_5RH_501_v2_0_9.dat")]:
        p=decoded_payload(Path(src).read_bytes());ref=scan(p)
        print("====",version,"====")
        print("MMIO_COUNTS",dict(Counter(name for name,_,_ in ref.values())))
        print("MMIO_XREFS_BEGIN")
        for pc,(name,value,literal) in sorted(ref.items()):
            if name not in ("GPIOA","GPIOB","GPIOC","GPIOD","GPIOE","AFIO","SPI1","I2C1","I2C2"):
                continue
            print("GPIO_REF",f"0x{pc:08X}",name,f"pool:0x{literal:08X}","POST",context(p,pc,hi=58))
        print("MMIO_XREFS_END")
if __name__=="__main__":
    main()
