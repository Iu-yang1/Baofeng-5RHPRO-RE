//! Original V2 *register-level* board HAL adapters.
//!
//! This module binds verified OEM software GPIO A/B/C/D/E register offsets,
//! SPI2 panel PB12/PA12 and SPI3 register initialization to generic actual
//! register access. It can run on hardware after the true XL9951Q silicon,
//! GPIO clocks/mux and QFN64 pad-to-net mapping are established, but it does
//! NOT itself prove the physical MCU SKU, pin electrical identity, PA/PTT
//! switching, or NOR write recovery. No automatic TX restrictions.
//!
//! An embedded target implements RegisterIo with its platform-specific
//! volatile/MMIO primitives only after independent chip identification.

use crate::board_v2::{
    BoardGpio, Pin, Port, GPIOA_COMPAT_BASE, GPIOB_COMPAT_BASE,
    GPIOC_COMPAT_BASE, GPIOD_COMPAT_BASE, GPIOE_COMPAT_BASE,
    PANEL_RESET, PANEL_SPI2,
};
use crate::lcd::{OriginalPanelDelay, OriginalPanelReset, PanelBus};
use crate::spi3_nv::{
    SpiByteTransfer,
    OEM_SPI3_REGISTER_BASE, OEM_SPI3_CR2_CLEAR_MASK,
    OEM_SPI3_CRC_POLYNOMIAL,
    oem_spi3_cr1_after_configuration, oem_spi3_cr1_after_enable,
};

pub const OEM_COMPAT_GPIO_IDR_OFFSET:u32=0x08;
pub const OEM_COMPAT_GPIO_BSRR_OFFSET:u32=0x10;
pub const OEM_COMPAT_GPIO_BRR_OFFSET:u32=0x14;

pub const OEM_CORTEX_M_CPUID_ADDR:u32=0xE000_ED00;
pub const OEM_SPI3_CR1_OFFSET:u32=0;
pub const OEM_SPI3_CR2_OFFSET:u32=4;
pub const OEM_SPI3_CRCPR_OFFSET:u32=0x10;

/// Source-style register addresses are not an identification of any
/// exact XL9951Q QFN64 pad, clock domain, or vendor-provided PAC.
pub trait RegisterIo {
    type Error;
    fn read32(&mut self,address:u32)->Result<u32,Self::Error>;
    fn write32(&mut self,address:u32,value:u32)->Result<(),Self::Error>;
    fn read16(&mut self,address:u32)->Result<u16,Self::Error>;
    fn write16(&mut self,address:u32,value:u16)->Result<(),Self::Error>;
}

pub const fn compatible_gpio_base(port:Port)->u32 {
    match port {
        Port::A=>GPIOA_COMPAT_BASE,
        Port::B=>GPIOB_COMPAT_BASE,
        Port::C=>GPIOC_COMPAT_BASE,
        Port::D=>GPIOD_COMPAT_BASE,
        Port::E=>GPIOE_COMPAT_BASE,
    }
}

/// MCU vendor candidate evidence alone is insufficient for a PAC.
/// CPUID is a standard architected ARM system register but identifies
/// core/variant, not XL9951Q manufacturer or pinout.
pub fn read_architected_cpuid<IO:RegisterIo>(io:&mut IO)->Result<u32,IO::Error> {
    io.read32(OEM_CORTEX_M_CPUID_ADDR)
}

pub struct OemCompatibleGpio<IO> {
    pub registers:IO,
}
impl<IO> OemCompatibleGpio<IO> {
    pub const fn new(registers:IO)->Self {Self{registers}}
}

impl<IO:RegisterIo> BoardGpio for OemCompatibleGpio<IO> {
    type Error=IO::Error;
    fn set_level(&mut self,pin:Pin,high:bool)->Result<(),Self::Error> {
        let addr=compatible_gpio_base(pin.port)
            + if high {OEM_COMPAT_GPIO_BSRR_OFFSET} else {OEM_COMPAT_GPIO_BRR_OFFSET};
        // STM32F1-style write-one set/reset registers, observed in OEM
        // binary at GPIOB and GPIOA software addresses.
        self.registers.write32(addr,pin.mask() as u32)
    }
    fn sample(&mut self,pin:Pin)->Result<bool,Self::Error> {
        let idr=self.registers.read32(
            compatible_gpio_base(pin.port)+OEM_COMPAT_GPIO_IDR_OFFSET
        )?;
        Ok(idr & pin.mask() as u32 != 0)
    }
}

/// Only original source-supported SPI3 register initialization; caller
/// must first configure the board's real clock and PB3/4/5 mux/electrical
/// state, not guessed from the alternate MCU's datasheet.
pub fn configure_original_spi3_registers<IO:RegisterIo>(
    io:&mut IO,
)->Result<(),IO::Error> {
    let base=OEM_SPI3_REGISTER_BASE;
    // OEM 0x08031804/08/10 write SPI control registers with STRH.
    // The peripheral's 16-bit register access width matters; avoid
    // widening these stores to 32-bit MMIO writes on an unknown MCU.
    let cr1=io.read16(base+OEM_SPI3_CR1_OFFSET)?;
    let cr2=io.read16(base+OEM_SPI3_CR2_OFFSET)?;
    io.write16(base+OEM_SPI3_CR1_OFFSET,
        oem_spi3_cr1_after_configuration(cr1))?;
    io.write16(base+OEM_SPI3_CR2_OFFSET,
        cr2 & !OEM_SPI3_CR2_CLEAR_MASK)?;
    io.write16(base+OEM_SPI3_CRCPR_OFFSET,OEM_SPI3_CRC_POLYNOMIAL)?;
    io.write16(base+OEM_SPI3_CR1_OFFSET,
        oem_spi3_cr1_after_enable(cr1))?;
    Ok(())
}

/// This is a real PanelBus adapter for a board with working GPIO/SPI2
/// primitives. The stock binary establishes software PB12 CS, PA12 DC.
/// Chip-select is released after each command/data transfer. Actual
/// panel wiring and data/CS setup/hold remain bench-verification items.
pub struct OemSpi2PanelBus<'a, SPI, GPIO> {
    pub spi:&'a mut SPI,
    pub gpio:&'a mut GPIO,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PanelHalError<SP,GP> {
    ChipSelect(GP),
    DataCommand(GP),
    Spi(SP),
    Deselect(GP),
    SpiAndDeselect{spi:SP,deselect:GP},
    DcAndDeselect{dc:GP,deselect:GP},
}

impl<SPI: SpiByteTransfer, GPIO: BoardGpio> OemSpi2PanelBus<'_,SPI,GPIO> {
    fn transfer(&mut self,data:bool,bytes:&[u8])
        ->Result<(),PanelHalError<SPI::Error,GPIO::Error>> {
        self.gpio.set_level(PANEL_SPI2.chip_select,false)
            .map_err(PanelHalError::ChipSelect)?;
        let dc=self.gpio.set_level(PANEL_SPI2.command_data,data);
        if let Err(dc)=dc {
            return match self.gpio.set_level(PANEL_SPI2.chip_select,true) {
                Ok(())=>Err(PanelHalError::DataCommand(dc)),
                Err(deselect)=>Err(PanelHalError::DcAndDeselect{dc,deselect}),
            };
        }
        let transfer=(||->Result<(),SPI::Error> {
            for &b in bytes {self.spi.transfer_byte(b)?;}
            Ok(())
        })();
        let release=self.gpio.set_level(PANEL_SPI2.chip_select,true);
        match (transfer,release) {
            (Ok(()),Ok(()))=>Ok(()),
            (Err(spi),Ok(()))=>Err(PanelHalError::Spi(spi)),
            (Ok(()),Err(gpio))=>Err(PanelHalError::Deselect(gpio)),
            (Err(spi),Err(deselect))=>Err(PanelHalError::SpiAndDeselect{spi,deselect}),
        }
    }
}
impl<SPI:SpiByteTransfer,GPIO:BoardGpio> PanelBus for OemSpi2PanelBus<'_,SPI,GPIO> {
    type Error=PanelHalError<SPI::Error,GPIO::Error>;
    fn command(&mut self,byte:u8)->Result<(),Self::Error> {
        self.transfer(false,&[byte])
    }
    fn data(&mut self,bytes:&[u8])->Result<(),Self::Error> {
        self.transfer(true,bytes)
    }
}

/// Join original software PA8 panel-reset GPIO with its original delay
/// interface. The delay argument must remain the OEM's raw unit.
pub struct OemPanelResetAdapter<'a, G, D> {
    pub gpio:&'a mut G,
    pub delay:&'a mut D,
}
impl<G:BoardGpio,D:OriginalPanelDelay> OriginalPanelReset
    for OemPanelResetAdapter<'_,G,D> {
    type Error=G::Error;
    fn set_reset_high(&mut self,high:bool)->Result<(),Self::Error> {
        self.gpio.set_level(PANEL_RESET,high)
    }
    fn wait_oem_argument(&mut self,argument:u32) {
        self.delay.wait_oem_argument(argument)
    }
}

/// The original 22-key matrix uses two GPIOC input snapshots separated
/// by source-specific direction/pull-state transitions. The bus is
/// responsible for the actual electrical setup, not fabricated here.
pub trait OemMatrixPort {
    type Error;
    fn first_sample(&mut self)->Result<u16,Self::Error>;
    fn second_sample(&mut self)->Result<u16,Self::Error>;
}

pub fn scan_original_two_pass_keypad<M:OemMatrixPort>(
    matrix:&mut M,
)->Result<Option<crate::keypad::KeyIndex>,M::Error> {
    let first=matrix.first_sample()?;
    let second=matrix.second_sample()?;
    Ok(crate::keypad::scan(first,second))
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::lcd::reset_oem_panel;
    use std::vec::Vec;

    #[derive(Default)]
    struct Registers {
        reads:Vec<(u32,u32)>,writes:Vec<(u32,u32)>,
        reads16:Vec<(u32,u16)>,writes16:Vec<(u32,u16)>,
        fail_write_on:Option<usize>,
    }
    impl RegisterIo for Registers {
        type Error=&'static str;
        fn read32(&mut self,a:u32)->Result<u32,Self::Error> {
            Ok(self.reads.iter().find(|(addr,_)|*addr==a).map(|x|x.1).unwrap_or(0))
        }
        fn write32(&mut self,a:u32,v:u32)->Result<(),Self::Error> {
            if self.fail_write_on==Some(self.writes.len()+self.writes16.len()+1) {return Err("MMIO");}
            self.writes.push((a,v));Ok(())
        }
        fn read16(&mut self,a:u32)->Result<u16,Self::Error> {
            Ok(self.reads16.iter().find(|(addr,_)|*addr==a).map(|x|x.1).unwrap_or(0))
        }
        fn write16(&mut self,a:u32,v:u16)->Result<(),Self::Error> {
            if self.fail_write_on==Some(self.writes.len()+self.writes16.len()+1) {return Err("MMIO");}
            self.writes16.push((a,v));Ok(())
        }
    }

    #[test]
    fn gpio_uses_original_idr_bsrr_brr_register_offsets() {
        let mut gpio=OemCompatibleGpio::new(Registers{
            reads:std::vec![(0x40010808,0x400)],
            ..Registers::default()
        });
        let a10=Pin{port:Port::A,bit:10};
        assert_eq!(gpio.sample(a10),Ok(true));
        gpio.set_level(Pin{port:Port::B,bit:6},true).unwrap();
        gpio.set_level(Pin{port:Port::B,bit:6},false).unwrap();
        gpio.set_level(PANEL_RESET,false).unwrap();
        assert_eq!(gpio.registers.writes,std::vec![
            (0x40010C10,0x40),(0x40010C14,0x40),
            (0x40010814,0x100),
        ]);
    }

    #[test]
    fn spi3_oem_cr1_cr2_crc_setup_and_enable_order_is_observable() {
        let mut registers=Registers{
            reads16:std::vec![(0x40003C00,0x3040),(0x40003C04,0xABCD)],
            ..Registers::default()
        };
        configure_original_spi3_registers(&mut registers).unwrap();
        assert!(registers.writes.is_empty());
        assert_eq!(registers.writes16,std::vec![
            (0x40003C00,0x3357),(0x40003C04,0xA3CD),
            (0x40003C10,7),(0x40003C00,0x3357),
        ]);
    }

    #[test]
    fn failed_register_setup_does_not_issue_enable() {
        let mut r=Registers{fail_write_on:Some(3),..Registers::default()};
        assert_eq!(configure_original_spi3_registers(&mut r),Err("MMIO"));
        assert_eq!(r.writes16.len(),2);
        assert!(r.writes.is_empty());
    }

    struct Spi {tx:Vec<u8>,fail_at:Option<usize>}
    impl SpiByteTransfer for Spi {
        type Error=&'static str;
        fn transfer_byte(&mut self,x:u8)->Result<u8,Self::Error> {
            if self.fail_at==Some(self.tx.len()+1){return Err("SPI");}
            self.tx.push(x);Ok(0)
        }
    }
    struct Gpio {writes:Vec<(Pin,bool)>}
    impl BoardGpio for Gpio {
        type Error=&'static str;
        fn set_level(&mut self,p:Pin,h:bool)->Result<(),Self::Error>{
            self.writes.push((p,h));Ok(())
        }
        fn sample(&mut self,_:Pin)->Result<bool,Self::Error>{Ok(false)}
    }

    #[test]
    fn spi2_panel_adapter_uses_source_pb12_pa12_and_releases_cs() {
        let mut spi=Spi{tx:Vec::new(),fail_at:None};
        let mut gpio=Gpio{writes:Vec::new()};
        let mut panel=OemSpi2PanelBus{spi:&mut spi,gpio:&mut gpio};
        panel.command(0x2A).unwrap();
        panel.data(&[0x11,0x22]).unwrap();
        assert_eq!(spi.tx,std::vec![0x2A,0x11,0x22]);
        assert_eq!(gpio.writes,std::vec![
            (PANEL_SPI2.chip_select,false),
            (PANEL_SPI2.command_data,false),
            (PANEL_SPI2.chip_select,true),
            (PANEL_SPI2.chip_select,false),
            (PANEL_SPI2.command_data,true),
            (PANEL_SPI2.chip_select,true),
        ]);
    }

    #[test]
    fn spi_failure_still_deselects_panel() {
        let mut spi=Spi{tx:Vec::new(),fail_at:Some(2)};
        let mut gpio=Gpio{writes:Vec::new()};
        let mut panel=OemSpi2PanelBus{spi:&mut spi,gpio:&mut gpio};
        assert_eq!(panel.data(&[0xFF,0xAA]),Err(PanelHalError::Spi("SPI")));
        assert_eq!(gpio.writes.last(),Some(&(PANEL_SPI2.chip_select,true)));
    }

    struct Delay {args:Vec<u32>}
    impl OriginalPanelDelay for Delay {
        fn wait_oem_argument(&mut self,arg:u32){self.args.push(arg);}
    }
    #[test]
    fn original_lcd_gpio_reset_sequence_uses_raw_delays() {
        let mut gpio=Gpio{writes:Vec::new()};
        let mut delay=Delay{args:Vec::new()};
        let mut reset=OemPanelResetAdapter{gpio:&mut gpio,delay:&mut delay};
        reset_oem_panel(&mut reset).unwrap();
        assert_eq!(delay.args,std::vec![0x14,0xC8,0x14]);
        assert_eq!(gpio.writes,std::vec![
            (PANEL_RESET,true),(PANEL_RESET,false),(PANEL_RESET,true),
        ]);
    }

    struct Keybus {codes:[u16;2],calls:usize,fail:bool}
    impl OemMatrixPort for Keybus {
        type Error=&'static str;
        fn first_sample(&mut self)->Result<u16,Self::Error>{
            self.calls+=1;Ok(self.codes[0])
        }
        fn second_sample(&mut self)->Result<u16,Self::Error>{
            self.calls+=1;
            if self.fail {Err("second")} else {Ok(self.codes[1])}
        }
    }
    #[test]
    fn real_two_pass_keypad_interface_delivers_source_index_and_error() {
        let code=crate::keypad::ORIGINAL_SCAN_CODES[9]<<1;
        let mut bus=Keybus{codes:[code&0x3C0,code&0x3E],calls:0,fail:false};
        assert_eq!(scan_original_two_pass_keypad(&mut bus),Ok(Some(crate::keypad::KeyIndex(9))));
        assert_eq!(bus.calls,2);
        bus.fail=true;
        assert_eq!(scan_original_two_pass_keypad(&mut bus),Err("second"));
    }

    #[test]
    fn cpuid_probe_is_architected_read_not_fabricated_device_id() {
        let mut r=Registers{reads:std::vec![(OEM_CORTEX_M_CPUID_ADDR,0x410FC241)],
            ..Registers::default()};
        assert_eq!(read_architected_cpuid(&mut r),Ok(0x410FC241));
    }
}
