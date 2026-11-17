//! End-to-end independent menu edit → RGB565 → source-style SPI2 bus.
//!
//! This is a real logical display transport through source-confirmed
//! software PB12/PA12 signals. Rendering strings are diagnostic and the
//! physical pad/panel connection still requires on-board measurement.

use uv5rh_pro_core::lcd::{FrameBuffer,FRAME_PIXELS};
use uv5rh_pro_core::menu_lcd::render_menu_diagnostics;
use uv5rh_pro_core::oem_board_hal::OemSpi2PanelBus;
use uv5rh_pro_core::oem_menu_ui::{
    IndependentMenu,MenuAction,MenuMode,
};
use uv5rh_pro_core::oem_config_getter::{OemWorkingConfig,OEM_CONFIG_STORAGE_LEN};
use uv5rh_pro_core::oem_config_setter::{
    LogicalNvJournal,OemSetterPreCall,
};
use uv5rh_pro_core::oem_menu_ui::OemSetterHelper;
use uv5rh_pro_core::oem_nv_compat::OemNvWriteLayout;
use uv5rh_pro_core::board_v2::{BoardGpio,Pin,PANEL_SPI2};
use uv5rh_pro_core::spi3_nv::SpiByteTransfer;

#[derive(Default)]
struct Spi {wire:Vec<u8>}
impl SpiByteTransfer for Spi {
    type Error=&'static str;
    fn transfer_byte(&mut self,byte:u8)->Result<u8,Self::Error>{
        self.wire.push(byte);Ok(0)
    }
}
#[derive(Default)]
struct IoPins {events:Vec<(Pin,bool)>}
impl BoardGpio for IoPins {
    type Error=&'static str;
    fn set_level(&mut self,p:Pin,h:bool)->Result<(),Self::Error>{
        self.events.push((p,h));Ok(())
    }
    fn sample(&mut self,_:Pin)->Result<bool,Self::Error>{Ok(false)}
}
#[derive(Default)]
struct Nv {writes:Vec<(u32,u8)>}
impl LogicalNvJournal for Nv {
    type Error=&'static str;
    fn update_one(&mut self,addr:u32,v:u8)->Result<(),Self::Error>{
        self.writes.push((addr,v));Ok(())
    }
}
struct Hooks;
impl OemSetterHelper for Hooks {
    type Error=&'static str;
    fn invoke(&mut self,_:OemSetterPreCall,_:u8)->Result<(),Self::Error>{
        Err("no unverified hook needed")
    }
}

#[test]
fn configuration_editor_renders_live_value_and_flushes_real_rgb565_bytes() {
    let mut working=OemWorkingConfig::new([0;OEM_CONFIG_STORAGE_LEN]);
    let mut menu=IndependentMenu {selected_id:13,mode:MenuMode::Browse};
    menu.action(MenuAction::BeginEdit,&mut working);
    for _ in 0..10 {menu.action(MenuAction::Increment,&mut working);}
    assert_eq!(menu.screen(&mut working).visible_value,0x0A);
    assert_eq!(working.bytes[12],0); // preview is not prematurely committed

    let mut pixels=vec![0u16;FRAME_PIXELS];
    let mut fb=FrameBuffer::new(&mut pixels).unwrap();
    render_menu_diagnostics(&mut fb,menu.screen(&mut working));
    let before=fb.pixel(0,0).unwrap();

    let mut spi=Spi::default();
    let mut gpio=IoPins::default();
    {
        let mut panel=OemSpi2PanelBus{spi:&mut spi,gpio:&mut gpio};
        fb.flush_rect(&mut panel,0,0,2,2).unwrap();
    }
    assert_eq!(&spi.wire[..11],&[
        0x2A,0,0,0,1,0x2B,0,0,0,1,0x2C,
    ]);
    let rgb=before.to_be_bytes();
    assert_eq!(&spi.wire[11..13],&rgb);
    assert_eq!(gpio.events.first(),Some(&(PANEL_SPI2.chip_select,false)));
    assert_eq!(gpio.events.last(),Some(&(PANEL_SPI2.chip_select,true)));
    assert_eq!(spi.wire.len(),11+4*2);

    let mut nv=Nv::default();
    let mut hooks=Hooks;
    menu.confirm(&mut working,&mut nv,&mut hooks,
        OemNvWriteLayout::LoaderConsistent,true).unwrap();
    assert_eq!(nv.writes,vec![(0x7993,10)]);
    assert_eq!(working.bytes[12],10);
    assert_eq!(menu.mode,MenuMode::Browse);

    render_menu_diagnostics(&mut fb,menu.screen(&mut working));
    assert!(pixels.iter().any(|&p|p!=0)); // rerendered committed view
}
