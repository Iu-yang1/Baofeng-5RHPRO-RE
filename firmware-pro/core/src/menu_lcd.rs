//! Firmware-native 160x128 menu diagnostic display layer.
//!
//! The original OLED/LCD framebuffer dimensions, RGB565 wire order and
//! display update are grounded in OEM V2; literal strings here ("CFG",
//! "VAL", "EDIT") and glyph bitmaps are independent UI placeholders,
//! NOT a claim of recovered OEM font assets/menu layout.
//!
//! This paints a real FrameBuffer that can use the existing SPI2 PanelBus.

use crate::lcd::{FrameBuffer, FRAME_HEIGHT, FRAME_WIDTH};
use crate::oem_menu_ui::MenuScreenState;

pub const MENU_BG: u16=0x0000;
pub const MENU_TOP: u16=0x0019;
pub const MENU_VALUE: u16=0xFFFF;
pub const MENU_ACCENT: u16=0x07E0;
pub const MENU_EDIT: u16=0xFBE0;
pub const MENU_WARN: u16=0xF800;

fn glyph(ch:u8)->[u8;7] {
    match ch {
        b'0'=>[14,17,19,21,25,17,14],
        b'1'=>[4,12,4,4,4,4,14],
        b'2'=>[14,17,1,2,4,8,31],
        b'3'=>[30,1,1,14,1,1,30],
        b'4'=>[2,6,10,18,31,2,2],
        b'5'=>[31,16,16,30,1,1,30],
        b'6'=>[14,16,16,30,17,17,14],
        b'7'=>[31,1,2,4,8,8,8],
        b'8'=>[14,17,17,14,17,17,14],
        b'9'=>[14,17,17,15,1,1,14],
        b'A'=>[14,17,17,31,17,17,17],
        b'B'=>[30,17,17,30,17,17,30],
        b'C'=>[14,17,16,16,16,17,14],
        b'D'=>[30,17,17,17,17,17,30],
        b'E'=>[31,16,16,30,16,16,31],
        b'F'=>[31,16,16,30,16,16,16],
        b'G'=>[14,17,16,23,17,17,14],
        b'I'=>[14,4,4,4,4,4,14],
        b'L'=>[16,16,16,16,16,16,31],
        b'N'=>[17,25,21,19,17,17,17],
        b'O'=>[14,17,17,17,17,17,14],
        b'R'=>[30,17,17,30,20,18,17],
        b'T'=>[31,4,4,4,4,4,4],
        b'U'=>[17,17,17,17,17,17,14],
        b'V'=>[17,17,17,17,17,10,4],
        b'W'=>[17,17,17,21,21,21,10],
        b'Y'=>[17,17,10,4,4,4,4],
        b':' =>[0,4,4,0,4,4,0],
        b' ' =>[0;7],
        _=>[0;7],
    }
}

pub fn draw_ascii(frame:&mut FrameBuffer<'_>,x:usize,y:usize,
    text:&[u8],scale:usize,ink:u16) {
    for (i,ch) in text.iter().enumerate() {
        let bitmap=glyph(*ch);
        let ox=x+i*6*scale;
        for (dy,row) in bitmap.iter().enumerate() {
            for dx in 0..5 {
                if row & (1 << (4-dx)) != 0 {
                    frame.fill_rect(ox+dx*scale,y+dy*scale,scale,scale,ink);
                }
            }
        }
    }
}

pub const fn hex2(byte:u8)->[u8;2] {
    const fn ascii(d:u8)->u8 {if d<10 {b'0'+d} else {b'A'+d-10}}
    [ascii(byte>>4),ascii(byte&0x0F)]
}

/// Actually renders pixels in the project framebuffer rather than only
/// returning abstract text commands. No font/memory alignment guess
/// about the original manufacturer is involved.
pub fn render_menu_diagnostics(
    frame:&mut FrameBuffer<'_>,screen:MenuScreenState
) {
    frame.fill_rect(0,0,FRAME_WIDTH,FRAME_HEIGHT,MENU_BG);
    frame.fill_rect(0,0,FRAME_WIDTH,28,MENU_TOP);
    draw_ascii(frame,8,9,b"CFG",2,MENU_VALUE);
    draw_ascii(frame,9,38,b"ID:",1,MENU_ACCENT);
    draw_ascii(frame,60,32,&hex2(screen.config_id),2,MENU_VALUE);
    draw_ascii(frame,9,69,b"VAL:",1,MENU_ACCENT);
    draw_ascii(frame,60,62,&hex2(screen.visible_value),2,
        if screen.changed {MENU_EDIT} else {MENU_VALUE});
    frame.fill_rect(0,98,FRAME_WIDTH,30,MENU_TOP);
    if screen.editing {
        draw_ascii(frame,8,105,b"EDIT",1,MENU_EDIT);
    } else {
        draw_ascii(frame,8,105,b"VIEW",1,MENU_VALUE);
    }
    if screen.changed {
        draw_ascii(frame,58,105,b"DIRTY",1,MENU_EDIT);
    }
    if !screen.write_supported {
        draw_ascii(frame,94,116,b"RO",1,MENU_WARN);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::lcd::FRAME_PIXELS;

    #[test]
    fn hex_view_renders_actual_pixels_for_id_value_and_edit_state() {
        let mut pixels=std::vec![0u16;FRAME_PIXELS];
        let mut frame=FrameBuffer::new(&mut pixels).unwrap();
        render_menu_diagnostics(&mut frame,MenuScreenState {
            config_id:0x1A,current_value:0x03,visible_value:0xFA,
            editing:true,changed:true,write_supported:true,
        });
        assert_eq!(frame.pixel(0,0),Some(MENU_TOP));
        assert_eq!(frame.pixel(0,40),Some(MENU_BG));
        assert_eq!(frame.pixel(0,126),Some(MENU_TOP));
        assert!(pixels.iter().any(|&x|x==MENU_EDIT));
        assert!(pixels.iter().any(|&x|x==MENU_ACCENT));
        assert_eq!(hex2(0xFA),[b'F',b'A']);
    }

    #[test]
    fn source_noop_setter_uses_read_only_marker_without_disabling_navigation() {
        let mut pixels=std::vec![0u16;FRAME_PIXELS];
        let mut frame=FrameBuffer::new(&mut pixels).unwrap();
        render_menu_diagnostics(&mut frame,MenuScreenState {
            config_id:0x20,current_value:0,visible_value:0,
            editing:false,changed:false,write_supported:false,
        });
        assert!(pixels.iter().any(|&p|p==MENU_WARN));
        assert!(!pixels.iter().any(|&p|p==MENU_EDIT));
    }
}
