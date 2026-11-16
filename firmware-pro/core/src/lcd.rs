//! OEM UV-5RH Pro V2 SPI2 LCD protocol and 160x128 RGB565 scanout.
//!
//! The stock V2 image uses command 0x2A (column), 0x2B (row), and 0x2C
//! (memory write), and a 320-byte framebuffer row stride at 0x20004B76.
//! The display controller variant, physical QFN pads, reset timing,
//! orientation and display-ON initialization still require validation.

pub const FRAME_WIDTH: usize = 160;
pub const FRAME_HEIGHT: usize = 128;
pub const FRAME_PIXELS: usize = FRAME_WIDTH * FRAME_HEIGHT;
pub const FRAME_STRIDE_BYTES: usize = FRAME_WIDTH * 2;
pub const ORIGINAL_FRAMEBUFFER_SRAM: u32 = 0x2000_4B76;
pub const ORIGINAL_FRAMEBUFFER_END_EXCLUSIVE: u32 =
    ORIGINAL_FRAMEBUFFER_SRAM + (FRAME_PIXELS * 2) as u32;

pub const CASET: u8 = 0x2A;
pub const RASET: u8 = 0x2B;
pub const RAMWR: u8 = 0x2C;

/// HAL provides command/data selection, SPI2 chip-select and transfer.
/// Whether a panel needs separate DC/CS delays remains board-specific.
pub trait PanelBus {
    type Error;

    fn command(&mut self, byte: u8) -> Result<(), Self::Error>;
    fn data(&mut self, bytes: &[u8]) -> Result<(), Self::Error>;
}

/// Framebuffer content uses native u16 RGB565; the OEM wire order is MSB first.
/// The caller owns SRAM; we never allocate a 40 KiB frame on the stack.
pub struct FrameBuffer<'a> {
    pixels: &'a mut [u16],
}

impl<'a> FrameBuffer<'a> {
    pub fn new(pixels: &'a mut [u16]) -> Option<Self> {
        if pixels.len() != FRAME_PIXELS {
            return None;
        }
        Some(Self { pixels })
    }

    pub fn pixel(&self, x: usize, y: usize) -> Option<u16> {
        if x >= FRAME_WIDTH || y >= FRAME_HEIGHT {
            return None;
        }
        Some(self.pixels[y * FRAME_WIDTH + x])
    }

    pub fn put(&mut self, x: usize, y: usize, color: u16) -> bool {
        if x >= FRAME_WIDTH || y >= FRAME_HEIGHT {
            return false;
        }
        self.pixels[y * FRAME_WIDTH + x] = color;
        true
    }

    pub fn fill_rect(&mut self, x: usize, y: usize, width: usize, height: usize, color: u16) {
        let end_x = x.saturating_add(width).min(FRAME_WIDTH);
        let end_y = y.saturating_add(height).min(FRAME_HEIGHT);
        for row in y.min(FRAME_HEIGHT)..end_y {
            for col in x.min(FRAME_WIDTH)..end_x {
                self.pixels[row * FRAME_WIDTH + col] = color;
            }
        }
    }

    /// Send a rectangular region using original 0x2A/0x2B/0x2C sequence.
    /// This is a synchronous reference path. DMA, chunking and rotation can
    /// be implemented by the eventual MCU-specific HAL.
    pub fn flush_rect<B: PanelBus>(
        &self, bus: &mut B, x: usize, y: usize, width: usize, height: usize
    ) -> Result<(), B::Error> {
        let right = x.saturating_add(width).min(FRAME_WIDTH);
        let bottom = y.saturating_add(height).min(FRAME_HEIGHT);
        if x >= right || y >= bottom {
            return Ok(());
        }

        bus.command(CASET)?;
        bus.data(&[0, x as u8, 0, (right - 1) as u8])?;
        bus.command(RASET)?;
        bus.data(&[0, y as u8, 0, (bottom - 1) as u8])?;
        bus.command(RAMWR)?;

        // Avoid a large temporary buffer: stream RGB565 pixels two bytes
        // at a time, matching the original frame update's high->low order.
        for row in y..bottom {
            for col in x..right {
                bus.data(&self.pixels[row * FRAME_WIDTH + col].to_be_bytes())?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    #[derive(Debug, PartialEq, Eq)]
    enum Op { Command(u8), Data(Vec<u8>) }
    #[derive(Default)]
    struct Recorder { operations: Vec<Op>, fail_after: Option<usize> }
    impl PanelBus for Recorder {
        type Error = &'static str;
        fn command(&mut self, byte: u8) -> Result<(), Self::Error> {
            if self.fail_after == Some(self.operations.len()) { return Err("SPI"); }
            self.operations.push(Op::Command(byte));
            Ok(())
        }
        fn data(&mut self, data: &[u8]) -> Result<(), Self::Error> {
            if self.fail_after == Some(self.operations.len()) { return Err("SPI"); }
            self.operations.push(Op::Data(data.to_vec()));
            Ok(())
        }
    }

    #[test]
    fn memory_layout_is_consistent_with_gnss_dma_start() {
        assert_eq!(FRAME_STRIDE_BYTES, 320);
        assert_eq!(ORIGINAL_FRAMEBUFFER_END_EXCLUSIVE, 0x2000_EB76);
        assert_eq!(0x2000_EB88u32 - ORIGINAL_FRAMEBUFFER_END_EXCLUSIVE, 18);
    }

    #[test]
    fn rgb565_frame_put_and_clipped_fill() {
        let mut data = std::vec![0u16; FRAME_PIXELS];
        let mut fb = FrameBuffer::new(&mut data).unwrap();
        fb.fill_rect(158, 126, 6, 7, 0xF800);
        assert_eq!(fb.pixel(158, 126), Some(0xF800));
        assert_eq!(fb.pixel(159, 127), Some(0xF800));
        assert_eq!(fb.pixel(157, 126), Some(0));
        assert!(!fb.put(160, 127, 1));
        assert!(fb.put(0, 0, 0x07E0));
        assert_eq!(fb.pixel(0, 0), Some(0x07E0));
    }

    #[test]
    fn write_window_commands_and_pixel_endianness() {
        let mut data = std::vec![0u16; FRAME_PIXELS];
        let mut fb = FrameBuffer::new(&mut data).unwrap();
        fb.put(5, 9, 0xF81F);
        fb.put(6, 9, 0x07E0);
        let mut recorder = Recorder::default();
        fb.flush_rect(&mut recorder, 5, 9, 2, 1).unwrap();
        assert_eq!(recorder.operations, std::vec![
            Op::Command(0x2A), Op::Data(std::vec![0,5,0,6]),
            Op::Command(0x2B), Op::Data(std::vec![0,9,0,9]),
            Op::Command(0x2C), Op::Data(std::vec![0xF8,0x1F]),
            Op::Data(std::vec![0x07,0xE0]),
        ]);
    }

    #[test]
    fn empty_window_skips_bus() {
        let mut data = std::vec![0u16; FRAME_PIXELS];
        let fb = FrameBuffer::new(&mut data).unwrap();
        let mut bus = Recorder::default();
        fb.flush_rect(&mut bus, 100, 20, 0, 10).unwrap();
        assert!(bus.operations.is_empty());
    }

    #[test]
    fn spi_failure_propagates_without_continuing_data_transfer() {
        let mut data = std::vec![0u16; FRAME_PIXELS];
        let fb = FrameBuffer::new(&mut data).unwrap();
        let mut bus = Recorder { fail_after: Some(5), ..Recorder::default() };
        assert_eq!(fb.flush_rect(&mut bus, 0, 0, 1, 1), Err("SPI"));
        assert_eq!(bus.operations.len(), 5);
    }

    #[test]
    fn wrong_frame_size_is_rejected() {
        let mut data = [0u16; 4];
        assert!(FrameBuffer::new(&mut data).is_none());
    }
}
