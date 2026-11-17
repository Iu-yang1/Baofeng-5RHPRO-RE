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


/// Reset GPIO and timings observed in V2 0x0801501C..0x08015048.
/// Timings are *raw argument units* of the OEM delay helper, not milliseconds.
pub trait OriginalPanelReset {
    type Error;
    fn set_reset_high(&mut self, high: bool) -> Result<(), Self::Error>;
    fn wait_oem_argument(&mut self, argument: u32);
}
pub trait OriginalPanelDelay { fn wait_oem_argument(&mut self, argument: u32); }

pub fn reset_oem_panel<R: OriginalPanelReset>(reset: &mut R) -> Result<(), R::Error> {
    reset.set_reset_high(true)?;
    reset.wait_oem_argument(0x14);
    reset.set_reset_high(false)?;
    reset.wait_oem_argument(0xC8);
    reset.set_reset_high(true)?;
    reset.wait_oem_argument(0x14);
    Ok(())
}

/// The panel's exact model and physical rotation are not yet proven.
/// The two data bytes below are the original conditional MADCTL results.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OemOrientation { OriginalA0, Alternate60 }
impl OemOrientation {
    pub const fn madctl(self) -> u8 {
        match self {
            Self::OriginalA0 => 0xA0,
            Self::Alternate60 => 0x60,
        }
    }
}
pub const OEM_GAMMA_POSITIVE: [u8; 16] = [
    0x0B, 0x21, 0x0C, 0x16, 0x2E, 0x27, 0x1F, 0x25,
    0x25, 0x24, 0x2C, 0x38, 0x00, 0x03, 0x00, 0x10,
];
pub const OEM_GAMMA_NEGATIVE: [u8; 16] = [
    0x0E, 0x1E, 0x0E, 0x18, 0x33, 0x2D, 0x28, 0x2A,
    0x28, 0x26, 0x2F, 0x3C, 0x00, 0x05, 0x05, 0x10,
];

/// Exact logical command/data stream from V2's branch-compatible setup.
/// Register transfers are serialized as bytes, as in OEM `0x0800755C`.
pub const OEM_SETUP_BEFORE_MADCTL: &[(u8, &[u8])] = &[
    (0xB1, &[0x05, 0x3C, 0x3C]),
    (0xB2, &[0x05, 0x3C, 0x3C]),
    (0xB3, &[0x05, 0x3C, 0x3C, 0x05, 0x3C, 0x3C]),
    (0xB4, &[0x03]),
    (0xC0, &[0xA4, 0x04, 0x84]),
    (0xC1, &[0xC1]),
    (0xC2, &[0x0D, 0x00]),
    (0xC3, &[0x8D, 0x2A]),
    (0xC4, &[0x8D, 0xEE]),
    (0xC5, &[0x0C]),
];
fn send_oem_pair<B: PanelBus>(
    panel: &mut B, command: u8, bytes: &[u8]
) -> Result<(), B::Error> {
    panel.command(command)?;
    for &value in bytes {
        panel.data(&[value])?;
    }
    Ok(())
}

/// Original V2 0x0801504C..0x0801521A. OEM does NOT send 0x29
/// here; first actual framebuffer transfer sends Display On later.
pub fn initialize_oem_registers<B: PanelBus, D: OriginalPanelDelay>(
    panel: &mut B,
    delay: &mut D,
    orientation: OemOrientation,
) -> Result<(), B::Error> {
    panel.command(0x11)?;
    delay.wait_oem_argument(0x64);
    for &(command, values) in OEM_SETUP_BEFORE_MADCTL {
        send_oem_pair(panel, command, values)?;
    }
    send_oem_pair(panel, 0x36, &[orientation.madctl()])?;
    send_oem_pair(panel, 0xE0, &OEM_GAMMA_POSITIVE)?;
    send_oem_pair(panel, 0xE1, &OEM_GAMMA_NEGATIVE)?;
    send_oem_pair(panel, 0x35, &[0x00])?;
    send_oem_pair(panel, 0x3A, &[0x05])?;
    Ok(())
}

/// Original SRAM 0x20000FD8 tracks this phase. Call only after a
/// successful first frame transfer; preserve display-on retry on SPI error.
#[derive(Default)]
pub struct FirstFrameDisplayOn { sent: bool }
impl FirstFrameDisplayOn {
    pub const fn new() -> Self { Self { sent: false } }
    pub const fn is_on(&self) -> bool { self.sent }
    pub fn after_frame<B: PanelBus>(&mut self, bus: &mut B) -> Result<(), B::Error> {
        if !self.sent {
            bus.command(0x29)?;
            self.sent = true;
        }
        Ok(())
    }
}

#[cfg(test)]
mod oem_panel_init_tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;
    #[derive(Debug, PartialEq, Eq)]
    enum Operation { Command(u8), Data(u8) }
    #[derive(Default)]
    struct Bus { events: Vec<Operation>, fail_command: Option<u8> }
    impl PanelBus for Bus {
        type Error = &'static str;
        fn command(&mut self, cmd: u8) -> Result<(), Self::Error> {
            if self.fail_command == Some(cmd) { return Err("command"); }
            self.events.push(Operation::Command(cmd));
            Ok(())
        }
        fn data(&mut self, data: &[u8]) -> Result<(), Self::Error> {
            for &byte in data { self.events.push(Operation::Data(byte)); }
            Ok(())
        }
    }
    #[derive(Default)]
    struct Delay { calls: Vec<u32> }
    impl OriginalPanelDelay for Delay {
        fn wait_oem_argument(&mut self, argument: u32) {
            self.calls.push(argument);
        }
    }
    #[derive(Default)]
    struct Reset { ops: Vec<(bool, u32)>, last: bool }
    impl OriginalPanelReset for Reset {
        type Error = &'static str;
        fn set_reset_high(&mut self, high: bool) -> Result<(), Self::Error> {
            self.last = high;
            self.ops.push((high, 0));
            Ok(())
        }
        fn wait_oem_argument(&mut self, argument: u32) {
            self.ops.push((self.last, argument));
        }
    }
    #[test]
    fn reset_high_low_high_preserves_raw_oem_delays() {
        let mut p = Reset::default();
        reset_oem_panel(&mut p).unwrap();
        assert_eq!(p.ops, std::vec![
            (true,0), (true,0x14),
            (false,0), (false,0xC8),
            (true,0), (true,0x14),
        ]);
    }
    #[test]
    fn both_oem_madctl_branches_preserve_gamma_and_rgb565() {
        for (orientation, setting) in [
            (OemOrientation::OriginalA0, 0xA0),
            (OemOrientation::Alternate60, 0x60),
        ] {
            let mut panel = Bus::default();
            let mut delay = Delay::default();
            initialize_oem_registers(&mut panel, &mut delay, orientation).unwrap();
            assert_eq!(delay.calls, std::vec![0x64]);
            assert_eq!(panel.events[0], Operation::Command(0x11));
            let i = panel.events.iter().position(|x| *x == Operation::Command(0x36)).unwrap();
            assert_eq!(panel.events[i+1], Operation::Data(setting));
            let g = panel.events.iter().position(|x| *x == Operation::Command(0xE0)).unwrap();
            for (idx, &value) in OEM_GAMMA_POSITIVE.iter().enumerate() {
                assert_eq!(panel.events[g+idx+1], Operation::Data(value));
            }
            let neg = panel.events.iter().position(|x| *x == Operation::Command(0xE1)).unwrap();
            for (idx, &value) in OEM_GAMMA_NEGATIVE.iter().enumerate() {
                assert_eq!(panel.events[neg+idx+1], Operation::Data(value));
            }
            assert!(panel.events.ends_with(&[Operation::Command(0x3A), Operation::Data(0x05)]));
            assert!(!panel.events.contains(&Operation::Command(0x29)));
        }
    }
    #[test]
    fn display_on_is_once_after_first_frame_and_retryable() {
        let mut state = FirstFrameDisplayOn::new();
        let mut panel = Bus { fail_command: Some(0x29), ..Bus::default() };
        assert_eq!(state.after_frame(&mut panel), Err("command"));
        assert!(!state.is_on());
        panel.fail_command = None;
        state.after_frame(&mut panel).unwrap();
        state.after_frame(&mut panel).unwrap();
        assert!(state.is_on());
        assert_eq!(panel.events, std::vec![Operation::Command(0x29)]);
    }
}
