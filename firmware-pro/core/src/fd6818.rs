//! UV-5RH Pro OEM FD6818 two-wire register transport.
//!
//! V2 stock image drives an I2C-compatible 0x71 seven-bit device,
//! with 0xE2 as write byte and 8-bit register + 16-bit big-endian data.
//! The hardware-specific PA14/PC15 GPIO timing is provided by the board HAL.
//! Chip-ID, analog calibration, RF switching and LCD wiring remain unmeasured.

use crate::rda5807m::I2cRegisterBus;

pub const I2C_ADDRESS_7BIT: u8 = 0x71;
pub const STOCK_WRITE_ADDRESS_8BIT: u8 = 0xE2;
pub const STOCK_READ_ADDRESS_8BIT: u8 = 0xE3;

/// Raw original application register addresses, not unconditionally
/// interchangeable with another manufacturer's FD6818 register numbering.
pub const REG_FREQUENCY_HI: u8 = 0x39;
pub const REG_FREQUENCY_LO: u8 = 0x38;
pub const REG_STATE: u8 = 0x30;
pub const ORIGINAL_STATE_WORD: u16 = 0xC3FA;

pub struct Fd6818<B> {
    bus: B,
}

impl<B: I2cRegisterBus> Fd6818<B> {
    pub const fn new(bus: B) -> Self {
        Self { bus }
    }

    pub fn write_register(&mut self, reg: u8, value: u16) -> Result<(), B::Error> {
        let [hi, lo] = value.to_be_bytes();
        self.bus.write(I2C_ADDRESS_7BIT, &[reg, hi, lo])
    }

    pub fn read_register(&mut self, reg: u8) -> Result<u16, B::Error> {
        let mut response = [0u8; 2];
        self.bus
            .write_read(I2C_ADDRESS_7BIT, &[reg], &mut response)?;
        Ok(u16::from_be_bytes(response))
    }

    /// Keep the original high-word first, low-word second ordering.
    /// No Hz-to-PLL conversion is implied by a raw 32-bit tuning word.
    pub fn write_frequency_word(&mut self, raw_word: u32) -> Result<(), B::Error> {
        self.write_register(REG_FREQUENCY_HI, (raw_word >> 16) as u16)?;
        self.write_register(REG_FREQUENCY_LO, raw_word as u16)
    }

    pub fn into_bus(self) -> B {
        self.bus
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    #[derive(Default)]
    struct Recorder {
        writes: Vec<(u8, Vec<u8>)>,
        result: [u8; 2],
        fail_on_call: Option<usize>,
        calls: usize,
    }

    impl I2cRegisterBus for Recorder {
        type Error = &'static str;

        fn write(&mut self, addr: u8, data: &[u8]) -> Result<(), Self::Error> {
            self.calls += 1;
            if self.fail_on_call == Some(self.calls) {
                return Err("failed transaction");
            }
            self.writes.push((addr, data.to_vec()));
            Ok(())
        }

        fn write_read(
            &mut self, addr: u8, data: &[u8], out: &mut [u8]
        ) -> Result<(), Self::Error> {
            self.write(addr, data)?;
            out.copy_from_slice(&self.result);
            Ok(())
        }
    }

    #[test]
    fn raw_register_write_matches_oem_big_endian_format() {
        let mut radio = Fd6818::new(Recorder::default());
        radio.write_register(REG_STATE, ORIGINAL_STATE_WORD).unwrap();
        let bus = radio.into_bus();
        assert_eq!(STOCK_WRITE_ADDRESS_8BIT, I2C_ADDRESS_7BIT << 1);
        assert_eq!(STOCK_READ_ADDRESS_8BIT, (I2C_ADDRESS_7BIT << 1) | 1);
        assert_eq!(bus.writes[0], (0x71, std::vec![0x30, 0xC3, 0xFA]));
    }

    #[test]
    fn original_frequency_word_is_high_register_then_low_register() {
        let mut radio = Fd6818::new(Recorder::default());
        radio.write_frequency_word(0x12345678).unwrap();
        let bus = radio.into_bus();
        assert_eq!(bus.writes, std::vec![
            (0x71, std::vec![0x39, 0x12, 0x34]),
            (0x71, std::vec![0x38, 0x56, 0x78]),
        ]);
    }

    #[test]
    fn raw_read_retains_big_endian_order() {
        let mut radio = Fd6818::new(Recorder {
            result: [0x48, 0x19], ..Recorder::default()
        });
        assert_eq!(radio.read_register(0), Ok(0x4819));
    }

    #[test]
    fn failed_first_write_does_not_issue_second_write() {
        let mut radio = Fd6818::new(Recorder {
            fail_on_call: Some(1), ..Recorder::default()
        });
        assert_eq!(radio.write_frequency_word(0x12345678), Err("failed transaction"));
        let bus = radio.into_bus();
        assert_eq!(bus.calls, 1);
        assert!(bus.writes.is_empty());
    }

    #[test]
    fn failed_second_write_is_propagated() {
        let mut radio = Fd6818::new(Recorder {
            fail_on_call: Some(2), ..Recorder::default()
        });
        assert_eq!(radio.write_frequency_word(0x12345678), Err("failed transaction"));
        let bus = radio.into_bus();
        assert_eq!(bus.calls, 2);
        assert_eq!(bus.writes.len(), 1);
    }
}
