//! I2C index-access transaction contract, derived from the stock Pro V2 code.
//!
//! Firmware V2.0.09 uses 0x22/0x23 for write/read, an 8-bit register
//! selector and 16-bit big-endian data. GPIO timing/pins belong to the HAL.
//! This module intentionally does not claim successful physical chip access.
pub const INDEX_ADDRESS_7BIT: u8 = 0x11;
pub const STOCK_WRITE_ADDRESS_8BIT: u8 = 0x22;
pub const STOCK_READ_ADDRESS_8BIT: u8 = 0x23;

/// The transport performs a single I2C write, or write then repeated-start read.
pub trait I2cRegisterBus {
    type Error;

    fn write(&mut self, address: u8, data: &[u8]) -> Result<(), Self::Error>;
    fn write_read(
        &mut self,
        address: u8,
        command: &[u8],
        response: &mut [u8],
    ) -> Result<(), Self::Error>;
}

pub struct IndexedFmRadio<B> {
    bus: B,
}

impl<B: I2cRegisterBus> IndexedFmRadio<B> {
    pub const fn new(bus: B) -> Self {
        Self { bus }
    }

    pub fn read_register(&mut self, register: u8) -> Result<u16, B::Error> {
        let mut received = [0u8; 2];
        self.bus
            .write_read(INDEX_ADDRESS_7BIT, &[register], &mut received)?;
        Ok(u16::from_be_bytes(received))
    }

    pub fn write_register(&mut self, register: u8, value: u16) -> Result<(), B::Error> {
        let [hi, lo] = value.to_be_bytes();
        self.bus.write(INDEX_ADDRESS_7BIT, &[register, hi, lo])
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
    struct MockBus {
        last_write: Vec<u8>,
        last_read_command: Vec<u8>,
        last_address: u8,
        response: [u8; 2],
        fail: bool,
    }

    impl I2cRegisterBus for MockBus {
        type Error = &'static str;

        fn write(&mut self, address: u8, data: &[u8]) -> Result<(), Self::Error> {
            if self.fail { return Err("mock write failure"); }
            self.last_address = address;
            self.last_write = data.to_vec();
            Ok(())
        }

        fn write_read(
            &mut self,
            address: u8,
            command: &[u8],
            response: &mut [u8],
        ) -> Result<(), Self::Error> {
            if self.fail { return Err("mock read failure"); }
            self.last_address = address;
            self.last_read_command = command.to_vec();
            response.copy_from_slice(&self.response);
            Ok(())
        }
    }

    #[test]
    fn index_mode_write_is_register_then_big_endian_word() {
        let mut radio = IndexedFmRadio::new(MockBus::default());
        radio.write_register(0x03, 0x12AB).unwrap();
        let bus = radio.into_bus();
        assert_eq!(bus.last_address, 0x11);
        assert_eq!(bus.last_write.as_slice(), &[0x03, 0x12, 0xAB]);
        assert_eq!(STOCK_WRITE_ADDRESS_8BIT, 0x22);
    }

    #[test]
    fn index_mode_read_is_register_then_two_bytes() {
        let mut radio = IndexedFmRadio::new(MockBus {
            response: [0x58, 0x04], ..MockBus::default()
        });
        assert_eq!(radio.read_register(0x00), Ok(0x5804));
        let bus = radio.into_bus();
        assert_eq!(bus.last_address, 0x11);
        assert_eq!(bus.last_read_command.as_slice(), &[0x00]);
        assert_eq!(STOCK_READ_ADDRESS_8BIT, 0x23);
    }

    #[test]
    fn transport_errors_are_propagated_not_treated_as_valid_zero() {
        let mut radio = IndexedFmRadio::new(MockBus {
            fail: true, ..MockBus::default()
        });
        assert_eq!(radio.read_register(0), Err("mock read failure"));
        assert_eq!(radio.write_register(0, 0), Err("mock write failure"));
    }
}
