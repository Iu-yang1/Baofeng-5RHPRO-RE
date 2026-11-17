//! Source-grounded UV-5RH Pro V2 logical NV read transport over SPI3.
//!
//! OEM V2 0x080141DC issues 0x03 + three big-endian address bytes,
//! clocks out the data with 0xFF, and brackets the operation with
//! GPIOA15 software CS low/high. Byte exchange calls V2 0x08031814.
//! The software port bit is NOT a proven XL9951Q physical package pad.

use crate::board_v2::{BoardGpio, OEM_SPI3_NV_CS_SOFTWARE};
use crate::nv_store::LogicalNvReader;

pub const OEM_NOR_READ_OPCODE: u8 = 0x03;
pub const OEM_NOR_READ_DUMMY: u8 = 0xFF;
pub const OEM_NOR_ADDRESS_BITS: u8 = 24;

/// The OEM byte-exchange call does not report a distinct timeout flag;
/// an actual HAL must supply transfer failure separately from valid 0x00.
pub trait SpiByteTransfer {
    type Error;
    fn transfer_byte(&mut self, tx: u8) -> Result<u8, Self::Error>;
}

#[derive(Debug, PartialEq, Eq)]
pub enum OemSpi3NvReadError<SpiError, GpioError> {
    AddressExceeds24Bits,
    Select(GpioError),
    Transfer(SpiError),
    Deselect(GpioError),
    TransferAndDeselect { transfer: SpiError, deselect: GpioError },
}

/// Adapter only for the original V2 application's read transaction.
/// Does not perform NOR writes, erases, device-ID probes or unlocks.
pub struct OemSpi3NvReader<'a, SPI, GPIO> {
    pub spi: &'a mut SPI,
    pub gpio: &'a mut GPIO,
}
impl<'a, SPI, GPIO> OemSpi3NvReader<'a, SPI, GPIO> {
    pub fn new(spi: &'a mut SPI, gpio: &'a mut GPIO) -> Self {
        Self { spi, gpio }
    }
}

impl<SPI, GPIO> LogicalNvReader for OemSpi3NvReader<'_, SPI, GPIO>
where
    SPI: SpiByteTransfer,
    GPIO: BoardGpio,
{
    type Error = OemSpi3NvReadError<SPI::Error, GPIO::Error>;

    fn read(&mut self, logical_address: u32, out: &mut [u8]) -> Result<(), Self::Error> {
        if logical_address > 0x00FF_FFFF {
            return Err(OemSpi3NvReadError::AddressExceeds24Bits);
        }

        self.gpio.set_level(OEM_SPI3_NV_CS_SOFTWARE, false)
            .map_err(OemSpi3NvReadError::Select)?;

        let transfer = (|| -> Result<(), SPI::Error> {
            self.spi.transfer_byte(OEM_NOR_READ_OPCODE)?;
            self.spi.transfer_byte((logical_address >> 16) as u8)?;
            self.spi.transfer_byte((logical_address >> 8) as u8)?;
            self.spi.transfer_byte(logical_address as u8)?;
            for byte in out {
                *byte = self.spi.transfer_byte(OEM_NOR_READ_DUMMY)?;
            }
            Ok(())
        })();

        // Leave the selected chip deselected even when one exchange fails.
        // Preserve both errors if the bus and the CS release fail together.
        let deselect = self.gpio.set_level(OEM_SPI3_NV_CS_SOFTWARE, true);
        match (transfer, deselect) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(transfer), Ok(())) => Err(OemSpi3NvReadError::Transfer(transfer)),
            (Ok(()), Err(deselect)) => Err(OemSpi3NvReadError::Deselect(deselect)),
            (Err(transfer), Err(deselect)) => {
                Err(OemSpi3NvReadError::TransferAndDeselect { transfer, deselect })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::board_v2::Pin;
    use crate::nv_store::read_oem_nv_snapshot;
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::vec::Vec;

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Op { ChipSelect(bool), Byte(u8) }
    type Events = Rc<RefCell<Vec<Op>>>;

    struct Spi {
        events: Events,
        reads: Vec<u8>,
        calls: usize,
        fail_on: Option<usize>,
    }
    impl SpiByteTransfer for Spi {
        type Error = &'static str;
        fn transfer_byte(&mut self, tx: u8) -> Result<u8, Self::Error> {
            self.calls += 1;
            self.events.borrow_mut().push(Op::Byte(tx));
            if self.fail_on == Some(self.calls) { return Err("SPI3 timeout"); }
            if tx == OEM_NOR_READ_DUMMY && !self.reads.is_empty() {
                return Ok(self.reads.remove(0));
            }
            Ok(0)
        }
    }

    struct Gpio {
        events: Events,
        fail_high: bool,
        fail_low: bool,
    }
    impl BoardGpio for Gpio {
        type Error = &'static str;
        fn set_level(&mut self, pin: Pin, high: bool) -> Result<(), Self::Error> {
            assert_eq!(pin, OEM_SPI3_NV_CS_SOFTWARE);
            self.events.borrow_mut().push(Op::ChipSelect(high));
            if high && self.fail_high { return Err("CS high"); }
            if !high && self.fail_low { return Err("CS low"); }
            Ok(())
        }
        fn sample(&mut self, _: Pin) -> Result<bool, Self::Error> {
            unreachable!()
        }
    }

    fn fixture(reads: Vec<u8>) -> (Events, Spi, Gpio) {
        let events = Rc::new(RefCell::new(Vec::new()));
        let spi = Spi {
            events: events.clone(), reads, calls: 0, fail_on: None,
        };
        let gpio = Gpio {
            events: events.clone(), fail_high: false, fail_low: false,
        };
        (events, spi, gpio)
    }

    #[test]
    fn original_spi3_read_selects_then_sends_opcode_and_24bit_address() {
        let (events, mut spi, mut gpio) = fixture(std::vec![0x27, 0x28, 0x60, 0x61]);
        let mut reader = OemSpi3NvReader::new(&mut spi, &mut gpio);
        let mut out = [0u8; 4];
        reader.read(0xC5C0, &mut out).unwrap();
        assert_eq!(out, [0x27, 0x28, 0x60, 0x61]);
        assert_eq!(*events.borrow(), std::vec![
            Op::ChipSelect(false),
            Op::Byte(0x03), Op::Byte(0x00), Op::Byte(0xC5), Op::Byte(0xC0),
            Op::Byte(0xFF), Op::Byte(0xFF), Op::Byte(0xFF), Op::Byte(0xFF),
            Op::ChipSelect(true),
        ]);
    }

    #[test]
    fn spi_error_releases_cs_and_is_not_converted_into_received_zero() {
        let (events, mut spi, mut gpio) = fixture(Vec::new());
        spi.fail_on = Some(5);
        let mut reader = OemSpi3NvReader::new(&mut spi, &mut gpio);
        let mut bytes = [0u8; 2];
        assert_eq!(reader.read(0xC5C0, &mut bytes),
            Err(OemSpi3NvReadError::Transfer("SPI3 timeout")));
        assert_eq!(events.borrow().last(), Some(&Op::ChipSelect(true)));
    }

    #[test]
    fn select_and_deselect_errors_are_distinguished() {
        let (events, mut spi, mut gpio) = fixture(Vec::new());
        gpio.fail_low = true;
        let mut reader = OemSpi3NvReader::new(&mut spi, &mut gpio);
        assert_eq!(reader.read(0, &mut []), Err(OemSpi3NvReadError::Select("CS low")));
        assert_eq!(*events.borrow(), std::vec![Op::ChipSelect(false)]);

        let (_, mut spi, mut gpio) = fixture(Vec::new());
        gpio.fail_high = true;
        let mut reader = OemSpi3NvReader::new(&mut spi, &mut gpio);
        assert_eq!(reader.read(0, &mut []), Err(OemSpi3NvReadError::Deselect("CS high")));
    }

    #[test]
    fn simultaneous_spi_and_deselect_failure_retains_both_causes() {
        let (_, mut spi, mut gpio) = fixture(Vec::new());
        spi.fail_on = Some(1);
        gpio.fail_high = true;
        let mut reader = OemSpi3NvReader::new(&mut spi, &mut gpio);
        assert_eq!(reader.read(0, &mut []),
            Err(OemSpi3NvReadError::TransferAndDeselect {
                transfer: "SPI3 timeout", deselect: "CS high",
            }));
    }

    #[test]
    fn address_is_24bit_and_not_a_mcu_flash_absolute_address() {
        let (events, mut spi, mut gpio) = fixture(Vec::new());
        let mut reader = OemSpi3NvReader::new(&mut spi, &mut gpio);
        assert_eq!(reader.read(0x0100_0000, &mut []),
            Err(OemSpi3NvReadError::AddressExceeds24Bits));
        assert!(events.borrow().is_empty());
    }

    #[test]
    fn spi3_adapter_reaches_full_snapshot_loader_without_embedded_nv_values() {
        let mut data = std::vec![0x28; 4];
        data.extend(std::iter::repeat_n(0u8, 0x82 * 2));
        let (_, mut spi, mut gpio) = fixture(data);
        let mut reader = OemSpi3NvReader::new(&mut spi, &mut gpio);
        let snapshot = read_oem_nv_snapshot(&mut reader, [2, 3]).unwrap();
        assert_eq!(snapshot.frequency_trims.original_bytes, [0x28; 4]);
        assert_eq!(snapshot.raw_profiles.second.values.len(), 64);
    }
}
