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


/// Confirmed V2 setup calls its generic delay helper with this raw argument.
/// No clock/tick unit is established by the static instruction sequence.
pub const OEM_SETUP_DELAY_ARGUMENT: u32 = 0x0190;

/// Board HAL supplies whatever time unit the original delay helper uses.
/// Host tests can capture the request without hardware or a timing guess.
pub trait StockDelay {
    fn wait_original_argument(&mut self, argument: u32);
}

/// Original V2 setup reads a cached REG_37 halfword then masks/sets bits.
pub const fn oem_setup_reg37(previous: u16) -> u16 {
    (previous & 0xFDF0) | 0x020F
}

/// Stock runtime tuning performs wrapping 32-bit addition before writing
/// upper/lower halves; the quantity is NOT a frequency in Hz.
pub const fn oem_tuning_add(raw_table_word: u32, correction_word: u32) -> u32 {
    raw_table_word.wrapping_add(correction_word)
}


/// FD6818 REV.1.0.0 programming guide: one raw frequency unit = 10 Hz.
/// The 0x39/0x38 register layout is independently present in the OEM V2
/// application; OEM calibration tables and real RF accuracy are still unknown.
pub const FREQUENCY_QUANTUM_HZ: u64 = 10;
pub const OEM_RX_STATE_WORD: u16 = 0xBFF1;
pub const OEM_TX_STATE_WORD: u16 = 0xC1FE;

/// Round to the nearest 10 Hz, permitting the chip's full 32-bit tuning range.
/// Returns None only if the requested word exceeds the representable range.
pub const fn frequency_hz_to_word(frequency_hz: u64) -> Option<u32> {
    let word = frequency_hz / FREQUENCY_QUANTUM_HZ
        + if frequency_hz % FREQUENCY_QUANTUM_HZ >= 5 { 1 } else { 0 };
    if word > u32::MAX as u64 { None } else { Some(word as u32) }
}

/// This selects only the FD6818's on-chip RF state word. It does NOT
/// establish board PA bias/PTT, antenna switch or actual radiated power.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RficState { Idle, Receive, Transmit }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrequencyWriteError<E> { UnrepresentableFrequency, Bus(E) }

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

    /// OEM V2 `0x0800A428` setup prefix only. This is not a complete
    /// TX/RX/PTT/PA sequence, nor evidence of a real powered-on RF state.
    /// The caller supplies the original raw tuning word and cached reg37.
    pub fn apply_oem_setup_prefix<D: StockDelay>(
        &mut self,
        raw_word: u32,
        cached_reg37: u16,
        delay: &mut D,
    ) -> Result<(), B::Error> {
        self.write_register(0x51, 0x0300)?;
        self.write_frequency_word(raw_word)?;
        self.write_register(0x37, oem_setup_reg37(cached_reg37))?;
        self.write_register(REG_STATE, 0x0000)?;
        self.write_register(REG_STATE, 0xBFF1)?;
        delay.wait_original_argument(OEM_SETUP_DELAY_ARGUMENT);
        Ok(())
    }

    /// OEM V2 `0x0800AFE4`: table word + correction, then 0x39/0x38.
    /// The table-index selection is application state, not a PLL formula.
    pub fn write_oem_corrected_tuning_word(
        &mut self,
        raw_table_word: u32,
        correction_word: u32,
    ) -> Result<(), B::Error> {
        self.write_frequency_word(oem_tuning_add(raw_table_word, correction_word))
    }

    /// Datasheet-compatible 10 Hz frequency encoding, then OEM high/low
    /// register write order. This is not a substitute for board calibration.
    pub fn write_frequency_hz(
        &mut self,
        frequency_hz: u64,
    ) -> Result<(), FrequencyWriteError<B::Error>> {
        let word = frequency_hz_to_word(frequency_hz)
            .ok_or(FrequencyWriteError::UnrepresentableFrequency)?;
        self.write_frequency_word(word).map_err(FrequencyWriteError::Bus)
    }

    /// Combine FD6818's documented 10-Hz word with the OEM V2
    /// 0xC5C0 four-byte trim formula (signed 50 Hz/step).
    /// Real per-unit trim bytes must come from the target's NV store.
    pub fn write_frequency_hz_with_oem_trim(
        &mut self,
        frequency_hz: u64,
        original_trim_byte: u8,
    ) -> Result<(), FrequencyWriteError<B::Error>> {
        let base = frequency_hz_to_word(frequency_hz)
            .ok_or(FrequencyWriteError::UnrepresentableFrequency)?;
        let trim = crate::nv_rf::original_trim_word(original_trim_byte);
        self.write_frequency_word(base.wrapping_add(trim))
            .map_err(FrequencyWriteError::Bus)
    }

    /// OEM V2 state values cross-check the FD6818 programming guide:
    /// idle=0, RX=0xBFF1, TX=0xC1FE, all at OEM register 0x30.
    /// Neither TX path nor board PA enable is implied by this isolated call.
    pub fn select_rfic_state(&mut self, state: RficState) -> Result<(), B::Error> {
        self.write_register(REG_STATE, 0x0000)?;
        let value = match state {
            RficState::Idle => return Ok(()),
            RficState::Receive => OEM_RX_STATE_WORD,
            RficState::Transmit => OEM_TX_STATE_WORD,
        };
        self.write_register(REG_STATE, value)
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

    #[derive(Default)]
    struct WaitRecorder { calls: std::vec::Vec<u32> }
    impl StockDelay for WaitRecorder {
        fn wait_original_argument(&mut self, argument: u32) {
            self.calls.push(argument);
        }
    }

    #[test]
    fn verified_oem_setup_prefix_preserves_order_and_original_raw_wait() {
        let mut radio = Fd6818::new(Recorder::default());
        let mut delay = WaitRecorder::default();
        radio.apply_oem_setup_prefix(0x1234_5678, 0xFFFF, &mut delay).unwrap();
        assert_eq!(radio.into_bus().writes, std::vec![
            (0x71, std::vec![0x51, 0x03, 0x00]),
            (0x71, std::vec![0x39, 0x12, 0x34]),
            (0x71, std::vec![0x38, 0x56, 0x78]),
            (0x71, std::vec![0x37, 0xFF, 0xFF]),
            (0x71, std::vec![0x30, 0x00, 0x00]),
            (0x71, std::vec![0x30, 0xBF, 0xF1]),
        ]);
        assert_eq!(delay.calls, std::vec![0x190]);
    }

    #[test]
    fn oem_setup_preserves_masked_state_and_aborts_on_bus_failure() {
        assert_eq!(oem_setup_reg37(0), 0x020F);
        assert_eq!(oem_setup_reg37(0x1234), 0x123F);
        let mut radio = Fd6818::new(Recorder {
            fail_on_call: Some(4), ..Recorder::default()
        });
        let mut delay = WaitRecorder::default();
        assert_eq!(radio.apply_oem_setup_prefix(0x1234_5678, 0, &mut delay),
                   Err("failed transaction"));
        assert_eq!(radio.into_bus().writes.len(), 3);
        assert!(delay.calls.is_empty());
    }

    #[test]
    fn oem_runtime_tuning_adds_raw_correction_with_32bit_wrap() {
        assert_eq!(oem_tuning_add(0xFFFF_FFF0, 0x30), 0x20);
        let mut radio = Fd6818::new(Recorder::default());
        radio.write_oem_corrected_tuning_word(0xFFFF_FFF0, 0x30).unwrap();
        assert_eq!(radio.into_bus().writes, std::vec![
            (0x71, std::vec![0x39, 0, 0]),
            (0x71, std::vec![0x38, 0, 0x20]),
        ]);
    }


    #[test]
    fn fd6818_guide_frequency_example_is_409_75_mhz() {
        assert_eq!(frequency_hz_to_word(409_750_000), Some(0x0271_3A98));
        assert_eq!(frequency_hz_to_word(145_500_000), Some(14_550_000));
        assert_eq!(frequency_hz_to_word(145_500_004), Some(14_550_000));
        assert_eq!(frequency_hz_to_word(145_500_005), Some(14_550_001));
        assert_eq!(frequency_hz_to_word(u32::MAX as u64 * 10), Some(u32::MAX));
        assert_eq!(frequency_hz_to_word(u32::MAX as u64 * 10 + 5), None);
    }

    #[test]
    fn fd6818_hz_tuning_emits_oem_high_word_before_low_word() {
        let mut rf = Fd6818::new(Recorder::default());
        assert_eq!(rf.write_frequency_hz(409_750_000), Ok(()));
        assert_eq!(rf.into_bus().writes, std::vec![
            (0x71, std::vec![0x39, 0x02, 0x71]),
            (0x71, std::vec![0x38, 0x3A, 0x98]),
        ]);
    }

    #[test]
    fn fd6818_rfic_state_words_do_not_assume_external_pa_gpio() {
        for (state, word) in [
            (RficState::Receive, 0xBFF1u16),
            (RficState::Transmit, 0xC1FEu16),
        ] {
            let mut rf = Fd6818::new(Recorder::default());
            rf.select_rfic_state(state).unwrap();
            assert_eq!(rf.into_bus().writes, std::vec![
                (0x71, std::vec![0x30, 0x00, 0x00]),
                (0x71, std::vec![0x30, (word >> 8) as u8, word as u8]),
            ]);
        }
        let mut rf = Fd6818::new(Recorder::default());
        rf.select_rfic_state(RficState::Idle).unwrap();
        assert_eq!(rf.into_bus().writes,
                   std::vec![(0x71, std::vec![0x30, 0x00, 0x00])]);
    }

    #[test]
    fn frequency_with_stock_trim_writes_frequency_and_signed_trim() {
        let mut rf = Fd6818::new(Recorder::default());
        rf.write_frequency_hz_with_oem_trim(409_750_000, 0x29).unwrap();
        assert_eq!(rf.into_bus().writes, std::vec![
            (0x71,std::vec![0x39,0x02,0x71]),
            (0x71,std::vec![0x38,0x3A,0x9D]),
        ]);
        let mut rf=Fd6818::new(Recorder::default());
        rf.write_frequency_hz_with_oem_trim(409_750_000, 0x27).unwrap();
        assert_eq!(rf.into_bus().writes[1],(0x71,std::vec![0x38,0x3A,0x93]));
    }

    #[test]
    fn frequency_write_error_and_state_bus_failure_are_propagated() {
        let mut rf = Fd6818::new(Recorder::default());
        assert_eq!(rf.write_frequency_hz(u64::MAX),
                   Err(FrequencyWriteError::UnrepresentableFrequency));
        assert!(rf.into_bus().writes.is_empty());

        let mut rf = Fd6818::new(Recorder {
            fail_on_call: Some(2), ..Recorder::default()
        });
        assert_eq!(rf.select_rfic_state(RficState::Transmit), Err("failed transaction"));
        assert_eq!(rf.into_bus().writes.len(), 1);
    }

}
