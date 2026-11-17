//! OEM V2 RF-adjacent 0x82-byte nonvolatile record transport.
//!
//! This is the recovered record *format and copy*, not proof that the
//! 64 halfwords are physical VCO/RSSI/power calibration coefficients.
//! Actual values are stored on a radio and absent from the upgrade image.

pub const OEM_NV_RECORD_BYTES: usize = 0x82;
pub const OEM_NV_HALFWORDS: usize = 0x40;
pub const OEM_NV_INDEX_BASE: u32 = 0x7A90;
pub const OEM_NV_INDEX_STRIDE: u32 = 0x98;
pub const OEM_NV_REFERENCE_HEADER_ADDRESS: u32 = 0x7982;
pub const OEM_SRAM_RECORD_BASE: u32 = 0x2000_246C;
pub const OEM_SRAM_RECORD_COUNT_ADDRESS: u32 = OEM_SRAM_RECORD_BASE + 0x10;
pub const OEM_SRAM_RECORD_VALUES_ADDRESS: u32 = OEM_SRAM_RECORD_BASE + 0x12;

/// Mode index originates from original V2 configuration selectors 2/3.
pub const fn nv_record_address(selector: u8) -> u32 {
    OEM_NV_INDEX_BASE + OEM_NV_INDEX_STRIDE * selector as u32
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawNvRfRecord {
    /// Original two header bytes are retained; software interpretation unknown.
    pub raw_header: [u8; 2],
    pub values: [u16; OEM_NV_HALFWORDS],
}
impl RawNvRfRecord {
    /// OEM 0x08012CD6..0x08012CF6 copies 64 big-endian words from +2.
    /// The unpacked array is host-endian but not interpreted as Hz or power.
    pub fn from_original_bytes(original: &[u8; OEM_NV_RECORD_BYTES]) -> Self {
        let mut values = [0u16; OEM_NV_HALFWORDS];
        let mut i = 0;
        while i < OEM_NV_HALFWORDS {
            values[i] = u16::from_be_bytes([original[2 + i*2], original[3 + i*2]]);
            i += 1;
        }
        Self {
            raw_header: [original[0], original[1]],
            values,
        }
    }
}


/// V2 0x08012BB8 reads four per-mode RF frequency trim bytes at 0xC5C0.
/// 0x08012BD0..0x08012BF0 converts each to a signed 32-bit correction.
/// This is independently consumed by 0x0800DDB8 / 0x0800AFF0.
pub const OEM_FREQUENCY_TRIM_NV_ADDRESS: u32 = 0xC5C0;
pub const OEM_FREQUENCY_TRIM_COUNT: usize = 4;
pub const OEM_FREQUENCY_TRIM_NEUTRAL_BYTE: u8 = 0x28;
pub const OEM_FREQUENCY_TRIM_MAX_RAW_BYTE: u8 = 0x60;
pub const OEM_FREQUENCY_TRIM_UNITS_PER_BYTE: i32 = 5;
pub const OEM_FREQUENCY_TRIM_HZ_PER_BYTE: i32 = 50;

/// Convert an original EEPROM trim byte to an additive raw 10-Hz word.
/// Values > 0x60 are overwritten with 0x28 by stock code; values < 0x28
/// produce negative corrections, stored as 32-bit two's complement.
pub const fn original_trim_word(value: u8) -> u32 {
    let normalized = if value > OEM_FREQUENCY_TRIM_MAX_RAW_BYTE {
        OEM_FREQUENCY_TRIM_NEUTRAL_BYTE
    } else { value };
    ((normalized as i32 - OEM_FREQUENCY_TRIM_NEUTRAL_BYTE as i32)
        * OEM_FREQUENCY_TRIM_UNITS_PER_BYTE) as u32
}
pub const fn original_trim_hz(value: u8) -> i32 {
    original_trim_word(value) as i32 * 10
}
pub const fn original_trim_bank(values: [u8;4]) -> [u32;4] {
    [
        original_trim_word(values[0]),
        original_trim_word(values[1]),
        original_trim_word(values[2]),
        original_trim_word(values[3]),
    ]
}

pub const OEM_SRAM_SECOND_BANK_COUNT_ADDRESS: u32 =
    OEM_SRAM_RECORD_COUNT_ADDRESS + OEM_NV_RECORD_BYTES as u32;
pub const OEM_SRAM_SECOND_BANK_VALUES_ADDRESS: u32 =
    OEM_SRAM_SECOND_BANK_COUNT_ADDRESS + 2;

/// The OEM copies a second 64-word record via 0x08012D36..0x08012D56.
/// Both banks are opaque per-device NV data, not compiled-in calibration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawNvRfBankPair {
    pub first: RawNvRfRecord,
    pub second: RawNvRfRecord,
}
impl RawNvRfBankPair {
    pub fn from_original_records(
        first: &[u8; OEM_NV_RECORD_BYTES],
        second: &[u8; OEM_NV_RECORD_BYTES],
    ) -> Self {
        Self {
            first: RawNvRfRecord::from_original_bytes(first),
            second: RawNvRfRecord::from_original_bytes(second),
        }
    }
}

/// Four original constants at 0x0800A6CA..0x0800A6DC are copied to
/// SRAM 0x200102B0. Their physical interpretation remains unverified.
pub const OEM_RF_WORKING_WORDS: [u32;4] = [
    0x002F_03E7, 0x002F_1786, 0x002F_2343, 0x002F_31E1,
];

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn original_mode_record_addresses_retain_eeprom_stride() {
        assert_eq!(nv_record_address(2), 0x7BC0);
        assert_eq!(nv_record_address(3), 0x7C58);
        assert_eq!(OEM_NV_REFERENCE_HEADER_ADDRESS, 0x7982);
        assert_eq!(OEM_SRAM_RECORD_VALUES_ADDRESS, 0x2000_247E);
    }
    #[test]
    fn record_copies_all_64_original_big_endian_words_from_plus_two() {
        let mut input = [0u8; OEM_NV_RECORD_BYTES];
        input[0] = 0xA5;
        input[1] = 0x5A;
        for i in 0..64 {
            input[2 + i*2] = i as u8;
            input[3 + i*2] = (255 - i) as u8;
        }
        let record = RawNvRfRecord::from_original_bytes(&input);
        assert_eq!(record.raw_header, [0xA5,0x5A]);
        assert_eq!(record.values[0], 0x00FF);
        assert_eq!(record.values[63], 0x3FC0);
        assert_eq!(record.values.len(), 64);
    }
    #[test]
    fn four_stock_working_values_are_raw_not_frequency_hz() {
        assert_eq!(OEM_RF_WORKING_WORDS, [
            0x002F03E7,0x002F1786,0x002F2343,0x002F31E1,
        ]);
    }

    #[test]
    fn four_oem_trim_bytes_use_signed_fifty_hz_steps() {
        assert_eq!(OEM_FREQUENCY_TRIM_NV_ADDRESS,0xC5C0);
        assert_eq!(original_trim_word(0x28),0);
        assert_eq!(original_trim_word(0x29),5);
        assert_eq!(original_trim_hz(0x29),50);
        assert_eq!(original_trim_word(0x60),280);
        assert_eq!(original_trim_hz(0x60),2800);
        assert_eq!(original_trim_word(0x61),0);
        assert_eq!(original_trim_word(0),(-200i32) as u32);
        assert_eq!(original_trim_hz(0),-2000);
        assert_eq!(original_trim_bank([0x28,0x29,0x60,0]),
                   [0,5,280,(-200i32) as u32]);
    }


    #[test]
    fn two_64_word_nv_banks_have_back_to_back_layout() {
        assert_eq!(OEM_SRAM_SECOND_BANK_COUNT_ADDRESS,0x200024FE);
        assert_eq!(OEM_SRAM_SECOND_BANK_VALUES_ADDRESS,0x20002500);
        let mut a=[0u8;OEM_NV_RECORD_BYTES];
        let mut b=[0u8;OEM_NV_RECORD_BYTES];
        a[2]=0x12;a[3]=0x34;b[2]=0x56;b[3]=0x78;
        let pair=RawNvRfBankPair::from_original_records(&a,&b);
        assert_eq!(pair.first.values[0],0x1234);
        assert_eq!(pair.second.values[0],0x5678);
    }

}
