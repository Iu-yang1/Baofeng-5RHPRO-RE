//! Original V2.0.09 keyboard lookup decoded from scatterload SRAM.
//!
//! Logical indices are proved from the original 22-entry scan table.
//! Button legends and QFN64 pad numbers are NOT yet established.
pub const KEY_COUNT: usize = 22;
pub const ORIGINAL_SCAN_CODES: [u16; KEY_COUNT] = [
    0x01A8, 0x00E1, 0x0170, 0x0168, 0x0162, 0x0161,
    0x01B0, 0x01A4, 0x01A2, 0x01A1, 0x00F0, 0x00E8,
    0x00E4, 0x00E2, 0x0164, 0x01D0, 0x01C2, 0x01C8,
    0x01C4, 0x0160, 0x01A0, 0x00F1,
];

/// The original V2 scan logic returns an index 0..21 or 0xFF if unmatched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyIndex(pub u8);

/// Combine the two GPIOC input snapshots as done by original Thumb code:
/// first pass reads PC6..PC9; the second reads PC1..PC5.
/// Direction changes and electrical settling are a board-HAL responsibility.
pub const fn normalized_code(first_idr: u16, second_idr: u16) -> u16 {
    ((first_idr & 0x03C0) | (second_idr & 0x003E)) >> 1
}

pub fn from_code(code: u16) -> Option<KeyIndex> {
    ORIGINAL_SCAN_CODES
        .iter()
        .position(|&candidate| candidate == code)
        .map(|index| KeyIndex(index as u8))
}

pub fn scan(first_idr: u16, second_idr: u16) -> Option<KeyIndex> {
    from_code(normalized_code(first_idr, second_idr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_lookup_has_22_distinct_keys() {
        for (index, &code) in ORIGINAL_SCAN_CODES.iter().enumerate() {
            assert_eq!(from_code(code), Some(KeyIndex(index as u8)));
            assert_eq!(
                ORIGINAL_SCAN_CODES.iter().filter(|&&x| x == code).count(),
                1
            );
        }
    }

    #[test]
    fn gpio_two_pass_merge_recovers_original_codes() {
        for (index, code) in ORIGINAL_SCAN_CODES.iter().copied().enumerate() {
            let raw = code << 1;
            let first_idr = raw & 0x03C0;
            let second_idr = raw & 0x003E;
            assert_eq!(scan(first_idr, second_idr), Some(KeyIndex(index as u8)));
        }
    }

    #[test]
    fn unrelated_gpio_bits_do_not_change_scan() {
        let example = ORIGINAL_SCAN_CODES[8] << 1;
        assert_eq!(scan((example & 0x03C0) | 0xFC3F,
                        (example & 0x003E) | 0xFFC1),
                   Some(KeyIndex(8)));
    }

    #[test]
    fn no_match_remains_unknown() {
        assert_eq!(from_code(0x01FF), None);
        assert_eq!(scan(0, 0), None);
    }
}
