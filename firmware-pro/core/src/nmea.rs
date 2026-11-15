//! MCU-independent NMEA sentence framing with checksum verification.
pub const MAX_BODY_BYTES: usize = 128;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SentenceKind { Gga, Rmc, Zda, Other([u8; 3]) }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sentence { pub talker: [u8; 2], pub kind: SentenceKind, pub body_bytes: usize }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NmeaError { Overflow, NoChecksum, InvalidChecksumHex, ChecksumMismatch, ShortHeader }
/// Incremental parser: HAL supplies bytes from DMA or UART.
pub struct Framer { body: [u8; MAX_BODY_BYTES], len: usize, receiving: bool }
impl Default for Framer { fn default() -> Self { Self::new() } }
impl Framer {
    pub const fn new() -> Self {
        Self { body: [0; MAX_BODY_BYTES], len: 0, receiving: false }
    }
    pub fn reset(&mut self) { self.receiving = false; self.len = 0; }
    pub fn push(&mut self, byte: u8) -> Option<Result<Sentence, NmeaError>> {
        if byte == b'$' { self.receiving = true; self.len = 0; return None; }
        if !self.receiving { return None; }
        match byte {
            b'\r' => None,
            b'\n' => { self.receiving = false; Some(self.finish()) }
            _ => {
                if self.len == MAX_BODY_BYTES {
                    self.receiving = false;
                    return Some(Err(NmeaError::Overflow));
                }
                self.body[self.len] = byte; self.len += 1; None
            }
        }
    }
    fn finish(&self) -> Result<Sentence, NmeaError> {
        let body = &self.body[..self.len];
        if body.len() < 8 { return Err(NmeaError::ShortHeader); }
        let star = body.len() - 3;
        if body[star] != b'*' { return Err(NmeaError::NoChecksum); }
        let hi = nibble(body[star+1]).ok_or(NmeaError::InvalidChecksumHex)?;
        let lo = nibble(body[star+2]).ok_or(NmeaError::InvalidChecksumHex)?;
        let sum = body[..star].iter().copied().fold(0, |x, b| x ^ b);
        if sum != (hi << 4 | lo) { return Err(NmeaError::ChecksumMismatch); }
        if star < 5 || body[..5].iter().any(|b| !b.is_ascii_uppercase()) {
            return Err(NmeaError::ShortHeader);
        }
        let kind_bytes = [body[2], body[3], body[4]];
        let kind = match &kind_bytes {
            b"GGA" => SentenceKind::Gga,
            b"RMC" => SentenceKind::Rmc,
            b"ZDA" => SentenceKind::Zda,
            _ => SentenceKind::Other(kind_bytes),
        };
        Ok(Sentence { talker: [body[0],body[1]], kind, body_bytes: self.len })
    }
}
fn nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte-b'0'),
        b'A'..=b'F' => Some(byte-b'A'+10),
        b'a'..=b'f' => Some(byte-b'a'+10),
        _ => None
    }
}
#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::{format, string::String};
    fn sample(body: &str) -> String {
        let crc = body.bytes().fold(0u8, |x, b| x ^ b);
        format!("{}{}*{:02X}\r\n", '$', body, crc)
    }
    fn consume(p: &mut Framer, sentence: &str) -> Result<Sentence, NmeaError> {
        sentence.bytes().filter_map(|b| p.push(b)).last().unwrap()
    }
    #[test]
    fn gga_sentence_and_talker() {
        let mut p = Framer::new();
        let s = sample("GNGGA,123519,4807.038,N,01131.000,E,1,08");
        assert_eq!(consume(&mut p, &s), Ok(Sentence {
            talker: *b"GN", kind: SentenceKind::Gga, body_bytes: s.len()-3
        }));
    }
    #[test]
    fn rmc_zda_streaming_chunks() {
        let mut p = Framer::new();
        for body in ["GPRMC,123519,A", "GNZDA,201530.00,04,07,2002"] {
            let s = sample(body); let mid=s.len()/2;
            for &b in &s.as_bytes()[..mid] { assert!(p.push(b).is_none()); }
            let result = s.as_bytes()[mid..].iter().filter_map(|&b| p.push(b)).last().unwrap();
            assert!(result.is_ok());
        }
    }
    #[test]
    fn checksum_rejection_and_recovery() {
        let mut p = Framer::new();
        let mut broken = sample("GPGGA,111");
        let i = broken.find('*').unwrap();
        broken.replace_range(i+1..i+3, "FF");
        assert_eq!(consume(&mut p, &broken), Err(NmeaError::ChecksumMismatch));
        assert_eq!(consume(&mut p, &sample("GPRMC,123,A")).unwrap().kind,
                   SentenceKind::Rmc);
    }
    #[test]
    fn invalid_hex_and_overflow() {
        let mut p = Framer::new();
        assert_eq!(consume(&mut p, "$GPGGA,1*XY\r\n"), Err(NmeaError::InvalidChecksumHex));
        p.push(b'$');
        for _ in 0..MAX_BODY_BYTES { assert_eq!(p.push(b'X'), None); }
        assert_eq!(p.push(b'Y'), Some(Err(NmeaError::Overflow)));
        assert_eq!(p.push(b'\n'), None);
        assert_eq!(consume(&mut p, &sample("GNZDA,123")).unwrap().kind, SentenceKind::Zda);
    }
    #[test]
    fn ignores_noise_and_tracks_other_kinds() {
        let mut p = Framer::new();
        for &b in b"noise\n" { assert_eq!(p.push(b), None); }
        assert_eq!(consume(&mut p, &sample("GPGSV,3,1,09")).unwrap().kind,
                   SentenceKind::Other(*b"GSV"));
    }
}
