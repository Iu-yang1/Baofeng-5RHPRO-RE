//! OEM V2 FD6818 AF register routing and configuration contracts.
//!
//! Mapped to original RFIC bus transactions, not a proven external
//! microphone/speaker amplifier or actual board audio pad connection.

use crate::fd6818::Fd6818;
use crate::rda5807m::I2cRegisterBus;

pub const OEM_AUDIO_MODE_REGISTER: u8 = 0x47;
pub const OEM_AUDIO_COMPANION_REGISTER: u8 = 0x48;
pub const OEM_AUDIO_OPTION_REGISTER: u8 = 0x43;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OriginalAudioCache {
    pub reg47: u16,
    pub reg48: u16,
}
impl OriginalAudioCache {
    pub const fn new(reg47: u16, reg48: u16) -> Self {
        Self { reg47, reg48 }
    }

    /// OEM 0x0800A310: mode 9 uses special 0x6740/0xB3AA;
    /// normal values replace bits 11:8 of cached reg47. For mode 3
    /// the original code skips updating companion register 0x48.
    /// Mode-to-audible-UI-label mapping has not been proven.
    pub fn apply_mode<B: I2cRegisterBus>(
        &mut self,
        rf: &mut Fd6818<B>,
        mode: u8,
    ) -> Result<(), B::Error> {
        let reg47 = if mode == 9 {
            0x6740
        } else {
            (self.reg47 & !0x0F00) | ((mode as u16) << 8)
        };
        rf.write_register(OEM_AUDIO_MODE_REGISTER, reg47)?;
        self.reg47 = reg47;
        if mode != 3 {
            let reg48 = if mode == 9 { 0xB3AA } else { self.reg48 };
            rf.write_register(OEM_AUDIO_COMPANION_REGISTER, reg48)?;
            self.reg48 = reg48;
        }
        Ok(())
    }

    /// Original 0x0800A398..0x0800A3A8 toggles raw register 0x43
    /// between these two control words. Physical audio meaning unknown.
    pub fn apply_reg43_variant<B: I2cRegisterBus>(
        &mut self,
        rf: &mut Fd6818<B>,
        enabled: bool,
    ) -> Result<(), B::Error> {
        rf.write_register(OEM_AUDIO_OPTION_REGISTER,
            if enabled { 0x3028 } else { 0x4048 })
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;
    #[derive(Default)]
    struct Recorder {
        packets: Vec<(u8, Vec<u8>)>,
        fail_at: Option<usize>,
        attempts: usize,
    }
    impl I2cRegisterBus for Recorder {
        type Error = &'static str;
        fn write(&mut self, addr:u8, data:&[u8]) -> Result<(),Self::Error> {
            self.attempts += 1;
            if self.fail_at == Some(self.attempts) { return Err("I2C"); }
            self.packets.push((addr,data.to_vec()));
            Ok(())
        }
        fn write_read(&mut self, _:u8, _: &[u8], _: &mut [u8])
            -> Result<(),Self::Error> { unreachable!() }
    }
    #[test]
    fn normal_mode_changes_cached_47_and_preserves_48() {
        let mut c=OriginalAudioCache::new(0xF0F0,0x1234);
        let mut rf=Fd6818::new(Recorder::default());
        c.apply_mode(&mut rf,2).unwrap();
        assert_eq!(c.reg47, 0xF2F0);
        assert_eq!(c.reg48, 0x1234);
        assert_eq!(rf.into_bus().packets, std::vec![
            (0x71,std::vec![0x47,0xF2,0xF0]),
            (0x71,std::vec![0x48,0x12,0x34]),
        ]);
    }
    #[test]
    fn original_mode_three_skips_reg48_and_nine_forces_both() {
        let mut c=OriginalAudioCache::new(0,0);
        let mut rf=Fd6818::new(Recorder::default());
        c.apply_mode(&mut rf,3).unwrap();
        c.apply_mode(&mut rf,9).unwrap();
        assert_eq!(c,OriginalAudioCache::new(0x6740,0xB3AA));
        assert_eq!(rf.into_bus().packets, std::vec![
            (0x71,std::vec![0x47,0x03,0x00]),
            (0x71,std::vec![0x47,0x67,0x40]),
            (0x71,std::vec![0x48,0xB3,0xAA]),
        ]);
    }
    #[test]
    fn reg43_variants_match_oem_without_claiming_amp_gpio() {
        let mut c=OriginalAudioCache::new(0,0);
        let mut rf=Fd6818::new(Recorder::default());
        c.apply_reg43_variant(&mut rf,true).unwrap();
        c.apply_reg43_variant(&mut rf,false).unwrap();
        assert_eq!(rf.into_bus().packets,std::vec![
            (0x71,std::vec![0x43,0x30,0x28]),
            (0x71,std::vec![0x43,0x40,0x48]),
        ]);
    }
    #[test]
    fn bus_failure_keeps_unsent_cache_and_does_not_continue() {
        let mut c=OriginalAudioCache::new(0x0000,0x0000);
        let mut rf=Fd6818::new(Recorder {
            fail_at:Some(1), ..Recorder::default()
        });
        assert_eq!(c.apply_mode(&mut rf,1),Err("I2C"));
        assert_eq!(c,OriginalAudioCache::new(0,0));
        assert_eq!(rf.into_bus().attempts,1);
    }
}
