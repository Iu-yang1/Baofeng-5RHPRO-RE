# UV-5RH Pro independent firmware workspace (P1)

This directory is **not a flashable firmware image**. The real Pro MCU, bootloader
recovery behavior, startup/linker script and board pin mapping remain unverified.

## Experimental MCU ID UART firmware (source only)

A minimal Cortex-M3/M4 Thumb diagnostic source is now available at
[diagnostics/mcu-id-uart](diagnostics/mcu-id-uart/README.md). It can be
cross-compiled into an ELF and emits CPUID and optional vendor ID fields
through a **candidate USART1** UART path. Its startup address, programming
cable UART wiring, clock state, compatibility and recovery path have **not**
been verified on the target. It is not an installable Baofeng update file.
The PC [serial listener](../tools/probe_radio_mcu_uart.py) only receives
bytes and never uploads or erases firmware.

Current independent Rust module:
- `core/`: dependency-free `no_std` NMEA frame/checksum parser tested on host.
- Data ingestion is expected to use the proven V2 original firmware path
  USART2 at 9600 bit/s with IDLE interrupt + DMA reception; the hardware-specific
  implementation is intentionally not present here.

Host build and test:

```sh
cargo test --manifest-path firmware-pro/core/Cargo.toml --offline
cargo check --manifest-path firmware-pro/core/Cargo.toml --lib --offline
```

Future modules will include protocol handling (GPS fields, APRS/AX.25),
radio-state transitions, the FD6818 interface, LCD control and board HAL.
Do not copy a standard UV-5RH `at32f421-pac`, `memory.x`, or GPIO map
into this firmware until the **UV-5RH Pro** MCU/pinout is independently identified.

The reference projects `bf-5rh-firmware-open` and `bf-k61-firmware-aura`
are GPL-3.0; their source was not copied into this core module.

Chinese engineering design and acceptance milestones:
[UV-5RH Pro firmware architecture V1](../docs/uv5rh-pro-firmware-architecture-v1.zh-CN.md).

## OEM reverse-engineered RF/UI contracts (2026-11-17)

The [cross-version hardware-software evidence report](../docs/pro-v2-board-rf-ui-static-audit.zh-CN.md)
confirms the following independently developed `no_std` modules, all
host-testable without a real MCU or device access:

- `core/src/keypad.rs`: original 22-key lookup, two-phase GPIOC scan mask
  `0x03C0/0x003E`; real physical button legends remain unassigned.
- `core/src/fd6818.rs`: the **FD6818** (not FD6818B) OEM two-wire register
  contract, I2C 7-bit `0x71`, big-endian 16-bit words; register `0x39/0x38`
  accepts a raw 32-bit tuning word, **not Hz**.
- `core/src/rda5807m.rs`: separate broadcast FM indexed I2C 7-bit `0x11`,
  command prefix then 16-bit big-endian data.
- `core/src/lcd.rs`: software 160×128 RGB565 framebuffer and SPI2
  command/data/rectangle scanout via `0x2A/0x2B/0x2C`, display controller
  ST7735-like but actual chip/orientation/offset unmeasured.
- `core/src/board_v2.rs`: candidate **GPIO port-bit contract only**
  (RF PA14/PC15, FM PC14/PA11, LCD PB12/PA12), not a physical QFN64 pad
  map, a fully clocked HAL, or a verified radio startup.

The original OEM panel clear loops use `CMP #0xA0` and `CMP #0x80` with
320-byte rows, so 160×128 is based on executed-code candidates and the
original SRAM framebuffer, not an arbitrary reference-radio display size.

The independent RF application logic still needs Hz-to-FD6818 tuning math,
FD6818 RX/TX state calibration, PA control, RF timing, menu/key legends,
LCD init/reset/rotation and target-CPU startup. These are explicit unverified
implementation tasks, not additional default locks on supported functions.


## OEM RFIC tune/state core progress (2026-11-17)

[Detailed RF tuning and UI control-flow audit](../docs/pro-v2-rf-tuning-state-ui-flow.zh-CN.md)
now validates OEM V2's 32-bit raw table-based tune plus correction,
registers `0x39/0x38`, and I2C write sequences for OEM state register
`0x30`: idle `0x0000`, RX `0xBFF1`, TX `0xC1FE`. FD6818
REV.1.0.0 guide documents a 10 Hz frequency word quantum. We expose both
`write_frequency_hz` and `write_oem_corrected_tuning_word` so unknown
board calibration is not discarded; the original setup prefix is a separate
`apply_oem_setup_prefix` with an injected delay contract.

This is an executable, unit-tested **RFIC-level core**. It is not a
physically verified PA/PTT/audio HAL or a complete radio/UI firmware. LCD
and keypad are still software-level contracts, not MCU startup/physical
pad validation.


## OEM V2 RF calibration, AF routing and LCD startup (2026-11-17)

The [full Chinese read-only evidence report](../docs/pro-v2-rf-calibration-audio-lcd-hal.zh-CN.md)
adds the original four-mode signed 50 Hz trim formula from NV logical
`0xC5C0`, two opaque 64-word NV records, FD6818 audio register
`0x47/0x48/0x43` transactions, and the complete original LCD reset,
register/gamma/orientation init and first-frame display enable. Modules:

- `core/src/nv_rf.rs`: four raw trim bytes, 50 Hz signed compensation,
  two 0x82-byte original NV record parsers and OEM raw constants
- `core/src/fd6818.rs`: compensated RFIC frequency write
- `core/src/audio.rs`: original RFIC audio mode cached-word behavior
- `core/src/lcd.rs`: SPI2 panel startup orchestration and display-on
- `core/src/board_v2.rs`, `keypad.rs`: source-backed GPIO software bit
  roles, including independently sampled A9/A10 inputs

**These are software-port interfaces and simulated transports.** They
cannot be advertised as proof of a QFN64 pad map, an actual TX-PA bias,
TDA2822 signal routing, 22 physical key legends or a bootable image.


## OEM logical NV read → mode trim → RFIC tuning

The [read-only logical NV calibration pipeline](../docs/pro-v2-nv-calibration-pipeline.zh-CN.md)
now joins the original four-byte signed-trim encoding to the existing
FD6818 32-bit raw tuning path without inventing a physical EEPROM/NOR
driver or mode-to-band mapping.

- `core/src/nv_store.rs` defines `LogicalNvReader` (read only) and
  `read_oem_nv_snapshot`, which loads four original trim bytes and two
  130-byte opaque records using caller-supplied profile selectors.
- `core/src/nv_rf.rs` retains the four original bytes in
  `OemFrequencyTrims` and exposes bounds-checked mode-index selection.
  Original bytes above `0x60` remain in memory but evaluate to a
  zero correction, matching the OEM branch.
- `core/src/fd6818.rs` now accepts a four-mode trim set in both the
  original raw-word path and the optional datasheet-backed Hz path.
  A missing trim index is reported before issuing RFIC bus transactions.

Mock transport tests cover logical addresses and lengths, negative
frequency corrections, invalid-high neutral behavior, both 64-word
profile records, sequential read failure stages and FD6818 write order.
This is not a device-specific NV HAL or a validated RF transceiver image.
