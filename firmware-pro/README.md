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


### Source-backed SPI3 logical NV reads (software-only)

V2 application routine `0x080141DC` has now been checked against the
original instruction bytes: it asserts software GPIOA15 CS, issues
SPI3 `0x03` + three address bytes and transfers `0xFF` for each
received NV byte, before deasserting CS. The five OEM byte calls target
`0x08031814`. `core/src/spi3_nv.rs` implements this read-only
transport over an abstract byte-exchange bus and `BoardGpio`, retaining
hardware error information and without granting erase/program capability.
The matching [instruction audit](../docs/pro-v2-nv-calibration-pipeline.zh-CN.md)
is checked in CI. This identifies software GPIO bits, not QFN physical pads.


## V2 six-chain source contracts: runtime RF mode and configuration IDs

The [new OEM six-chain research report](../docs/pro-v2-six-chain-source-evidence.zh-CN.md)
verifies the original SPI3/GPIOB software register setup, four frequency
windows against both archived V1/V2 versions, and the runtime
`state -> map byte -> 4 signed trim words -> RFIC tuning` chain.

- `core/src/rf_mode.rs`: source-backed RF software windows
  136–174, 200–260, 350–399 and 400–520 MHz, with original
  out-of-window **trim index 0 fallback**, and a caller-supplied live
  mapping for the original two-level lookup
- `core/src/fd6818.rs`: select loaded trim from the current runtime
  mode byte before the existing 32-bit original RFIC tuning operation
- `core/src/oem_menu.rs`: 67 original configuration-ID TBB dispatch
  offsets as **read-only research addresses**; IDs are neither physical
  keycap indices nor proven visible menu pages
- `core/src/spi3_nv.rs`: host-tested source-compatible SPI3 CR1
  setup/enable calculation without declaring physical pad assignments

Tests and source audits live under `tests/test_pro_v2_*_audit.py`
and `tools/pro_v2_*_audit.py`. FD6818 TX-related register sequences
and GPIO output bits are software facts; they do not establish a real
PA bias control, analog microphone/speaker wiring, physical PTT button,
complete menu state machine, MCU vendor or flashable system HAL.


## OEM V2 working-configuration / special key and RFIC-TX prefix

The [source reconstruction](../docs/pro-v2-config-getter-menu-event-rfic-tx-v4.zh-CN.md)
adds these host-verifiable components to the existing `no_std` core:

- `oem_config_getter.rs`: 67 original configuration IDs mapped to the
  `0x20004580` working SRAM field layout, with seven OEM bounds repairs
  (they modify RAM, **not** proven to commit any NOR settings)
- `oem_menu_event.rs`: software-only outcomes for original scanned key
  indices `0x13/0x14` conditioned on their source-backed configuration
  fields and three opaque helper results; no invented physical keycaps
- `audio.rs`: original TX-related RFIC register prefix, audio mode 1,
  REG50 low 15 bits, REG70=0, REG30=0xC1FE; distinct from a board-level
  PA/PTT state machine
- `tools/pro_v2_config_getter_semantics_audit.py`: all 67 original
  Thumb-case entries plus source-aligned event conditions, checked in CI.

The full navigable UI menu, external analog audio and verified XL9951Q
QFN64 physical HAL remain unfinished evidence-backed work.


## OEM V5 configuration transaction and board-software contracts

[Source-evidence V5 (Chinese)](../docs/pro-v2-config-nv-setter-restore-rf-audio-hal-v5.zh-CN.md)
extends the `no_std` core with `oem_config_setter.rs` (61 OEM setter
cases, raw bitfield encoding, optional **single-byte** logical NOR
journal request, no-op cases and opaque side-effect notifications),
`oem_config_restore.rs` (the three original logical NV read groups,
34 direct main-record byte remappings and startup repairs), and a
39-byte `OemWorkingConfig` buffer.

The original getter is still 67 cases; a getter range is not a
writable-menu count. The independent core explicitly preserves raw
OEM setter/restore inconsistencies, notably the two swapped startup
source bytes for working offsets `+0x0C/+0x0D` and the mismatch for
setter ID `0x17` / working `+0x20`. The `LogicalNvJournal`
interface must be bound to an independently verified board backend;
it is not a claim that physical SPI3 NOR writes or recovery were tested.

Further V5 work adds a source-compatible PB6 GPIO/shadow fragment
and a REG43/13 audio-control subpath. External PA/PTT/analog audio
and XL9951Q package pinouts remain physically unverified.
