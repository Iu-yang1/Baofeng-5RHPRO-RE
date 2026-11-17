# Baofeng UV-5RH Pro Reverse Engineering

This fork is the development workspace for an alternative-firmware research project targeting the **Baofeng UV-5RH Pro**.

Original reverse-engineering archive: https://github.com/kholdfuzion/Baofeng-5RHPRO-RE

> **Hardware correction (2026-11-16): the UV-5RH Pro MCU package is QFN-64, as confirmed by the user.** Earlier photo-based LQFP64 identification and any LQFP64 pin-number guidance are retracted. Published LQFP64 parts in the comparative table are **not** package matches for this radio. MCU vendor and SKU remain unknown; firmware-only analysis continues.

### Pre-scatterload FLASH_ACR configuration confirmed (V1/V2)

Further [V1/V2 Reset-stage Flash ACR instruction analysis](docs/xl9951q-pre-scatterload-flash-acr.zh-CN.md)
verifies the two original stock firmware versions share **exactly the same
168-byte early clock routine**, with PC-relative `0x40021000` RCC and
`0x40022000` Flash controller bases. The routine updates FLASH_ACR prefetch
and latency **before** ARM scatterload; the reset wrapper also writes VTOR
`0xE000ED08` with `0x08000000`. These are visible Flash *timing* controls,
not confirmed external SPI NOR XIP mapping.

The later AIR32 SDK-style `0x4002228C` ROM/QSPI unlock still takes place
after scatterload. Mask ROM / OEM bootloader mapping remains unknown.

```sh
python tools/xl9951q_pre_scatterload_flash_acr.py --json
```

### XL9951Q startup Flash/QSPI stage-order evidence (no device access)

A [new read-only V1/V2 ROM and scatterload sequencing audit](docs/xl9951q-boot-high-flash-vs-qspi-audit.zh-CN.md)
confirms that the V2 compressed SRAM source at `0x08061A54` is **within the
401,408-byte original upgrade payload** and that the restored 7,084-byte
SRAM segment matches its independently verified digest. The AIR32-compatible
ROM helper's `0x4002228C` QSPI-labelled unlock is reached from the
**application main after the initial ARM scatterload**; it is not itself
evidence of pre-scatterload external NOR XIP mapping.

An unknown mask ROM or bootloader may still preconfigure an alias, and the
chip's actual internal Flash capacity has **not** been measured. This research
neither reads a real MCU nor creates any flashable image.

```sh
python tools/xl9951q_pre_scatterload_mapping_audit.py firmware/BF_5RH_501_v2_0_9.dat --v1 firmware/BF_5RH_501_v1_1_04.dat --json
```

### Verified component catalogue record for the unidentified MCU

The user confirmed the UV-5RH Pro main device is **QFN64** and provided the
[JLCPCB catalogue record for `XL9951Q` / `C9900238147`](https://jlcpcb.com/partdetail/JLCPCBAssembly-XL9951Q/C9900238147),
which specifies **QFN-64_8x8**. This is a strong match for the previously
observed `XL9951Q`-like board marking, but the page classifies the part
under `JLCPCB Assembly` / `Others/SMT` and gives **no** semiconductor
manufacturer, CPU core, Flash/RAM size, original datasheet or pinout.
The 8×8 mm figure is a **catalogue** body dimension, not a physical measurement
on this radio.

The physical part **label** is now plausibly identified, but the MCU's
silicon origin and commercial die type **remain unknown**. The six stock
AIR32-style ROM helpers establish **software lineage, not chip branding**.
[Detailed catalogue evidence (中文)](docs/uv5rhpro-six-stock-mcu-lineage.zh-CN.md).

### Offline Flash-driver and upgrade-protocol evidence (V1/V2)

A [new stock-binary and host-updater audit](docs/xl9951q-flash-updater-protocol.zh-CN.md)
confirms **220 byte-identical bytes** of Flash erase/program/unlock routines
in both V1/V2 application images and direct callers referencing
`0x0807F800`. V2 application code also uses a 4096-byte data unit, which
**does not prove** the physical Flash erase-page size.

The `fw_updater.py` host sends 1024-byte data blocks with relative addresses,
and its 512 KiB constant is a host-side bound, **not measured silicon Flash
capacity**. The 0x08000000–0x08000FFF bootloader/ROM remains unobserved.

```sh
python tools/xl9951q_flash_paths_audit.py --json
```

### XL9951Q OEM UpgradeTool IL and external SPI NOR journal chain (read-only)

[New evidence report (中文)](docs/xl9951q-upgradetool-il-spi-nor-journal.zh-CN.md)
and offline audits validate the OEM Release `Radio.exe` managed IL directly:
the `DoReadData` method is an empty one-byte `ret`, while `DoWriteData`
uses `DOWNLOAD`, an opaque 16-byte `F-ERASE` frame, 1024-byte
relative-offset chunks and a final ACK without whole-image readback.
No firmware-backup implementation is demonstrated by this updater.

V1 and V2 application code separately send external NOR `0x03` read,
`0x02` program, `0x20` sector erase, `0x05` status and `0x06`
write-enable commands, using `0x001FE000` as a NOR staging offset
and `0x0807F800` as an internal-Flash metadata/journal candidate.
This does **not** identify the XL9951Q silicon or establish bootloader
mapping, physical MCU erase geometry, XIP or recovery correctness.

```sh
python tools/upgrade_tool_il_audit.py --verify
python tools/xl9951q_high_flash_nor_audit.py --json
```

### XL9951Q cold-start application journal recovery (V1/V2)

The [new two-version cold-start journal recovery study (中文)](docs/xl9951q-journal-cold-start-recovery.zh-CN.md)
confirms actual early-initialization calls into a backup recovery routine:
V1 `0x08027BFC` → `0x0800AB74`; V2 `0x080340F4` →
`0x08010400`. The routine reads an 8-byte MCU Flash transaction
record at `0x0807F800` (little-endian NOR sector address, then
completion byte), compares an external NOR backup at `0x001FE000`
with the target in 64-byte chunks, and when different restores the
complete 4 KiB NOR sector before clearing the journal.

**This confirms software recovery logic, not power-loss reliability.**
The journal-clear call directly follows the NOR restore call, without
an independent success check in the recovery function; there is no
backup CRC in this routine. No hardware operation or firmware flashing
was conducted.

```sh
python tools/xl9951q_journal_recovery_audit.py --json
```

### XL9951Q: verified Reset-to-recovery and NOR error-path analysis

The [cross-version Reset-to-journal and NOR status/error report (中文)](docs/xl9951q-reset-nor-error-propagation.zh-CN.md)
extends the existing cold-start recovery audit all the way to the OEM
Reset vector (`0x0800123D`), scatterload handoff, and the main
prologue's fourth direct `BL` into recovery, for both V1.1.04
and V2.0.09. Normal return from earlier startup functions remains a
precondition; this is static CFG evidence, not a hardware boot trace.

The SPI NOR RDSR `0x05` loop checks WIP bit0, not a full post-write
verification or bounded retry. Each NOR erase/program path waits for WIP
to clear; the recovery caller still clears MCU Flash journal metadata
immediately after the NOR restore call without testing a distinct
success result. These are specific software fault windows, **not**
proof of failures on a real GT25Q16A.

```sh
python tools/xl9951q_reset_nor_error_audit.py --json
```

### SPI3 byte-transfer errors, IWDG startup, and NOR journal integrity (V1/V2)

The [new read-only cross-version verification report (中文)](docs/xl9951q-spi-wdt-recovery-integrity.zh-CN.md)
tracks the lower SPI3 byte exchange into NOR read-status and the
IWDG configuration that precedes startup journal recovery.
Both applications use the same 76-byte SPI3 transfer implementation,
with two status polls bounded at `0xC8` and `0` returned on timeout.
Because the NOR `0x05` status reader tests bit0 of this same return
value, an SPI receive timeout can be misinterpreted as WIP cleared.
Both applications configure a `0x40003000` IWDG-compatible watchdog
before invoking journal replay; the NOR WIP loop itself does not
reload the watchdog.

This resolves the currently available **offline software evidence**;
it does not measure XL9951Q actual watchdog seconds, silicon identity,
NOR physical operation, or power-loss robustness.

```sh
python tools/xl9951q_spi_wdt_integrity_audit.py --json
```

### UV-5RH Pro RF, keypad and SPI2 panel: stock-source grounded contracts

[New cross-version V1/V2 RF/UI reverse-engineering report (中文)](docs/pro-v2-board-rf-ui-static-audit.zh-CN.md)
verifies the original 22-key input table from decompressed stock V2 SRAM,
the matching V1/V2 GPIOC two-phase matrix scanner, separate bit-banged
two-wire interfaces for **FD6818 at I2C 0x71** and **RDA5807M at 0x11**,
and the original FD6818 16-bit register/32-bit raw tuning-word ordering.

The OEM V2 **SPI2 LCD** uses separate command/data wrappers with
PB12/PA12 candidate control signals, the ST7735-compatible
`0x11/0x36/0x3A=0x05/0x2A/0x2B/0x2C` instruction family,
and a directly verified **160×128 RGB565 / 320 B row-stride** framebuffer
at `0x20004B76`. These are software-MMIO facts, **not** measured
physical QFN64 pads or a confirmed panel manufacturer/model.

Independent MCU-neutral Rust `no_std` implementations live in
[firmware-pro/core](firmware-pro/core): keypad code matching, FD6818
raw I2C word access, FM radio indexed-register access, LCD framebuffer
and scanout, and a separated source-grounded V2 pin contract. The complete
TX/PA, LCD hardware initialization, keyboard labels and board boot
requirements are still under reverse engineering. **No flashable
firmware or complete board HAL is claimed.**

```sh
python tools/pro_v2_board_io_audit.py --json
cargo test --manifest-path firmware-pro/core/Cargo.toml --offline
```

### Pro FD6818: OEM raw tuning flow and guide-backed 10 Hz encoding

The [new RFIC tuning/state and UI call-flow analysis (中文)](docs/pro-v2-rf-tuning-state-ui-flow.zh-CN.md)
reconstructs original V2 raw-tune selection from `0x2000246C`,
32-bit wrapping correction, and the high/low split into `0x39/0x38`.
The FD6818 REV.1.0.0 programming guide explicitly defines **10 Hz
per tuning-word unit**, matching those stock registers. The V2 firmware
also uses `0xBFF1` / `0xC1FE` as RFIC RX/TX state values written to its
OEM **`0x30`** register; the guide names `0x03` for the equivalent
state, so this firmware preserves the OEM map.

The independent `firmware-pro/core/src/fd6818.rs` now exposes
guide-backed Hz encoding, original raw adjustment, tested RX/TX chip
state commands, and the OEM setup-prefix register sequence. **These are
RFIC logic operations, not verified board PTT, PA or RF output.** The
22-key scanner's key-event consumers are identified, but physical
legends and complete UI behavior remain unverified.

```sh
python tools/pro_v2_rf_ui_flow_audit.py --json
cargo test --manifest-path firmware-pro/core/Cargo.toml --offline
```

### UV-5RH Pro: recovered RF trim, NV banks, AF routing and full LCD startup (V2)

The [detailed offline board/HAL audit (中文)](docs/pro-v2-rf-calibration-audio-lcd-hal.zh-CN.md)
verifies four OEM frequency-trim bytes read at logical NV address `0xC5C0`.
The original firmware computes **signed `5*(clamp_high_to_40(b)-40)`
raw tuning-word units**, equivalent to **50 Hz per stored byte step**
against FD6818's documented 10 Hz frequency encoding. The two separate
0x82-byte NV profiles each hold 64 big-endian u16 words; their per-unit
contents and field semantics remain unknown.

The independent `no_std` core now implements that OEM tuning correction,
two opaque NV profile records, and RFIC AF register transactions
(`0x47/0x48/0x43`). It also reproduces the original SPI2 LCD **PA8
high/low/high reset sequence, full power/frame-rate/gamma/orientation/
RGB565 setup, and `0x29` display-on after the first completed frame**.
Software GPIOA9 and GPIOA10 are separate input channels and GPIOB/PA1/PD2
output candidates are recorded without inventing physical assignments.

**Unresolved:** XL9951Q physical silicon/QFN pad map, externally wired
PTT/PA/speaker amplifier, actual NV calibration bytes, keycap labels,
and full radio/menu behavior. This is **Host-tested firmware logic, not
a validated board HAL, nor a flashable release**.

```sh
python tools/pro_v2_full_board_audit.py --json
cargo test --manifest-path firmware-pro/core/Cargo.toml --offline
```

## Current status

**P0: read-only stock firmware reverse engineering; P1: host-tested MCU-neutral alternative-firmware core started.**

There is no verified, flashable replacement firmware in this repository yet. The new `firmware-pro/core` is a host-tested, `no_std` **protocol core**, not an MCU port.

Target-radio menu reports **Firmware `v2_0_09`** and **Software `v1_1_04`**. These two fields are recorded exactly; they do **not** prove that both upgrade files should be flashed, or establish the MCU/PCB revision.

### Offline analysis (Python 3.10+; Capstone 5 required for instruction tracing)

```sh
python tools/firmware_inspect.py --strict firmware/*.dat
python tools/firmware_inspect.py --json firmware/BF_5RH_501_v2_0_9.dat
python -m pip install "capstone==5.0.6"
python -m unittest discover -s tests -v
python tools/clock_register_trace.py firmware/BF_5RH_501_v2_0_9.dat
python tools/thumb_window.py firmware/BF_5RH_501_v2_0_9.dat --start 0x08031BF4 --end 0x08031C98
```

The inspection tool prints package signatures, raw version fields, payload sizes, SHA-256, XOR marker clues, and Cortex-M vector heuristics. It cannot communicate with or reprogram a radio. GitHub Actions runs the same checks against all six archived firmware images and publishes a metadata-only inventory.

Read [P0 research and acceptance criteria (简体中文)](docs/p0-firmware-research.zh-CN.md), [V2.0.09 clock initialization disassembly (简体中文)](docs/v2-0-09-clock-init-disassembly.zh-CN.md), and [portability review of the Rust UV-5RH firmware (简体中文)](docs/reference-firmware-portability.zh-CN.md).

**Clock-reconstruction status:** the decoded V2.0.09 startup code enables an external high-speed clock, programs PLL source/multiplier fields and switches the system clock. Register interpretations currently follow the AT32F403A/407-compatible map; the exact MCU, physical crystal frequency and absolute CPU frequency are not verified. Tools do not connect to radio hardware.

### UART/TIM cross-version SDK fingerprint

The V2 firmware contains a UART baud-rate calculation matching the structure of the STM32F4 Standard Peripheral Library `USART_Init` routine, including OVER8-sensitive fraction rounding. USART and timer instruction windows in archived V1 and V2 firmware align at the same `+0xC134` offset and each tested 24-byte window matches exactly. **This suggests shared SDK routines, not that the actual MCU is an STM32F4.**

Run (Python 3.10+, Capstone 5):

```sh
python tools/peripheral_clock_constraints.py firmware/BF_5RH_501_v2_0_9.dat
python tools/compare_sdk_windows.py firmware/BF_5RH_501_v1_1_04.dat firmware/BF_5RH_501_v2_0_9.dat --pair 0x08026C50:0x08032D84:24 --pair 0x0802640C:0x08032540:24
```

See [V2 UART/TIM SDK fingerprint report (简体中文)](docs/v2-0-09-uart-timer-sdk-fingerprint.zh-CN.md).

### V2.0.09 clock tree: function-level evidence

The clock getter at `0x08030C30` contains **8,000,000 Hz** and **4,000,000 Hz** source constants. The reset-path CRM register writes and the getter form a consistent **conditional** 8 MHz HEXT → PLL ×6 → SYSCLK/HCLK 48 MHz, PCLK1 24 MHz and PCLK2 48 MHz software clock tree. Physical oscillator frequency and MCU identity have **not** been measured or confirmed.

Three `USART_Init` callers configure **USART3 19,200**, **USART2 9,600** and **USART1 115,200** baud. Five timer call chains compute the prescaler from PCLK1; one sets `TIM3 ARR=1999`, consistent with a 1 ms update period under the compatible APB1 timer-doubling rule. These are firmware-derived conditional calculations, not measurements.

```sh
python tools/v2_clock_tree_model.py firmware/BF_5RH_501_v2_0_9.dat
python tools/timer_clock_callers.py firmware/BF_5RH_501_v2_0_9.dat
python tools/usart_clock_callers.py firmware/BF_5RH_501_v2_0_9.dat
```

Read the [function-level V2 clock tree / UART / timer reverse-engineering report (简体中文)](docs/v2-0-09-clock-tree-dataflow.zh-CN.md) for the complete register addresses, machine-code evidence, limitations and V1/V2 comparison.

### Experimental MCU identification using the programming cable

An experimental, **compile-only** Cortex-M3/M4 MCU identity diagnostic
is available at [firmware-pro/diagnostics/mcu-id-uart](firmware-pro/diagnostics/mcu-id-uart/README.md).
It can report ARM CPUID and conditional vendor identity fields over a
candidate USART1 UART connection; a host serial parser is included.
This is **not a tested, installable firmware image**: the factory update
protocol contains a Flash-erase step, and the V2 GPIO/UART physical path,
startup clock and recovery behavior are not verified. There is no SWD
or physical device ID read in the repository so far.

### Six-version MCU software lineage: confirmed, physical SKU still unknown

All six archived UV-5RH Pro stock firmware versions (V1.0.92, V1.0.97,
V1.1.00, V1.1.04, V2.0.07 and V2.0.09) contain **the same 216 bytes**
at the AIR32-style ROM helper window `0x08001280–0x08001357`.
This strengthens the shared **AIR32/MH32/MH2103 SDK-lineage** finding,
but does **not** identify the physical manufacturer.

The official MegaHunt MH2103A *family* has 128–1024 KiB Flash options.
**Hardware correction:** the user confirms this MCU is **QFN64**, not
LQFP64. The published **MH2103ARPT6 is LQFP64 / 256 KiB**, while
the 512/1024 KiB MH2103A V-package SKUs use **LQFP100**. **None of
these published standard SKUs match the reported QFN64 package**. The same SKU-versus-series
distinction applies to AIR32F103. Original V2 startup requires a
readable program address at `0x08061A54`; no external SPI NOR alias has
been verified. AT32F403A/407 resource-compatible parts remain
candidates, not proofs of ROM interface compatibility.

[Detailed evidence and six-version script (中文)](docs/uv5rhpro-six-stock-mcu-lineage.zh-CN.md).

```sh
python tools/stock_mcu_lineage.py
python tools/v2_mcu_candidate_matrix.py firmware/BF_5RH_501_v2_0_9.dat
```

### V1/V2 instruction-level identity-register audit

[中文报告：UID / F_SIZE / ARM CPUID / AT32 PID 的 Thumb CFG 读取审计](docs/v1-v2-mcu-id-cfg-reads.zh-CN.md)
extends the read-only firmware audit from literal-address occurrence checks
to **resolved Thumb LDR/LDRH/LDRB effective-address evidence** across
conditional branches, MOVW/MOVT pairs and local SRAM/stack aliases.

In **both** original V1.1.04 and V2.0.09 images, seven ID-proximal
address sources yield **one** resolved MCU identity access: the ROM helper
at `0x080012A4` loads UID0 from `0x1FFFF7E8`. The six other source
values are ARM SCB VTOR/AIRCR/SCR addresses, **not** CPUID. No additional
F_SIZE, CPUID or AT32 PID/Project ID reads were resolved within the
bounded model. This cannot exclude indirect or ROM-internal accesses.

```sh
python tools/v1_v2_mcu_id_cfg_reads.py firmware/BF_5RH_501_v2_0_9.dat --v1 firmware/BF_5RH_501_v1_1_04.dat --show-accesses
```

### Original V1/V2 MCU electronic-ID cross-check (read-only analysis)

The firmware uses an **AIR32-style UID[31:0] dispatch** at `0x1FFFF7E8`,
but no live device UID, Flash F_SIZE, ARM CPUID, Artery DEBUG_IDCODE,
Artery Project ID, or SW-DP DPIDR has been measured. The Artery
AT32F403A/407 Series ID is in UID[95:88] at `0x1FFFF7F3`; its
`0xE0042000` device PID is distinct from the SWD-port DPIDR. Neither
CPUID nor an ARM SW-DP DPIDR identifies the MCU vendor. Stock V1/V2
image literal xrefs and a privacy-preserving **offline only** decoder now
have automated regression tests.

[Read the vendor-specific identification table and limitations (简体中文)](docs/v1-v2-mcu-readonly-id-evidence.zh-CN.md).

```sh
python tools/v2_mcu_identity_xrefs.py firmware/BF_5RH_501_v2_0_9.dat
python tools/mcu_readonly_id_evidence.py --cpuid 0x410FC241 --flash-size-halfword 0x0200 --debug-id 0x700502CE --project-byte 0x07 --dpidr 0x2BA01477
```

The numeric IDs in the example above are *published test fixtures*, not
measurements from the user's radio. Full device-unique UIDs are never
echoed to reports.

### V2 USART/GNSS and independent firmware architecture

Stock V2.0.09 instruction-backed evidence now links **USART2 9600 baud + DMA1 CH6 + IDLE ISR** to a real **NMEA GGA decoder**; USART3 **19200 baud + DMA1 CH3** implements an XOR-encoded transmit protocol, and USART1 **115200 baud** uses an interrupt-driven 20-byte receive ring. Roles of USART1 and USART3 remain under investigation.

The [V2 UART / IRQ / independent firmware architecture report (简体中文)](docs/uv5rh-pro-firmware-architecture-v1.zh-CN.md) documents instruction addresses, DMA SRAM buffers, memory layout and the next MCU/HAL milestones.

A small original MCU-agnostic Rust module is now available at [firmware-pro/core](firmware-pro/README.md). It handles NMEA sentence framing and checksum verification; it is not yet a complete GNSS decoder and does not operate RF hardware.

```sh
python tools/v2_uart_protocol_evidence.py firmware/BF_5RH_501_v2_0_9.dat
python tools/v2_memory_layout.py firmware/BF_5RH_501_v2_0_9.dat
cargo test --manifest-path firmware-pro/core/Cargo.toml --offline
```

### Pro V2 MCU identification (amoxu methodology, verified exclusions)

[Read the Chinese source-backed MCU identification report](docs/v2-0-09-mcu-identification-amoxu.zh-CN.md).

The **standard AT32F421C8T7** used in ordinary UV-5RH/5RM is excluded by **five** independent Pro V2 facts: actual scatterload reads Flash at `0x08061A54` (>64KiB), startup RAM/MSP exceeds 16KiB, three USARTs are initialized, USART2 uses a DMA1-channel-6-compatible address, and user-confirmed QFN64 differs from the standard LQFP48 part. **Do not reuse its 64K/16K linker or PAC.**

AT32F403ARET7/ARGT7, AT32F407RET7/RGT7 and GD32F303RGT6 may satisfy some resource requirements, but **their published LQFP64 standard parts do not match the user's actual QFN64 package**. They are no longer shortlisted as matching standard physical part numbers. The original clock getter treats CRM_CFG bit28 as part of the PLL multiplier, while AT32F403A/407 official manuals assign it to ADC prescaling. Thus even family-level registers have unresolved differences.

```sh
python tools/v2_mcu_candidate_matrix.py firmware/BF_5RH_501_v2_0_9.dat
python tools/v2_mcu_identity_xrefs.py firmware/BF_5RH_501_v2_0_9.dat
python tools/at32_readonly_id_decode.py --cpuid 0x410FC241 --debug-id 0x700502CE --project-byte 0x07  # synthetic example only
```

The identification scripts operate read-only on the stock package or supplied numeric IDs. No physical SWD identity read was performed.

### Pro V2 AIR32-compatible SDK lineage (not a confirmed chip ID)

[Source-level AIR32 SDK fingerprint report (简体中文)](docs/v2-0-09-air32-sdk-fingerprint.zh-CN.md)
verifies the proprietary three-stage register unlock, QSPI control keys, ROM `SysFreq_Set` callback,
SRAM-window magic, RCC bit28 multiplier algorithm and recovered divider tables against
the published AIR32F103 SDK. The application's `0x10000 / 0x380000 / 1` argument tuple
maps to HSE/1, PLL x16 and FLASH_Div_2; for the compiled-in 8 MHz source this implies
a **conditional 128 MHz request**, not a measured frequency or proof it always executes.
The documented **AIR32F103RPT6 256 KiB Flash is too small** for the stock V2 scatterload
access at `0x08061A54`; software lineage must not be confused with physical part identity.

```sh
python tools/v2_air32_sdk_fingerprint.py firmware/BF_5RH_501_v2_0_9.dat --v1 firmware/BF_5RH_501_v1_1_04.dat
```

### Pro V1/V2 inter-basic-block RCC alias trace

[中文技术报告：Thumb CFG / MOVW-MOVT / SRAM 寄存器指针分析](docs/v1-v2-rcc-cfg-dataflow.zh-CN.md)
adds branch-aware constant propagation, conservative stack/SRAM pointer
round-trips, and register-indirect branch resolution to the firmware
research tooling. Both stock V1/V2 images yield **43 candidate RCC
store/instruction pairs**, including **13 newly recovered** compared
with the earlier 30-site straight-line scan; known RCC MOVW/MOVT pairs
within the tested 96-byte window were not found in either stock image.
These are *possible static paths*, not observed execution or proof that
runtime clock switching is absent. Unknown ROM callbacks and physical
MCU identity remain unresolved.

```sh
python tools/v2_rcc_cfg_dataflow.py firmware/BF_5RH_501_v2_0_9.dat --v1 firmware/BF_5RH_501_v1_1_04.dat --json
```

### Pro V2 ROM UID-branch CFGR and bounded RCC MMIO audit

[中文：ROM 分支及 RCC 直接寄存器写入审计](docs/v2-0-09-rom-cfgr-mmio-audit.zh-CN.md)
checks stock `0x1A/0x1B/0x1C` dispatch registers and the `0x1C`-specific
CFGR pre-mask `0xEFC3FFFF` (clears bit 28 and bits 21:18) before ROM
`SysFreq_Set`; all paths subsequently write HSE PLL source via
`(CFGR & ~0x30000) | 0x10000`. A bounded straight-line literal-base MMIO
scan gives 26 referenced RCC base loads and 30 unique store/address
candidates in each V1/V2 image. This scan cannot rule out indirect
stores, constructed addresses, function pointers, or ROM-side writes.

```sh
python tools/v2_rom_cfgr_mmio_audit.py firmware/BF_5RH_501_v2_0_9.dat --v1 firmware/BF_5RH_501_v1_1_04.dat --json
```

### Pro V2 clock *runtime order*: Reset → main → PLL x16 → TIM/USART

[Original-byte runtime call graph and BRR/PSC analysis (简体中文)](docs/v2-0-09-pll-runtime-order-peripherals.zh-CN.md)
proves the startup-linked main entry, shared V1/V2 PLL path, and
statically reachable TIM3/USART1/2/3 initialization paths. The initial
48 MHz Reset-stage profile **is not the sole application clock**.
When the conditional AIR32-compatible 8 MHz HSE ×16 ROM request succeeds,
the expected SYSCLK/HCLK is 128 MHz with APB1 64 MHz, APB2 128 MHz;
USART BRR16 estimates are 0x0457 (115200), 0x1A0B (9600), and
0x0D05 (19200), and TIM3 PSC is 63 instead of 23 for the same 1 ms tick.
These are *conditional calculations*, not a physical clock or register read.

```sh
python tools/v2_pll_runtime_order.py firmware/BF_5RH_501_v2_0_9.dat --v1 firmware/BF_5RH_501_v1_1_04.dat --json
```

### Pro V2 UID/ROM helper comparison

[Boot ROM/UID conditional dispatch research (简体中文)](docs/v2-0-09-bootrom-uid-dispatch.zh-CN.md) reconstructs a firmware-visible ROM callback at `0x1FFFD000+0x0C`, UID low-word byte comparisons (not the official Artery series ID), two complementary writes to `0x4002228C`, and the actual V2 application call chain. The exact helper machine code from `0x08001280` is **216/216 bytes identical** across V1.1.04 and V2.0.09. This does **not** identify the MCU or prove the helper runs on every startup.

```sh
python tools/v2_bootrom_dispatch.py firmware/BF_5RH_501_v2_0_9.dat --v1 firmware/BF_5RH_501_v1_1_04.dat
```

## Original collected utilities

- `fwtool.py`: package XOR packing/unpacking tool.
- `fw_updater.py`: serial update tool; **erases and writes radio Flash**.
- `font_updater.py`: font update tool; **writes to radio storage**.
- `firmware/`: collected original upgrade packages.
- `CPS_5RH/`, `FontTool/`, `UpgradeTool/`: vendor utility binaries.

The presence of a firmware updater is **not** proof that a full Flash backup or recovery of a nonbooting device is possible.

## Related work

- [sophiel-meow/bf-5rh-firmware-open](https://github.com/sophiel-meow/bf-5rh-firmware-open) — experimental Rust firmware for **UV-5RH/5RM**, not a drop-in UV-5RH Pro image. The project is GPL-3.0; direct source reuse requires honoring its license.


### OEM V2 logical NV calibration integration

The [independent NV-to-FD6818 integration report (中文)](docs/pro-v2-nv-calibration-pipeline.zh-CN.md)
adds a host-testable **read-only logical NV backend** to
`firmware-pro/core`. It loads original four-byte frequency trims from
logical `0xC5C0` and two caller-selected `0x82`-byte opaque profiles
(`0x7A90 + 0x98*selector`), then selects the signed 32-bit correction
by original software index before writing the FD6818 `0x39/0x38` word.
The physical nonvolatile device, per-radio values, real mode-to-band
mapping, PA/PTT wiring and XL9951Q MCU port remain unidentified.


The V2 NV read routine is further decoded down to the actual
**SPI3 NOR `0x03` + 24-bit address + `0xFF` read transaction**, with
software GPIOA15 chip select and byte-exchange calls to `0x08031814`.
The new read-only `core/src/spi3_nv.rs` transport and
`tools/pro_v2_spi3_nv_read_audit.py` verify this contract. It does not
identify the external NOR die or physical XL9951Q QFN pad. See the
[updated evidence report](docs/pro-v2-nv-calibration-pipeline.zh-CN.md).
