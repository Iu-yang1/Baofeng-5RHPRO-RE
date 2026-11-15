# Baofeng UV-5RH Pro Reverse Engineering

This fork is the development workspace for an alternative-firmware research project targeting the **Baofeng UV-5RH Pro**.

Original reverse-engineering archive: https://github.com/kholdfuzion/Baofeng-5RHPRO-RE

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

The **standard AT32F421C8T7** used in ordinary UV-5RH/5RM is excluded by **five** independent Pro V2 facts: actual scatterload reads Flash at `0x08061A54` (>64KiB), startup RAM/MSP exceeds 16KiB, three USARTs are initialized, USART2 uses a DMA1-channel-6-compatible address, and user board photos show LQFP64 instead of LQFP48. **Do not reuse its 64K/16K linker or PAC.**

AT32F403ARET7/ARGT7, AT32F407RET7/RGT7 and GD32F303RGT6 are resource-compatible candidates, **not chip identifications**. The original clock getter treats CRM_CFG bit28 as part of the PLL multiplier, while AT32F403A/407 official manuals assign it to ADC prescaling. Thus even family-level registers have unresolved differences.

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
