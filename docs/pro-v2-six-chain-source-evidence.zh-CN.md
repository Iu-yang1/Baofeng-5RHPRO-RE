# UV-5RH Pro V1/V2 六条逆向链路：MCU、SPI3/GPIO、RF 模式、PA/PTT、音频与菜单

取证日期：2026-11-17。基线：已合并 PR #31/#32；独立 Rust `no_std` 核心仅经主机 Mock 与静态机器码审计。原厂镜像：`firmware/BF_5RH_501_v1_1_04.dat`、`firmware/BF_5RH_501_v2_0_9.dat`。

**证据等级：** Ⅰ=原厂 V1/V2 机器码或 scatterload 直接证据；Ⅱ=原厂 V2 单版本 Thumb/MMIO 直接证据；Ⅲ=厂商公开型号/编程手册交叉参照；Ⅳ=缺少原理图/物理测量，尚不能确证。每一条软件 GPIO A/B/C 位号均不是 XL9951Q QFN64 封装的焊盘号。本轮没有执行、读取或擦写用户电台，也没有发布任何可刷写镜像。

## 1. XL9951Q MCU 身份与存储容量

结论：**仍未唯一识别实际晶圆厂及芯片 SKU。**

- Ⅰ：V2 应用向量 Reset `0x0800123D`、初始 MSP `0x20011308`；scatterload 从 `0x08061A54` 起恢复 7,084 B SRAM，源数据确实存在于归档的 V2 应用镜像中。成功运行所需地址窗口跨越大约 395 KiB、复位时静态 SRAM 区超出 64 KiB，不能把它当成标准低容量 AT32F421 平台。
- Ⅰ/Ⅲ：六份原厂镜像重复使用 AIR32/MegaHunt 风格 ROM SDK 路径、`0x1FFFF7E8` 系统 UID 低字与 `0x1FFFD00C` ROM 分派、`0x4002228C` 特殊寄存器解锁。可判断软件平台关联，**不能据此认定 XL9951Q 由何厂生产**。
- Ⅲ/Ⅳ：用户确认 QFN-64，目录有 XL9951Q QFN64_8x8 料号，但官方公开的 AT32F403A/407 标准 64-pin 和 MegaHunt MH2103A 高容量常见 SKU 使用不同封装/资源组合。官方公开规格的内核、SRAM、Flash、器件型号之间不得交叉拼接。
- Ⅳ：没有在本次对话提供或读取 CPUID、SWD DEBUG_IDCODE、Flash Size、真正的 QFN64 PAD 连通性及 Bootloader 身份。软件寄存器像 STM32F1/AIR32 不等于证明可移植其 MCU PAC、`memory.x` 或启动代码。

复核参考：[六份镜像及 QFN64 平台谱系](uv5rhpro-six-stock-mcu-lineage.zh-CN.md)、[AIR32 SDK 指纹](v2-0-09-air32-sdk-fingerprint.zh-CN.md)、[只读器件身份建议](v1-v2-mcu-readonly-id-evidence.zh-CN.md)。

## 2. SPI3/GPIO 软件初始化和 NV 读取

Ⅱ：V2 `0x08006B48–0x08006BC2` 的 SPI3 初始化，包含：

```text
0x08006B4E: peripheral clock helper    0x00201100 / 0x08007054
0x08006B56: GPIO clock-enable request   (1 << 15) / 0x08030B9C
0x08006B5C: GPIOB pin mask              0x0038 = software PB3,PB4,PB5
0x08006B74: GPIOB mode setup            0x08006FB8
0x08006B7C: GPIOB alternate input/setup 0x080070B0
0x08006BB0: SPI3 compatible MMIO base    0x40003C00
0x08006BBA: write SPI3 CR1/CR2/CRC init 0x080317DC
0x08006BC2: set SPI3 SPE bit6           0x080317B2
```

原厂在栈上构造九个半字配置项：

```text
00 00, 01 04, 00 00, 00 02, 00 01,
02 00, 00 10, 00 00, 00 07
```

以 `0x080317DC` 的 OR 逻辑形成 CR1 配置字 `0x0317`，保留先前 CR1 的 `0x3040` 位，清除 CR2 bit11，写 CRC polynomial `0x0007`；随后 SPE 置位。因此本次在 `core/src/spi3_nv.rs` 加入可独立测试的 CR1 初始化/使能纯计算，不在未知 MCU 上执行无依据的物理 GPIO 写入。

Ⅱ：原厂 `0x080141DC` 对 SPI3 发送 `0x03` + 24-bit 地址 + `0xFF` 连续读取；软件片选使用 GPIOA bit15（`0x40010814` BRR 拉低、`0x40010810` BSRR 拉高），软件字节传输目标 `0x08031814`。该函数遇到超时可能返回 `0x00`，属于源码中可见的异常路径；独立 HAL 抽象已经将失败与合法数据区分。当前不能据此确定 SPI3 SCK/MISO/MOSI 的 QFN64 实际 PAD 编号、总线时钟频率或 CS 电气可靠性。

## 3. 四组 RF 校准索引与原厂频率窗口

Ⅰ：原厂 V2 `0x08031AEC` 从 `0x2000245C + 8*状态槽位` 读取原始 32-bit 频率相关量，按四个区间比较，选择并写入 `0x20000072 + 状态槽位` 的校准索引。V1.1.04 镜像同样出现八个**相邻且唯一**的边界比较字面量，位于 `0x08025B60–0x08025B7C`；V2 对应 `0x08031BD4–0x08031BF0`。

| 运行时校准索引 | 原厂整数比较对应的频率窗口（包含边界） | V2 原厂写入 |
| --- | --- | --- |
| 0 | 136–174 MHz | `0x08031B1A` 初始化 R7=0，`0x08031B22` 写回 |
| 1 | 200–260 MHz | `0x08031B48` R7=1，`0x08031B4A` 写回 |
| 2 | 350–399 MHz | `0x08031B62` R7=2，`0x08031B64` 写回 |
| 3 | 400–520 MHz | `0x08031B7E` R7=3，`0x08031B80` 写回 |

**重要的窗口外分支：** V2 `0x08031B7C BHI 0x08031BA2`，随后 `STRB R7,[R1,R0]`；在这一进入链中 R7 初始为 0，因此窗口外返回**校准索引 0**，不是禁止调谐或禁止发射。本结论限定于这个被静态证明的模式表写入函数及相关路径，不能替代所有上层程序行为。

原厂真正的调谐消费路径为：

```text
s = RAM8[0x20000069]
i = RAM8[0x20000072 + s]
delta = RAM32[0x2000246C + 4*i]
reg39:reg38 = 32bit_original_frequency_word + delta
```

ARM scatterload 初值在 `0x20000072..0x20000081` 全部为零，**并非运行时最终映射**。新的 `core/src/rf_mode.rs` 实现来源可追踪的四频率窗口、窗口外 fallback0、动态 SRAM 模式索引查询；`Fd6818::write_oem_raw_tuning_for_runtime_selector` 将两级查询接入原有 RFIC 调谐路径，保留全频率 RFIC API，不把校准分区冒充 TX 限制。

上述频率窗口只是**软件校准表**，不提供 VHF/UHF 物理带通、谐波过滤器、天线切换、PA 增益/偏置或发射资格的证据。

## 4. PTT 输入与外部 PA 的软件控制候选

Ⅱ：`0x08010998` 的两段 GPIOC 键矩阵扫描外，读取软件 GPIOA bit9 低有效标志；另 `0x08010722/0x08030A2E` 读取 bit10，作用于 UI 状态条件。`0x0800B0D8`、`0x0800B0F0` 将原始 22 键扫描索引与 `0x0D` 比较。这些都是**软件索引/输入条件**，不能在未观察真实键帽时就命名为物理 PTT。

Ⅱ：PB6 在 `0x0800DA34/0x0800DA46` 附近切换，上层调用点包括 `0x0801075E`；PB1 的一次长业务流程包含 `0x08009A8E` 拉低与 `0x08009BB0` 拉高。PB8/14、PA1、PD2 等还有既有审计。至此确认有软件外设控制序列，**但没有 PAD-to-PA_EN、T/R 开关、HTL7G06S011P 偏置与实体 PTT 的 PCB 网络/高低电平证明**。不能将某个原厂 GPIO 单纯改名为 PA_EN。

## 5. FD6818 内部音频与真实模拟音频通路

Ⅱ：原厂 `0x0800A8E0–0x0800A902` 的一条 TX 相关子路径先调用 `0x0800A310` 并传入音频模式 1，然后向 FD6818 寄存器 `0x50`、`0x70` 写入 `0`，再向 `0x30` 写入 `0xC1FE`。这是**已知的部分控制序列**，不能宣称其包含完整发射音频、PTT 或 PA 时序。独立核心早已支持 `0x47/0x48/0x43` 音频寄存器写入，本轮将调用点固定为审计而不假定电声信号实际经过哪个运放。

Ⅳ：TDA2822、LM2904B 模拟音频链路及静音网络、麦克风输入、扬声器放大器使能、外部耳机接口仍需 PCB 引脚连通或实机电平/波形。单靠 RFIC 寄存器设置不能证明音频模拟接线。

## 6. UI 键盘、配置分发与菜单状态机

Ⅰ/Ⅱ：原厂 22 项 GPIOC 扫描码表已存在于 `keypad.rs`，额外 A9/A10 是另一路软件输入。V2 配置读取入口 `0x0800E454` 通过：

```text
CMP.W IP,#0x43
BHS 0x0800E4D4
TBB [PC,IP]  @ 0x0800E482
table base   = 0x0800E486 (67 unsigned-byte offsets)
target       = table_base + 2 * table[config_id]
```

恢复并固定原厂全部 67 字节分发偏移，`0x13/14/15/16` 配置 ID 分别进入 `0x0800E556/0x0800E55E/0x0800E55A/0x0800E562`。其中 ID 0x20/0x28/0x29 共用 `0x0800E4D4`（其他若干 ID 也可能共用出口）。这些是**配置读取 case 数**，不等于可视菜单条目数或物理键位数。

当前代码 `core/src/oem_menu.rs` 暴露配置 ID→原厂分派目标的**只读研究地址**，没有调用原厂代码；完整 UI 菜单需要继续核对 `0x08010AB0–0x08010CE0` 的上层事件状态、菜单绘制、设置读取/写入和原厂字库/实际按键触发记录。在缺少此闭环之前，不应伪造「所有菜单已运行」。

## 7. 复现与剩余证据

```sh
python -m pip install "capstone==5.0.6"
python tools/pro_v2_rf_window_audit.py --json
python tools/pro_v2_mode_ui_contract_audit.py --json
python tools/pro_v2_spi3_tx_af_ui_callchain_audit.py --json
python -m unittest discover -s tests -v
cargo test --manifest-path firmware-pro/core/Cargo.toml --offline
cargo check --manifest-path firmware-pro/core/Cargo.toml --lib --offline
```

研究窗口工具 `scripts/pro_v2_six_chain_scout.py` 可以按 `--focus mcu`、`--focus spi_gpio`、`--focus rf_modes`、`--focus ptt_pa`、`--focus audio`、`--focus ui` 单独运行；半字扫 BL 候选不代替受控流程图，不能从偶遇字节证明实际执行。

**当前仍缺的关键外部证据：** XL9951Q SWD/只读真实身份字段及 QFN64 焊盘；主板照片/万用表物理连续性；PA_EN/TR/实体 PTT 的实际 GPIO 接线；TDA2822/LM2904B/音频 DAC/ADC 与静音电路示波器追踪；逐个按键实体标签对原厂扫描码记录；运行时菜单事件/屏幕渲染的真实记录。没有上述证据，不会生成可刷写 firmware.bin、不选择臆测的 MCU PAC / 链接脚本，也不将软件 TXON 当成实机发射成功。

复核参考：既有 [RF/UI 校准报告](pro-v2-rf-calibration-audio-lcd-hal.zh-CN.md)、[原厂 SPI3 NV 读取](pro-v2-nv-calibration-pipeline.zh-CN.md)、[原厂板级 IO 交叉验证](pro-v2-board-rf-ui-static-audit.zh-CN.md)。
