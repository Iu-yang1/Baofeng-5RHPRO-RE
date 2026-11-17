# UV-5RH Pro V2：独立固件逻辑 NV 读取与四路 FD6818 频率校正接线

日期：2026-11-17。范围：**只读逻辑非易失存储（NV）→ 原厂四路调谐校正 → RFIC 寄存器写入**。本轮将此前已核实的原厂规则接入 MCU 无关 Rust `no_std` 核心，并不声称取得任何实际设备 NV 数据或完成整机板级 HAL。

## 1. 取证基础和内存地址的层次

| 原厂证据 | 地址 / 格式 | 可确认的含义 |
| --- | --- | --- |
| V2 `0x08012BB8` → `0x080141DC` | 逻辑地址 `0xC5C0`，读取 4 字节 | 四个原始 RF 频率校正字节，不属于 MCU 绝对 Flash 地址 |
| V2 `0x08012BD0–0x08012BEE` | `b > 0x60 ? 0x28 : b`；`5*(b-0x28)` | 32-bit 二补数调谐字校正，FD6818 指南每字单位 10 Hz |
| V2 `0x08012CAA–0x08012D56` | `0x7A90+0x98*selector`，每次读 `0x82` 字节 | 每份前 2 字节保留，后面 64 个大端半字 |
| V2 `0x0800DDB8` / `0x0800AFE4` | 软件模式索引、4 字节表和 32-bit ADD | 选中一项校正字，叠加原始 RFIC 调谐字，最后写 `0x39/0x38` |

以上的 RF 校正地址、算式及调用点来自已合并的 [RF 校准、音频、LCD/HAL 审计](pro-v2-rf-calibration-audio-lcd-hal.zh-CN.md) 和 [RF/UI 状态流分析](pro-v2-rf-tuning-state-ui-flow.zh-CN.md)。它们不能自动证明具体每项校正对应 VHF/UHF、哪颗 NOR 的绝对地址，或原厂读协议使用了什么物理总线。

## 2. 本轮实现：明确划分 NV 读取与 RFIC 状态

- `nv_store::LogicalNvReader`：提供 `read(logical_address, &mut [u8])` 的只读抽象，不做写入、擦除或 Flash 映射。
- `nv_store::read_oem_nv_snapshot(reader, [selector_a, selector_b])`：按顺序读取 `0xC5C0` 四字节、第一份、第二份 `0x82` 字节配置记录，发生读取故障时返回出错阶段，不假装返回完整快照。
- `nv_rf::OemFrequencyTrims`：保留设备原始四字节；`word_at(index)` / `hz_at(index)` 才应用原厂归零分支和带符号单位换算。
- `fd6818::Fd6818::write_oem_corrected_tuning_word_for_mode`：原始 32-bit 表调谐字加选定校正字，按照原厂高 16 位写 `0x39`、低 16 位写 `0x38`。
- `fd6818::Fd6818::write_frequency_hz_with_oem_mode_trim`：仅当上层希望使用 FD6818 编程指南定义的 10-Hz Hz 编码时使用；保留原有 raw-table API，以防实际运行期调谐表包含尚未还原的其他参数。

模式索引是**原厂软件模式索引**，不是实体按键编号，也不是我们假设的 VHF/UHF 命名。越界索引返回 `UnknownTrimIndex`，不发任何 I²C 寄存器指令；这用于防止错误索引误取内存，不是对支持频率或发射模式施加额外限制。输入为 `0x61` 至 `0xFF` 的原始字节在 `OemFrequencyTrims` 里**仍原样保存**，只有用于调谐时才替换为中性 `0x28` 的等价计算结果。

## 3. 开发级调用示意

```rust
use uv5rh_pro_core::nv_store::{read_oem_nv_snapshot, LogicalNvReader};
use uv5rh_pro_core::fd6818::Fd6818;

// nv_reader: 由后续板级驱动实现的原厂逻辑 NV 只读协议。
// i2c_bus: 由后续板级驱动实现的 RFIC 两线寄存器总线。
// selectors: 从实际配置状态解析得到的两个原厂 profile selector。
let snapshot = read_oem_nv_snapshot(&mut nv_reader, selectors)?;
let mut rfic = Fd6818::new(i2c_bus);
rfic.write_oem_corrected_tuning_word_for_mode(
    original_runtime_tuning_word,
    &snapshot.frequency_trims,
    verified_oem_mode_index,
)?;
```

此示意不包含可运行在 XL9951Q 上的启动/PinMux/时钟配置，不假定板级 PA/PTT 连接，也没有臆造每台机器的 NV 字节。

## 4. 验收与后续待证事项

```sh
cargo test --manifest-path firmware-pro/core/Cargo.toml --offline
cargo check --manifest-path firmware-pro/core/Cargo.toml --lib --offline
python -m unittest discover -s tests -v
python tools/pro_v2_full_board_audit.py --json
```

新增 Mock NV 测试应验证：三个逻辑地址和长度、双 Bank 大端解析、四个校正边界与越界索引、每个读取阶段失败时停止后续读取、负校正及 FD6818 写入顺序。实际是否通过以 GitHub Actions 验收为准。

**当前仍无法凭已归档固件推断**：真实逻辑 NV 后端和物理 NOR 的地址关系、读取协议 ACK/CRC 的完整细节、每个模式对应的射频硬件路径、实际校准值、外部 PA 偏置与天线切换、QFN64 物理焊盘、TDA2822/LM2904B 走线以及完整固件 Bootloader/链接布局。

下一轮最有价值的工作是继续沿 `0x080141DC` 的存储协议和 `0x0800DDB8` 的模式选择源追踪，形成可经原厂指令断言的逻辑 NV HAL 传输合同，并利用可用的只读设备/板级证据进一步闭合真实 IO。


## 5. 新补充的 V2 SPI3 直接读取证据与可运行只读适配器

对原厂 V2.0.09 的 `0x080141DC–0x0801422A` 执行了独立半字和 Thumb BL 解码验证。该函数的**确切软件传输结构**如下：

```text
GPIOA15 software CS = low      ; 0x40010814 BRR
SPI3.transfer(0x03)            ; 原厂 NOR Read Data 指令
SPI3.transfer(addr[23:16])     ; 传入 32-bit 参数取低 24 bit
SPI3.transfer(addr[15:8])
SPI3.transfer(addr[7:0])
repeat length:
    buf[i] = SPI3.transfer(0xFF)
GPIOA15 software CS = high     ; 0x40010810 BSRR
```

其中，五处直接 `BL` 分别位于 `0x080141F0`、`0x080141F8`、`0x08014200`、`0x08014206`、`0x08014210`，目标均为 `0x08031814`（已通过早前 SPI3/IWDG 审计确认的 OEM SPI3 字节交换例程）。`0x08012BBC` 对本函数的调用也已通过 Thumb BL 相对位移计算交叉确认。

这将 `0xC5C0` 从仅有「逻辑 NV 读取参数」的证据层次提升为：**原厂应用在 SPI3 的 0x03 读取事务中发送的 24-bit 地址值**。同时仍不可唯一确认外部 NOR 的实际芯片型号、PCB 焊盘、电压、电气时序或连接质量。

新增 `core/src/spi3_nv.rs`：

- `OemSpi3NvReader` 为 `LogicalNvReader` 提供读路径；后端只要求 `SpiByteTransfer` 与现有软件级 `BoardGpio`，不绑定未知 XL9951Q PAC 或 GPIO 物理焊盘。
- 原样发送读指令、三字节地址和 `0xFF`，读出数据返回上层解析器；没有写使能、擦除、页编程、擦除区几何猜测或烧录接口。
- 总线发生错误时执行片选释放，并区分“SPI3 传输失败”“片选操作失败”“两者同时失败”。这不是限制设备能力，而是避免 OEM SPI3 `0x08031814` 的超时直接返回 `0` 被无意视作真实数据的问题。
- 24-bit 地址窗口来自原厂显式发送三个地址字节；越界时不做高字节隐式截断。

取证工具 `tools/pro_v2_spi3_nv_read_audit.py` 对关键半字、GPIOA 寄存器 literal、SPI3 BL 目标及 `0x03/0xFF` 指令逐项校验；`tests/test_pro_v2_spi3_nv_read_audit.py` 含关键指令和 BL 变异负例。GitHub Actions 只上传 JSON 证据，不上传原厂固件镜像。

新的可执行 Host 测试覆盖 `NV SPI3 read → 四字节 Trim + 双份 profile → FD6818 高低半字` 的软件链路。**剩余 HAL 缺口现在主要集中在 XL9951Q SPI3/GPIO 的实际外设时钟与 PinMux、CPU 晶圆厂/物理封装焊盘、实机校准数据及 PA/PTT/音频/键帽连线，而不再是该 NV 读取事务的软件字节序列。**
