# UV-5RH Pro V2.0.09：配置读取、特殊键事件与 RFIC TX 控制片段（PR #34）

研究日期：2026-11-17。依据：归档原厂 V2.0.09 `.dat` 解码后的真实 Thumb 指令、67 字节 TBB 跳表和主机模拟测试。它是 PR #33 的下一轮**软件侧取证**，不包含实体电路测量或可刷写产物。

## 1. 67 个配置 ID 已由跳转地址恢复到字段表达式

- `0x0800E454` 入口加载 `R1=0x20004580`，该址是**工作 SRAM 中的配置结构**，并非 NOR 的逻辑地址。
- `0x0800E47C` 比较 `config_id < 0x43`；`0x0800E482` 执行 `TBB [PC,IP]`；`0x0800E486..0x0800E4C8` 是 **67 字节跳表数据**，不可按连续 Thumb 指令反汇编。
- 真正的 case 从 `0x0800E4CA` 开始，到 `0x0800E63E`。返回值均在 `R0`；超过表上界的 ID 进入 `0x0800E4D4`，返回初始化值 0。
- 全部直接字段访问所需 SRAM 偏移在 `0..37` 内；因此新的核心用最小 38 字节配置工作结构表示**该读取器访问的字段范围**，不声称这是完整 EEPROM/NOR 配置格式。

### 按配置 ID 分组的原始表达式

这里的 `b[n]` 表示 `RAM8[0x20004580+n]`，移位与掩码均作用于 8-bit 值。

| 配置 ID（十六进制） | OEM 读取表达式 / 行为 |
| --- | --- |
| `00,01` | `b[0],b[1]`，大于 2 则**将工作 SRAM 字节改为 0** |
| `02,03` | `b[2],b[3]`，大于 10 则改为 0 |
| `04,05` | `b[4]>>4`、`b[4]&0x0F` |
| `06` | `b[5]` |
| `07` | `b[6]`，大于 1 则改为 0 |
| `08` | `b[7]`，大于 10 则改为 **5** |
| `09..0F` | `b[8..14]` 逐字节读 |
| `10..12` | `b[16]`、`b[19]`、`b[20]`（其中 `12` 大于 4 则改 0） |
| `13..17` | `b[28],b[30],b[29],b[31],b[32]` |
| `18..1D` | `b[21]` 的 bit7、bit6、bit5、bit4、bits[3:2]、bits[1:0] |
| `1E,1F` | `b[22]` 的 bit7、bit6 |
| `20` | 常量 0 |
| `21,22` | `b[23]` 的 bit7、bits[6:5] |
| `23..26` | `b[24]` 的 bit7、bits[6:5]、bit4、bit3 |
| `27` | `b[25]` 的 bit7 |
| `28,29` | 常量 0 |
| `2A..2E` | `b[26]` 的 bit7、bits[6:5]、bit3、bit2、bits[1:0] |
| `2F..33` | `b[27]` 的 bits[7:5]、bit4、bit3、bit2、bit0 |
| `34..38` | `b[33],b[15],b[34],b[17],b[18]` |
| `39,3A,3B` | 常量 1、`b[35]` bit6、常量 1 |
| `3C` | `b[36]` |
| `3D..42` | `b[37]` 的 bit7、bit6、bit5、bit4、bit3、bit2 |

**重要修正：** 原厂 `0x0800E454` 是带副作用的 getter。发生越界时，它直接把修正值写回**RAM 工作配置结构**，但目前并没有在本函数中发现向 SPI NOR 提交这些改动的行为。不能把 getter 的 RAM 修正称为“已经保存到 EEPROM”。

`firmware-pro/core/src/oem_config_getter.rs` 用显式 `ConfigRead` 数据表重建上述 67 项，`OemWorkingConfig::read` 精确处理 byte/bitfield、缺省常量和七种越界修正。通过主机测试验证不同原始字节组合和缓存修改。

## 2. 按键扫描值 0x13 / 0x14 的双分支

在上层 OEM `0x08010B46..0x08010C16` 中，条件分支分别：

- 扫描码 `0x13` 读取配置 ID `0x13`、`0x14`（即 `b[28]`、`b[30]`）；
- 扫描码 `0x14` 读取配置 ID `0x15`、`0x16`（即 `b[29]`、`b[31]`）。

要进入其中一条专门的 GPIOC 矩阵重配置路径，两个对应设置之一需等于 `0x10`，原厂另外三个 helper `0x0800DAB4`、`0x0800E17C`、`0x0800E70C` 的结果都为 0，且配置 ID 6 的读值非零。

两条软件事件分别置位其 UI 状态 word 的 bit14、bit15，对应 `0x08010BAE` 与 `0x08010C12`。本次核心 `oem_menu_event.rs` 只输出这两个**软件事件标记**，并通过主机测试模拟三个 helper 的结果；不会给按键赋予未经验证的物理名称、绕过原厂其它状态分支或直接操作 GPIO。

这条链仍只是**完整菜单事件状态机的局部有条件分支**；菜单绘制、编辑值、保留页与 NV 提交需要继续追踪，不能将其描述成“67 个菜单已完成”。

## 3. FD6818 发射相关寄存器控制片段

原厂另一条已经识别的 TX 相关子路径 `0x0800A8E0..0x0800A902` 的**明确寄存器事务顺序**：

1. 通过 `0x0800A310` 选择 FD6818 音频模式 1，按照原厂缓存重写 `REG_47`，随后写 `REG_48`；
2. 将 RFIC 缓存的 `REG_50` word 保留低 15 位（`UBFX #0,#15`），写入 `REG_50`；
3. 写 `REG_70 = 0x0000`；
4. 写 `REG_30 = 0xC1FE`（已知 OEM 芯片 TX 状态字）。

新 `audio::OriginalAudioCache::apply_oem_rfic_tx_prefix` 用抽象 I²C 总线顺序执行这些写入，测试验证原始字节序、缓存更新以及第 3 笔发送失败时不会继续写入后续 TX 状态字。它只复现**芯片内部 TX 相关子序列**，不控制外部 HTL7G06S011P PA、天线 T/R 开关、实体 PTT，亦不证明麦克风、TDA2822/LM2904B 的模拟线路。

其余不同 TX/RX 分支可能调用更多外围例程。仍然不能将这段子序列描述为“整机发射状态机已完整恢复”。

## 4. XL9951Q 与电路仍未解决的证据边界

- 原厂散见 `0x400108xx` / `0x40010Cxx` 与 `0x40003C00` 只说明 STM32F1/AIR32 类**软件寄存器布局**；不证明 XL9951Q 晶圆厂、QFN64 物理 PAD 到网络的映射。
- 不把普通 UV-5RH 的 `SYN2A-000/AT32F421`、`BK4819` 或 `FD6818B` 映射搬来：这些属于不同硬件 SKU，并且 64 KiB Flash / 16 KiB SRAM 无法解释当前 Pro V2 的代码与 SRAM 映射。
- 后续需要真实 SWD 只读 CPUID/PID 与板上器件身份、PCB 网络连续性、PA/TR/PTT 电平与音频波形，才能闭合整机 HAL。不得生成未经验证的可刷写镜像。只读 SWD 仍应先确认目标电平与焊盘身份。

**外部交叉材料：** [amoxu 普通版 RE 项目](https://github.com/amoxu/Baofeng-UV-5RM-5RH-RE) 与 [FD6818B YP07 分支讨论](https://github.com/amoxu/Baofeng-UV-5RM-5RH-RE/issues/18) 可以参考逆向流程，但不构成 Pro 电路数据。[CHIRP UV-5RH Pro GPS Issue #12255](https://chirpmyradio.com/issues/12255) 提到原厂 `.xlc` 频道条目 48 字节；那是另一层 **CPS 频道记录格式**，不能与这里的 `0x20004580` SRAM 配置结构 38 字节最小访问跨度混为一谈。

## 5. 回归测试与验收命令

```sh
python tools/pro_v2_config_getter_semantics_audit.py --json
python tools/pro_v2_spi3_tx_af_ui_callchain_audit.py --json
python -m unittest discover -s tests -v
cargo test --manifest-path firmware-pro/core/Cargo.toml --offline
cargo check --manifest-path firmware-pro/core/Cargo.toml --lib --offline
```

`tests/test_pro_v2_config_getter_semantics_audit.py` 覆盖 67 处跳转首指令及变异，限制修正路径、常量分支、Rust 结构跨度；在此之前还保留了 V1/V2 校准查表、SPI3 和完整 LCD 既有离线回归。

**交付状态：** 67-case 配置读取 + 局部 UI 特殊键软件事件 + TX 相关 RFIC 寄存器序列实现；物理板级 HAL 与完整菜单仍是待后续取证工程。


> **V5 校正（2026-11-17）：** 本报告 38 字节仅是 `0x0800E454`
> 配置 getter 最小访问范围。经原厂上电恢复 `0x080105DC`
> 进一步核对，工作结构还会写 `+0x26`，因此独立核心实际
> 分配 **39 字节**。61 项 setter 的 NV 保存与字段重排见
> [V5 取证报告](pro-v2-config-nv-setter-restore-rf-audio-hal-v5.zh-CN.md)。
