# UV-5RH Pro 主控与射频芯片调查（P0.1）

调查日期：2026-11-15。研究目标：用户设备菜单报告 `Firmware v2_0_09`、`Software v1_1_04`。**这两个菜单标签与固件包的 V1/V2 适配关系仍不能直接对应。**

## 证据分级

- **A：实机芯片丝印/调试 ID/总线读取与匹配数据手册，适用于指定 PCB。**
- **B：同一机型另一批次的拆机报告或重复测量，不能自动扩展到所有修订。**
- **C：同系列替代机型、固件静态推断或个人推测。**
- **未知：尚无可信具体证据。**

| 芯片/模块 | 当前结果 | 证据 | 是否适用于目标 V2 实机 |
| --- | --- | --- | --- |
| 主 MCU | 预计为 ARM Cortex-M 兼容核，具体芯片与制造商未知 | B/C：2025 年 Ghidra 的 Thumb 代码确认；2026 年原厂固件向量/代码指纹 | 未确认 |
| 射频基带/RFIC | **FD6818** | B：2024 年 10 月 UV-5RH Pro GPS 拆机（OK2MOP） | V2 尚需核对 |
| FD6818B | 普通 UV-5RH YP07 确认存在，不能当成 Pro 的芯片 | B：2026 年其他 PCB 修订 | 未确认，不能互换驱动 |
| 功放 | 早期拆机出现 11W 级 RF MOSFET 器件 | B：OK2MOP 拆机讨论提及 | 器件具体丝印与 V2 待核对 |
| GNSS | 早期 Pro 具备独立 GNSS 模块；社区归属到 Wintec 供应线索 | B：拆机讨论 | 厂家/型号未确认 |
| Bluetooth | 不同 Pro 主板有空焊位或蓝牙配置 | B：2025 年高清拆机及升级讨论 | 用户设备有无模块待核对 |
| MCU 调试 | 早期板照片有人指出 SWCLK/SWDIO/GND/3V3 测试点 | B：2024 年拆机评论 | 实机丝印、连线及访问权限待核对 |
| FM 广播 IC | 无可靠适用于 Pro V2 的型号结论 | 未知 | 不使用普通版 RDA5807 的板级假设 |
| LCD 控制器 | 无可靠适用于 Pro V2 的型号结论 | 未知 | 不复制普通版 ST7735 的地址与 GPIO |

## 最重要的公开资料

1. UV-5RH Pro GPS 的原始拆机/固件讨论（2024—2025）：https://github.com/amoxu/Baofeng-UV-5RM-5RH-RE/issues/10 。OK2MOP 在 2024-10-19 的评论中直接称射频芯片为 FD6818；对 MCU 只是推测 Cortex-M0，**没有确认具体型号**。2025-06，kholdfuzion 通过 Ghidra 找到 ARM Cortex 特征，并实机验证了经 XOR 0xC8 修改后刷入的镜像。
2. Pro 蓝牙写频版高清拆机帖（2025-10-16）：https://www.mydigit.cn/forum.php?mod=viewthread&tid=557361 。公开正文提到紫色 PCB、显示屏背部标注、GPS 有源天线与预留/蓝牙相关布局，但图片在未登录模式下不能读取芯片标号；不能从该帖子正文得出 MCU 型号。
3. Pro V1.2 主板蓝牙改装讨论：https://forum.hamcq.cn/d/7330 。提到 `E2PD2347` 并推测 `CH571R`，**此处讨论的是蓝牙相关模块，不是已证实的主控 MCU**；未成功加装，不应把此推断列为硬件定论。
4. FCC 与目标机型关联： https://fccid.io/2AJGM-5RHPRO 。内部照片、原理图与方框图作为保密记录未公开，公开 FCC 测试报告不能证明 MCU/RFIC 芯片型号；注意排除旧机型 `UV-5R Pro` 的 2020 年 FCC 文件（名称相似，不是 5RH Pro）。
5. 普通 UV-5RH 逆向，**仅用于对照**：https://github.com/amoxu/Baofeng-UV-5RM-5RH-RE 。其中 `SYN2A-000 / AT32F421C8T7`、`BK4819` 与 64KiB Flash、16KiB SRAM 是普通版实机结果，不适用于 Pro 的芯片识别。
6. `FD6818` 与 `FD6818B` 差异说明：https://github.com/amoxu/Baofeng-UV-5RM-5RH-RE/issues/18 。2026 年普通 UV-5RH YP07 的 FD6818B 不与 FD6818 全寄存器兼容，因此驱动移植前必须确认确切变体。
7. 方案商重标 MCU 的同系列背景：https://github.com/amoxu/Baofeng-UV-5RM-5RH-RE/issues/6 。KDH32xxx、KD32F401RBT6 等见于其他机型；**这些都不是 UV-5RH Pro 的芯片型号证明**。

## 我们的固件静态证据

2026-11-15 的 read-only CI 解析结果（https://github.com/Iu-yang1/Baofeng-5RHPRO-RE/actions/runs/43686122320）：

| 原厂升级包 | 去混淆的初始栈指针候选 | Reset 向量候选 | 主体长度 |
| --- | --- | --- | ---: |
| `BF_5RH_501_v1_1_04.dat` | `0x2000FB98` | `0x0800123D` | 466944 B |
| `BF_5RH_501_v2_0_9.dat` | `0x20011308` | `0x0800123D` | 401408 B |

以上候选 SP 相对 SRAM 基址 `0x20000000` 分别为 64,408 B 和 70,408 B。它们是对解混淆包体前 8 字节的静态解释，并非对 SRAM 实际物理上限的测量。

若该向量表是芯片实际执行的 Cortex-M 应用向量表，则 Pro 固件显然**不能直接采用普通 UV-5RH 的 16KiB SRAM/60KiB 应用 Flash 链接脚本**。这只是排除不相容板级参数，不等于确认真实 MCU、SRAM 容量或中断映射。

### 工具与分析限制

- `tools/mcu_fingerprint.py` 对全部 32-bit 对齐字进行粗筛：数据与 Thumb 指令的两条 16-bit 半字组合会产生大量**假地址**，这份结果只用于原始数据对比，不得当作已验证的外设寄存器地图。
- `tools/cortex_m_literals.py` 通过 Capstone 从向量入口沿 Thumb 控制流寻找真实 PC-relative LDR 的常量引用，能够进一步降低误判；它仍不能确认运行时硬件型号，需要交叉核对汇编控制流、PCB 丝印与调试器 ID。
- 当前没有读取、写入、擦除、重置无线电的代码路径，也不制造所谓匹配 V2 的可刷镜像。

## 具体下一步

1. **影像鉴别：** 目标实机主板两面高清图、PCB 丝印修订、MCU 封装与顶面激光字；对焦近景拍摄 RFIC、GNSS 模块、功率管与外部存储器。
2. **非破坏性 SWD 硬件识别：** 在测量并核实引脚后用 SWD 读取 DPIDR、CPUID 等识别信息；不进行解除读保护、mass erase 或写 Flash。若锁定，则记录调试状态，继续静态分析。
3. **固件交叉验证：** 比较 V1/V2 复位入口、RCC/CRM 及 GPIO 地址、NVIC 向量分布、SPI/UART 寄存器访问，排除不兼容 MCU 家族。
4. **RFIC 驱动边界：** 使用 FD6818 数据和公开驱动作为候选，在 Pro 芯片标号或读回 Chip ID 得到证实时再确定 `FD6818` / `FD6818B` 等驱动分支。
5. **再做 HAL：** 完成 MCU 架构、Flash、SRAM、时钟和引脚清单后才写 Pro 独立启动代码。

**当前不推荐刷写普通 UV-5RH Rust 固件或把 V1/V2 Pro 镜像混刷。**
