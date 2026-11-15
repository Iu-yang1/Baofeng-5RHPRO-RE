# UV-5RH Pro MCU / RFIC 硬件证据调查（2026-11-15）

> 研究范围：**BAOFENG UV-5RH Pro**；用户设备菜单报告「固件 \`v2_0_09\`、软件 \`v1_1_04\`」。
>
> 本文件是公开资料核查与既有固件包元数据交叉验证；**并未拆解用户设备、访问调试端口或读回实际芯片寄存器。**

## 一、当前结论（证据与推断分离）

| 组件 | 目前判断 | 依据与适用范围 | 置信度 |
| --- | --- | --- | --- |
| MCU 架构 | ARM Cortex-M / Thumb 固件形态 | Pro 固件向量候选与 kholdfuzion 的 Ghidra 分析 | 高于纯推测，具体 ARM 子型号未知 |
| MCU 生产厂家、具体型号 | **未确认** | 公开的 2024 年 Pro PCB 拆机分析者无法识别芯片 | 未知 |
| RFIC | **FD6818** | 2024 年 UV-5RH Pro GPS PCB 拆机讨论 | 较高，但**用户 V2 PCB 未核实** |
| FD6818B / BK4819 / BK4829 | 可作为 *对比对象*，不可直接认定是本机 | 普通 UV-5RH/5RM 存在多种不同 RFIC 修订 | 非本机证据 |
| RF PA | 分立 RF MOSFET；社区拆机讨论引用 HTL7G06S011P 数据手册 | 基于早期 Pro 板子；未验证本机 PA 的准确型号与链路 | 中/低 |
| GNSS | 被拆机开发者归于 Wintec Semi 的 GNSS 模块；所链接候选为 GM36 | 候选模块的完整料号和本机批次尚未核实 | 中/低 |
| LCD 控制器 | 未确认 | 公开照片帖子提及屏幕背面可见型号，但登录限制妨碍直接核对 | 未知 |
| 外部 Flash | 未确认 | **不等同**普通 UV-5RH 的 XMC 25QH16CJI；不能从固件包大小推断类型 | 未知 |
| SWD | 早期 Pro PCB 拆解称有 SWCLK / SWDIO / GND / 3V3 触点 | 未证实用户 V2 板上连接和调试权限 | 待本机验证 |

参考原始资料：
- [amoxu Issue #10：UV-5RH Pro GPS 主板、RFIC、MCU 与 SWD 讨论](https://github.com/amoxu/Baofeng-UV-5RM-5RH-RE/issues/10)
- [2025-10 数码之家：UV-5RH PRO 蓝牙写频版详细拆机](https://www.mydigit.cn/forum.php?mod=viewthread&tid=557361)（部分照片/回复须登录）
- [FCC ID 2AJGM-5RHPRO](https://fccid.io/2AJGM-5RHPRO)（2024 年申报；内部照片、原理图受长期保密限制）
- [sophiel-meow：普通 UV-5RH YP07 / FD6818B 逆向详解](https://github.com/amoxu/Baofeng-UV-5RM-5RH-RE/issues/18)
- [普通 UV-5RH/5RM 逆向](https://github.com/amoxu/Baofeng-UV-5RM-5RH-RE)
- [GM36 模块资料（仅为拆机讨论中链接的候选，不是已验证本机料号）](https://www.wintec-semi.com/product-77809-180472.html)

## 二、从真实 V2.0.09 升级文件得到的静态线索

本仓库 P0 的自动检查已验证全部六份升级包；报告见 [p0-firmware-inventory.zh-CN.md](p0-firmware-inventory.zh-CN.md)：

- 包头剥离及 XOR 0xC8 处理后，\`BF_5RH_501_v2_0_9.dat\` 主体长 **401408 字节 = 392 KiB**（不意味着 CPU 片内 Flash 一定为 392 KiB）。
- 假定主体前 8 字节为 Cortex-M 初始向量表，其初始栈顶候选为 **0x20011308**；相对于 \`0x20000000\` 偏移 **70408 字节，约 68.76 KiB**。
- 复位向量候选为 **0x0800123D**（最低位为 1，符合 Thumb 入口形式）。
- 已有 GitHub 研究者使用 Ghidra 的 ARM Cortex 反汇编模型，认为反汇编结果匹配该固件代码风格。
- V1 与 V2 镜像有不同包头 0x30 字段及不同主体长度；真实 GPIO、时钟、电源、屏幕、PA 控制可能改变。跨板刷写在公开实测中曾产生背光反向、语音异常。

这些条件**不支持**直接套用普通 UV-5RH \`AT32F421C8T7\` 的 **64 KiB Flash / 16 KiB RAM** 链接脚本；在常规 \`0x20000000\` SRAM 映射且该数值确为初始 SP 的前提下，这台目标板需要高于 68 KiB 的可寻址 SRAM。要防止两个逻辑错误：栈顶偏移不等于已经探明的 SRAM 物理容量；升级包主体长度不等于芯片 Flash 容量。

**目前不能据此命名 MCU 为 STM32F401、AT32F415、KD32F401 或任何其他具体型号。** 这些仅是不同机型出现过的芯片或备选架构，均缺乏这台 Pro V2 板的硬件证据。

## 三、射频芯片兼容性边界

来自 [sophiel-meow 2026 年研究](https://github.com/amoxu/Baofeng-UV-5RM-5RH-RE/issues/18)，但验证对象为**普通 UV-5RH，非本机 Pro**：

- FD6818 的片内 ID 寄存器 \`0x00\` 在已研究设备上返回 \`0x4819\`，研究者发现其寄存器风格与 BK4819 高度类似；
- FD6818B 的寄存器 \`0x00\` 返回 \`0x4829\`，实测兼容性更接近 BK4829；
- FD6818 和 FD6818B **不可简单互换驱动**；
- Rust 参考项目 \`sophiel-meow/bf-5rh-firmware-open\` 中 \`src/drivers/fd6818b.rs\` 主要针对 FD6818B / 0x4829；若本机确为 FD6818，应优先对比 FD6818 版本驱动和芯片寄存器；
- **以上两个 ID 不是对用户 Pro 实机的读取结果**。

源：[bf-5rh-firmware-open](https://github.com/sophiel-meow/bf-5rh-firmware-open)。

## 四、可执行的 MCU 鉴别步骤（按信息增益排序）

1. **获取本机 PCB 的完整、清晰照片**：主板两面、最大 48/64 引脚 QFP 芯片丝印、射频芯片表面激光字、PCB revision、GNSS 模块和屏幕背面料号。已有公开照片主要来自早期或蓝牙写频变体，不能证明 V2.0.09 使用相同板卡。
2. **离线比较向量表、复位入口与外设寄存器访问**：列举 Cortex-M 中断向量规模、Thumb/Thumb-2 指令类型、时钟/AFIO/GPIO/UART/SPI 基址，利用厂家 SVD/SDK 比对。可排除候选，仍不等于确定厂家。
3. **SWD 只读探测**：若确认目标板上具有 SWCLK、SWDIO、GND、3V3 测试点，使用 CMSIS-DAP 或同级探头，以目标板的 3.3V 作为电平参考；首先检查 SW-DP ID、CPUID (\`0xE000ED00\`) 与调试访问权限。不要把 3V3 盲目作为外部供电输入。**即使获得 ARM CPUID，也只能确认核心类型，需结合厂家设备 ID、芯片表面丝印与反汇编对照。**
4. **检查外部 Flash JEDEC ID 与 RFIC REG 0x00**：仅在已经证明芯片连接及总线初始化后执行只读查询；读取外部 NOR 型号、RFIC chip ID，可直接确定驱动移植方向。
5. **再构建 Pro 专用 HAL 和启动映射**。未经确认不得采用普通 UV-5RH 的 AT32F421 PAC、60 KiB 应用 FLASH、GPIO 分配和 ST7735 驱动。

完成 MCU 识别的验收应包括：芯片丝印、核心标识、外设地址/中断向量匹配、内存范围/链接基址的至少两项相互独立证据；完成射频芯片识别的验收应包括清晰丝印或者可信的只读芯片 ID（最好二者均有）。

## 五、固件版本字段风险

用户分别报告「固件 \`v2_0_09\`」及「软件 \`v1_1_04\`」。这两个值作为原样记录保留。

公开的社区例子常将 \`v2_0_09\` 称为软件/固件版本，V2 板的硬件版本常见 \`v1_0_4\`。而 \`v1_1_04\` 又是仓库中**旧硬件分支升级镜像的文件名**。两者不能在缺少实际界面/设备信息读取的情况下解释成两个独立固件分区，也不能据此断言目标硬件一定为 \`v1_0_4\`。

关联资料：
- [CHIRP UV-5RH Pro #11669](https://chirpmyradio.com/issues/11669)
- [HamCQ V1/V2 硬件跨刷实践](https://forum.hamcq.cn/d/6358)

## 六、当前开发决策

先**确定 MCU 与 RFIC**，再决定是否直接移植 Rust 工程。现阶段只进行静态分析与只读鉴别；不生成「适配 Pro」名义的可刷镜像，不把其他机型的寄存器表当作实机已验证配置。逐步验证不应演变为无依据的发射功能禁用；针对 PTT 持续发射、错误射频切换和固件擦除等有明确故障模式的操作，设计必要的状态机和恢复机制。

后续优先级：**V2 本机 PCB / MCU 丝印 → SWD / 向量表指纹 → RFIC 0x00 → 外部 Flash → LCD/GNSS → Rust HAL**。


## 七、找到的射频芯片原始寄存器资料

**[FD6818 Programming Guide Rev.1.0.0（75 页；网络存档为机器翻译英文版）](https://www.glaver.org/blog/UV-17/FD6818.pdf)**

可用于研究：三线串口时序、PLL/VCO、频点与带宽、RX/TX 状态、静噪/RSSI、CTCSS/DCS、FSK、音频、功率控制与调制偏差。因翻译质量、资料版本和器件差异，**文档中的寄存器名称及地址不应直接等同到 Pro 的实际寄存器映射**。

辅助参考：[RadioFoundry：其他设备 FD6818 驱动与实测寄存器](https://radiofoundry.org/docs/spec/hardware-dm32)；该文档明确指出某些产品中 FD6818 的使用地址与编程手册不同，不能将外机的初始化字节序列直接烧入 UV-5RH Pro。

射频末级元件的备选资料：[HTL7G06S011P LDMOS 数据手册](https://www.watechelectronics.com/Public/Uploads/uploadfile2/files/20241107/HTL7G06S011PProductdatasheetrev1.8.pdf)。**这是早期拆机讨论所链接的型号，不等于已核实用户电台焊接的器件。**
