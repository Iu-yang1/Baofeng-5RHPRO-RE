# UV-5RH Pro V2.0.09 MCU 型号排查：按 amoxu 的思路对照原厂固件和官方 PID

研究对象是本仓库 firmware/BF_5RH_501_v2_0_9.dat，及用户曾提供的 V2 PCB 照片。主控为 LQFP64、丝印近似 XL99?1Q / 2404CJW9；**尚未读取实机芯片 DEBUG_IDCODE，也未最终确定厂商和料号**。

## 1. 哪些方法可以沿用 amoxu？

[amoxu/Baofeng-UV-5RM-5RH-RE](https://github.com/amoxu/Baofeng-UV-5RM-5RH-RE) 的研究对象为普通 UV-5RM/UV-5RH（使用 BK4819、SYN2A-000 这类定制丝印），其 README 表述 MCU 为 AT32F421C8T7（64 KiB Flash、16 KiB SRAM）。该项目通过 PCB、SWD、Flash/启动区转储和启动器逆向进行鉴别，并包含专用 .BF 加密/封装工具。

本项目复用其**鉴别步骤**：照片/封装 → 本机原厂固件中断向量与机器码 → MCU 官方器件规格 → 真实 SWD PID → Flash/ROM/时钟特殊寄存器交叉验证；**不**移植普通版的 AT32F421x8_FLASH.ld、4 KiB bootloader 布局、.BF 格式或需刷入的 bootloader dumper。Pro 使用带 0x50 字节头和 XOR 0xC8 的 .dat，原厂 V2 程序与普通版并非同一目标。

## 2. V2.0.09 实际固件证据

| 项目 | 固件/图片证据 | 解释 |
| --- | --- | --- |
| MCU 封装 | 用户 PCB 照片，64 个周边引脚 | LQFP64，丝印仍无法对应公开商品型号 |
| 应用大小 | .dat 去头解码后 **401408B / 392 KiB** | 仅有文件大小不足以确认内部 Flash |
| **真实启动读取的 Flash 地址** | scatterload 描述符指向 **0x08061A54**；经 Thumb 解压过程成功还原 7084B | 不只是文件尾部填充，固件初始化会访问 0x0806xxxx 代码存储地址 |
| 初始 SRAM 区域 | DATA 7084B + 清零区 63324B = **70408B**；向量 MSP 候选 **0x20011308** | 若依常规 SRAM 0x20000000 映射，16/64 KiB 无法承载；不等于测得 RAM 总容量 |
| UART/IRQ | USART1/2/3 初始化分别为 **115200/9600/19200**，均有独立中断处理 | 至少三套 USART 兼容实例 |
| DMA | USART2 使用 **0x4002006C**，兼容 DMA1 CH6；接收 GNSS NMEA | 仅具 5 通道 DMA 的小 MCU 不符 |
| Flash/CRM | 原厂 PC-relative LDR 实际引用 **0x40022000** 与 **0x40021000** | 符合 STM32F1/AT32F403A 类地址布局，不能单独认定厂商 |

## 3. 初步芯片筛选（通过 ≠ 确认）

| 具体料号 | 官方 Flash / SRAM | 封装和外设 | 静态结论 |
| --- | --- | --- | --- |
| AT32F421C8T7（amoxu 普通版） | **64 / 16 KiB** | **LQFP48，2 USART，5 DMA 通道** | **排除标准器件：5 项相互独立的不符** |
| AT32F403ARET7 | 512 KiB / 支持 96 KiB SRAM 配置 | LQFP64，至少 3 USART | 尚未排除，不能确认 |
| AT32F403ARGT7 | 1024 KiB / 支持 96 KiB SRAM 配置 | LQFP64，至少 3 USART | 尚未排除，不能确认 |
| AT32F407RET7 | 512 KiB / 支持 96 KiB SRAM 配置 | LQFP64，至少 3 USART | 尚未排除，不能确认 |
| AT32F407RGT7 | 1024 KiB / 支持 96 KiB SRAM 配置 | LQFP64，至少 3 USART | 尚未排除，不能确认 |
| GD32F303RET6 | 512 / **64 KiB** | LQFP64，3 USART | 按已观察 SRAM 初始化边界排除 |
| GD32F303RGT6 | 1024 / 96 KiB | LQFP64，3 USART | 尚未排除，不能确认 |

注意：**资源符合不构成芯片正向识别**，也可能存在其他厂家兼容 MCU 或厂商定制重标芯片。不能用“可能是定制芯片”否定明确的资源/封装矛盾。标准 AT32F4212 同样只有 64 KiB Flash、16 KiB SRAM、LQFP48。

参考官方：
- [AT32F421](https://arterytek.com/en/product/AT32F421.jsp) 和 [AT32F4212](https://arterytek.com/cn/product/AT32F4212.jsp)
- [AT32F403A](https://arterytek.com/en/product/AT32F403A.jsp) 和 [AT32F407](https://arterytek.com/en/product/AT32F407.jsp)
- [GD32F303RGT6](https://www.gigadevice.com.cn/product/mcu/mcus-product-selector/gd32f303rgt6)

## 4. 负面指纹：CRM_CFG bit28 与 AT32F403A/407 手册不一致

V2.0.09 的时钟查询函数在 **0x08030C58** 对 CRM_CFG 右移 28 位、**0x08030C5A** 左移 31 位检查原始 bit28、**0x08030C5C** 根据结果分支，按该值选择 PLL 倍频扩展算法。默认 bit28=0 的软件模型给出 HEXT=8MHz、PLL×6、SYSCLK≈48MHz。

而 [AT32F403A/407 Reference Manual V2.02](https://static.chipdip.ru/lib/639/DOC046639644.pdf) **第 63–64 页**定义 PLLMULT 为 **bits30:29 + bits21:18**，**bit28 为 ADC 分频 ADCDIV 扩展位**，不是 USB 分频，也不是 PLL 倍频高位。说明资源适配的 AT32F403A/407 **还有待解释的软件函数/厂商寄存器位域矛盾**。可能是 SDK 的未用高倍频分支、复用 SDK 的实现问题，或本机 MCU 寄存器语义另有不同，不能先挑一个答案。

## 5. 原厂应用存在 UID/ROM 特殊调用链，但不证明 Reset 直接执行

新增工具在 V2 原厂程序中找到：

- **0x080012A2** 通过真实 LDR 字面量访问 **0x1FFFF7E8**，随后读取其 32 位值；**0x080012A8 / 0x080012C2 / 0x080012DC** 比较最高字节是否 **0x1A / 0x1B / 0x1C**；
- 特定条件下调用 **0x1FFFD000 + 0x0C** 的系统 ROM 函数指针；还观察到 **0x40016C00** 及 **0x40022000 + 0x28C** 附近的特殊寄存器操作；
- 反之，没有在该镜像发现 **0xE0042000** 和 **0x1FFFF7F3** 的直接字面量引用。

根据 AT32F403A/407 官方手册，0x1FFFF7E8 是 UID 的低 32 位，而系列 ID 位于 0x1FFFF7F0 的最高字节。因此 **0x1A/1B/1C 比较的是 UID[31:24]，不是型号或官方 Series ID**，不能从固件得出本机 PID。后续已验证三层直接 BL 调用链、V1/V2 共 216 字节完全相同，以及 0x4002228C 上 A5A5A5A5/5A5A5A5A 两次特殊写入，但没有实机读回或 ROM 函数体，不能定义这些魔数用途。详见 [V2 UID/ROM 指纹报告](v2-0-09-bootrom-uid-dispatch.zh-CN.md)。

## 6. 参照 amoxu 方式获取真芯片型号

[AT32F403A/407 Reference Manual §27.4.1 第 486 页](https://static.chipdip.ru/lib/639/DOC046639644.pdf) 给出了可通过 SWD 读取的 DEBUG_IDCODE PID 对照：

| 只读地址 | 含义 |
| --- | --- |
| **0xE000ED00** | ARM CPUID，只可确认内核类型 |
| **0xE0042000** | AT32F403A/407 DEBUG_IDCODE，命中其官方 PID 表可确定具体型号 |
| **0x1FFFF7F3** | amoxu 源码标注的 Artery 项目类型字节（0x07=403A、0x08=407、0x09=421）；**不是通用 Cortex-M 地址** |
| **0x1FFFF7E0** | amoxu 源码标注的 Flash 容量字段；适用性取决于实际 MCU |

官方支持的具体 PID：
- **0x700502CE → AT32F403ARET7 / LQFP64 / 512 KiB**
- **0x70050345 → AT32F403ARGT7 / LQFP64 / 1024 KiB**
- **0x700502D2 → AT32F407RET7 / LQFP64 / 512 KiB**
- **0x7005034C → AT32F407RGT7 / LQFP64 / 1024 KiB**

这些只是**参考匹配表**，尚未读回。若可以使用已确认 SWDIO/SWCLK/GND/电压参考焊盘，请先确保目标板逻辑电压与探头一致，再用 J-Link/CMSIS-DAP 一类的 SWD 工具执行下面的 **只读 memory 命令**（J-Link Commander 命令格式，需先正确连接芯片）。

~~~
mem32 0xE000ED00 1
mem32 0xE0042000 1
mem8  0x1FFFF7F3 1
mem16 0x1FFFF7E0 1
~~~

不要执行 Flash erase、RDP unlock、Option Bytes 修改或强行刷入 amoxu 的普通版 dumper。若芯片未知、读取受限或存在保护，**报告无法读取即可**；不能以读不到 PID 判定它不是 Artery。无需读取 0x1FFFF7E8 之后的设备 96 位唯一 ID，也不要提供供电线去强制给已上电主板注入电源。接入 SWD 可能影响运行时序，探测时应处于 RX、不要进行 RF 发射。

获取这些值后，仓库的纯离线解析工具可比对官方表：

~~~sh
python tools/at32_readonly_id_decode.py --cpuid 0x410FC241 --debug-id 0x700502CE --project-byte 0x07
~~~

**上面是合成示例，不是用户 Pro 真正读到的数值。** 对官方表外的 PID 保持“未知”判断而非伪造厂商。

## 7. 固件开发决定

当前只可确定：标准 AT32F421C8T7 排除；AT32F403A/407 及部分大容量 GD32F303 等仍属于候选。**不得直接选 AT32F403ARET7 来生成 Pro 的 PAC、GPIO 映射、启动文件或链接脚本**；还需要真实 PID 与 PLL 差异交叉验证。目前 Rust no_std 通用业务核心可以继续编写，尚无可刷入的 Pro 自主固件镜像。

复现：
~~~sh
python -m pip install "capstone==5.0.6"
python tools/v2_mcu_candidate_matrix.py firmware/BF_5RH_501_v2_0_9.dat
python tools/v2_mcu_identity_xrefs.py firmware/BF_5RH_501_v2_0_9.dat
python -m unittest discover -s tests -v
~~~

## 8. 更新：匹配 AIR32/MegaHunt 兼容 SDK，不等于确认 AIR32RPT6

新的 [AIR32 源码级指纹报告](v2-0-09-air32-sdk-fingerprint.zh-CN.md) 发现 `0x400210F0` 门控、三级解锁、`0x40016C18` SRAM 操作、`0x4002228C` QSPI 密钥、`0x1FFFD00C` ROM `SysFreq_Set`、CFGR bit28 计算及分频表**均与 AIR32F103 SDK 高度吻合**。从而前述“CFGR bit28 与 AT32 不一致”应视为 AT32 反向证据、AIR32 SDK 正向证据，而不是软件必然有错。

但是 AIR32F103RPT6 的官方规格为 **256 KiB Flash / 96 KiB SRAM / LQFP64**，本固件的真实 scatterload Flash 读取地址超过 256 KiB 的终点。它不能作为已确认的可刷写 MCU。AIR32/MH32F103A/MH2103A 等软件兼容谱系可作为后续调查线索，尚不满足实物认定条件。无需变更“保持 Rust HAL 芯片无关、不刷机”的开发决策。
