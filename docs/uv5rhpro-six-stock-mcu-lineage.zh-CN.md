# UV-5RH Pro：六版原厂固件谱系与 MH2103A / AIR32 / AT32 具体型号交叉筛选

日期：2026-11-16。**重大更正：用户已明确指出 MCU 是 QFN-64，而非先前错误识别的 LQFP64。** 该更正覆盖此前所有根据 LQFP64 进行的型号筛选。**只研究归档文件及公开的官方芯片型号资料，没有连接电台或写入任何数据**。此报告讨论的是“可运行原厂程序的芯片技术谱系”，不能把“使用某套 SDK”直接等同于“焊有该品牌的芯片”。

## 核心发现一：六版固件共享同一段关键 ROM 辅助函数机器码

实际使用仓库的 XOR 0xC8 校验解码器，逐份读取如下六个文件；将程序区
\`0x08001280–0x08001357\`（216 字节）与 V2.0.09 比较：

| 文件 | 解码载荷 | ROM helper 216 字节匹配 |
| --- | ---: | --- |
| \`BF_5RH_501_v1_0_92.dat\` | 458752 B = 448 KiB | 216 / 216 |
| \`BF_5RH_501_v1_0_97.dat\` | 458752 B = 448 KiB | 216 / 216 |
| \`BF_5RH_501_v1_1_00.dat\` | 462848 B = 452 KiB | 216 / 216 |
| \`BF_5RH_501_v1_1_04.dat\` | 466944 B = 456 KiB | 216 / 216 |
| \`BF_5RH_501_v2_0_7.dat\` | 401408 B = 392 KiB | 216 / 216 |
| \`BF_5RH_501_v2_0_9.dat\` | 401408 B = 392 KiB | 216 / 216 |

全部 **6/6** 通过字节完全一致检查，并保留同一套 ROM helper 中的 UID0 分支及特殊寄存器/ROM 调用相关代码。这表明跨版本长期复用相同平台级软件，更有理由专门分析其 SDK 来源。

所有版本均存在 12 项已选“关键值”中的 9 个对齐 32-bit 字面量，包括：
\`0x1FFFF7E8\`、\`0x1FFFD000\`、\`0x400210F0\`、
\`0x40016C00\`、\`0x4002228C\`、三级解锁密钥
\`0xA7D93A86\`、\`0xAB12DFCD\`、\`0xCDED3526\`，及 \`0x200183FF\`。
**不能说其余三个值“没有使用”**：
\`0x40016C18\` 可从基址+偏移构造；
\`0xA5A5A5A5\`、\`0x5A5A5A5A\` 可由 Thumb 指令立即数表示。
对真实读取/写入含义的强证据已在
[ROM 分支指令校验](v2-0-09-bootrom-uid-dispatch.zh-CN.md)和
[AIR32 SDK 源代码指纹校验](v2-0-09-air32-sdk-fingerprint.zh-CN.md)
中完成；不要将原始文字池计数当成动态可达证明。

## 核心发现二：兆讯恒达原厂的 MH2103A 确实有高容量型号，但不能跨封装拼接规格

[兆讯恒达 MH2103A 原厂产品页](https://www.megahuntmicro.com/article/40/24.html)
明确给出 **Cortex-M3、216 MHz、128/256/512/1024 KiB Flash、32/64/96 KiB SRAM**，以及 LQFP48/64/100/144 系列封装。这只是**系列组合**。

具体料号公开选型信息下，需要逐个核对：

| 标准公开型号 | 标称 Flash / SRAM | 标准封装 | 与实机 QFN-64、V2 0x08061A54 及 RAM 地址要求 |
| --- | --- | --- | --- |
| AIR32F103RPT6 | 256 / 96 KiB | LQFP64 | **封装不匹配**，且线性 Flash 容量不够 |
| MH2103ARPT6 | 256 / 96 KiB | LQFP64 | **封装不匹配**，且线性 Flash 容量不够 |
| MH2103AVET6 | 512 / 96 KiB | LQFP100 | Flash 可以解释；**封装不匹配** |
| MH2103AVGT6 | 1024 / 96 KiB | LQFP100 | Flash 可以解释；**封装不匹配** |
| AIR32F103VET6 | 512 / 96 KiB | LQFP100 | **封装不匹配** |
| AT32F403ARET7 | 512 / 96 KiB | LQFP64 | Flash/SRAM 资源可用；**标准封装不匹配**，ROM 语义待核对 |
| AT32F403ARGT7 | 1024 / 96 KiB | LQFP64 | Flash/SRAM 资源可用；**标准封装不匹配**，ROM 语义待核对 |

资源约束来自 [原厂 V2 实际 scatterload 与内存布局](v2-0-09-mcu-identification-amoxu.zh-CN.md)：
压缩数据源实际从 \`0x08061A54\` 读取（相对 0x08000000 偏移
\`0x61A54\`），常规线性程序窗口须至少覆盖 **391 KiB**；初始 MSP
\`0x20011308\` 对应 **70408 字节以上的 SRAM 地址空间**。程序包总大小
与片内 Flash 容量不自动等价，仍可能存在异常映射/别名；外置
GT25Q16A 2 MiB SPI NOR 已由照片独立确认，但**没有证据证明将其映射到
0x08060000 或用于当前 scatterload**。

资料：
- [兆讯恒达 MH2103A 官方系列](https://www.megahuntmicro.com/article/40/24.html)
- [兆讯恒达官方 MCU 选型入口](https://www.megahuntmicro.com/lists/10.html)，逐 SKU 选型行
- [合宙 AIR32F103 官方资料](https://wiki.luatos.com/chips/air32f103/mcu.html)和
  [从 SXX32 迁移时的 UID0 识别表](https://wiki.luatos.com/chips/air32f103/switchFromSxx.html)
- [雅特力 AT32F403A 产品列表](https://arterytek.com/en/product/AT32F403A.jsp)
- [社区维护的 AIR32/MH32F103A/MH2103A 兼容模板](https://github.com/IOsetting/air32f103-template)，非厂商芯片鉴别凭证

**证据强度应明确分层**：

1. **强**：六版原厂文件包含相同 216 字节代码、V1/V2 原厂实际 Thumb 访问
   \`0x1FFFF7E8\`，三级魔数 + \`0x1FFFD00C\` 与开源 AIR32 SDK 对应。
   这是**代码谱系鉴定**，不是实时器件测量。
2. **中强**：MH2103A/MH32F103A 与 AIR32F103 的软件兼容关系（社区模板）
   和兆讯恒达 M3/高容量 SKU 的官方资源，是**同源芯片候选**的支持。
   不能说公开的 MH2103ARPT6 自带 512 KiB。
3. **独立但不充分**：用户确认 QFN-64（取代此前错误的照片 LQFP64 判断）、模糊 \`XL99?1Q\` 顶面码、
   2 MiB 外部 NOR；没有可核验公开顶面码解码规则，不把 \`XL\` 字母
   直接推断为特定制造商。
4. **仍未得到**：实机 CPUID、F_SIZE、厂商 PID、内部/外部地址映射真值。
   单靠 SDK 编译产物在逻辑上不能唯一恢复 CPU 真实商标或 SKU。

## 2026-11-16 用户封装更正：QFN-64 对候选结论的根本影响

此前助手把照片中的主控错误判断为 LQFP64，用户现已明确更正为 **QFN-64**。按实际封装，这些标准 `...T6`、`...T7` 料号即使 Flash、SRAM 容量符合，也不能视为**封装匹配的候选实物料号**。具体而言：

- 雅特力 [AT32F403A V2.04 数据手册](https://arterychip.com/download/DS/DS_AT32F403A_V2.04_EN.pdf)公布 QFN48、LQFP48、LQFP64、LQFP100，没有公开的标准 **QFN64 AT32F403A**。此结论不代表别的 AT32 系列或 OEM 没有 QFN64。
- [GD32F303 官方产品页](https://www.gigadevice.com.cn/product/mcu/main-stream-mcus/gd32f30x-series/gd32f303)列出的标准封装也为 LQFP48/64/100/144，而非 QFN64。
- [兆讯恒达官方 MCU 选型表](https://www.megahuntmicro.com/lists/10.html)中的 MH2103ARPT6 为 **LQFP64**，MH2103AVET6/AVGT6 为 **LQFP100**，没有在已核实列表找到 QFN64 的标准对应料号。
- 标准 AIR32F103RPT6 在已核实目录里同样是 **LQFP64**。

因此：**上述具体公开 SKU 均与 QFN-64 不符**；但 AIR32/MH32 同源 SDK 的 216 字节跨版本相同代码结论**不受影响**。下一轮应寻找 QFN64 封装的 OEM/私有料号、不同厂家的实际封装图以及顶面标记规则；在此之前实际 MCU 的制造商/商业型号仍为 UNKNOWN。

以 QFN-64 为准，**原先建议的 LQFP64 脚位编号、SWDIO/SWCLK/NRST 位置和 GPIO 引脚直接连接结论全部撤回**。不允许从 LQFP64 对照表推断 QFN64 焊盘；用户当前要求纯软件分析，也无需任何接线或刷写。

## 2026-11-16 新增：XL9951Q 的独立器件目录验证

用户进一步提供了 [JLCPCB XL9951Q 器件详情](https://jlcpcb.com/partdetail/JLCPCBAssembly-XL9951Q/C9900238147)。这是第一次从固件和模糊照片以外，找到与用户主板丝印直接对应的正式元器件目录条目：

| JLCPCB 页面字段 | 实际列出 |
| --- | --- |
| MFR.Part # | **XL9951Q** |
| JLCPCB Part # | **C9900238147** |
| Package | **QFN-64_8x8** |
| Description | QFN-64(8x8) SMT ROHS |
| Manufacturer | **JLCPCB Assembly**（平台的目录归类标签，不足以认定真正芯片设计/晶圆制造商） |
| 类别 | Others / SMT |
| 官方芯片数据手册 | **页面未提供** |
| CPU / 内部 Flash / SRAM | **未公开** |

用户实际清点的主控为 **QFN 封装、64 个端子**，与目录的 QFN-64 匹配；目录上的 **8×8 mm 属于登记规格，尚无主板外形尺寸独立测量**。照片初读为 `XL99?1Q`，结合用户早先抄录 `XL9951Q` 与本条目录，现在有可靠的“**封装 + 丝印 + 已登记订货号**”线索。

应当严格区分：

1. **实物零件标签：XL9951Q** —— 获得独立公开目录对应，可作为当前主控首要标签。
2. **CPU 内核 / Flash / ROM 技术体系** —— 仍然只能依据六版原厂 ARM/Thumb 固件和 AIR32/MH32 风格初始化接口进行软件谱系分析。
3. **原始芯片生产者 / OEM 供货商 / 实际 Flash 容量** —— JLCPCB 目录没有证明，不能凭 `JLCPCB Assembly` 的 Manufacturer 栏猜测。
4. **QFN64 引脚排布** —— 该条目是一个封装登记，没有经过验证的功能引脚定义；不可借用标准 LQFP64 的 SWD/UART 脚位。

因此，对外准确的当前结论是：**“UV-5RH Pro 主控顶面标记疑似 XL9951Q，用户确认 QFN64；XL9951Q / C9900238147 的公开器件目录登记为 QFN-64_8x8。实物半导体制造商及 MCU 芯片型号未定。”** 这比“直接认为 AIR32F103RPT6 / MH2103ARPT6 / AT32F403ARET7”更符合现有证据。

## 2026-11-16：关于高 Flash 地址是否来自板载 SPI NOR 的新审计

新增 [XL9951Q：scatterload 与 QSPI 解锁的启动顺序核对](xl9951q-boot-high-flash-vs-qspi-audit.zh-CN.md)，对 V2 原厂 **`0x08061A54` 压缩 SRAM 数据源**进行真实解压内容、原厂升级包覆盖区间和 Reset→scatterload→main→PLL/ROM helper 调用点交叉验证。数据显示 7084 字节 SRAM 初始化段来自原厂应用升级包内的压缩数据；**应用主入口的 `0x4002228C` QSPI 解锁晚于 scatterload**，所以不能解释其发生前就已能访问的高 Flash 地址。启动器及掩膜 ROM 是否另外建立映射仍未知；并未排除片外 NOR 的其他用途或读写方式。

## 复现及可继续解决的问题

\`\`\`sh
python -m pip install "capstone==5.0.6"
python -m unittest discover -s tests -v
python tools/stock_mcu_lineage.py --json
python tools/v2_mcu_candidate_matrix.py firmware/BF_5RH_501_v2_0_9.dat --json
\`\`\`

CI 将六版报告归档为 \`stock-six-version-mcu-lineage.json\`，同时更新
\`v2-mcu-matrix.json\`。工具只读取固件包字节，不发送串口指令。

下阶段仍可在软件侧提高可信度：追踪 \`0x4002228C\` 附近的 QSPI/Flash
初始化与 scatterload 的程序读取时间顺序，确认是否存在对外部 NOR
或存储器别名的**可证实**映射；将 UID0 分支的实际调用时序与 6 个版本
的完整调用图比较。若无法证明映射或 ROM 语义，则物理商业型号应继续
保留为 **UNKNOWN**，不通过估计置信度伪造精确料号。
