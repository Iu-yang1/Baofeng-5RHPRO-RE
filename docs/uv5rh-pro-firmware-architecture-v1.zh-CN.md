# UV-5RH Pro V2.0.09：串口/中断逆向与新固件架构 V1

**研究对象：** 用户的 BAOFENG UV-5RH Pro，菜单显示固件 \`v2_0_09\`、软件 \`v1_1_04\`。分析基线为 \`firmware/BF_5RH_501_v2_0_9.dat\`，采用已复核的 \`0x50\` 字节头与 XOR \`0xC8\` 解包方式。**本轮没有连接或刷写任何实机。**

## 一、实际逆向结论

以下证据来自原厂 Thumb 指令、ISR 向量和 DMA 初始化，绝非对普通 UV-5RH 的类推。

| 子系统 | 固件中直接观察到的证据 | 判断及可信度 |
| --- | --- | --- |
| USART1 | \`0x40013800\`，初始化 \`115200\`；中断向量索引 53 → \`0x08032BA5\`；\`0x08032B40\` 在 RXNE 中断读取 DR，将字节写入 \`0x200045A7\` 的 **20 字节环形缓冲区**，读写计数位于 \`0x200000FE\` | **115200、RXNE、20 字节 ring：高可信；外部设备身份未知** |
| USART2 | \`0x40004400\`，初始化 \`9600\`；中断向量索引 54 → \`0x08032BA9\`；IDLE 中断路径 \`0x08032BA8–0x08032BE2\`；DMA 地址 \`0x4002006C\`（按 STM32F1 兼容布局是 DMA1 CH6），目标 SRAM \`0x2000EB88\`，长度 **\`0x500=1280\` 字节** | **GNSS NMEA 接收，强证据** |
| GNSS 应用解析器 | USART2 IDLE ISR 进入 \`0x0800F1CC\` 标志设置，\`0x0800F1DC\` 消费 DMA 数据，\`0x0800F22A\` 检查 \`'$'\`，\`0x0800F234\`、\`0x0800F244\`、\`0x0800F24A\` 判断 \`GGA\`；其他分支对 \`R\` / \`Z\` 语句类型字符分流 | 与板载 **ATGM336H-5N31** 一致，USART2→GNSS 的**软件角色已可高度确认**；仍无物理引脚/波形实测 |
| USART3 | \`0x40004800\`，初始化 \`19200\`；中断向量索引 55 → \`0x08032BED\`；DMA \`0x40020030\`（STM32F1 兼容 DMA1 CH3），目标 SRAM \`0x2000F218\`，长度 **\`0xC8=200\` 字节** | 有独立编码协议的串口；不应当成 GNSS UART |
| USART3 发送 | \`0x080063C4\` 开始的发送循环，从 \`0x20001852\` 读取 1 字节异或因子，在 \`0x080063DE EORS R6,R0\` 后经 \`0x08032D98\` 写 USART DR | **存在软件 XOR 发送编码的原厂指令证据**；是否用于 CPS/写频仍需继续解析帧字段，不能直接写成“已确认写频口” |
| DMA1 CH4/5 向量 | 索引 30/31 均指向 \`0x08001257\` 候选默认处理函数 | 与 USART2/3 **IDLE 中断 + DMA 字节计数**设计相容，并非直接证明 DMA 中断已经使用 |
| CRM 运行时写入 | 已发现 \`0x08030D0E\`、\`0x08030D6E\`、\`0x08030D84\` 等用于改变 CFG 字段的通用函数 | 说明**存在改变时钟相关位域的工具函数**，不等于实机执行了运行期主频切换。应根据具体 caller 继续过滤 |

**关于串口空闲中断：** 依照 STM32 兼容标准库的 USART IT 编码，原厂通过 \`0x0424\` 判断 IDLE 事件，读取 USART SR/DR 清除条件，操作 DMA 通道计数后在普通任务上下文处理报文。这比“在 ISR 中逐字节解析完整 NMEA”更符合原厂代码结构。

上述数字中的 \`USART\`、\`DMA1 Channel\`、\`RXNE\`、\`IDLE\` 命名使用当前最匹配的 **STM32F1 兼容寄存器/中断语义**；它们**不能单独确定主控厂商或真实板级引脚**。第一组 NMEA 证据不依赖 MCU 的品牌推测。

### 逆向脚本复现

\`\`\`sh
python -m pip install "capstone==5.0.6"
python tools/v2_uart_irq_evidence.py firmware/BF_5RH_501_v2_0_9.dat
python tools/v2_uart_protocol_evidence.py firmware/BF_5RH_501_v2_0_9.dat
python tools/v2_memory_layout.py firmware/BF_5RH_501_v2_0_9.dat
python -m unittest discover -s tests -v
\`\`\`

本轮的 \`tools/v2_uart_protocol_evidence.py\` 会逐条核查对应 Thumb 指令与 PC 相对常量池值；原厂代码变化时直接报告指纹不匹配，而不是沿用旧结论。

> **时钟实现补充：** [Reset / main PLL ×16 与 USART/TIM3 调用顺序](v2-0-09-pll-runtime-order-peripherals.zh-CN.md) 说明早期 48 MHz Reset 假设并不固定代表 UART/TIM 初始化时的时钟。若应用的 AIR32 风格 ROM 时钟配置成功，条件主频可为 128 MHz。未来 `ClockTree` 必须在配置时钟后统一给 USART BRR 和 TIM PSC 提供相同的实时 PCLK 数据，避免保留复位阶段频率。

## 二、启动 RAM 布局对自主固件的价值

恢复 ARM \`__scatterload\` 的两条记录，可建立原厂镜像的**静态内存占用边界**：

| 区域 | 起始地址 | 字节数 | 结束地址（不包含） |
| --- | --- | ---: | --- |
| 初始静态数据 \`.data\`（从压缩数据解出） | \`0x20000000\` | 7,084 | \`0x20001BAC\` |
| 清零区域（BSS / 运行时保留区域候选） | \`0x20001BAC\` | 63,324 | **\`0x20011308\`** |
| 镜像中断向量初始 MSP | — | — | **\`0x20011308\`** |

\`7084+63324=70408=0x11308\`，两区域无间隙地连接到原厂向量表候选初始栈顶，这是有价值的交叉验证。**它不证明物理 SRAM 总容量就是 70,408 字节**，也不能据此直接为新固件生成真实芯片的链接脚本。原厂清零区可能包含运行时预留空间。

## 三、我们的新固件建议采用什么技术路线？

**推荐：独立 Rust \`no_std\` 应用 + Pro 专用板级 HAL + 分开的更新/恢复工具。**

原因：
1. V2 的业务流程有独立于特定 MCU 的逻辑，如 NMEA、配置管理、频道数据库、APRS/AX.25、卫星多普勒和 UI 状态机。这些可以现在开发并在 PC 上测试。
2. 真实 MCU 仍没有可靠的厂商/型号识别。如果现在复制普通 UV-5RH 的 \`at32f421-pac\`、\`memory.x\` 和 GPIO 表，可能编译通过但立即写错寄存器。
3. 原厂 SPI NOR GT25Q16A、GNSS ATGM336H-5N31、RFIC FD6818 与音频/PA 器件已获得重要身份线索，能据此先定义接口，再逐步填实硬件驱动。
4. 参考仓库 [bf-5rh-firmware-open](https://github.com/sophiel-meow/bf-5rh-firmware-open) 采用 Rust、\`cortex-m-rt\`、AT32F421 PAC 和图形组件；[bf-k61-firmware-aura](https://github.com/sophiel-meow/bf-k61-firmware-aura) 具有 FD6818 驱动。**两者是其它电台的实现，不可直接刷入 Pro，也不可照抄其引脚定义**。

### 建议源代码结构

\`\`\`text
firmware-pro/
  core/                  # 已建立：no_std、无 MCU 依赖
    src/nmea.rs           # 已实现：流式句子封装与 XOR 校验
  protocol/              # 后续：AX.25/APRS、CPS 帧、GPS 结构字段
  radio-core/            # 后续：RX/TX/PTT/频道/静噪/音频状态机
  board-uv5rh-pro-v2/    # 待 MCU/引脚核实，才实现寄存器与 PAC
  drivers/
    fd6818/              # RFIC 控制总线、收发状态及频率寄存器
    gt25q16a/            # 外部 SPI NOR、ID/SFDP、资源与持久化
    atgm336h/            # USART2 → DMA/IDLE → NMEA → GNSS fix
    lcd/                 # 面板接口、背光、字库和输入
  app/                   # 桌面产品功能：双 VFO、扫描、APRS、卫星
  tools/                 # 独立镜像打包、升级和恢复检查
\`\`\`

目录中只有 \`core/\` 的 NMEA 部分已实际创建；其余是有序开发规划，不是已交付模块。

### 软件层之间的接口约定

- \`ClockTree\`：给 HAL 提供实测或 MCU SDK 校验的 \`sysclk_hz\`、\`pclk1_hz\`、\`pclk2_hz\`、\`timer_input_hz\`。原厂默认 48 MHz 是**启动候选配置**而不是不可修改的产品限制。
- \`SerialPort\`：按实例分别分配端口和缓冲区。第一版以 \`GNSS=USART2/9600\` 为软件侧目标；USART3 必须保留其原始 XOR 兼容层，不能直接合并进 NMEA 驱动。USART1 设备角色先留待逆向确认。
- \`GnssService\`：流式字节、整句 checksum 验证、GGA/RMC/ZDA 业务解析、UTC 更新分开；处理 DMA 切包、粘包和校验失败时不污染最近有效定位。
- \`RadioFrontend\`：逻辑层使用 \`set_rx_frequency\`、\`set_tx_frequency\`、\`enable_rx\`、\`enable_tx\`、\`read_squelch/rssi\` 等接口；具体 FD6818 寄存器序列与板上 PA 控制引脚放在 HAL，避免将普通版 FD6818B 的驱动假定成完全兼容。
- \`StationState\`：RX/TX 切换做明确的状态转换和事务顺序（关闭旧路径→配置新路径→激活），异常时明确恢复状态；支持协议和硬件正确实现的功能默认开放，不凭主观安全疑虑锁定频段或禁止调谐。
- \`PersistentStore\`：将频道数据、校准数据、用户设置与字库分开；GT25Q16A 有 2MiB 容量，但**其实际存储分区尚未逆向**，不得直接覆盖原厂内容。

### 为什么现在先写 GNSS 核心？

这轮已经能直接用 V2 原厂指令证明 USART2 的 NMEA 消费路径。因此建立了独立的 \`firmware-pro/core\` Rust library：

- \`#![no_std]\`、没有第三方依赖，可供后续任何 Cortex-M HAL 使用；
- \`nmea::Framer\` 支持逐字节 / DMA 分块输入和 \`$...*HH\` NMEA XOR 校验；
- 识别 GGA、RMC、ZDA 语句类型和 GN/GP 等 talker ID；
- 对损坏校验、溢出、分包、前置噪声和重同步提供 Host 测试。

目前它是**NMEA framing + checksum 层**，**尚不包含经纬度字段、卫星状态、GNSS 校时或 UART DMA 实机驱动**；不应声称已经完成完整 GNSS 功能。

\`\`\`sh
cargo test --manifest-path firmware-pro/core/Cargo.toml --offline
cargo check --manifest-path firmware-pro/core/Cargo.toml --lib --offline
\`\`\`

源码为本项目独立编写，没有直接复制外部 GPL 驱动。两份参考 Rust 固件仓库均为 **GPL-3.0**；如果将其源代码移植入我们未来的发行版，必须解决整体发布许可证及源代码履约问题。当前只引用架构思路。

## 四、向“真正能刷机”的固件推进的验收路线

| 迭代 | 工作包与产物 | 验收证据 | 是否需要实机 |
| --- | --- | --- | --- |
| **P0 已完成研究阶段** | 原厂包、启动、CRM、SRAM scatterload、USART2 GNSS 指纹，主控候选范围 | 各原厂字节校验、反汇编、CI | 否 |
| **P1 正在启动** | 跨 MCU Rust core：NMEA、频道数据结构、状态机、AX.25 数学模块 | Host 逻辑单测、\`no_std\` 编译 | 否 |
| **P2 MCU 专用 HAL** | 确认真实 MCU/PAC、启动入口、NVIC、时钟、GPIO、USART2 DMA、LCD 接口；产出板级引脚表和链接脚本 | 静态对照 + 程序下载后的 UART/LCD/GPIO readback | **是，最终验收需要** |
| **P3 基础电台功能** | FD6818 收发频率、FM RX/TX、静噪、PTT、TDA2822 音频、双 VFO、频道与扫描 | 接收解调、假负载 TX、频谱/功率/谐波、状态切换与错误恢复 | **是** |
| **P4 GNSS/APRS/卫星** | GGA/RMC/ZDA、位置和 UTC；AFSK/AX.25；频率偏移与卫星跟踪 | 合成报文、录制 IQ/AF、Dire Wolf 解码和实机接收/发射 | Host 先行，实机最终验收 |
| **P5 升级与发布** | 独立打包流程、正式镜像、回退/恢复方案、机型和固件版校验 | 镜像可重现 SHA256、原厂恢复实证和全链路复测 | **是** |

**不把“必须完成所有硬件测试”作为写代码的前置门槛**：P1 可以立即开发和验证；只是不能把没有测试过的刷机、RF 功率和 GPIO 映射说成已经验收。防止 PTT 意外持续发射、PA 误使能、无效 RFIC 应答关联错误，以及无法恢复的 Flash 擦除等机制都有具体故障模式依据，应保留。它们不是通用功能禁用门槛。

### 固件包与恢复策略

已知原厂包可通过 \`fwtool.py\` 解包、修改和重打包，也有 \`fw_updater.py\` 可以通过串口执行升级。但**我们目前没有证明这台设备在坏镜像下仍能进入升级器，也没有确认 MCU 真实 Flash 擦写分区、签名约束和备份完整性**。所以在新固件工程中将：
1. 继续以“原厂镜像不可改”方式保留固件基线。
2. 独立开发与验证新固件 core，启动和板级包位于明确的 experimental 路径。
3. MCU、映射和恢复路径得到充分证据后才使用厂商 PAC 与真实 linker-script 构建设备镜像。
4. 独立记录升级镜像的头部、长度、CRC/XOR、目标版号和设备处理流程，区分**可重打包**与**可安全恢复**。

## 五、下一轮最值得追踪的地址

| 优先级 | 地址 | 任务 |
| --- | --- | --- |
| 最高 | \`0x0800F1DC\` | NMEA 字段解释 → 定位 / 时间结构和状态更新 |
| 高 | \`0x080063C4\`、\`0x08032B2C\` | USART3 XOR 发送 / DMA 接收帧，恢复私有串口协议边界 |
| 高 | \`0x08018748\` | USART1 的 20 字节 RX 环应用级消费函数，确定角色 |
| 高 | \`0x08030D0E\`、\`0x08030D6E\`、\`0x08030D84\` | 遍历 CRM_CFG 通用配置函数的调用点，判定是否有运行时重新切换 PLL |
| 中 | \`0x0800CAxx\`、\`0x080103xx\`、\`0x08018Cxx\` | GPIO 模式设置与复用脚推断；在未知主控上不直接当成最终 Pro 引脚表 |

### 阅读与引用

- 本 fork [V2 时钟树与 SRAM 数据流报告](v2-0-09-clock-tree-dataflow.zh-CN.md)。
- 本 fork [主板照片及外围器件核实](uv5rhpro-v2-photo-verified-components.zh-CN.md)。
- [bf-5rh-firmware-open：普通版 AT32F421 Rust 固件](https://github.com/sophiel-meow/bf-5rh-firmware-open)，GPL-3.0。
- [bf-k61-firmware-aura：FD6818 Rust 驱动参考](https://github.com/sophiel-meow/bf-k61-firmware-aura)，GPL-3.0。
- [ST RM0008：STM32F10x 中断、USART、DMA 与外设地址候选手册](https://www.st.com/resource/en/reference_manual/rm0008-stm32f101xx-stm32f102xx-stm32f103xx-stm32f105xx-and-stm32f107xx-advanced-armbased-32bit-mcus-stmicroelectronics.pdf)。STM32 兼容结构只是**验证用参照**，不是确认实际主控型号。

结论：**以“原厂 firmware reverse engineering → 高可信接口合同 → host 验证 no_std 业务模块 → MCU/板级 HAL → 可启动与 RF 验证”的顺序最节省返工。** 不建议在 MCU 未确认前直接照搬普通版固件重新刷机。
