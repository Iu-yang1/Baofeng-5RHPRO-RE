# UV-5RH Pro V2.0.09：USART / TIM 驱动指纹及主频交叉验证

2026-11-15，基于用户 fork 仓库保存的两份官方升级镜像进行**只读离线反汇编**：

- \`firmware/BF_5RH_501_v2_0_9.dat\`（主要目标）。
- \`firmware/BF_5RH_501_v1_1_04.dat\`（跨版本对照）。

本轮 CI：[V2 peripheral clock constraints](https://github.com/Iu-yang1/Baofeng-5RHPRO-RE/actions/runs/43700663976)。

## 一、方法和边界

保留现有 Pro \`.dat\` 的 \`0x50\` 字节包头 + XOR \`0xC8\` 解码方式，**不使用普通 UV-5RH 的 \`.BF\` 解密逻辑**。在 Reset 向量候选和经过 Capstone 解码的控制流中传播局部常量，追踪标准 STM32F1 风格外设地址 \`USARTx_BRR\`、\`TIMx_PSC\`、\`TIMx_ARR\` 的读写指令。结果不是实机运行轨迹，也不能只靠命名识别实际 MCU。

本次扩展的候选寄存器映射：
- USART1 \`0x40013800\`，USART2 \`0x40004400\`，USART3 \`0x40004800\`，UART4 \`0x40004C00\`，UART5 \`0x40005000\`；偏移 \`+0x08\` 为 BRR，\`+0x0C\` 为 CR1。
- TIM1 \`0x40012C00\`、TIM2 \`0x40000000\`、TIM3 \`0x40000400\`、TIM4 \`0x40000800\`、TIM5 \`0x40000C00\`、TIM6 \`0x40001000\`、TIM7 \`0x40001400\`、TIM8 \`0x40013400\`；偏移 \`+0x28\` 为 PSC，\`+0x2C\` 为 ARR。

以上是**待确认的候选寄存器表**。

## 二、实际识别结果

| 项目 | V1.1.04 | V2.0.09 |
| --- | ---: | ---: |
| vector-seeded 候选 Thumb 指令 | 22306 | 29165 |
| CRM/RCC 静态访问指令数 | 91 | 91 |
| USART2 地址候选访问指令数 | 21 | 21 |
| USART1 地址候选访问指令数 | 2 | 2 |
| TIM3 地址候选访问指令数 | 10 | 10 |
| BRR 写入指令候选 | \`0x08026C50\` | **\`0x08032D84\`** |
| ARR 写入指令候选 | \`0x0802640C\` | **\`0x08032540\`** |
| PSC 写入指令候选 | \`0x08026410\` | **\`0x08032544\`** |

三组代码地址相差 **\`0xC134\`**。将两对 USART/TIM 窗口各 24 字节逐字节对齐比较，结果均为 **100% 完全一致**。这支持两版固件**至少在这些窗口内复用了相同机器码**；不能据此声称全部驱动库、全部代码或所有中断向量完全一致。

**重要：下列函数是针对 USARTx/TIMx 参数化的通用初始化例程。** 静态传播产生的 \`USART2\`/\`TIM3\` 标签只表示已分析的候选调用路径，不能据此认定电台只使用 USART2/TIM3，更不能确定 GNSS 或 RFIC 分别连接哪个端口。

## 三、最强 SDK 指纹：USART 初始化

V2 反汇编 \`0x08032CE0–0x08032D88\` 的实际指令线索：

1. \`0x08032D16: BL 0x08030C30\`，先调用候选的外设时钟频率查询函数；是否就是原厂 \`RCC_GetClocksFreq\` 要用其实现交叉验证。
2. \`0x08032D1C\` 的常量池给出 \`0x40013800\`，用于与 USART1 地址比较，以选择 APB1 或 APB2 时钟。
3. \`0x08032D1E: MOVS R2,#0x64\`，出现十进制 100 作为定点缩放因子。
4. \`0x08032D2C\`、\`0x08032D34\`、\`0x08032D48\` 等出现 \`UDIV\`，其中 \`0x08032D40–0x08032D44\` 的加法左移组合等效于 **×25**。
5. \`0x08032D5E\` 读取 \`[USARTx+0x0C]\`，\`0x08032D60\` 检查 bit15 候选；两条分支分别使用 **8/16** 倍过采样的分数处理。
6. \`0x08032D62: MOV.W R3,#0x32\`，出现舍入常量 **50**。
7. \`0x08032D70: AND #7\` 与 \`0x08032D7E: AND #0xF\` 分别对应 8/16 倍采样路径的分数位掩码。
8. \`0x08032D84: STRH R0,[R4,#8]\` 写入候选 \`USARTx_BRR\`。

**这组常量和分支，与 STM32F4 Standard Peripheral Library 的 \`stm32f4xx_usart.c::USART_Init()\` 波特率配置算法高度吻合**。尤其是常量 25、100、50 与 \`USART_CR1_OVER8\` bit15/分数掩码 7/15 的组合，具有比单个 UART 基址更高的 SDK 指纹辨识度。

资料：
- [ST STM32F4 标准库的 \`stm32f4xx_usart.c\` 开源存档](https://github.com/dbridges/stm32f4-discovery-lib/blob/master/StdPeriph/src/stm32f4xx_usart.c)，函数 \`USART_Init\`。
- [ST RM0090，USART_CR1 bit15 OVER8 和 BRR 定点表示](https://www.st.com/resource/en/reference_manual/dm00031020-stm32f405-415-stm32f407-417-stm32f427-437-and-stm32f429-439-advanced-arm-based-32-bit-mcus-stmicroelectronics.pdf)。
- [ST RM0008，STM32F10x USART_CR1 bit15 是保留位](https://www.st.com/resource/en/reference_manual/rm0008-stm32f101xx-stm32f102xx-stm32f103xx-stm32f105xx-and-stm32f107xx-advanced-armbased-32bit-mcus-stmicroelectronics.pdf)。
- [AT32F403A/407 Reference Manual，USART_BAUDR=fCK/DIV（字面寄存器不一定具有 ST OVER8 相同语义）](https://doc.platan.ru/pdf/datasheets/artery/RM_AT32F403A_407_EN_V2_02.pdf)。

**结论的边界：** 启动 CRM 代码与 STM32F10x 风格一致，同时 UART 算法与 STM32F4 标准库一致，这说明工程可能移植/复用了不同 ST 兼容 SDK 的实现；不能仅据此确认具体 MCU 是 STM32F4、STM32F1 或 AT32。尤其 STM32F4 真实 RCC 基址一般不是 \`0x40021000\`，故“代码来源”与“芯片实际身份”必须分开。

## 四、TIM 初始化是传入结构体，而非固定频率常量

V2 \`0x080324F8\` 开始的代码比较多个 TIM 基址并加载参数：
- \`0x0803253E: LDRH R2,[R1,#4]\`，\`0x08032540: STRH R2,[R0,#0x2C]\`：**ARR 来自调用者的结构体 offset+4**。
- \`0x08032542: LDRH R2,[R1]\`，\`0x08032544: STRH R2,[R0,#0x28]\`：**PSC 来自同一结构体 offset+0**。
- \`0x08032552: MOVS R1,#1\`，\`0x08032554: STRH R1,[R0,#0x14]\`：向 **EGR 写入 UG=1**，请求更新事件以应用分频参数。

这高度符合通用 \`TIM_TimeBaseInit\` 的参数结构，而不是某一组硬编码时钟分频。因此不能把本地函数里的 ARR/PSC 写操作视为固定周期，下一步必须追踪**调用此函数的每个 callsite 以及对应的参数结构体值**。

参考：[STM32F4 SPL \`TIM_TimeBaseInitTypeDef\` 定义与字段](https://ese.han.nl/STM32/stm32f4stdlibrary/html/struct_t_i_m___time_base_init_type_def.html)。

## 五、当前仍不能直接计算绝对主频

在从 Reset 出发的已分析路径中，**USART2 BRR 静态写点 1 个，常数写入 0 个；TIM PSC/ARR 均是动态传参**。若未来取得一个确切的 \`USART_BRR\` 且独立知道波特率，才可以在 ST 的 16 倍过采样模型下条件计算 \`PCLK ≈ BRR × baud\`。对 OVER8=1，需要改用对应 8 倍算法。

本项目在 \`tools/peripheral_clock_constraints.py\` 中实现**只在发现确定 BRR 常数时**生成频率算术候选；绝不把“未找到写入常数”替换为虚构 9600、115200 或 72 MHz。若发现邻近同定时器 PSC+ARR 的常数，才计算其纯数学时钟除数 \`(PSC+1)×(ARR+1)\`，不凭除数臆测时基。

## 六、下一步

- 追踪 \`0x08030C30\` 候选时钟查询函数，核对 HEXT 的固件常量、PLL 高位倍频配置，以及 \`PCLK1/PCLK2\` 输出值。
- 给 \`USART_Init\` / \`TIM_TimeBaseInit\` 建立**函数调用点索引**，回溯每个实际调用者传入的波特率、PSC、ARR，区分 GNSS UART、K 口串口与其他通道。
- 使用 V1/V2 \`+0xC134\` 的相对地址映射辅助自动匹配**更多标准外设库函数**，但仍要逐块检验机器码和重定位差异。

## 七、复现

\`\`\`bash
python -m pip install "capstone==5.0.6"
python -m unittest discover -s tests -v
python tools/peripheral_clock_constraints.py firmware/BF_5RH_501_v2_0_9.dat
python tools/peripheral_clock_constraints.py --scope vectors firmware/BF_5RH_501_v1_1_04.dat firmware/BF_5RH_501_v2_0_9.dat
python tools/compare_sdk_windows.py firmware/BF_5RH_501_v1_1_04.dat firmware/BF_5RH_501_v2_0_9.dat --pair 0x08026C50:0x08032D84:24 --pair 0x0802640C:0x08032540:24
\`\`\`

本轮测试覆盖合成 USART BRR 写入、动态配置不虚构常数、TIM 参数邻近与跨实例隔离、原厂包校验和字节窗口平移比较。GitHub Actions 输出仅保存元数据和摘要；不上传解码后固件，也无任何写设备操作。
