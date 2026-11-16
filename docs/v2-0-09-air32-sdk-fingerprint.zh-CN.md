# UV-5RH Pro V2.0.09：AIR32F103 SDK 指纹与 MCU 身份鉴别

日期：2026-11-15。使用归档原厂 `BF_5RH_501_v2_0_9.dat` 与 `BF_5RH_501_v1_1_04.dat`，并与合宙开源 AIR32F103 SDK **源码逐项**对比。本报告为**离线固件谱系鉴定**，不是实机 MCU 身份确认。

> **后续 Reset 路径补证：** [V1/V2 主入口及时钟外围初始化验证](v2-0-09-pll-runtime-order-peripherals.zh-CN.md) 已将 `0x080173DC` 追溯至 V2 Reset → ARM scatterload → `0x080340E0` 主入口（直接 `BL` 在 `0x080340EA`），且在 USART/TIM3 初始化之前。V1 同样存在对应结构。ROM 回调仍由 UID 分支决定，因此 128 MHz 是具有启动路径证据的**条件请求**，而非已经测得的实际主频。

## 一、重大修正：ROM 辅助函数并非无法识别的随机魔数

在官方开源 SDK [AIR_RCC_PLLConfig](https://github.com/openLuat/luatos-soc-air32f103/blob/c10eaeb13dd133f35bc9d8ed1137072897339db2/Libraries/AIR32F10xLib/src/air32f10x_rcc_ex.c) 中：

1. 写 `0x400210F0 = 1` 开启内部系统配置门控；
2. 依次向 `0x40016C00` 写 `A7D93A86`、`AB12DFCD`、`CDED3526`；
3. 向 `0x4002228C` 写 `A5A5A5A5`，源码注释为 QSPI 解锁；
4. 通过 `SysFreq_Set` 间接调用 `*(uint32_t *)0x1FFFD00C`；
5. 更新 `RCC->CFGR` 的 PLL 输入来源，随后反向重新上锁；对应 `0x4002228C = 5A5A5A5A`。

原厂 V2 函数 `0x08001260` 不仅使用同样地址/常量，还保存 `[0x40016C18]`，临时写 `0x200183FF` 后恢复。这项扩展在 AIR32 SDK 的 [startup_air32f10x.s](https://github.com/openLuat/luatos-soc-air32f103/blob/c10eaeb13dd133f35bc9d8ed1137072897339db2/Libraries/STARTUP/gcc/startup_air32f10x.s) 中有相同写入；因此更符合 **AIR32 系列的隐藏 SRAM/系统配置逻辑**，而非此前 AT32 手册中称作 I2S2EXT 的普通功能。在原厂 0x080013E4–0x0800140C 的真实文字池中，以上十个关键常量均被确认。

| 特征 | V2.0.09 观察 | AIR32F103 SDK |
| --- | --- | --- |
| SYSCFG 门控 | `0x400210F0` | 同一地址及写入次序 |
| 三级解锁 | `A7D93A86 → AB12DFCD → CDED3526` | 相同 |
| SRAM 窗口 | `0x40016C18` 保存、`0x200183FF` 修改、恢复 | 启动汇编包含相同写入 |
| Flash/QSPI 控制 | `0x4002228C = A5A5A5A5`，返回写 `5A5A5A5A` | 相同，源码注释为 QSPI |
| ROM 接口 | `[0x1FFFD000+0x0C]` | 宏名 `SysFreq_Set` |
| RCC 时钟函数 | CFGR bit28 扩展 PLL 倍频 | [官方 SDK RCC_GetClocksFreq](https://github.com/openLuat/luatos-soc-air32f103/blob/c10eaeb13dd133f35bc9d8ed1137072897339db2/Libraries/AIR32F10xLib/src/air32f10x_rcc.c) 使用相同算法 |
| SRAM 时钟分频表 | `[0,0,0,0,1,2,3,4,1,2,3,4,6,7,8,9]` | 同一字节序列 |
| ADC 分频表 | `[2,4,6,8]` | [早期 SDK 文件](https://github.com/openLuat/luatos-soc-air32f103/blob/c10eaeb13dd133f35bc9d8ed1137072897339db2/ModuleDemo/AT_Air724_Air600U/libraries/AIR32F10xLib/src/air32f10x_rcc_ex.c) 同一序列 |

这些吻合指向源代码层面的 AIR32/MegaHunt 兼容 SDK 复用，**明显强于**单靠外设地址/封装做的器件推测。但是即使 SDK 血缘明确，也不能直接由软件二进制推出芯片制造商和商业料号。

## 二、确认包装函数传入的三个参数的 SDK 意义

上层静态调用链：`0x080173DE → 0x0803235E → 0x08032386 BL 0x08001260`。

根据 [AIR32 RCC 常量头文件](https://github.com/openLuat/luatos-soc-air32f103/blob/c10eaeb13dd133f35bc9d8ed1137072897339db2/Libraries/AIR32F10xLib/inc/air32f10x_rcc.h) 与 [FlashClkDiv 头文件](https://github.com/openLuat/luatos-soc-air32f103/blob/c10eaeb13dd133f35bc9d8ed1137072897339db2/Libraries/AIR32F10xLib/inc/air32f10x_rcc_ex.h)：

| 传入寄存器 | 原厂字节对应值 | SDK 含义 |
| --- | --- | --- |
| R0 | `0x00010000` | `RCC_PLLSource_HSE_Div1` |
| R1 | `0x00380000` | `RCC_PLLMul_16` |
| R2 | `1` | `FLASH_Div_2` |

因此此前“参数接口完全未知”的表述应修正为：**应用侧 `AIR_RCC_PLLConfig` 风格接口可按 SDK 映射；ROM 函数体内部和 UID 特殊分支的实际硬件语义仍未确认**。

若物理 HSE 确实为原厂软件中编译的 8 MHz，该调用请求 PLL ×16，亦即条件 `SYSCLK=128 MHz`。此前重建的“Reset 配置为 48 MHz”也是有效的另一条代码配置路径；不能把 **48 MHz** 说成唯一主频，也不能因存在 128 MHz 调用点便认定设备始终在 128 MHz 运行。需要进一步确认上层调用时序、ROM 实施情况与是否存在动态切换。

UID 低字最高字节 `0x1A/0x1B/0x1C` 对应的**条件分支不能视作 MCU 型号**：其中 `0x1A/0x1B` 路径与 SDK 常见 `SysFreq_Set(pllmul, latency, 0, 1)` 形式相容；`0x1C` 路径使用不同实参安排，并临时修改 CFGR，仍须独立研究。

## 三、最关键的型号矛盾：AIR32F103RPT6 的 Flash 不够

合宙公布的 [AIR32F103 芯片数据手册](https://c.vue2.cn/attachment/20220605164850945_AIR32F103%E8%8A%AF%E7%89%87%E6%95%B0%E6%8D%AE%E6%89%8B%E5%86%8C1.0.0.pdf) 列出标准 `AIR32F103RPT6` 为 **LQFP64、256 KiB Flash、96 KiB SRAM**。本仓库 V2 scatterload 真实数据读取地址 `0x08061A54`：从 Flash 基址 `0x08000000` 算偏移 `0x61A54`（约 390.6 KiB），**超过标准商业型号公开的 256 KiB Flash 规格**。

所以：**固件使用 AIR32 风格 SDK ≠ AIR32F103RPT6 确认**。应保留芯片兼容实现、重标芯片/定制 Flash 容量、不同供应链的同源 SDK 等候选，但不能在无证据的情况下把任一猜想写成结论。标准 `AIR32F103RPT6` 应按其公开规格列入“资源不匹配”；即使芯片 ROM 存在存储器映射/隐藏资源，仍需额外证据证明可寻址和可可靠使用。

[IOsetting 的跨系列移植模板](https://github.com/IOsetting/air32f103-template) 明确把 `AIR32F103x / MH32F103Ax / MH2103Ax` 作为软件兼容系列；同样**不是**对本机厂商的证明。其列出的标准 RPT6 系列容量也只有 256 KiB。

### 2026-11-16 补证：六版原厂 ROM helper 指纹保持 216/216 字节一致

[六版固件与逐 SKU 容量分析](uv5rhpro-six-stock-mcu-lineage.zh-CN.md)
已验证从 V1.0.92 到 V2.0.09 的六版归档固件均在
`0x08001280–0x08001357` 与 V2.0.09 完全相同。
这进一步证实共用 **AIR32 风格程序实现**的稳定性，但并不使
AIR32F103RPT6 或 MH2103ARPT6 这两个公开 256 KiB/LQFP64
型号自动满足本机的程序高地址要求。兆讯恒达更大容量的标准
MH2103A 型号使用不同封装；物理 SKU 继续未知。

## 四、下一步与板级固件决策

优先做原厂 **AIR32 风格初始化函数与上层调用点**的全图索引，再比较 V1/V2 是否复用相同时钟恢复策略。接下来在不接触硬件的情况下可追踪 RCC 修改点、PLL 频率请求何时触发、启动与应用不同的时钟状态，以及串口/定时器频率是否同步更新。

用于真正识别 MCU 的未来数据仍是经确认的只读 `CPUID / DEBUG_IDCODE / Flash 容量`（不同家族地址依官方手册调整），必要时结合显微镜下丝印/PCB 连线。**此轮没有 SWD 连接或刷机操作，也没有读取唯一 UID。** 因此 Rust `no_std` 核心仍保持芯片无关；不可未经确认就使用 AIR32F103RPT6 链接脚本或生成可刷机镜像。

## 五、可复现的离线验证

```sh
python -m pip install "capstone==5.0.6"
python -m unittest discover -s tests -v
python tools/v2_air32_sdk_fingerprint.py firmware/BF_5RH_501_v2_0_9.dat --v1 firmware/BF_5RH_501_v1_1_04.dat --json
python tools/v2_mcu_candidate_matrix.py firmware/BF_5RH_501_v2_0_9.dat
```

分析器通过现有 `v2_bootrom_dispatch.py` 的真实 Thumb 指令校验，再断言十项文字池常量、复原 SRAM 分频表、上层实参及 48 MHz 启动时钟假设。回归测试覆盖原厂镜像和篡改密钥、SRAM 窗口、PLL 参数的拒绝路径。所有结论均以固件和标注的 SDK 版本为依据；不联机连接或操作任何实机。
