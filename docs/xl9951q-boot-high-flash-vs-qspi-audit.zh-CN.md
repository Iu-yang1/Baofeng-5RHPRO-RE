# UV-5RH Pro / XL9951Q：原厂高 Flash 地址与 QSPI 解锁的启动顺序审计

更新：2026-11-16。本文以原厂 V1.1.04、V2.0.09 固件和已验证的 Thumb 启动指令为依据，研究 `0x08061A54` 为什么可以被读取，以及板载 GT25Q16A 2 MiB SPI NOR 是否有理由被认为是 XIP 程序存储器。**仅运行离线 Python 程序；没有 SWD、写频、刷机、固件上传、读出实机 Flash 或接入实体电台。**

## 一、可直接复核的三个事实

1. 归档原厂 V2 `BF_5RH_501_v2_0_9.dat` 解码为 **401408 B（392 KiB）**，假定链接基址 `0x08001000`；原厂 ARM scatterload 区域表给出的压缩数据源为 **`0x08061A54`**。因此它的解码包内偏移为 `0x60A54`（395860 B），**不是套用另一种芯片的 Flash 容量得到的估计**。这处地址在 401408 B 的解码升级包实际覆盖范围内。
2. `v2_scatterload_decode.inspect_tables` 从该处源数据执行指令定义的解压算法，恢复 **7084 B** 的 SRAM 初始化数据。完整解压结果的 SHA-256 为 `78b4cd40871079ecc1ceacf33f1379a8c76ea84a2b3b7155b98c4753d5ae7627`；该结论此前已经独立通过原厂固件测试。现在新增压缩源哈希、消耗字节数、来源覆盖范围和路径顺序的统一报告。
3. 已验证 V2 启动顺序是 **Reset (`0x0800123C`) → ARM scatterload (`0x08001220`) → 应用 main (`0x080340E0`) → PLL 请求 (`0x080340EA`) → `0x080173DE` → `0x08032386 BL 0x08001260`**。`0x08001260` 是 AIR32 风格 ROM/PLL helper，内含 `0x0800129E` 向 `0x4002228C` 写 `0xA5A5A5A5`，在 helper 末段 `0x0800133A` 向同一地址写 `0x5A5A5A5A`。V1 主入口 `0x08027BE8` 的对应调用点为 `0x08026252 BL 0x08001260`。两版复用同一 216 B ROM helper。

这一静态调用图说明：**应用主入口内的 AIR32/QSPI 解锁写入晚于 scatterload**。如果高 Flash 数据的可读性需要由某个映射器事先建立，那映射器就不能单纯是该应用主入口中、在 scatterload **之后**才调用的解锁写入。

这并不是证明芯片一定有原生 512 KiB Flash：启动器、未知掩膜 ROM 或隐藏映射机制可以在 Reset 之前实施初始化；这些部分不在目前的原厂应用镜像取证范围内，不能排除。

## 二、四种存储解释逐一判断

| 假设 | 当前证据 | 可以得出的结论 |
| --- | --- | --- |
| 正常线性映射的片内程序 Flash | scatterload 源地址连续位于 `0x08061A54`，对应数据在原厂固件包内部，按实际解压算法能恢复 SRAM 数据 | **与现象相容**，但物理片内容量、擦除单元和真实写入路径尚未知 |
| 以板载 GT25Q16A 为源、映射到 `0x0806xxxx` 的 XIP/别名 | 主板的 2 MiB SPI NOR 器件曾根据丝印辨识；没有已确认的映射窗口、片选/总线控制器配置、ROM 代码或实际总线操作记录 | **没有被证明**；不能由“板上有 NOR”直接推论高程序地址由它提供 |
| 在原厂启动器或掩膜 ROM 中预先建立映射 | 用户仓库升级包不包含这些隐藏内部实现 | **逻辑上可能，但未验证**，不应写成已经存在的硬件行为 |
| 把 AIR32 SDK 的 `0x4002228C` QSPI 解锁解释为“为前述 scatterload 建立 GT25Q16A 的外置存储映射” | 应用中这一帮助函数在 scatterload **完成后**才经主入口调用；且 SDK 所称 QSPI 解锁并非板载 NOR XIP 的数据手册证据 | 这一具体时间顺序**不成立**，但不能排除其他未知前置映射程序 |

注意 `0x08061A54` 本身**不是 CPU 实际运行指令的 PC**，而是原厂启动程序的压缩数据读取来源。因此不能把它与“从这一地址执行机器码”或“必须有外部 NOR 取指”混为一谈。

### 额外对照：合宙 AIR32 官方启动汇编中的 QSPI 时序

从合宙开源的 [AIR32F103 GCC startup_air32f10x.s（固定提交）](https://github.com/openLuat/luatos-soc-air32f103/blob/c10eaeb13dd133f35bc9d8ed1137072897339db2/Libraries/STARTUP/gcc/startup_air32f10x.s) 可以看到：启动汇编**先**将 `.data` 从 Flash 复制到 SRAM、对 `.bss` 清零（源码第 38–67 行），**再**写三级解锁、`0x200183FF` 和 `0x4002228C=0xA5A5A5A5`（第 68–83 行），随后重新锁定（第 84–97 行），才调用 `SystemInit`（第 101–102 行）。

这对“QSPI 解锁必然是在 SRAM 初始化之前启用外置 NOR”的推测构成**另一项不利证据**：公开 SDK 的启动汇编也是把这一解锁阶段安排在 SRAM 初始化**之后**，没有显示这段例程负责启动前程序映射。

**边界必须分清：** 合宙的上述文件是 GCC startup 示例，UV-5RH Pro 原厂镜像使用的则是有独立区域表的 ARM scatterload（Keil/ARM 风格），不能把合宙 GCC 的所有启动指令及设备时序强行替换成电台的真实启动行为。我们用原厂固件验证的是 ROM helper 的间接调用和顺序；合宙 startup 只用来核实该魔数操作在 SDK 中的设计语境。

## 三、关于 XL9951Q 器件登记与厂家

[JLCPCB XL9951Q / C9900238147](https://jlcpcb.com/partdetail/JLCPCBAssembly-XL9951Q/C9900238147) 页面给出 `MFR.Part # = XL9951Q`、`Package = QFN-64_8x8`、`Manufacturer = JLCPCB Assembly`、`Category = Others / SMT`，但没有芯片内核、Flash/SRAM、芯片原始制造商、内存映射或功能引脚定义。用户已实际清点 MCU 为 QFN-64，封装与条目匹配。**此资料能帮助确认零件目录标签，不能说明 XL9951Q 物理上采用哪一家的 die。**

本轮另以精确型号、嘉立创订货号等查阅公开网络，没有获得新的可信 XL9951Q 原厂芯片数据手册。因此暂不把 `XL` 释义为任何已命名的半导体公司，不推测实际 CPUID 和内部 Flash 总容量。

与此独立，原厂六版固件的 216 B 同一系统 ROM helper 与 [合宙 AIR32 SDK 的 `AIR_RCC_PLLConfig`](https://github.com/openLuat/luatos-soc-air32f103/blob/c10eaeb13dd133f35bc9d8ed1137072897339db2/Libraries/AIR32F10xLib/src/air32f10x_rcc_ex.c) 在控制寄存器、三级解锁和间接 ROM 回调形式上吻合。**这是 SDK 谱系证据，不是 XL9951Q 的商业芯片类型鉴定。**

## 四、可复现步骤及测试口径

```sh
python -m pip install "capstone==5.0.6"
python tools/xl9951q_pre_scatterload_mapping_audit.py firmware/BF_5RH_501_v2_0_9.dat --v1 firmware/BF_5RH_501_v1_1_04.dat
python tools/xl9951q_pre_scatterload_mapping_audit.py firmware/BF_5RH_501_v2_0_9.dat --v1 firmware/BF_5RH_501_v1_1_04.dat --json
python -m unittest discover -s tests -v
```

脚本采用已验证的 Reset→main 调用图、原厂 ROM 指令校验、ROM helper 直接 BL 扫描、压缩源范围审计和解压 SHA-256 交叉核对；并列明了全部仍待确认的条件。结果经 CI 保存为 `xl9951q-pre-scatterload-flash-evidence.json`。为了避免泄露不必要的业务数据，只输出地址、长度和 SHA-256，不输出整包或原始设备身份 UID。

**下一步继续纯软件研究时，应优先分析 Reset 所调用的 `0x080323DC` 及其所有已确认前置调用，核对是否存在能在 scatterload 之前配置 Flash/QSPI 映射的代码。** 需要为“没有该映射”提供覆盖足够完整的代码审计范围，而不能依赖这次的时间顺序得出全镜像绝对否定。软件证据不能唯一决定半导体制造商，最终物理型号仍标为 **UNCONFIRMED**。
