# UV-5RH Pro V2.0.09 V5：配置写入与 NV 恢复、RF/音频及 HAL 取证

取证日期：2026-11-17。基线：已经合并 PR #31–#34。本轮仅基于仓库归档原厂 V2 固件静态 Thumb 指令、主机模拟及 CI；没有对真实电台执行 MCU 调试读写、NOR 擦写或射频发射。原厂完整可刷写固件、外部 PA/PTT 网络和 XL9951Q QFN64 PAD 分配**仍未恢复**。

## 1. 配置 UI：67 个读取 ID 与 61 个写入 ID 不是同一分发表

V2 配置读取器 `0x0800E454` 已能解释 ID `0x00..0x42`（67 项）。本轮进一步追踪到完全不同的**原厂配置写入器**：

```text
0x080164A0   push.w  {...,lr}
0x080164A4   ldr     r4,[pc,...]   ; 0x20004580 工作配置 SRAM
0x080164A6   mov     ip,r0         ; 第一个调用参数 config_id
0x080164AA   ldrb.w  r0,[sp,#4]    ; 第二个调用参数的低字节
0x080164C8   mov.w   r5,#0x7980    ; 默认逻辑 NV 基址
0x080164CC   cmp.w   ip,#0x3D     ; 61 个配置写入 ID
0x080164D0   bhs     0x080165B6   ; 超界走原厂 no-op
0x080164D2   tbb     [pc,ip]
0x080164D6   原厂 61 字节跳转表（是数据，不是 Thumb 指令）
0x08016514   第一个可执行 case 起点
...
0x0801677C   ldr     r0,[sp,#8]    ; 第三个参数：是否保存
0x0801677E   cmp     r0,#1
0x08016780   bne     0x0801678C
0x08016782   adds    r0,r5,r1     ; 逻辑 NV 地址
0x08016784   add     r2,sp,#4     ; 源 1 字节
0x08016786   movs    r1,#1        ; 写入长度 1
0x08016788   bl      0x080190E0  ; 原厂外部 NV 事务更新器
```

因此写入器**不是一次将配置结构整体写到 SPI NOR**，而是在调用方选择持久化时写一个指定逻辑地址的字节。部分配置是字节、半字节或位域，多个菜单 ID 会修改同一个 NV 字节。四个 ID `0x20,0x28,0x29,0x33`（十进制 32、40、41、51）走原厂 no-op，不改 RAM/不写 NV，不是独立固件新设功能门限。

**额外副作用**：写入 ID `0x23` 时原厂先调用 `0x0800DA10`（软件 PB6 控制），ID `0x27` 先调用 `0x0800CAEC`（尚未确定外设用途），然后修改配置位域与按需提交。独立核心将两者作为明确的 `pre_call` 标记暴露，不在未知 PCB 上凭猜测执行。

对应代码：[独立核心 `oem_config_setter.rs`](../firmware-pro/core/src/oem_config_setter.rs)、[原厂 61-case + NV 静态审计](../tools/pro_v2_config_nv_setter_audit.py)。

## 2. 原厂上电恢复：多地址读取、字段重排、软件边界修正

```text
0x0801049E..0x080104B6  逻辑地址 0x7980，读取 0x38=56 字节
0x080104BA..0x080105A2  从 56 字节中非连续抽取字段，填充工作 SRAM
0x080105A8..0x080105DC  逻辑地址 0x71，读取 4 字节，写入 +0x23..+0x26
0x080106B2..0x080106BC  逻辑地址 0x7A80，读取 1 字节，写入 +0x21
```

关键结论是：配置工作区 `0x20004580` 至少到偏移 `+0x26`，即 **39 字节**。先前 38 字节只是 67-case getter 最大访问到偏移 `+0x25` 的最小覆盖范围，不是整段 RAM 的长度。本轮已修正 `OEM_CONFIG_STORAGE_LEN=0x27`，单独固定 34 个已证实的主记录位置对应和三个来源地址。

原厂恢复还会按分支把若干非法值重置到 RAM（例如工作字节 `+8` 超过 10 归零、`+15` 超过 2 归零、`+18` 为 0 或超过 80 设为 1、`+36` 超过 4 归零、`+37` 为 `0xFF` 改为 `0xA0`）。这**不是**已证明写回 NOR；不应与 getter 运行时另外七处修正混淆。

对应代码：[原厂恢复映射 `oem_config_restore.rs`](../firmware-pro/core/src/oem_config_restore.rs)。

### 已发现两类原厂保存/恢复字段不一致

| 配置项 | 原厂写入器 NV | 上电恢复实际 NV | 备注 |
| --- | --- | --- | --- |
| ID `0x0D`（工作 +0x0C） | `0x7992` | `0x7993` | 恢复器的 `+0x0C`、`+0x0D` 两字段与 setter 的源索引交叉 |
| ID `0x0E`（工作 +0x0D） | `0x7993` | `0x7992` | 与上一行互换 |
| ID `0x17`（工作 +0x20） | `0x7980` | `0x799B` | 原厂 setter case 没有为该分支赋新 NV 偏移，落回入口初始 0 |

这些是**原厂镜像静态行为不一致**，不等同于已证明用户实机遇到配置丢失。是否还有上层绕过/兼容修正，需在真实输入场景中进一步追踪。项目保留原厂路径作为可复核基线，未来独立固件的修正策略必须区分原厂兼容和存储一致性；本轮没有将推测的修复自动写到真实 NOR。

另：原厂 getter 对配置 ID `0x39` 和 `0x3B` 返回常量 1，而 setter 对应 ID 仍会修改 `RAM+0x23` 的特定位；这一异步状态也被保留并记入测试，不把“getter 常量”误认为它不可能有 setter。

## 3. RF PA/PTT 软件候选进一步收窄

V2 `0x0800DA10`：

- 参数为非零时，顺序调用 `0x080014A4` 两次、`0x080102A0`，以及原厂 delay 参数 `0x32`；然后设置软件 GPIOB bit6、将 `0x200017FC` 影子状态设为 1，并清零相邻 16-bit 计数。
- 参数为零时，复位软件 GPIOB bit6，影子状态设为 0，未观察到相同的计数清零分支。
- **本轮确定 config setter ID `0x23` 先调用这段 PB6 例程，且其调用参数就是待写的设置值。** 因此 PB6 确实可以由某一设置控制，直接认定其为外部 PA_EN 或实体 PTT 是缺乏证据的。

`board_v2.rs` 增加 `OemPb6Shadow`，只重建已确认的 GPIO/影子变量**尾部**，事前三个未知 helper 不能被默默省略后宣称“整机已正常工作”。对真实 QFN64 PAD 的分配仍需 PCB 实测。

外部 HTL7G06S011P 偏置、T/R 开关、驻波检波、PTT 实体触点未完成连通性；本轮**没有默认禁止任何 RF 频率或 TX 模式**。原厂频率窗口是校准选择，不是发射门限。

## 4. 音频模拟链路与 RFIC 软件音频控制的分离

V2 `0x0800A354..0x0800A392` 是原厂 AF 选项函数的两个分支：

- 输入**非零**：读 FD6818 `REG_43`，清位 `0x7E00` 后写回 `REG_43`，再写 `REG_13=0x03FF`。
- 输入**零**：将 RFIC 缓存 `REG_47` 写成 `0x6042`，调用尚未完整解明的 `0x0800B51C(0)`，然后调用 `0x0800A310(0)`。不能忽略这一额外 helper 来假装已经完整恢复“音频复位”。

本轮新增 `audio::OriginalAudioCache::apply_oem_af_nonzero_subpath`，在模拟 I²C 上测试读-改-写顺序与内容。这里的 `REG_43/REG_13` 控制是**FD6818 内部软件访问**，不自动证明外部 TDA2822、LM2904B、MIC、耳机或扬声器模拟网络的引脚和静音控制。仍需 PCB 连通性、示波器测量。

## 5. XL9951Q 身份与整机 HAL 的当前边界

MCU 软件上仍可确认 STM32F1/AIR32 风格 MMIO、中断/启动相关地址、内部 Flash 日志、SPI3 及一个超出典型低容量 MCU 的 RAM/应用代码窗口。**本轮没有获得新的物理芯片 PID、CPUID、Flash Size、ROM ID 或 QFN64 PAD 电气证据，因此 XL9951Q 真实制造商和确切型号依旧未知。**

当前可实质交付的是可编译、可 Mock 的几层**芯片无关软件契约**：`I2cRegisterBus`、`BoardGpio`、`LogicalNvReader`、`LogicalNvJournal`、`OemWorkingConfig`、FD6818 和 LCD/GNSS 驱动。外部模拟 PA/PTT 及真实 MCU 复用引脚尚不能绑定，不能称为完成的板级 HAL。

### 需要的下一批实机证据（不改变固件）

| 类型 | 只读/测量目标 | 为什么必要 |
| --- | --- | --- |
| MCU | 如果能独立确认 SWD 焊盘和 IO 电压，读取 CPUID、调试 PID、ROM UID/容量字段及实际复位向量 | 将兼容软件谱系缩小到真正型号；未确认寄存器地址时不得强行探测 |
| 封装/网络 | XL9951Q QFN64 顶视照片、外部 Flash／FD6818／PA 偏置路径连通性 | 建立 MCU PAD→GPIO 软件位号→实际器件网络 |
| PTT/RF | 键压/释放时的 A9/A10 和候选 PB1/PB6/PB8 电平、PA/T-R 控制时序；射频输出接合适假负载 | 区分键盘、静音、射频开关与实际 PA 控制 |
| 音频 | MIC、耳机/扬声器、TDA2822、LM2904B 各输入输出的交流波形与使能逻辑 | 证明实际 AF 模拟拓扑，校验静音分支 |
| UI/NV | 修改少量指定菜单值后导出 **前后两份只读配置备份**，记录按键及 UI 展示 | 验证原厂 setter/restore 异常是否会影响实机，并确定菜单标签 |

这类实测应在无需改写 MCU/NOR 的前提下进行，不将未经确认的 ROM 地址作为可直接刷写的 MCU 存储布局。

## 6. CI 复现

```bash
python -m pip install "capstone==5.0.6"
python tools/pro_v2_config_nv_setter_audit.py --json
python tools/pro_v2_rf_audio_gpio_v5_audit.py --json
python -m unittest discover -s tests -v
cargo test --manifest-path firmware-pro/core/Cargo.toml --offline
cargo check --manifest-path firmware-pro/core/Cargo.toml --lib --offline
```

本轮源码审计分别锁定 61 项 setter 原厂 TBB/handler、56 字节恢复指令、可选单字节 journal 写入、PB6 影子分支与 FD6818 AF 寄存器操作，并进行反向指令变异测试。GitHub CI 不生成可刷写 BIN，不上传原厂镜像，只上传证据 JSON。

之前的 [V4 67 项读取器和 UI 事件报告](pro-v2-config-getter-menu-event-rfic-tx-v4.zh-CN.md) 仍适用；它的“38 字节配置工作结构”仅是当时 getter 可见的最小跨度，现已由 V5 启动恢复证据修正为 39 字节。
