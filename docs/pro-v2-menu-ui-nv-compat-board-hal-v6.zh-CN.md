# UV-5RH Pro V2 第六轮：菜单轮询状态、可编辑显示、NV 兼容矩阵与板级 HAL

基线：已合并 PR #35，原厂镜像 BF_5RH_501_v2_0_9.dat。所有可重复测试使用归档原厂代码、Rust `no_std` Core、模拟 NV/SPI/GPIO 以及 GitHub Actions；没有对用户真实电台执行刷写、擦除或发射。

## 一、菜单：区分原厂已经恢复的状态逻辑与独立 UI

原厂 UI 轮询函数 `0x080167B8–0x0801681C`：

| 原厂源证据 | 可精确确认的意义 |
|---|---|
| `0x080167BA` 加载 `0x20000104` | UI 软件状态根地址 |
| `0x080167BC/BE/C0` 取 `+0x10` bit7 并跳转 | 标志已置位时转向退出/状态4支路 |
| `0x080167C2` → `0x0800E0B8` | 菜单活动位：`0x2000182A` bit0 |
| `0x080167C8` → `0x0800E064` | 从现有 UI 结构取得当前选中配置 ID |
| `0x080167CE` → `0x0800D010` | 与先前选中 ID 比较 |
| `0x080167D8/DE/E6/EE/F4` | 原厂菜单更新、getter、值附属查表及外部绘制刷新 helper |
| `0x080167FE` `MOVW R1,#0xFFFF` | getter 为零时的原厂特殊备用参数 |
| `0x08016804–0E` | 软件状态 byte0 若为0改为1，并将 `+0x10` bit7 置位 |
| `0x08016812–1A` | 清除 `+0x10` bit7，并将状态 byte0 设为4 |

`oem_menu_ui.rs` 中 `OemMenuPollState::tick` 将上述**已证实**的条件恢复为可测试的软件状态转换；对 `0x0800D080`、`0x0800CB28`、`0x08014230` 等尚未完全分解的 OEM 绘制/事务 helper 只生成事件，不声称已经实现其完整硬件副作用。

原厂文字绘制 `0x08010DE4` 与矩形帧缓冲写入 `0x08010DB4` 指向 `0x20004B76`；已有 LCD Core 支持 160×128 RGB565 和 `0x2A/0x2B/0x2C` 刷新。现在 `menu_lcd.rs` 可以在这个真实帧缓冲上生成 **CFG ID、配置值、编辑/改动状态、源代码明确的不可写 ID**，并通过 SPI2 `PanelBus` 刷屏。**CFG、VAL、EDIT 等字符串和字形是独立固件的诊断 UI，不是原厂可见菜单的字库/排版复刻。**

`IndependentMenu` 将菜单编辑拆为浏览、开始编辑、增减预览、取消和保存；不把 22 个扫描码擅自命名为上下键/OK/返回键。界面本身不限制无线电频率或发射模式。原厂 setter 原本不支持的 ID 仍可浏览，其写入器返回原厂 no-op，不伪报已保存。源码中的两个附带硬件 helper（配置 ID 0x23 和 0x27）必须经 `OemSetterHelper` 注入，不直接视为 PA/PTT。

**为什么需要两种菜单模型？** 原厂轮询的一段状态机已经有机器码依据；对导航与显示标签仍缺完整原厂事件表及实体键位记录。在这部分证据未恢复时，可以先交付实际能运行的独立固件 UI，但不能用它倒推原厂状态机已全部复原。

## 二、57 项可写配置 ID：原厂保存/恢复兼容性矩阵

原厂 getter 为 67 case，setter 为 61 case（其中 ID 32、40、41、51 返回 no-op），因此单字节写入分析覆盖 **57 个可写 ID**。

可复现测试 `core/tests/menu_nv_compat_matrix.rs`：

```text
OriginalNvConfigSnapshot (56 B @0x7980, 4 B @0x71, 1 B @0x7A80)
       ↓ original startup mapping
OemWorkingConfig (39 B)
       ↓ original 61-case setter (write one byte/packed bitfield)
OemNvWriteLayout::{OriginalSetter, LoaderConsistent}
       ↓ LogicalNvJournal mock (exact one-byte write)
Simulated reboot → original startup mapping → compare working bytes
```

整套矩阵用同一套原厂工作 RAM 字段映射、同一输入 `value=1`，逐个模拟 setter，选择原厂写入地址与由原厂启动恢复计算出的地址。结果应为：

| 配置 ID | 原厂 setter 逻辑 NV | 原厂 loader 逻辑 NV | 预期原厂重启结果 |
| --- | --- | --- | --- |
| `0x0D`（13） | `0x7992` | `0x7993` | 源写入落入相邻字段 `+0x0D` |
| `0x0E`（14） | `0x7993` | `0x7992` | 源写入落入相邻字段 `+0x0C` |
| `0x17`（23） | `0x7980` | `0x799B` | 更改的是配置 ID0，目标字段恢复旧值 |

除这三项之外，已恢复的其余 54 个可写 ID 在**该组固定测试输入**下恢复到同一工作字节。测试还覆盖 ID23 对 ID0 的旁路覆盖、RAM-only 编辑不持久化、写入失败时不回显成功、逐个菜单 ID 显示与独立 UI 保存。

`oem_nv_compat.rs` 新增两种透明选择：

- `OriginalSetter`：完全保留原厂逻辑地址（包括已证实的不一致），适合原厂行为回归与兼容分析。
- `LoaderConsistent`：在**独立固件**中明确选择原厂 loader 所读取的逻辑地址，以便同一个工作字段在模拟重启后得到恢复。不会自动修改其他原厂地址，也不修改原厂镜像。

注意：矩阵证明的是本仓库归档原厂固件的**静态路径与模拟数据一致性**；不能据此断言实际设备没有更高层的配置迁移、隐藏上层恢复，或存在实机可见缺陷。在未核查实机之前，不对真实 NOR 做自动修复/批量迁移。

## 三、推进真正可接硬件的寄存器级 HAL

此前 Core 只暴露 `BoardGpio`、`PanelBus`、`SpiByteTransfer`、`LogicalNvReader`、`LogicalNvJournal` 等抽象。本轮的 `oem_board_hal.rs` 添加**具体的软件寄存器适配实现**：

| 部件 | 完成的接口和已知地址 | 仍需确认 |
|---|---|---|
| GPIO | `OemCompatibleGpio<RegisterIo>`；GPIOA/B/C/D/E 映射；IDR `+0x08`，BSRR `+0x10`，BRR `+0x14` | 实际 XL9951Q 寄存器兼容性与 QFN PAD |
| SPI3 | 从 `0x40003C00` 以 **16 位 MMIO** 读取旧 CR1/CR2，按原厂 `0x3040/0x0317/0x0800/CRC7` 生成配置并通过半字写入置 SPE（与原厂 `STRH` 宽度一致） | SPI3 时钟源、GPIOB3/4/5 复用、电气时序和 NOR 器件 |
| LCD SPI2 | `OemSpi2PanelBus` 将命令/数据真正转换为 GPIO PB12 软件 CS、PA12 D/C 和 SPI2 字节传输；失败时释放 CS | 物理 LCD 型号、引脚连通与线速 |
| LCD 复位 | `OemPanelResetAdapter` 根据原厂 PA8 电平序列和原始延时参数 `0x14/0xC8/0x14` 运行 | 原始延时单位与实际面板极性 |
| 键盘 | `OemMatrixPort` 接入 GPIOC 两阶段采样与 22 个原厂扫描码查询，保留扫描阶段错误 | 两次扫描之间的 GPIO 模式切换、实体键帽 |
| MCU 身份 | 标准 Cortex-M `CPUID` 只读接口 `0xE000ED00` | 具体芯片制造商、Debug ID、实际 SRAM/Flash、真实 SWD 焊盘 |

这套 HAL **不是简单重命名接口**：其 SPI2 可传输 RGB565 像素、GPIO 访问生成确定的 MMIO 地址和位掩码、SPI3 初始化生成确定的寄存器写入序列；Mock 测试可精确验证操作顺序和错误停止条件。执行时还需要目标 MCU 实现 `RegisterIo` 及正确的时钟与复用设置。这里没有加入自行推断的 TX 禁止范围，也未绑定未经证明的 PA_EN、模拟音频 MUTE 等物理网络。

真正完成电气板级 HAL 所需的下一步资料是 **XL9951Q SWD 只读 CPUID/调试身份读数和 64-pin 顶视照片/测量连通图**。未得到该证据之前，不能宣称此版本是可直接在目标 MCU 上启动的生产固件。

## 四、质量检查与可复现命令

```sh
python -m pip install capstone==5.0.6
python tools/pro_v2_menu_ui_state_audit.py --json
python tools/pro_v2_board_hal_v6_audit.py --json
python -m unittest discover -s tests -v
cargo test --manifest-path firmware-pro/core/Cargo.toml --offline
cargo check --manifest-path firmware-pro/core/Cargo.toml --lib --offline
```

GitHub Actions 的 Firmware offline analysis 提取原厂 Thumb 固定地址、原厂 SPI/GPIO/LCD/keypad 候选指令和执行分支，保证修改原厂指令后测试报错；Rust 对 UI、NV 字节、错误路径和 SPI2 端到端帧缓冲测试。输出仅证据元数据 JSON，**不发布或上传解密原厂固件**。

前置材料：[V5 配置存储与 RF/音频报告](pro-v2-config-nv-setter-restore-rf-audio-hal-v5.zh-CN.md)、[V4 配置读取与 UI 特殊键](pro-v2-config-getter-menu-event-rfic-tx-v4.zh-CN.md)。
