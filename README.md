# PE Reverse Analyzer

面向授权逆向分析与软件安全研究的本地优先平台。它把静态分析、动态证据、受审计的运行时能力、PE/APK 工作流、协议推断、源码/GUI 工程骨架、Semantic IR、证据清单和 Dashboard 组织为可追溯的分析会话。

[中文](README.md) · [English](README.en.md) · [项目知识图谱](docs/项目知识图谱.md) · [许可证](LICENSE)

> 中文版是 GitHub 默认展示文档。本文只描述当前 CLI 与 provider 已实现的行为；命令行接受但尚未接通真实 provider 的选项会明确标出。

## 能力总览

| 入口 | 当前实现 |
|---|---|
| `analyze` | 文件元数据、哈希、字符串、PE/APK/IPA 静态证据、熵/壳启发式、YARA、可选 Ghidra/Frida/Procmon、GUI 证据、Semantic IR 与报告。 |
| `capability` | 统一的 `supports -> plan -> validate -> execute -> rollback -> collect_artifacts` provider 生命周期、审计记录和 mock provider。 |
| `memory` | Windows 进程内存扫描、读取、前置条件绑定的写入、保护修改、分配、释放、受控 DLL 注入，以及 Frida hook trace 接口。 |
| `patch` | PE 补丁计划、失败关闭验证、写入新副本和回滚到新副本；当前可靠的端到端 CLI 路径是 `inline_patch`。 |
| `android` | APK 静态分析、受边界保护的解包、本地 ZIP 验证/复制，以及可选 apktool + apksigner 重建。 |
| `protocol` | 导入 PCAP/PCAPNG/JSON/JSONL/raw 被动证据，重组流、推断帧和字段并生成摘要。不是实时抓包器。 |
| `source reconstruct` | 根据样本与现有证据生成带 provenance/confidence 的可编辑工程骨架；不声称恢复完整原始源码。 |
| `dashboard` | 生成静态 Dashboard，或用内置 HTTP 服务查看会话、能力审计、平台分析、趋势和工件。 |
| `environment validate` | 发现可选依赖，并可执行受限的导入、版本或能力 probe，输出 `environment-validation.json`。 |

平台不会自动上传样本、报告、密钥或 trace。具体深度取决于样本类型、操作系统、目标权限以及本地可选工具。

## 快速开始

### 环境

- Python 3.10+
- `requirements.txt` 中的核心依赖：`pefile`、`capstone`、`requests`
- Windows 建议使用 PowerShell；Linux/macOS 可运行不依赖 Win32 provider 的本地分析流程

```powershell
python -m pip install -r requirements.txt
python -m reverse_analyzer --help
python -m reverse_analyzer list-tools
python -m reverse_analyzer capability list
```

发现可选依赖，或显式执行受限 probe：

```powershell
# 只发现依赖，不执行 probe
python -m reverse_analyzer environment validate --out .\out

# 对已发现依赖执行受限的导入、版本或能力 probe
python -m reverse_analyzer environment validate --execute-probes --out .\out
```

`environment-validation.json` 将依赖发现与 probe 验证分开记录：

- `discovered`：依赖已发现，但尚无成功执行的 probe。
- `verified`：受限 probe 已执行成功；它不等于真实样本、设备或 live target 的完整端到端验证。
- `dependency-gated`：文档显示形式，对应 JSON 机器值 `dependency_gated`。生产路径存在，但 probe、外部 runtime/toolchain 或 live-target E2E 证据仍未闭合。

初始化本地知识库并运行基础分析：

```powershell
python -m reverse_analyzer init-knowledge
python -m reverse_analyzer analyze .\sample.exe --out .\out --max-iterations 3
```

典型顶层工件包括：

```text
out/
  report.json
  report.md
  trace.jsonl
  analysis_graph.json
  semantic_ir.json
  evidence-manifest.json
  sessions/
```

### 状态语义

| 状态 | 含义 |
|---|---|
| `unavailable` | 当前平台或可选工具不满足执行条件。相应阶段通常在副作用前停止，同时保留结构化审计和报告。 |
| `partial` | 已得到有效结果，但某个深度解析器或可选依赖不可用。 |
| `failed` | 参数、权限、哈希、前置条件或验证真实失败。此状态不会伪装成 graceful `unavailable`。 |

## 主分析流水线

基础静态分析、本地规则和可选 Ghidra：

```powershell
python -m reverse_analyzer analyze .\sample.exe --out .\out
python -m reverse_analyzer analyze .\sample.exe --out .\out --decompile --ghidra-home C:\ghidra
```

可选动态证据与 GUI 分析：

```powershell
python -m reverse_analyzer analyze .\sample.exe --out .\out `
  --dynamic --dynamic-backend frida --dynamic-profile auto

python -m reverse_analyzer analyze .\sample.exe --out .\out `
  --gui --gui-runtime --gui-visual --reconstruct-gui
```

- 动态 profile 包括 `quick`、`behavior`、`unpacking`、`network`、`persistence` 和 `auto`；Frida/Procmon 缺失时对应阶段返回可解释状态。
- GUI 路径覆盖 WPF、WinForms、Win32、MFC、Qt、Electron、PyInstaller + PyQt/PySide、Delphi/VCL、Android XML/Compose、Flutter、React Native、UIKit/SwiftUI、Unity、WebView Hybrid 和保守回退。
- `--memory-analysis` 是分析流水线中的有界、只读快照/差分/RVA 映射功能；它与下文可产生副作用的 `memory` capability CLI 是两条不同路径。
- `--reconstruct` 和 `--reconstruct-gui` 只验证生成工程的文本、结构与元数据，不构建或启动工程。

离线验证证据清单：

```powershell
python -m reverse_analyzer evidence verify --manifest .\out\evidence-manifest.json
```

清单使用相对工件路径并记录大小、SHA-256 与 provenance，可检测缺失、篡改和越界路径。

## Capability Provider 框架

所有 capability provider 共享以下生命周期：

```text
supports -> plan -> validate -> execute -> rollback -> collect_artifacts
```

当前注册表：

| Capability | 真实 provider | Mock |
|---|---|---|
| `memory_runtime` | `windows_memory_runtime` | `mock` |
| `injector` | `windows_controlled_injector` | `mock` |
| `hook_runtime` | `frida_hook_runtime` | `mock` |
| `patch_executor` | `local_verified_patch` | `mock` |
| `android_rebuild` | `local_android_rebuild` | `mock` |

```powershell
# 查看注册表
python -m reverse_analyzer capability list

# 通用执行入口
python -m reverse_analyzer capability run `
  --capability memory_runtime `
  --action read `
  --pid 4242 `
  --out .\capability-out `
  --provider mock `
  --param address=0x7FF600001000 `
  --param size=64

# 从报告读取 capability audit
python -m reverse_analyzer capability show-audit `
  --report .\capability-out\report.json
```

- 默认选择优先级更高的真实 provider；指定 `--provider mock` 才会生成 `mocked` 审计和占位工件，不执行真实副作用。
- `--param key=value` 可重复使用；value 会先尝试按 JSON 解码，否则保留为字符串。
- `--rollback` 表示在执行成功后继续执行生成的回滚计划，用于验证可逆性。
- 每次运行创建 session、`trace.jsonl`、`report.json`、`report.md`、evidence manifest 和 capability audit，例如 `capabilities/memory_runtime_scan_audit.json`。
- provider interface 只统一生命周期与审计，不保证每个 provider 在每个平台都可执行。缺依赖、平台不符或 provider 明确未实现的动作会返回结构化 `unavailable`。

## 运行时内存、注入与 Hook

### Memory CLI

```text
memory {scan,read,write,protect,alloc,free,inject,hook-trace}
```

真实内存 provider 是 `windows_memory_runtime`，通过 `ctypes` 调用 Win32 API。它只在 Windows 上执行；其他平台返回 `unavailable` 且不修改目标。

只读操作：

```powershell
# 当前真实 scan 路径使用十六进制 AOB
python -m reverse_analyzer memory scan `
  --pid 4242 --out .\memory-scan `
  --pattern "4D 5A" --pattern-type aob

python -m reverse_analyzer memory read `
  --pid 4242 --out .\memory-read `
  --address 0x7FF600001000 --size 256
```

可逆写入、保护和分配示例；这里的 `--rollback` 会在操作后立即尝试回滚：

```powershell
python -m reverse_analyzer memory write `
  --pid 4242 --out .\memory-write `
  --address 0x7FF600001000 `
  --data "90 90" --encoding hex --expected "74 05" `
  --rollback

python -m reverse_analyzer memory protect `
  --pid 4242 --out .\memory-protect `
  --address 0x7FF600001000 --size 4096 `
  --protection PAGE_READWRITE --rollback

python -m reverse_analyzer memory alloc `
  --pid 4242 --out .\memory-alloc `
  --size 4096 --protection PAGE_READWRITE --rollback
```

释放要求传入精确 allocation base；provider 会先验证并完整捕获可回滚内容：

```powershell
python -m reverse_analyzer memory free `
  --pid 4242 --out .\memory-free `
  --address 0x000001ABC0000000 --size 4096
```

当前边界：

| 命令 | 当前真实行为与限制 |
|---|---|
| `scan` | 默认最多扫描 256 MiB、返回 256 个结果。CLI 接受 `aob/ascii/utf16/pointer`，但当前真实 provider 尚未转换后三种标签，只把 `--pattern` 解析为十六进制 AOB；provider 实际要求 pattern。 |
| `read` | 默认读取上限 16 MiB，并持久化有界证据。 |
| `write` | 当前 provider 总把 `--data` 和 `--expected` 当十六进制；CLI 暴露的其他 encoding 尚未接通。真实执行要求 `--expected`，且原始字节与 replacement 必须等长。 |
| `protect` | 范围必须完全位于一个 committed region。`--expected-protection` 会被 CLI 转发，但当前 provider 不消费该字段；provider 会自行记录实时保护值和 precondition hash。 |
| `alloc` | provider 接受 Win32 `PAGE_*` 名称或正整数。CLI 默认值 `rw` 当前不被真实 provider 接受，因此应显式传 `PAGE_READWRITE` 等值。 |
| `free` | 仅支持精确 allocation base、单一区域、可读且 committed 的 private allocation；无法完整捕获回滚内容时拒绝执行。 |

底层 `probe`、`regions`、`modules` 动作也已实现，但没有专用 memory 子命令；可通过通用 `capability run --capability memory_runtime --action ...` 调用。

### 受控 DLL 注入

```powershell
python -m reverse_analyzer memory inject `
  --pid 4242 --out .\inject-out `
  --dll C:\lab\trace.dll `
  --method load_library `
  --expected-sha256 <dll-sha256> `
  --rollback
```

- `windows_controlled_injector` 当前只在 Windows 实际执行 `LoadLibraryW` 路径。
- DLL 必须使用绝对路径；`--expected-sha256` 可把计划绑定到指定 payload。
- 回滚会尝试远程 `FreeLibrary`、释放临时内存并确认模块消失；目标中的额外模块引用可能阻止完全卸载。
- `manual_map` 已实现受控 Win32 执行与回滚路径，包括 PE32/PE32+ 映射、重定位、普通/延迟导入、TLS 回调、x64 异常表、节保护、入口点调用和逆序清理。普通回归使用确定性宿主夹具；真实 Windows 目标仍需要单独的门控 E2E 验收。

### Hook trace

真实 hook provider 是 `frida_hook_runtime`，支持 `api_hook`、`inline_hook` 和 `breakpoint_trace`。它依赖可选的 Python `frida` binding/runtime，只接受数据驱动的 hook specification，拒绝任意 JavaScript。缺少 Frida 时仍可生成计划，执行返回 `unavailable`。

当前可执行接口是通用 capability 命令：

```powershell
python -m reverse_analyzer capability run `
  --capability hook_runtime `
  --action api_hook `
  --pid 4242 `
  --out .\hook-out `
  --provider frida_hook_runtime `
  --param 'hook_specification={"type":"api_hook","module":"kernel32.dll","export":"CreateFileW"}' `
  --param duration_ms=10000
```

`memory hook-trace --plan ... --duration ... --backend ...` 便捷命令已经注册，但当前适配层转发的是 `plan_path`/`duration`/`backend`，provider 读取的是 `hook_specification`/`duration_ms`；它目前不会加载 plan 文件，也不会使用该 backend 参数。因此不要把该便捷命令视为已接通的真实 hook 执行路径。

## PE Patch：plan / verify / apply / rollback

当前可靠的 CLI 工作流是等长 `inline_patch`：

```powershell
python -m reverse_analyzer patch plan .\sample.exe `
  --out .\patch-session `
  --strategy inline_patch `
  --offset 0x120 `
  --replacement "90 90" `
  --operation-id replace-branch

python -m reverse_analyzer patch verify .\sample.exe `
  --plan .\patch-session\patch\plan.json `
  --out .\patch-session\patch

python -m reverse_analyzer patch apply .\sample.exe `
  --plan .\patch-session\patch\plan.json `
  --out .\patched.exe `
  --artifact-dir .\patch-session\patch

python -m reverse_analyzer patch rollback .\patched.exe `
  --plan .\patch-session\patch\rollback_plan.json `
  --out .\restored.exe `
  --artifact-dir .\patch-session\patch
```

- `patch plan --out X` 把工件写入 `X/patch/`；典型文件为 `plan.json`、`verify.json`、`risk_report.json` 和 `rollback_plan.json`。
- 输入 PE 始终只读；apply 与 rollback 都要求不同路径并写出新文件。apply 会在写入前重新 verify，rollback plan 绑定 patched SHA-256。
- 验证失败关闭：检查目标哈希、preimage、PE layout、策略契约、指令边界/CFG 和回滚可恢复性，并报告 PE directories、relocations 与 overlay 风险。
- `auto` 当前解析为 `inline_patch`。Parser 还接受 `code_cave_patch`、`section_extend_patch`、`resource_replace`、`iat_thunk_patch`、`entrypoint_redirect`、`overlay_preserve_patch`，但这些高级策略通常需要当前 CLI 未暴露的 intent 字段，不能视为通用端到端 CLI 能力。
- 缺少 `pefile` 时返回 `unavailable`。补丁落在 executable section 时，如果缺少 Capstone，或 PE 机器类型不是 x86 (`0x14c`)/x64 (`0x8664`)，指令验证不可用且整体 verification 为 `failed`。
- Authenticode 处理只检测 certificate table 并报告补丁可能使签名失效；不会验证证书链或重新签名。

同一引擎也通过 `patch_executor -> local_verified_patch` capability provider 暴露 `plan`、`validate`、`apply`、`rollback` 动作。

## Android：analyze / unpack / rebuild / verify

```powershell
# 完整 APK 静态分析流水线
python -m reverse_analyzer android analyze .\app.apk --out .\android-analysis

# 默认使用受边界保护的 Python ZIP 解包
python -m reverse_analyzer android unpack .\app.apk `
  --out .\android-unpack `
  --destination .\decoded

# 默认 zip_copy：验证后逐字节复制到新 APK
python -m reverse_analyzer android rebuild .\app.apk `
  --out .\android-rebuild `
  --apk-out .\rebuilt.apk `
  --strategy zip_copy

# 本地 ZIP/manifest 验证
python -m reverse_analyzer android verify .\rebuilt.apk `
  --out .\android-verify
```

`apktool_rebuild` 需要 apktool、apksigner 和有效签名配置：

```powershell
python -m reverse_analyzer android rebuild .\app.apk `
  --out .\android-rebuild `
  --project-dir .\decoded `
  --apk-out .\rebuilt-signed.apk `
  --strategy apktool_rebuild `
  --apktool C:\Tools\apktool.bat `
  --apksigner C:\Android\build-tools\35.0.0\apksigner.bat `
  --keystore C:\Keys\research.jks `
  --key-alias research
```

签名验证必须显式启用；仅传 `--apksigner` 不会自动运行：

```powershell
python -m reverse_analyzer android verify .\rebuilt-signed.apk `
  --out .\android-verify `
  --apksigner C:\Android\build-tools\35.0.0\apksigner.bat `
  --param verify_signature=true
```

- `android analyze` 是完整 `analyze` 流水线别名；其余命令使用 `local_android_rebuild` provider。
- `zip_copy` 是验证后的逐字节复制，输出哈希应与源 APK 相同；它不是“反编译后重新构建”。
- 缺少 apktool/apksigner 或签名配置时，外部工具阶段返回 `unavailable`。ADB 不是 rebuild 的必需依赖。
- ZIP 边界：最多 10,000 个成员、单成员 128 MiB、总解压量 768 MiB、最大压缩比 1,000。
- provider 会记录 rollback metadata；专用 `unpack` CLI 不暴露 `--rollback`，`rebuild` 暴露该选项。

## Protocol：capture / infer / summarize

```powershell
python -m reverse_analyzer protocol capture .\traffic.pcapng `
  --out .\protocol-out --format auto

python -m reverse_analyzer protocol infer .\messages.jsonl `
  --out .\protocol-infer --format jsonl

python -m reverse_analyzer protocol summarize .\stream.bin `
  --out .\protocol-summary --format raw
```

- 三个子命令当前都会运行完整流水线：`protocol_capture -> protocol_infer -> protocol_summarize -> protocol_analyze`。名称表示入口意图，不表示只执行单一阶段。
- `capture` 导入已有被动证据文件，不打开网卡，也不实时抓包。
- 支持 PCAP、PCAPNG、JSON、JSONL 和 raw；可进行 TCP 重组、UDP 双向 flow、长度前缀/分隔符/魔数/熵推断。
- 可识别 JSON、protobuf 形状、base64、gzip、zlib 和 msgpack。`msgpack` 是可选依赖；缺失时保留启发式识别并以 `partial`/warning 记录。
- 默认边界为输入 8 MiB、4,096 packets、1,024 messages、单 message 256 KiB，可用 `--max-bytes`、`--max-packets`、`--max-messages`、`--max-message-bytes` 调整。
- 输出包括 capture/flow/field 统计、inference、summary、逐消息 JSON、Semantic IR fragment、顶层 Semantic IR、evidence graph、report 和 manifest。
- source 不存在时返回结构化 `unavailable`，仍保留报告与 manifest。

## Source Reconstruction

```powershell
python -m reverse_analyzer source reconstruct .\sample.exe `
  --out .\source-out `
  --strategy auto `
  --decompile `
  --gui
```

该命令是强制启用 `--reconstruct` 的 `analyze` 别名。当前 strategy 只有 `auto`，自动选择：

- `unity-csharp`
- `android-kotlin`
- `android-java`
- `electron`
- `pyinstaller-python`
- `csharp`
- `cpp`
- `c`

输出位于 `<out>/reconstructed_<sample>/`。它是可编辑工程骨架，不是完整源码恢复；恢复函数和类型使用保守 placeholder/TODO，并为推断内容保留 provenance 与 confidence。默认重建路径不会构建或运行生成工程；只有调用方显式提供受限 runtime/behavior validation spec 时才执行相应本地命令，输入样本始终只读。

典型元数据：

```text
analysis/source_reconstruction.json
analysis/project.json
analysis/provenance.json
analysis/confidence.json
analysis/evidence_index.json
analysis/behavior_hints.json
analysis/equivalence_assessment.json
analysis/summary.json
```

`analysis/equivalence_assessment.json` 汇总 differential/static/runtime observed evidence，并把逐条 mismatch 关联到 Semantic IR 与 provenance。`matched` 只表示所提供、达到阈值的观测证据一致；`claim_scope` 固定为 `observed_evidence_only`，且 `complete_behavior_equivalence_proven` 始终为 `false`。它不自动证明完整源码恢复，也不证明完整行为、时序、环境或状态空间等价。

## Dashboard

```powershell
# 只生成静态 Dashboard
python -m reverse_analyzer dashboard --workspace . --out .\dashboard

# 生成后启动内置服务器
python -m reverse_analyzer dashboard --workspace . --out .\dashboard --serve

# 显式使用默认监听地址和端口
python -m reverse_analyzer dashboard --workspace . --out .\dashboard `
  --serve --host 127.0.0.1 --port 8088
```

- 不带 `--serve` 只生成 `index.html` 和 `data.json`。
- 默认 host 是 `127.0.0.1`，默认端口来自配置或 `8088`。`--serve` 会持续运行直到中断。
- `--host` 会原样用于监听；传入非 loopback 地址会改变暴露范围。
- 当前视图聚合 engine/Android/protocol/source analysis、capability audit、KnowledgeBase 推荐、session 对比与趋势、工件导航、Semantic IR、evidence graph、platform core 摘要，以及 workspace 内最新的有效 `environment-validation.json`。
- 环境面板分别展示 dependency discovery 与 probe verification，并保留 `discovered`、`verified` 和 `dependency_gated` 机器状态；源码恢复面板展示 observed-evidence assessment、维度和 mismatch，同时固定标明不声明完整行为证明。

## 依赖与平台限制

| 组件 | 类型 | 缺失时行为 |
|---|---|---|
| `pefile`、`capstone`、`requests` | `requirements.txt` 核心 Python 依赖 | 对应功能失败或按上文规则返回不可用；PE executable patch 验证可能整体失败。 |
| Ghidra | 可选外部工具 | 反编译阶段 `unavailable`，其余本地分析继续。 |
| Frida Python binding/runtime | 可选 | 动态采集/hook 执行 `unavailable`；可保留计划与静态证据。 |
| Procmon | 可选，Windows | Procmon 动态采集阶段 `unavailable`。 |
| `yara-python` | 可选 | YARA 深度减少，其余规则/静态证据继续。 |
| apktool、apksigner、Android build tools | 可选 | `apktool_rebuild` 或显式签名验证 `unavailable`；`zip_copy`/本地验证仍可用。 |
| `msgpack` | 可选 | msgpack 深度解析降级为启发式 `partial`。 |
| ADB | 可选 | 只影响其他 Android/dynamic 路径，不是 APK rebuild 的要求。 |
| Xcode、`xcrun`、签名身份、iOS 真实设备 | 可选，macOS/live target | 环境报告只能发现并探测工具链；离线 IPA 静态分析仍可用，重建、重签名和动态设备验证不在已完成范围。 |
| Win32 memory/injector/native-hook/debugger 与 UIA | Windows、目标权限、兼容架构、交互式桌面 | fake backend 和可选 smoke 不能闭合 live-target gate；缺少平台、权限、`comtypes` 或可见窗口时保持 `dependency-gated`、`partial` 或 `unavailable`。 |
| PresentMon、graphics bridge、ImGui bridge | 可选，Windows | probe 只确认工具或 bridge 响应；不证明进程内 Present hook、ImGui backend 或真实图形生命周期已实现并通过 E2E。 |
| kernel bridge、签名驱动、live IOCTL fixture | 外部 Windows lab stack | `environment-validation.json` 可呈现依赖状态，但当前 kernel runtime 仍是 `missing`；文件发现或 bridge probe 不构成驱动 E2E。 |
| MemProcFS/LeechCore、DMA 硬件与采集权限 | 外部硬件/runtime | 当前 DMA provider 仍是 `missing`；可执行文件 probe 不证明硬件初始化、地址转换或 live acquisition。 |
| `comtypes`、Tesseract、VLM provider | 可选 GUI/OCR/model runtime | UIA 需要 Windows 桌面和真实窗口；VLM/OCR 还需要非测试 provider、真实图像和成功请求，mock/plugin discovery 不闭合验证。 |

`windows_memory_runtime` 和 `windows_controlled_injector` 仅在 Windows 执行。即使平台正确，进程位数、目标生命周期、访问令牌、保护进程和内存权限也可能使操作以 `failed` 结束。PE patch、APK 本地处理、协议导入、报告和 Dashboard 本身不要求 Windows。

上述依赖的 `discovered`/`verified`/`dependency_gated` 仅是环境 readiness evidence，不会自动提升能力状态；逐能力的实现和验收边界以 [Skill Parity Matrix](docs/skill_parity_matrix.md) 为准。

## 分析模型 Provider 边界

Capability provider 与分析模型 provider 是两个独立层：

| 项目 | 当前行为 |
|---|---|
| 默认分析 provider | `RuleBasedProvider`，本地、确定性、无需网络。 |
| OpenAI-compatible 接口 | `OpenAICompatibleProvider` 仅提供适配边界；当前 `analyze` CLI 没有内置 HTTP transport。 |
| 远程调用 | 只有应用层显式启用并注入受控 `transport` 时才可能发生；仓库不会因设置 API 环境变量自动上传样本。 |

项目不包含模型越狱、安全策略绕过或“无限制模型”功能。

## 配置

| 环境变量 | 说明 |
|---|---|
| `REVERSE_ANALYZER_WORKSPACE` | 工作区根目录。 |
| `REVERSE_ANALYZER_KNOWLEDGE_DIR` | KnowledgeBase 目录。 |
| `REVERSE_ANALYZER_SESSIONS_DIR` | 会话目录。 |
| `REVERSE_ANALYZER_REPORTS_DIR` | 报告目录。 |
| `REVERSE_ANALYZER_DASHBOARD_PORT` | Dashboard 默认端口，默认 `8088`。 |
| `GHIDRA_HOME` | Ghidra 根目录；可被 `--ghidra-home` 覆盖。 |
| `OPENAI_API_KEY` / `OPENAI_BASE_URL` / `OPENAI_MODEL` | OpenAI-compatible provider 实例配置；不等于 CLI 已接通远程 transport。 |
| `REVERSE_ANALYZER_OPENAI_ENABLED` | provider 实例的显式远程开关；调用方仍需提供 transport。 |

## 开发验证

```powershell
python -m compileall reverse_analyzer tests
python -m unittest discover -s tests -v
git diff --check
```

仅对自己拥有、公开许可、CTF 或已获得明确授权的软件样本使用本项目。许可证以 [LICENSE](LICENSE) 为准。
