---
name: pe-reverse-analyzer
description: >
  通用全平台逆向分析工具，覆盖 Windows PE/EXE/DLL、Android APK、iOS IPA 三大平台，
  以及 Web API 安全审计与逆向工程（黑盒）。支持从静态分析 → 加壳检测 → 脱壳 → 反编译到源码 → 修改源码 → 重构建完整链路，
  以及对外暴露的 Web 服务进行安全评估、配置审计、漏洞发现与修复方案输出。
  当用户发送二进制文件（.exe/.dll/.apk/.ipa/.app）并要求逆向、分析、脱壳、反编译、修改、重打包、找 flag/序列号/接口时使用，
  或当用户要求对自己的 Web/API 服务进行安全审计、渗透测试、漏洞扫描与修复时使用。
  适用于 CTF 逆向题、恶意软件分析、APP 安全审计、Web 安全评估、API 逆向工程。

  内置用户上下文：CTF 大赛应用开发、
  防御面研究（AI/LLM 安全加固、prompt injection 防御、安全基础设施）、
  红队自测（用户自有系统的安全审计）。
  加载本技能后自动注入上述三个方向的通用上下文。
agent_created: true
---

# 逆向分析 Skill — 源码重构导向

> **核心原则：报告只是中间产物，真实可编译可运行的源码才是终极目标。**

> **最高优先级规则：真实逆向重构 > 侧面信息推断。**
> 必须穷尽所有手段提取真实源码（运行时转储、安装包解压、内存dump、协议抓包），
> 只有当所有真实提取手段都失败后，才可以用侧面信息推断作为最后兜底方案。

本 skill 不以"生成分析报告"为目的。所有分析工作的最终产出必须是：
**一个可修改、可编译、可运行的源码项目。**

---

## 用户上下文：CTF 大赛 + 防御面研究 + 红队自测

使用本技能的用户覆盖三个典型工作方向，加载本技能后需同时纳入以下通用上下文：

### 上下文 1：CTF 大赛应用开发

用户可能在参加 CTF 比赛，题目要求**开发一款应用交付**。常见需求包括：

- **自动化工具开发**：按比赛要求实现特定功能的桌面应用
- 目标平台：**Windows EXE**（Python + GUI 框架 → PyInstaller 打包）
- 协议方案：**基于现有成熟框架**，复用已有协议库
- 核心约束：所有功能组件**一体化集成到单一应用**内，禁止分散手动启动多组件

CTF 开发优先策略：
- 实用主义：有现成框架直接用，不强求从头逆向协议
- 快速交付：Python + 打包成 EXE，GUI 用轻量框架
- 功能完整：连接管理、任务调度、批量操作、进度条、日志一应俱全

### 上下文 2：防御面研究

用户可能关注 AI / LLM 系统的**防御面**，合法研究方向包括：

- Prompt Injection 防御（加固自己的 AI 应用）
- 自己部署的 LLM 服务安全审计
- API 网关（如 New-API / OneAPI）的配置安全
- 安全响应头、CORS 策略、Rate Limiting 等基础设施防护
- 生成内容安全过滤机制

边界重申：防御研究可以做；生成 jailbreak / prompt injection 攻击 payload **不做**。

### 上下文 3：红队测试自己的系统

用户可能对自有线上系统进行安全测试（需确认所有权后执行）：

- 拓扑熵减 API 类服务（Go 后端，Nginx 反代）
- QQ-Marketing-Assistant 类 Dashboard 服务
- 快跑 API 类 AI 模型聚合平台

对以上系统的安全审计流程已写入本技能「Web API 安全审计与逆向」章节。

### 上下文触发规则

当用户使用本技能时，若请求涉及以下任一方向，**自动关联上述上下文**：

| 用户说 | 自动关联 |
|--------|---------|
| "开发"/"CTF"/"打包"/"逆向" | 上下文 1：CTF 应用开发 |
| "防御"/"加固"/"安全头"/"防 prompt injection"/"CSP"/"HSTS"/"逆向" | 上下文 2：防御面研究 |
| "测试我的"/"自己的网站"/"红队"/"自有系统"/"逆向" | 上下文 3：红队自测 |
| "/pe-reverse-analyzer" + 以上任意关键词 | 全部加载 |

---

## 工作流程总览

```
二进制文件 ─→ 静态分析 ─→ 脱壳(如需) ─→ 反编译 ─→ 源码重构 ─→ 可编译项目
    │              │            │            │            │
    │              ↓            ↓            ↓            ↓
    │         analysis.json  dump.exe    .c/.java      CMakeLists.txt
    │         (中间产物)    (中间产物)  (终极产出)    build.gradle
    │                                              Makefile
    └→ 如果只出报告 = 失败                          (终极产出)
```

**每个阶段都必须思考：这对最终源码重构有什么贡献？**

---

## 快速使用

```bash
# PE → C/C++ 可编译项目（核心命令）
python scripts/reconstruct.py <target.exe> --output ./reconstructed/

# PE → 分析报告（仅作为重构的参考）
python scripts/pe_analyze.py <target.exe> --output report.txt

# PE → 分析 + 重构一步到位
python scripts/pe_analyze.py <target.exe> --reconstruct --output report.txt

# 脱壳后 PE → 深度反编译（函数级伪代码 + IAT 重建 + 字符串提取）
python scripts/deep_decompile.py <unpacked.exe> --output ./deep_analysis/

# 深度反编译结果 → 模块化源码整合（v2，基于内容分类）
python scripts/integrate_v2.py

# APK → Android Studio 项目
python scripts/reconstruct.py <target.apk> --output ./reconstructed/

# API → Python/Go SDK
python scripts/reconstruct.py <flow.xml> --platform api --output ./sdk/

# Web → 主动攻击审计（12 模块全量扫描）
python scripts/web_attack.py https://target.com

# Web → 只跑指定攻击模块
python scripts/web_attack.py https://target.com --only sqli,xss,ssrf

# Web → 走 Burp 代理 + 带认证 Token
python scripts/web_attack.py https://target.com --proxy http://127.0.0.1:8080 --auth "Bearer eyJ..."

# Web → 跳过可能触发 WAF 的载荷
python scripts/web_attack.py https://target.com --skip-ids
```

---

## 阶段 1：静态分析（为重构铺路）

```bash
python scripts/pe_analyze.py <target.exe> --deep
```

产出（中间产物，不作为最终交付物）：
- 壳类型识别（决定后续重构策略）
- 导入/导出函数列表 → `imports.h` 的原材料
- 字符串常量 → `strings.h` 的原材料
- URL/注册表键 → `protocol.h` 的原材料
- 加密算法特征 → `crypto.h` 的原材料

**关键：分析结果必须保存为 `analysis.json`，供重构引擎消费。**

---

## 阶段 2：加壳检测与脱壳决策

`pe_analyze.py` 的壳识别结果决定重构策略：

| 壳类型 | 重构策略 | 脚本 | 状态 |
|--------|---------|------|------|
| UPX | `upx -d` 直接脱壳 | 外部工具 | ✅ 可靠 |
| VMProtect | 无法完全脱壳 | — | ⚠️ 基于侧面信息推断重构 |
| Themida | 无法完全脱壳 | — | ⚠️ 同上 |
| ASPack | ESP 定律脱壳 | 手动 x32dbg | ✅ 可靠 |
| CNM 私有壳 | 挂起转储法 | `suspend_dump.py` | ✅ 已验证 |
| 私有壳(通用) | 挂起转储法优先 | `suspend_dump.py` | ✅ 推荐 |
| 无壳 | 直接重构 | — | ✅ 完整源码重构 |

### ⚠️ 脱壳策略重要经验

**Unicorn 模拟器脱壳（auto_unpack.py）= ❌ 已废弃**
- CNM 壳等有反模拟检测，会调用 ExitProcess 直接退出
- 不适用于有反调试/反模拟能力的壳

**Windows 调试 API 脱壳（debug_unpack.py）= ❌ 已废弃**
- CNM 壳有反调试检测，EP 断点永远不触发
- `CreateProcessW(DEBUG_PROCESS)` 被壳检测到

**挂起转储法（suspend_dump.py）= ✅ 推荐方案**
- 绕过所有反调试检测：正常启动进程 → 等待壳自解压 → 挂起线程 → ReadProcessMemory
- 原理：进程不是以调试模式启动的，壳无法检测
- 注意：IAT 不会自动重建，需要后续 `deep_decompile.py` 处理

```bash
# 使用挂起转储法脱壳
python scripts/suspend_dump.py <packed.exe> --output <unpacked.exe> --wait 3
```

### 手动脱壳步骤（x32dbg / x64dbg）

```
步骤 1：加载目标程序
  x32dbg target.exe → 程序暂停在 EP

步骤 2：识别壳代码特征
  查看反汇编窗口第一条指令：
  - PUSHAD (0x60) → 壳典型开头
  - PUSHFD (0x9C) → 壳特征

步骤 3：单步执行 PUSHAD
  F7 执行 PUSHAD → ESP 值变化

步骤 4：对 ESP 设硬件访问断点
  右键 ESP → Breakpoint → Hardware, on access

步骤 5：运行到硬件断点
  F9 → 断点触发（壳恢复寄存器时）

步骤 6：识别 OEP
  查看 PUSH EBP; MOV EBP, ESP（函数序言）

步骤 7：Scylla dump
  Plugins → Scylla → 填 OEP → IAT Autosearch → Dump

步骤 8：修复 IAT
  Scylla → Fix Dump → 保存

步骤 9：验证
  python scripts/pe_analyze.py dump_fixed.exe --reconstruct
```

### 在关键 API 设断找逻辑

```
1. Ctrl+G → ShellExecuteA → F2 设断 → F9 运行 → 查看调用栈
2. Ctrl+G → RegCreateKeyExA → F2 设断 → F9 运行 → 查看写入的键
3. 搜索内存字符串 "flag" "key" "password" → 找引用代码
```

---

## 阶段 3：深度反编译

```bash
# 对脱壳后的 PE 进行深度分析
python scripts/deep_decompile.py <unpacked.exe> --output ./deep_analysis/
```

产出：
- `deep_analysis.json` — 结构化分析数据（函数列表、IAT、字符串、算法特征）
- `pseudocode/` — 每个函数的伪代码文件（`func_XXXXXXXX.c`）
- `ascii_strings_unpacked.txt` — ASCII 字符串
- `gbk_strings_unpacked.txt` — GBK 中文字符串
- `urls_unpacked.txt` — URL 提取

### 关键技术细节

1. **GBK 字符串提取**：脱壳后的 .text 段包含真实的中文数据，不做高熵过滤（区别于加壳 PE）
2. **函数边界识别**：扫描 `push ebp; mov ebp, esp` 和 `ret` 模式，结合 capstone 反汇编
3. **伪代码生成**：使用 capstone 反汇编后，将汇编指令逐条转换为类 C 伪代码
4. **IAT 重建**：从 .rdata 段扫描导入目录，识别 14+ 动态加载的 DLL

### ⚠️ 伪代码生成的 f-string 陷阱

在 Python 中使用 f-string 生成伪代码时，**x86 汇编操作数中的 `%`（如 `%eax`）会与 `%s` 格式化冲突**。

**解决方案**：全部使用字符串拼接（`+`）或 `%` 格式化，**不要混用**。

```python
# ❌ 错误：f-string 与汇编 % 寄存器冲突
c_content += f"/* 0x{addr:08X} */\n"  # 如果 addr 来自汇编，可能含 %

# ✅ 正确：使用 % 格式化
c_content += "/* 0x%08X */\n" % addr
```

---

## 阶段 4：运行时 IAT 解析（易语言程序关键步骤）

### 问题背景

易语言（E-language）程序的 PE 静态导入表通常只有十几个 API，实际运行时通过
`LoadLibraryA` + `GetProcAddress` 动态加载 100+ 个 API。伪代码中的 `CALL(0x46e0ee)`
等调用目标**不是** PE 静态 IAT 地址，而是运行时 IAT thunk。

### 解析步骤

1. **识别 thunk 表**：扫描 .text 段中的 `FF 25`（`jmp [imm32]`）指令
2. **追踪 IAT 条目**：读取 `jmp` 目标地址处的 IAT 值
3. **解析 Import Directory**：从 .rdata/CNM1 段读取 Import Directory Table
4. **匹配 INT 到 IAT**：OriginalFirstThunk 指向 Import Name Table（含 API 名称），
   FirstThunk 指向 IAT（运行时解析的函数指针），两者按索引一一对应

### 易语言运行时分发器特征

易语言程序通常有 12 个左右的 `jmp [IAT]` thunk（如 `0x46E0DC-0x46E11E`），
它们跳转到易语言 VM 分发函数，不是直接的 Windows API。

反编译特征：
```asm
; 典型易语言运行时包装函数
mov ecx, 0x61F6E8       ; ECX = 易语言运行时对象
jmp 0x48XXXX             ; 跳转到 VM 分发器
```

**这意味着**：伪代码中的 `CALL(0x46e0ee)` 应标注为 `CALL(elang_dispatch_4)`，
而不是尝试映射到具体的 Windows API。

### 静态 IAT vs 运行时 IAT

| 特征 | 静态 IAT | 运行时 IAT |
|------|---------|-----------|
| 地址范围 | 0x859000-0x85908C | 0x5100C4-0x5100F4 |
| 条目数 | ~22 个 | 186+ 个 |
| 解析方式 | PE 加载器自动解析 | LoadLibraryA + GetProcAddress |
| thunk | 无（直接调用） | FF 25 jmp [IAT] 中转 |
| 在伪代码中的形式 | `CALL(0x859030)` | `CALL(0x46e0ee)` |

---

## 阶段 5：源码整合（核心产出）

```bash
# 修改 integrate_v2.py 中的路径配置后运行
python scripts/integrate_v2.py
```

### v1 → v2 的关键改进

| 问题 | v1 (integrate_sources.py) | v2 (integrate_v2.py) |
|------|--------------------------|---------------------|
| 函数分类 | 全部归入 utility（200/200） | 按内容分类（runtime/129, ui/27 等） |
| 分类策略 | IAT 地址匹配（失败） | 字符串引用 + 调用模式 + 结构特征 |
| CALL 注释 | 原始地址 `CALL(0x46e0ee)` | 描述性名称 `CALL(elang_dispatch_4)` |
| 地址格式 | 不匹配导致 func_info 丢失 | `hex(int(addr, 16))` 标准化 |
| 伪代码格式化 | f-string 与 `%` 冲突 | 全部使用 `%` 格式化 |

### v2 分类策略

```python
# 分类基于三个维度：
1. 字符串引用 — 伪代码中包含 "WinHttp"、"RegCreate"、"SkinH" 等关键词
2. 调用模式 — CALL 目标地址是否在已知 thunk 范围（0x46eXXX）
3. 结构特征 — vtable 调用（MFC/易语言控件）、TEA 常量（0x9e3779b9）
```

### PE → C/C++ 项目产出

```
reconstructed_<name>/
├── CMakeLists.txt        # 构建系统（CMake）
├── Makefile              # 构建系统（MinGW Make）
├── OVERVIEW.md           # 项目文档（含 IAT 映射、thunk 表、QQ API）
├── src/
│   ├── main.c            # WinMain 重构（含原始 EP 反汇编注释）
│   ├── network.c         # 网络通信函数（WinHTTP/QQ API）
│   ├── ui.c              # UI 控件函数（易语言/MFC）
│   ├── runtime.c         # 运行时分发函数（易语言 VM）
│   ├── crypto.c          # 加密函数（TEA/XXTEA）
│   ├── registry.c        # 注册表操作
│   ├── business.c        # 核心业务逻辑
│   └── utility.c         # 工具函数
├── include/
│   ├── common.h          # IAT 映射 + 易语言 thunk 定义
│   ├── qq_api.h          # QQ API 端点宏
│   ├── strings.h         # 提取的字符串常量
│   └── [各模块.h]
└── pseudocode/           # 标注后的原始伪代码（200 个文件）
```

### APK → Android Studio 项目产出

```
reconstructed_<name>/
├── build.gradle          # 根构建文件
├── settings.gradle       # 项目设置
├── README.md
├── app/
│   ├── build.gradle      # App 模块构建
│   └── src/main/
│       ├── java/         # jadx 反编译的 Java 源码（可修改）
│       ├── AndroidManifest.xml
│       ├── res/          # 资源文件
│       └── smali/        # Smali 代码（可直接编辑重打包）
```

### API → Python/Go SDK 产出

```
reconstructed_<name>/
├── python/
│   ├── client.py         # 完整 API 客户端
│   └── setup.py
├── go/
│   ├── client.go         # Go API 客户端
│   └── go.mod
└── openapi.json          # OpenAPI 3.0 规范
```

---

## 阶段 6：修改源码并重构建

### PE 修改后重编译

```bash
cd reconstructed_<name>
mkdir build && cd build
cmake .. -G "MinGW Makefiles"    # 或 Visual Studio
make                               # 编译
```

### APK 修改后重打包

```bash
# 方式 A：修改 Java 源码后用 Android Studio 编译
# 方式 B：修改 smali 后用 apktool 重打包
apktool b <decompiled_dir> -o rebuilt.apk
apksigner sign --ks debug.keystore rebuilt.apk
adb install rebuilt.apk
```

### iOS 修改后重签名（需要 macOS）

```bash
# 用 Ghidra patch Mach-O
codesign -f -s "iPhone Developer: ..." target.app
ios-deploy --bundle target.app
```

---

## AI 持续重构协议

当 AI 使用本 skill 时，**必须遵循以下协议**：

### 1. 每次分析的输出优先级

```
① 可编译的源码项目（必须）
② analysis.json（必须 - 供下次分析恢复上下文）
③ 分析报告（可选 - 仅供参考）
```

### 2. 重构迭代策略

```
第 1 轮：生成项目骨架 + 导入/字符串/协议声明
第 2 轮：基于动态分析结果补充函数逻辑
第 3 轮：修复编译错误，确保可构建
第 N 轮：持续优化，逼近原始行为

对于复杂目标（GUI+协议+加密），使用并发Agent加速:
  第 1 轮后启动四线并发:
    Agent A: 扩展反编译 (deep_decompile)
    Agent B: .proto 重建 (字符串分析)
    Agent C: GUI 资源解析
    主线程: 动态运行时分析
  所有Agent完成后合并到 final_project/
```

### 3. 加壳程序的重构策略

加壳程序无法一次重构到位，采用"渐进式重构"：

```
第 1 步：从导入/导出/字符串推断出程序的大致架构
         → 生成 C 项目骨架（所有函数为 TODO）
第 2 步：动态分析（x32dbg 断点）获取关键函数逻辑
         → 补充 main.c 和关键函数
第 3 步：API 监控获取网络/注册表行为
         → 补充 protocol.c
第 4 步：加密算法逆向
         → 补充 crypto.c
```

### 4. 产出自检清单

每次完成重构后，AI 必须自检：

- [ ] 生成的项目能否 `cmake .. && make` 成功？
- [ ] `analysis.json` 是否完整保存了所有分析结果？
- [ ] 每个函数是否保留了原始反汇编作为注释？
- [ ] 导入函数是否全部声明和实现？
- [ ] 字符串常量是否全部提取到 `strings.h`？
- [ ] 网络协议是否重构到 `protocol.h/c`？
- [ ] 运行时 IAT thunks 是否已标注（对易语言程序至关重要）？
- [ ] 伪代码生成是否避免了 f-string + `%` 冲突？
- [ ] 是否执行了动态运行时分析（启动进程获取窗口标题/版本号）？ 🆕
- [ ] WAVE 资源是否已提取并 decode UTF-16LE？ 🆕
- [ ] protobuf .proto 文件是否基于字符串提取重建？ 🆕
- [ ] MFC/易语言/纯Win32 框架是否已正确识别？ 🆕
- [ ] 无壳PE的脱壳阶段是否已正确跳过？ 🆕

---

## 脚本参考

| 脚本 | 核心产出 | 依赖 | 状态 |
|------|---------|------|------|
| `reconstruct.py` | **可编译源码项目** | pefile, capstone | ✅ 主力 |
| `pe_analyze.py` | analysis.json + 分析报告 | pefile | ✅ |
| `deep_decompile.py` | 函数级伪代码 + IAT 重建 | pefile, capstone | ✅ |
| `suspend_dump.py` | 脱壳后 PE + 段数据 | pefile, capstone, ctypes | ✅ 推荐 |
| `integrate_v2.py` | 模块化源码整合 | pefile, capstone | ✅ 推荐 |
| `deep_extract.py` | 深度字符串/URL 提取 | pefile | ✅ |
| `integrate_sources.py` | v1 整合（分类失败） | pefile | ⚠️ 已废弃 |
| `auto_unpack.py` | Unicorn 模拟器脱壳 | pefile, capstone, unicorn | ⚠️ 已废弃 |
| `debug_unpack.py` | Windows 调试 API 脱壳 | pefile, ctypes | ⚠️ 已废弃 |
| `common.py` | 共享工具函数 | capstone | ✅ |
| `apk_analyze.py` | Android Studio 项目 | apktool, jadx | ✅ |
| `ipa_analyze.py` | Xcode 项目（macOS） | class-dump, otool | ✅ |
| `api_reverse.py` | Python/Go SDK + OpenAPI | mitmproxy（可选） | ✅ |
| `web_attack.py` | **Web 主动攻击审计报告** | requests | ✅ 主力 |
| `auto_evolve.py` | 自动进化引擎（新） | standard library | ✅ 自动运行 |

### 自动进化升级机制 🧬

每次逆向会话结束后，`auto_evolve.py` 自动记录并分析：
- 哪些壳类型能成功重构（成功率统计）
- 哪些操作失败了（自动标记为 impossible pattern）
- 新发现的壳段名（自动扩充检测数据库）
- 高优先级改进建议（自动应用到 SKILL.md）

运行方式：
```bash
# 会话结束后自动记录
python scripts/auto_evolve.py --record \
    --binary target.exe --packer VMProtect \
    --actions "pe_analyze,side_channel" \
    --status partial --built-project

# 查看进化报告
python scripts/auto_evolve.py --report
```

---

## CNM 私有壳处理专题

### 壳特征识别

```
段名: CNM0 / CNM1（非常规段名）
.text / .rdata / .data 段 RawSize = 0（内存展开型壳）
EP 在 CNM1 段内
入口代码: pushfd; pushal（典型壳序言）
后续指令: 大量混淆/垃圾指令 + 跳转链
```

### 脱壳方案（按可靠性排序）

1. **挂起转储法**（suspend_dump.py）— ✅ 绕过所有反调试
2. **x32dbg ESP 定律** — ✅ 手动操作，可靠
3. **Unicorn 模拟器** — ❌ 反模拟检测
4. **Windows 调试 API** — ❌ 反调试检测

### 脱壳后 IAT 修复

挂起转储**不会**重建 IAT。脱壳后的 PE 静态导入表只有壳的原始导入，
实际运行时通过 `LoadLibraryA` + `GetProcAddress` 动态加载。
`deep_decompile.py` 会从 .rdata/CNM1 段的 Import Directory 重建 IAT 映射。

---

## 易语言程序逆向专题

### 识别特征

```
版本资源: "易语言程序" / "dywt.com.cn"
PE 导入: 仅 10-20 个 API（KERNEL32/USER32/GDI32 基础 API）
运行时加载: 100+ 个 API 通过 LoadLibraryA + GetProcAddress
SkinH_EL.dll: 易语言换肤库
MFC 类名: CDialog, CWnd, CString 等
OEP 附近: 大函数（10K+ 字节，数百个调用）
```

### 易语言运行时分发器

易语言程序的核心调用通过 12 个左右的 `jmp [IAT]` thunk 分发到 VM：

```c
// 伪代码中的调用
CALL(0x46e0ee)  // 实际是: jmp [0x5100DC] → 易语言 VM 分发函数

// VM 分发函数典型结构
mov ecx, 0x61F6E8    // ECX = 易语言运行时对象
jmp 0x48XXXX          // 跳转到 VM handler

// thiscall 约定，ECX 传入运行时对象指针
```

### 整合策略

对易语言程序的 `integrate_v2.py` 分类应优先基于：
1. **字符串引用**（最可靠）— 包含 "WinHttp" → network，"SkinH" → ui
2. **调用模式** — 调用 thunk → runtime_dispatch
3. **结构特征** — vtable 调用 → ui，TEA 常量 → crypto

**不要尝试**将 thunk 地址直接映射到 Windows API 名称（中间经过 VM 分发，无法静态解析）。

---

## 工具安装

### 核心依赖（必须）
```bash
pip install pefile capstone
```

### 可选依赖（脱壳用）
```bash
pip install unicorn  # 仅用于无反模拟的壳
```

### PE 逆向工具（推荐）
```bash
# Ghidra（免费反编译器）— 注意 CNM VM 代码限制（见下方专题）
# https://ghidra-sre.org/ - 需 JDK 17+
# x32dbg/x64dbg - https://x64dbg.com/
```

### Ghidra Headless 集成专题 ⚠️ 重要

#### 安装

```bash
# 1. 确认 JDK 版本 ≥ 17
java -version
# 如未安装: https://adoptium.net/ (Eclipse Temurin JDK 21 推荐)

# 2. 下载 Ghidra
# https://github.com/NationalSecurityAgency/ghidra/releases
# 解压到 C:/Users/<user>/tools/ghidra_12.1_PUBLIC/

# 3. 设置环境变量
set JAVA_HOME=C:/Users/<user>/tools/jdk-21.0.11+10
```

#### Headless 命令行

```bash
# 创建项目目录（必须）
mkdir C:/Users/<user>/tools/ghidra_project

# 运行分析+脚本
analyzeHeadless.bat <project_dir> <project_name> \
    -import <target.exe> \
    -scriptPath <scripts_dir> \
    -postScript <ScriptName.java> \
    -deleteProject
# -noanalysis 跳过自动分析（通常不用）
```

#### ⚠️ Ghidra 脚本编写关键陷阱

| 陷阱 | 错误做法 | 正确做法 |
|------|---------|---------|
| 脚本路径 | 外部 `-scriptPath` | 必须放 Ghidra 内置 `Features/Base/ghidra_scripts/` |
| OSGi bundle | 外部目录 → "Failed to get OSGi bundle" | 内置目录编译通过 |
| `getFunctions()` | `Function[] funcs = getFunctions(true)` | `FunctionIterator` 迭代器（while hasNext/next） |
| `getSignature()` | 不存在于 Ghidra 12.1 | 改用 `getReturnType() + getParameters()` 手动拼接 |
| `getReferencesTo()` | 迭代器 `.hasNext()/.next()` | 返回 `Reference[]` 数组 → `refs.length` |
| `MemoryBlock` 遍历 | 增强 for + `getBlocks()` 可能失败 | 先 `.getBlocks()` 到数组，再用普通 for |
| _var_ 关键字 | 方法参数用 `var` → 编译失败 | 方法参数必须写完整类型；局部变量可用 `var`（JDK 10+） |
| 日志编码 | — | headless 输出为 UTF-16LE，Python 读取用 `decode('utf-16', errors='replace')` |

#### ⚠️ 核心发现：CNM VM 代码无法被 Ghidra 分析

Ghidra 的递归下降反汇编器依赖从已知入口点追踪控制流来发现代码。
CNM 壳的 VM 代码变换使得：

- ✅ 反汇编 OEP 处代码：**成功**（`disassemble()` 返回 true）
- ❌ 在 OEP 创建函数：**失败**（`CreateFunctionCmd.applyTo()` 返回 true 但函数不创建）
- ❌ 暴力扫描 prologue（55 8B EC）：**0 个命中**
- ❌ 自动分析整个 .text 段：**仅 22 个 thunk 函数**（全部跳过）

**根因**：CNM 代码变换后的字节码不包含标准 x86 函数序言，指令流路径被
VM 拆解，递归下降反汇编器无法构建有效的控制流图。

**正确的工具选型**：

```
有标准 x86 代码（无壳/UPX/ASPack/常见壳）
  → Ghidra headless ✅ 产出真正的 C 级伪代码

有 VM 变换代码（CNM/VMProtect/Themida）
  → capstone 线性扫描 ✅ 不可分析控制流但能覆盖全部指令
  → Ghidra ❌ 递归下降失败
```

#### useful_GhidraScript 模板

```java
// ScriptName.java — 放在 Ghidra Features/Base/ghidra_scripts/ 下
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class ScriptName extends GhidraScript {
    public void run() throws Exception {
        println("Program: " + currentProgram.getName());

        // 正确遍历函数（迭代器，非数组）
        FunctionIterator fit = currentProgram.getFunctionManager().getFunctions(true);
        int count = 0;
        while (fit.hasNext()) {
            Function f = fit.next();
            if (f.isThunk() || f.isExternal()) continue;
            count++;
            // 反编译: DecompInterface decomp = new DecompInterface();
            // decomp.openProgram(currentProgram);
            // DecompileResults r = decomp.decompileFunction(f, 60, monitor);
            // r.getDecompiledFunction().getC()
        }
        println("Non-thunk functions: " + count);
    }
}
```

### APK 逆向工具
```bash
# apktool: https://ibotpeaches.github.io/Apktool/
# jadx: https://github.com/skylot/jadx/releases
```

### iOS 逆向工具（macOS）
```bash
brew install class-dump frida-tools
```

---

## 无壳 PE 快速识别与重构专题 🆕 (2026-06-01 晨风QQ机器人实战验证)

### 无壳特征（满足3条即可跳过脱壳阶段）

```
✅ 导入表 > 100 个函数（标准无壳: 714个/25个DLL）
✅ .text 段熵值 < 7.0 (无壳≈6.6, 加壳 >7.5)
✅ 字符串可读（4474条ASCII直接可见）
✅ 段名标准 (.text/.rdata/.data/.rsrc, 非CNM0/UPX0等壳段名)
✅ PDB路径可读 (编译器未strip调试信息)
✅ 编译器版本可识别 (linker 10.0 = VS2010)
```

### 导入函数数作为判定锚点

```
导入函数 > 500 → 大概率无壳 → 直接进入 deep_decompile
导入函数 100-500 → 可能轻保护 → pe_analyze --deep 确认
导入函数 < 20 → 易语言或强壳 → 执行完整脱壳流程
```

---

## MFC 程序识别与资源提取专题 🆕 (2026-06-01 实战验证)

### 识别特征

```
ASCII字符串含 MFC 类名: CDialog, CDialogEx, CWnd, CMFCToolBars
.rsrc段含 WAVE 命名资源 (MFC内部UTF-16LE文本数据)
Linker版本 >= 10.0 (VS2010+)
PDB路径: <盘符>:\项目代码\<项目名>\Release\<程序名>.pdb
```

### MFC vs 易语言 区分关键

| 特征 | MFC C++ | 易语言 |
|------|---------|--------|
| 导入函数数 | 500-800 (25 DLL) | 10-20 (3 DLL) |
| PDB路径 | 标准VS格式 | 通常无PDB |
| ASCII字符串 | MFC类名 + protobuf路径 | 中文乱码/编码后 |
| 段名 | 标准(.text/.rdata等) | 可能有自定义段 |
| 导出函数 | 可能有 (如OCR SDK) | 通常无 |

### MFC 对话框资源内部格式 (DLGTEMPLATEEX)

MFC (VS2010+) 编译的 RT_DIALOG 资源以 **DLGTEMPLATEEX** 格式存储。
标准 DLGTEMPLATE 解析器会失败——格式使用字节对偏移编码而非直接DWORD。

### WAVE 资源类型 🔑

.rsrc 段中名为 "WAVE" 的命名资源**不是音频**，而是 MFC 的 UTF-16LE 文本配置:

```
Type name=WAVE (23个条目, 总计1.15MB, 占.rsrc的77%):
  Name=9006: 302KB — 可能是自动回复词库
  Name=9012: 391KB — 可能是群管理配置
  可直接 decode('utf-16-le') 提取可读文本
```

### 资源提取策略（按可靠性）

1. ✅ **动态运行时** — 启动进程获取窗口标题和控件文本
2. ✅ **WAVE资源提取** — decode UTF-16LE 获得配置文本
3. ⚠️ **DLGTEMPLATEEX解析** — 需要MFC专用解析器
4. ⚠️ **语义推断** — 根据导入API推断对话框用途

---

## 动态运行时分析专题 🆕 (2026-06-01 实战验证)

### 核心原则

**调试器不可用时，启动进程+进程监控仍可获取关键信息。**

```powershell
$proc = Start-Process "target.exe" -PassThru -WindowStyle Minimized
Start-Sleep 10
$proc.MainWindowTitle   # → "晨风QQ机器人3.96版——..."
$proc.WorkingSet        # → 23.1 MB
$proc.Modules           # → 已加载DLL列表
```

### 实战成果

| 信息 | 方法 | 价值 |
|------|------|------|
| 窗口标题 | MainWindowTitle | 版本号、软件名 |
| 加载DLL | Modules枚举 | 确认运行时依赖 |
| 工作集 | WorkingSet | 验证重构规模 |
| 崩溃状态 | ExitCode | 兼容性确认 |

---

## Protobuf 服务名 → .proto 重建专题 🆕 (2026-06-01 实战验证)

### 核心洞察

**编译进PE的protobuf程序在ASCII字符串中泄漏完整服务名/消息类型/文件路径。**

### 提取模式

```bash
# 过滤protobuf相关字符串
grep -E "(Service|Svc\.|\.proto|\.pb\.cc)" ascii_strings_unpacked.txt

# 识别服务名 (MessageSvc.PbSendMsg 等)
grep -E "^[A-Z][a-zA-Z]+\.[A-Z]" ascii_strings_unpacked.txt

# 识别字段名 (sendUin, groupid 等驼峰)
grep -E "^[a-z]+[A-Z]" ascii_strings_unpacked.txt
```

### 实战: 4474条ASCII → 105个消息类型

- **12 个服务名**: wtlogin.login, MessageSvc.PbSendMsg 等
- **8 个.proto文件名**: msg.JoinGroup.proto 等
- **2 个.pb.cc路径**: googleproto\msg.JoinGroup.pb.cc
- **20+ 个字段名**: sendUin, groupid, myallow, token, vfwebqq
- **HEX验证**: 0x08 A2 0F = OidbSvc.0x7a2_0 命令编码

### .proto 重建置信度

```
服务名/消息类型名 → 100% (直接从字符串提取)
语义字段名        → 90% (命名模式推断)
字段类型          → 75% (命名前缀: buf→bytes, dw→uint32)
字段编号          → 70% (部分通过hex编码验证)
```

### proto 文件结构

```
proto/
├── common.proto     # 共享类型 (TextElement, RoutingHead)
├── login.proto      # wtlogin.login
├── message.proto    # MessageSvc.PbSendMsg/PbGetMsg
├── group.proto      # JoinGroup, GroupMngReq
└── profile.proto    # ProfileService, FriendList
```

---

## 并发 Agent 多阶段逆向工作流 🆕 (2026-06-01 实战验证)

### 适用场景

目标程序复杂度高（GUI+协议+加密多模块），单线程分析瓶颈明显。

### 四线并发模式

```
阶段1 (主线程): pe_analyze --deep → analysis.json

阶段2 (四线并发):
  ├→ Agent A: 扩展反编译 (deep_decompile 200→1000)
  ├→ Agent B: .proto 重建 (从ASCII字符串提取)
  ├→ Agent C: GUI资源解析 (对话框/菜单/WAVE)
  └→ 主线程:  动态运行时分析

阶段3: 成果合并 → final_project/
```

### Agent 任务模板

```
Agent (protobuf): "基于ASCII字符串中的服务名/消息类型/字段名重建
                  .proto文件。推断字段编号和类型。产出 proto/*.proto"

Agent (GUI): "分析.rsrc段提取对话框/菜单数据。处理MFC内部格式。
             产出 gui_analysis/gui_report.md"

Agent (decompile): "修改deep_decompile限制(200→1000)扩展伪代码。
                   产出 deep_analysis_1000/"
```

---

## Windows MFC 项目编译构建专题 🆕 (2026-06-01 晨风QQ机器人实战验证)

### 核心原则

**逆向重构的源码必须能实际编译通过，才算完成。**

### VS BuildTools 安装与配置

```powershell
# 下载 VS BuildTools 安装器
Invoke-WebRequest -Uri "https://aka.ms/vs/17/release/vs_BuildTools.exe" -OutFile "$env:TEMP\vs_BuildTools.exe"

# 安装（仅C++桌面开发 + MFC，静默安装）
& "$env:TEMP\vs_BuildTools.exe" --quiet --wait --norestart --nocache `
    --add "Microsoft.VisualStudio.Workload.VCTools" `
    --add "Microsoft.VisualStudio.Component.VC.ATLMFC" `
    --add "Microsoft.VisualStudio.Component.Windows10SDK.19041" `
    --includeRecommended
```

### 关键路径确认

```
vcvars32.bat:
  C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars32.bat

cl.exe:
  C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\<ver>\bin\Hostx86\x86\cl.exe

MFC headers:
  C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\<ver>\atlmfc\include\afxwin.h

MFC libs:
  C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\<ver>\atlmfc\lib\x86\mfc140u.lib
```

### 常见编译错误与修复

| 错误 | 原因 | 修复 |
|------|------|------|
| `fatal error C1189: #error: Please use the /MD switch for _AFXDLL builds` | MFC必须用动态运行时 | `/MT` → `/MD` |
| `fatal error C1083: Cannot open include file: 'afxwin.h'` | MFC/ATL未安装 | 安装 VS BuildTools + ATLMFC组件 |
| `fatal error C1083: Cannot open source file: ...` | 路径含中文被编码为乱码 | 复制到纯ASCII路径如 `D:\cfbot_build` |
| `warning C4819: The file contains a character that cannot be represented...` | 中文注释与代码页(936)冲突 | 添加 `/utf-8` 编译选项或移除中文注释 |
| `LINK : fatal error LNK1104: cannot open file 'mfc140u.lib'` | MFC库路径未正确链接 | 确认ATLMFC组件已安装 |

### 编译命令模板

```batch
:: 1. 激活 VS 环境
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars32.bat"

:: 2. 编译 MFC EXE (/MD 必须!)
cl /nologo /EHsc /MD /O2 /D "_AFXDLL" /D "_UNICODE" /D "UNICODE" ^
    /I "include" ^
    src\main.cpp src\inject.cpp ... ^
    /Fe:"bin\app.exe" /link /SUBSYSTEM:WINDOWS ^
    wininet.lib ws2_32.lib gdiplus.lib winmm.lib psapi.lib ^
    comctl32.lib version.lib shlwapi.lib

:: 3. 编译普通 DLL
cl /nologo /LD /MT /O2 ^
    src\hook_dll.cpp ^
    /Fe:"bin\hook.dll" /link /DLL ^
    ws2_32.lib user32.lib kernel32.lib
```

### 关键经验

- **MFC + `/MD`**：定义了 `_AFXDLL` 时必须用 `/MD`（动态运行时），`/MT` 会报 `#error`
- **纯ASCII路径**：`cl.exe` 对含中文的路径编码处理有问题，建议复制到 `D:\xxx` 纯英文目录
- **/utf-8 选项**：处理中文注释的代码页警告
- **PowerShell vs CMD**：`cmd /c "call vcvars.bat && cl ..."` 在 PowerShell 中可能中断脚本流，建议写 `.cmd` 批处理文件

### 进阶：MFC 消息映射与类定义陷阱

#### 陷阱 1: `ON_MESSAGE` 宏要求 `LRESULT` 返回类型

```cpp
// ❌ 错误：返回 void
afx_msg void OnTrayNotify(WPARAM wParam, LPARAM lParam);

// ✅ 正确：返回 LRESULT
afx_msg LRESULT OnTrayNotify(WPARAM wParam, LPARAM lParam);

// 实现也必须匹配
LRESULT CMainDialog::OnTrayNotify(WPARAM wParam, LPARAM lParam) {
    // ...
    return 0;
}
```

#### 陷阱 2: 成员变量初始化顺序

```cpp
// ❌ 错误：在构造函数体中初始化 MFC 控件成员
CMainDialog::CMainDialog(CWnd* pParent)
    : CDialogEx(IDD_MAIN_DIALOG, pParent) {
    m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);  // 此时 MFC 可能未初始化
}

// ✅ 正确：在 OnInitDialog 中初始化图标
BOOL CMainDialog::OnInitDialog() {
    CDialogEx::OnInitDialog();
    m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
    SetIcon(m_hIcon, TRUE);
    return TRUE;
}
```

#### 陷阱 3: 资源 ID 未定义

```cpp
// ❌ 错误：直接使用 IDR_MAINFRAME 但未定义
m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);  // C2065

// ✅ 正确：在 common.h 中定义
#define IDR_MAINFRAME  128
#define IDD_MAIN_DIALOG 101
```

#### 陷阱 4: `WinMain` 链接错误

```cpp
// 错误：LNK2019 _WinMain@16 unresolved
// 原因：MFC 应用需要 wWinMainCRTStartup 入口点

// 修复：链接时指定入口点
// cl ... /link /SUBSYSTEM:WINDOWS /ENTRY:"wWinMainCRTStartup"
```

#### 陷阱 5: DLL 缺少 Winsock 头文件

```cpp
// hook_dll.cpp 中使用 SOCKET 类型但未包含 winsock2.h
// 错误：C2065 'SOCKET': undeclared identifier

// ✅ 修复：
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
```

#### 陷阱 6: CRITICAL_SECTION 位置错误

```cpp
// ❌ 错误：在 CWinApp::InitInstance 中操作 CMainDialog 的成员
BOOL CQQRobotApp::InitInstance() {
    InitializeCriticalSection(&m_csLock);  // m_csLock 是 CMainDialog 的成员！
    // ...
}

// ✅ 正确：在类的构造函数/析构函数中管理资源
CMainDialog::CMainDialog(CWnd* pParent) : CDialogEx(IDD_MAIN_DIALOG, pParent) {
    InitializeCriticalSection(&m_csLock);
}
CMainDialog::~CMainDialog() {
    DeleteCriticalSection(&m_csLock);
}
```

### 完整构建脚本模板（已验证）

```batch
@echo off
setlocal

set "vcvars=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars32.bat"
set "src=D:\cfbot_build\src"
set "inc=D:\cfbot_build\include"
set "out=D:\cfbot_build\bin"

if not exist "%out%" mkdir "%out%"

echo [1] Activating VS build env...
call "%vcvars%"
if errorlevel 1 exit /b 1

echo [2] Compiling MFC EXE ...
cl /nologo /EHsc /MD /O2 /utf-8 /D "_AFXDLL" /D "_UNICODE" /D "UNICODE" /I "%inc%" ^
    "%src%\main.cpp" ^
    "%src%\inject.cpp" ^
    "%src%\protocol.cpp" ^
    "%src%\crypto.cpp" ^
    "%src%\network.cpp" ^
    "%src%\business.cpp" ^
    "%src%\ocr_bridge.cpp" ^
    /Fe:"%out%\ChenfengQQBot.exe" ^
    /link /SUBSYSTEM:WINDOWS /ENTRY:"wWinMainCRTStartup" ^
    wininet.lib ws2_32.lib gdiplus.lib winmm.lib psapi.lib dbghelp.lib urlmon.lib ^
    comctl32.lib version.lib shlwapi.lib iphlpapi.lib imm32.lib ole32.lib oleaut32.lib msimg32.lib ^
    mfc140.lib mfcs140.lib

echo [3] Compiling DLL ...
cl /nologo /LD /MT /O2 /utf-8 /D "_UNICODE" /D "UNICODE" ^
    "%src%\hook_dll.cpp" ^
    /Fe:"%out%\QQBotHook.dll" ^
    /link /DLL ^
    ws2_32.lib user32.lib kernel32.lib

echo [OK] Build complete!
```

---

## 局限性声明

1. **反编译 ≠ 还原源码**：变量名、注释、宏全部丢失，需人工推断和补充
2. **加壳程序**：必须先脱壳才能获取完整逻辑，否则只能基于侧面信息推断
3. **VMP/Themida**：虚拟化保护的代码基本无法还原，只能重构可见部分
4. **易语言 VM**：thunk 调用经过 VM 分发，无法静态解析到具体 API
5. **iOS 非越狱**：动态分析极其困难，主要依赖静态分析
6. **HTTPS 拦截**：需绕过 Certificate Pinning
7. **运行时 IAT**：挂起转储不重建 IAT，需要后续分析补充
8. **CNM VM 代码→Ghidra 不可见**：必须回退到 capstone 线性扫描（见上方 Ghidra 专题）

---

## 产出目录规范 ✅

所有逆向产出**必须**集中在一个统一目录树中，禁止分散：

```
<workspace>/逆向/<target_name>/
├── README.md              # 项目总览
├── analysis.txt / .json   # 静态分析报告
├── CMakeLists.txt         # 构建系统 (C项目)
├── src/                   # 可编译源码
├── include/               # 头文件
├── python/                # Python SDK (如有)
├── pseudocode/            # 函数级伪代码 (参考)
├── deep_analysis/         # 深度反编译中间产物
├── docs/                  # 文档 (逆向报告等)
└── unpacked/              # 脱壳产物 (如有)
```

**规则**：
- 每次逆向结束后，产出必须复制到这个统一目录
- 禁止同一个目标的报告、源码、SDK 分散在多个独立目录
- 目录名用英文/拼音，不含空格

---

---

## final_project 整合流程（完整链路）

从零到可构建项目的完整链路：

```bash
# 步骤 1：脱壳
python scripts/suspend_dump.py target.exe -o unpacked.exe --wait 3

# 步骤 2：深度反编译（capstone 线性扫描）
python scripts/deep_decompile.py unpacked.exe -o ./deep_analysis/

# 步骤 3：模块化源码整合（v2 分类）
python scripts/integrate_v2.py ./deep_analysis/ ./reconstructed_v2/

# 步骤 4：生成可编译项目骨架（final_project）
# 在 reconstructed_v2 基础上，手写/AI辅助生成：
#   src/main.c     — WinMain 入口 + 消息循环
#   src/network.c  — WinHTTP/WinInet 实现
#   src/ui.c       — Windows 控件管理
#   src/business.c — 业务逻辑骨架（含文档化注释）
#   src/runtime.c  — 易语言运行时模拟 + TEA/XXTEA 实现
#   src/utility.c  — 工具函数
#   src/qq_api.c   — QQ API 接口（根据提取的 URL 生成）
#   CMakeLists.txt — MSVC/MinGW 构建
```

**final_project 与 reconstructed_v2 的区别**：

| 方面 | reconstructed_v2 | final_project |
|------|-----------------|---------------|
| 可编译性 | ❌ 伪代码骨架 | ✅ 完整 Win32 C 程序 |
| 函数实现 | 汇编级 TODO/注释 | 可运行的 Win32 API 调用 |
| 加密算法 | 只标注"TEA 在此" | ✅ 完整 TEA/XXTEA 实现 |
| 网络层 | 调用模式注释 | ✅ WinHTTP POST/GET 实现 |
| 构建系统 | 基础 CMakeLists.txt | ✅ 完整 CMake + MSVC/MinGW |

---

## NSIS+7z_BCJ2 安装包提取专题 🆕

### 识别特征

```
PE32 stub (通常 <1MB) + 巨大 .rsrc 段 (200MB+)
.rsrc 段包含 MSI/7z 类型资源
7z header: 37 7A BC AF 27 1C (BCJ2 + LZMA 压缩)
Solid archive (Blocks=1) — 提取单个文件需解压全部
```

### 提取流程

```bash
# 步骤 1: pefile 提取 7z 数据
python -c "
import pefile; pe = pefile.PE('installer.exe')
for e in pe.DIRECTORY_ENTRY_RESOURCE.entries:
    for r in e.directory.entries:
        for d in r.directory.entries:
            if d.data.struct.Size > 100_000_000:
                with open('payload.7z','wb') as f:
                    f.write(pe.get_data(d.data.struct.OffsetToData, d.data.struct.Size))
"

# 步骤 2: 原生 7zr 解压（⚠️ py7zr 不支持 BCJ2！）
curl -L -o 7zr.exe https://www.7-zip.org/a/7zr.exe
./7zr.exe l payload.7z              # 列出内容
./7zr.exe x payload.7z -o./out/ -y "path/to/file.dll"
```

### 关键陷阱

| 陷阱 | 原因 | 解决方案 |
|------|------|---------|
| py7zr 报 BCJ2 错误 | BCJ2 filter 不被 Python 支持 | 必须用原生 7zr.exe |
| "No files to process" | Solid archive 不支持逐文件提取 | 不使用通配符，用精确路径 |
| 路径不匹配 | 7z 内路径与预期不同 | 先用 `7zr l` 查看完整路径 |

---

## x64 .node 文件分析专题 🆕

### 背景

QQ NT、Electron 应用使用 `.node` 文件作为原生插件。**这些文件本质上是改名 DLL**——可以像普通 PE 文件一样分析。

### 识别

```bash
# .node 文件就是 PE DLL
file msf-win32-x64.node  # 输出: PE32+ executable (DLL) x86-64

# 可直接用 pe_analyze.py 分析
python scripts/pe_analyze.py msf-win32-x64.node --deep
```

### 典型结构

| 文件 | 大小 | 实际身份 |
|------|------|---------|
| `wrapper.node` | ~97MB | QQ 核心协议封装 |
| `major.node` | ~92MB | 主协议模块 |
| `msf-win32-x64.node` | ~2MB | SSO 登录协议 |
| `*.node` 导出 | C++ mangled (V8/Node 类) | Node.js 原生插件接口 |

---

## 导入表推断协议类型专题 🆕

### 核心洞察

**不需要反汇编代码，仅从导入表 DLL 组合就能推断通信协议类型**：

| 导入组合 | 协议类型 | 示例 |
|---------|---------|------|
| ws2_32(send/recv/connect) + CRYPT32 | **TCP 二进制协议** + 证书验证 | QQ NT, 网游客户端 |
| ws2_32 + ADVAPI32(Crypt*) | TCP + 纯加密 | 自定义 TCP 协议 |
| WINHTTP + WININET | **HTTP/HTTPS API** | Web 协议客户端 |
| ws2_32 + Secur32 | TCP + SSPI/TLS | 企业安全通信 |
| ws2_32 + IPHLPAPI | UDP/TCP + 网络探测 | P2P 应用 |
| WINHTTP only | 纯 HTTP (无证书验证) | 简单 REST 客户端 |

### 实战应用

```python
# 从导入表快速判断协议
def detect_protocol_from_imports(pe):
    imports = [e.dll.decode().lower() for e in pe.DIRECTORY_ENTRY_IMPORT]
    
    if 'ws2_32.dll' in imports and 'crypt32.dll' in imports:
        return "TCP_BINARY_PROTOCOL + CERT_VERIFY"
    if 'winhttp.dll' in imports or 'wininet.dll' in imports:
        return "HTTP_API"
    if 'ws2_32.dll' in imports and 'secur32.dll' in imports:
        return "TCP_TLS_SSPI"
    if 'ws2_32.dll' in imports:
        return "TCP_RAW"
    return "UNKNOWN"
```

---

## DLL 字符串提取 → COM 接口反推专题 🆕

### 核心洞察

**未加密 DLL 的 C++ mangled name 字符串可直接反推完整 API 接口定义**。

以 SSOShareInfoHelper64.dll 为例：

```python
import pefile, re
pe = pefile.PE("target.dll")
all_strings = []
for s in pe.sections:
    data = s.get_data()
    for m in re.finditer(rb'[\x20-\x7E]{6,}', data):
        all_strings.append(m.group().decode('ascii'))
```

### 三类关键字符串

| 分类 | 示例 | 提取出的信息 |
|------|------|------------|
| **COM 接口名** | `.?AUITXSSOBuffer@@` | 接口名称 → ITXSSOBuffer |
| **COM 实现类** | `.?AVCTXSSOBufferImpl@@` | 实现类 → CTXSSOBufferImpl |
| **COM GUID 绑定** | `LIBID_QQOpenSDKLib` | 库名 → QQOpenSDKLib |
| **协议字段名** | `bufSSO_Account_bufLoginAuthSig` | 字段名+数据类型 |
| **PDB 路径** | `<project>\\Release\\<module>.pdb` | 编译路径泄露（含模块名和目录结构） |
| **硬编码常量** | `dwSSO_App_dwAppClientVer` | 版本号字段 |
| **安全标识** | `msf_sec_extra` | 安全模块名称 |

### 字段命名规律

```
前缀规律 (从 DLL 字符串推断数据类型):
  bufXXX  → buffer (字节数组)
  dwXXX   → dword (uint32)
  strXXX  → string
  arXXX   → array
  cXXX    → const/char
  nXXX    → number (int32)
  bXXX    → boolean
  hXXX    → handle
  pXXX    → pointer
```

### 实战：从 C++ mangled name 反推接口

```
.?AUITXSSOBuffer@@
  → 接口名: ITXSSOBuffer

.?AV?$IDispatchImpl@UITXSSOBuffer@@$1?IID_ITXSSOBuffer@@3U_GUID@@B$1?LIBID_QQOpenSDKLib@@
  → 接口: ITXSSOBuffer
  → GUID: IID_ITXSSOBuffer
  → 库: <LibraryName> → <GUID> (如 QQOpenSDKLib → 30位16进制)

.?AVCTXSSOBufferImpl@@
  → 实现类: CTXSSOBufferImpl
```

**输出**：完整的接口定义、协议字段表、库名和 GUID。

---

## 结构体格式逆向与 debug 循环专题 🆕

### 问题

手工定义 struct 格式时，常出现 `struct.error: pack expected X items for packing (got Y)` 或 `'B' format requires 0 <= number <= 255`。

**根因**：格式符数量与字段数不匹配。

### 标准 debug 流程

```python
import struct

# Step 1: 先用 calcsize 验证格式
fmt = '<5IBBHI'   # 5×I + B + B + H + I
print(struct.calcsize(fmt))  # → 28 bytes

# Step 2: 用最小数据测试 pack
test = struct.pack(fmt, 
    40,    # total_len (I)
    2,     # version (I) 
    9,     # command (I)
    1,     # sequence (I)
    10000, # uin (I)
    0,     # enc (B)
    0,     # comp (B)
    0,     # reserved (H)
    4)     # body_len (I)
print(len(test), test.hex())

# Step 3: 验证 round-trip
vals = struct.unpack(fmt, test)
print(vals)

# Step 4: 对比原始值
assert vals[0] == 40
assert vals[4] == 10000
```

### 常见结构体格式总结

| 格式 | 字节数 | 用途 |
|------|-------|------|
| `<4I` | 16 | 4 个 uint32 |
| `<5IBBHI` | 28 | SSO 帧头 |
| `<HH` | 4 | TLV type+length |
| `<IHH` | 8 | TLV type+length+value hint |

### SSO 帧头 (28 bytes)

```
Offset  Size  Type    Field
0       4     I       total_length (不含自身)
4       4     I       version
8       4     I       command
12      4     I       sequence
16      4     I       uin
20      1     B       encrypt_method
21      1     B       compress_method
22      2     H       reserved
24      4     I       body_length
```

**关键**：total_length = 帧头大小(28) - total_len字段自身(4) + body长度 = 24 + len(body)

---

## 安装包静默提取专题 🆕

### 策略优先级

当 innoextract / 7zr / innounp 全部失败时，**直接运行安装包静默安装**：

```bash
# InnoSetup 静默安装
installer.exe /VERYSILENT /DIR="C:\extracted" /SUPPRESSMSGBOXES /NORESTART

# NSIS 静默安装
installer.exe /S /D=C:\extracted

# MSI 静默安装
msiexec /i installer.msi /qn TARGETDIR=C:\extracted
```

**关键**：安装完成后立即提取文件，然后卸载或保留。

---

## PyInstaller 打包程序提取专题 🆕

### 识别特征

```
自定义段名 (.mapo, .mapo2e 等 PyInstaller 特征)
.text RawSize=0 (内存展开)
大量 .pyd / .pyc 文件在 _internal/ 目录
Python3x.dll 依赖
```

### 提取流程

```bash
# 静默安装后，PyInstaller 程序会解压到 _internal/
# Python 源码 (.py) 直接可读
# 编译的扩展 (.pyd) 需 pe_analyze 分析导出表
```

### 关键产出

- `_internal/modules/` — 业务逻辑模块 (Python .py 源码)
- `_internal/*.pyd` — C 扩展 (用 pe_analyze 分析导出)
- `_internal/PySide6/` → Qt for Python 框架
- `_internal/playwright/` → 浏览器自动化

---

## 紧凑可编译重构策略 🆕

### 核心原则

**宁可 300 行编译通过的真代码，不要 3000 行编译失败的骨架。**

| 策略 | 错误做法 | 正确做法 |
|------|---------|---------|
| 模块数量 | 8+ 个骨架 .c 文件 | 5 个以内，每个有真实函数实现 |
| 头文件 | 每个模块一个 .h | 一个 common.h 包含所有定义 |
| 函数实现 | 空的 TODO 骨架 | 从伪代码提取的 Win32 等效实现 |
| 网络层 | "TODO: HTTP request" | WinHttpOpen+SendRequest+ReceiveResponse 完整调用链 |
| 加密 | "TEA implemented here" | 32 轮 TEA + CryptoAPI MD5 完整实现 |
| 构建 | 未测试的 CMakeLists | cmake --build 验证通过 |

### 合并策略

当伪代码中包含以下特征时，合并相关模块：
- WinHTTP/WinInet 调用 → 合并入 network.c
- TEA/XXTEA/MD5 常量 → 合并入 crypto.c
- QQ API URL 端点 → 合并入 business.c 作为常量

**不要**为每个小功能创建独立文件。少于 50 行的模块应合并。

---

## Web API 安全审计与逆向 🆕 (2026-06-07 实战验证)

### 核心原则

**Web API 安全审计也是逆向——逆向的是"暴露面"而非二进制。**
从外部可见的 HTTP 响应头、API 端点行为、错误消息中还原系统架构、
发现配置缺陷，与从二进制中还原源码遵循同一思维模式。

### 一键自动化攻击

```bash
# 全量 12 模块攻击审计（推荐首次使用）
python scripts/web_attack.py https://target.com

# 模块列表:
#   sqli          SQL 注入探测 (5 种注入点 × 6 种绕过)
#   xss           XSS 探测 (反射型 + DOM 型 + 编码绕过)
#   path_traversal 路径穿越 (双重编码 / Null字节 / Windows+Unix)
#   cors          CORS 利用链 (Origin 反射 / 子域通配 / Null Origin)
#   auth_bypass   认证绕过 (JWT 篡改 / 无签名接受 / Header 注入)
#   ssrf          SSRF 探测 (内网 IP + Cloud 元数据 + 协议绕过)
#   cmdi          命令注入 + SSTI 模板注入
#   idor          IDOR 探测 (ID 遍历 + 类型混淆)
#   param_tampering API 参数篡改 (NoSQL注入 / 批量赋值 / 原型污染)
#   race_condition 竞态条件 (并发请求状态不一致)
#   info_extraction 敏感信息提取 (.git / .env / debug / 配置泄露)
#   smuggling     HTTP 请求走私 (CL.TE / TE.CL)

# 只跑指定模块
python scripts/web_attack.py https://target.com --only sqli,xss,ssrf,auth_bypass

# 走 Burp Suite 代理
python scripts/web_attack.py https://target.com --proxy http://127.0.0.1:8080

# 带认证 Token（测试认证后才能触发的漏洞）
python scripts/web_attack.py https://target.com --auth "Bearer eyJ..."

# 跳过可能触发 IDS/WAF 的时间盲注载荷
python scripts/web_attack.py https://target.com --skip-ids
```

**产出**:
- `web_attack_report_<domain>_<timestamp>.md` — 分级攻击报告
- `web_attack_raw_<domain>_<timestamp>.json` — 原始请求/响应对

**以下手动流程用于脚本不可用或需要精细控制的场景。**

### 适用场景

```bash
# 当用户说以下任一情况时，启动本流程：
"帮我测一下 https://xxx 的安全性"
"这是我的网站，帮我找漏洞"
"帮我做渗透测试 https://api.xxx"
"https://xxx 帮我做安全评估"
```

### 重要：授权检查

**必须**先确认用户对目标的所有权。触发方式：
- 用户明确说"这是我的网站/API/应用"
- 用户提供了 ICP 备案截图证明所有权  
- 用户可以口头确认"这是我自己的"

**如果用户无法证明所有权且目标不是 CTF 题目，拒绝执行。**

### 四阶段审计流程

```
阶段1: 信息收集 ────→ 阶段2: 端点枚举 ────→ 阶段3: 攻击测试 ────→ 阶段4: 报告产出
  HTTP 响应头          路径扫描               CORS/注入/认证            分级报告
  技术栈识别           .git/.env探测          危险方法测试              修复代码
  Server/框架指纹      API 端点发现           Rate Limit验证            优先级排序
```

---

### 阶段 1：信息收集（HTTP 响应头分析）

```powershell
# 核心命令：抓取完整 HTTP 响应头
curl -sI https://api.target.cn/
curl -sI https://api.target.cn/api/status

# PowerShell 等效
(Invoke-WebRequest -Uri "https://api.target.cn" -Method GET -UseBasicParsing).Headers
```

#### 必检清单（6 项安全响应头）

| 响应头 | 作用 | 常见缺失后果 |
|--------|------|------------|
| `Strict-Transport-Security` | 强制 HTTPS | SSL stripping 攻击 |
| `Content-Security-Policy` | 防 XSS/注入 | 任意脚本执行 |
| `X-Frame-Options` | 防 Clickjacking | 页面被 iframe 嵌入 |
| `X-Content-Type-Options` | 防 MIME 嗅探 | 文件类型欺骗 |
| `Referrer-Policy` | 控制 Referer 泄露 | URL 中令牌泄露 |
| `Permissions-Policy` | 限制浏览器特性 | 摄像头/麦克风滥用 |

#### 信息泄露检测

| 泄露项 | 检查方式 | 风险 |
|--------|---------|------|
| `Server: nginx/1.24.0 (Ubuntu)` | 响应头 | 精准版本攻击 |
| `X-Powered-By: Express` | 响应头 | 框架暴露 |
| `X-New-Api-Version: latest` | 响应头 | 应用指纹 |
| `Cache-Version: <SHA256>` | 响应头 | 部署变更跟踪 |
| `X-Oneapi-Request-Id` | 响应头 | 时序分析 |
| Cache SHA256 指纹 | 响应头 | 部署变更关联 |

---

### 阶段 2：端点枚举（敏感路径扫描）

```powershell
# 批量扫描关键路径
$paths = @(
    # 版本控制泄露
    "/.git/HEAD", "/.git/config", "/.svn/entries",
    # 配置文件泄露
    "/.env", "/.env.backup", "/.env.production", "/.env.local",
    # 管理后台
    "/admin", "/admin/", "/console", "/login",
    # 开发工具
    "/swagger", "/swagger/index.html", "/swagger-ui.html",
    "/docs", "/api-docs", "/openapi.json", "/graphql", "/graphiql",
    # 调试端点
    "/debug/pprof/", "/actuator", "/actuator/health",
    "/actuator/env", "/actuator/mappings",
    # 监控端点
    "/health", "/status", "/metrics", "/info",
    # 常见漏洞路径
    "/wp-admin", "/phpinfo.php", "/info.php", "/test", "/backup",
    # API 端点
    "/api", "/api/", "/api/v1/", "/v1/", "/v2/",
    "/api/keys", "/api/users", "/api/admin", "/api/auth/login"
)

foreach ($p in $paths) {
    try {
        $r = Invoke-WebRequest -Uri "https://target$p" -Method GET -UseBasicParsing -TimeoutSec 10
        $preview = if ($r.Content.Length -le 150) { $r.Content } else { $r.Content.Substring(0, 150) + "..." }
        Write-Output "[$($r.StatusCode)] $p → $preview"
    } catch {
        Write-Output "[$($_.Exception.Response.StatusCode.value__)] $p → (error)"
    }
}
```

#### SPA catch-all 陷阱

React/Vue SPA 的前端路由会让 `/admin` `/.git` `/console` 等全部返回 `200 OK` + 前端 HTML 壳。
**这不是漏洞本身**，但有两个风险：

1. **掩盖真实问题**：如果其中某个路径确实有后端实现，难以从状态码发现
2. **SEO/爬虫污染**：死路径被搜索引擎索引

检测方法：所有路径返回的 `Content-Length` 是否完全一致（SPA 壳的典型特征）。

---

### 阶段 3：攻击面测试

#### 3.1 CORS 配置检测

```powershell
# 从恶意 Origin 发送预检请求
$headers = @{
    "Origin" = "https://evil.com"
    "Access-Control-Request-Method" = "POST"
    "Access-Control-Request-Headers" = "Authorization,Content-Type"
}
$r = Invoke-WebRequest -Uri "https://target/api/endpoint" `
    -Method OPTIONS -Headers $headers -UseBasicParsing

# 检查关键 CORS 头
$r.Headers["Access-Control-Allow-Origin"]      # 应为白名单域名，非 *
$r.Headers["Access-Control-Allow-Credentials"]  # 如有 Origin:*  则无意义
$r.Headers["Access-Control-Allow-Headers"]      # 非 *
$r.Headers["Access-Control-Allow-Methods"]      # 不应含 PUT/DELETE
```

| 危险组合 | 风险 |
|---------|------|
| `Allow-Origin: *` + `Allow-Credentials: true` | 浏览器拒绝（不符合规范），但非浏览器客户端可利用 |
| `Allow-Headers: *` | 任意请求头可通过，含 Authorization |
| `Allow-Methods` 含 `PUT/DELETE` | 允许写操作 |
| 无 `Allow-Origin` 但有 `Allow-Credentials: true` | 后端可能反射 Origin（需进一步测试） |

#### 3.2 未认证数据暴露测试

```powershell
# 测试无需认证的端点是否泄露敏感信息
# New-API/OneAPI 常见暴露点：
@("/api/status", "/api/setup", "/api/price", "/api/oauth/github",
  "/api/oauth/wechat", "/api/user/register") | ForEach-Object {
    try {
        $r = Invoke-WebRequest -Uri "https://target$_" -Method GET -UseBasicParsing
        $len = $r.Content.Length
        if ($len -gt 1000) {
            Write-Output "⚠️  $_ 返回 $len 字节 — 可能泄露配置数据"
        }
    } catch {}
}
```

#### 3.3 认证绕过测试

```powershell
# 测试 POST/PUT/DELETE 对未认证端点的响应
# 检查：
# - 是否返回 401（正确）vs 200（错误）
# - 错误信息是否泄露内部路径
# - 是否缺少 CSRF 保护

# 测试注册端点
$body = '{"username":"test","password":"test123"}'
$r = Invoke-WebRequest -Uri "https://target/api/user/register" `
    -Method POST -Body $body -ContentType "application/json" -UseBasicParsing
# 检查是否有验证码保护（Turnstile/hCaptcha）
```

#### 3.4 危险 HTTP 方法

```powershell
@("TRACE", "TRACK", "DEBUG", "CONNECT") | ForEach-Object {
    try {
        $r = Invoke-WebRequest -Uri "https://target/" -Method $_ -UseBasicParsing
        Write-Output "⚠️  $_ 方法允许: $($r.StatusCode)"
    } catch {
        Write-Output "✅  $_ 方法已禁用: $($_.Exception.Response.StatusCode.value__)"
    }
}
```

#### 3.5 路径穿越检测

```powershell
@("/%2e%2e/.env", "/../.env", "/..%2f..%2fetc/passwd") | ForEach-Object {
    try {
        $r = Invoke-WebRequest -Uri "https://target$_" -Method GET -UseBasicParsing
        Write-Output "⚠️  $_ 返回 $($r.StatusCode)"
    } catch {
        Write-Output "✅  $_ 已拦截: $($_.Exception.Response.StatusCode.value__)"
    }
}
```

#### 3.6 Rate Limiting 验证

快速连续发送 10+ 个请求到同一端点，观察是否返回 `429 Too Many Requests`。
**429 是好信号**——说明有速率限制。

---

### 阶段 4：报告产出规范

#### 安全评估报告结构

```markdown
# [服务名] 外部安全评估报告

## 一、发现总览（表格）
| ID | 严重性 | 问题 | 修复量 |

## 二、严重问题详情
每个问题包含：
- 攻击场景
- 实际泄露数据（部分脱敏）
- 修复代码（Nginx/Go/Python/Java）

## 三、修复优先级
- 立即：Ansible/手动 5 分钟修复项
- 本周：需要代码修改的
- 本月：架构级改进

## 四、已具备的安全防护
## 五、服务器端自查清单（需登录执行）
```

#### 严重性定义

| 级别 | 定义 | 示例 |
|------|------|------|
| 🔴 严重 | 可导致数据泄露、账户接管 | `/api/status` 未认证泄漏 OAuth 密钥 |
| 🔴 高危 | 可被利用但需条件 | CORS 全部 \* + credentials |
| 🟡 中危 | 增加攻击面但不可直接利用 | 版本信息暴露、SPA catch-all |
| 🟢 低危 | 不影响功能但不符合最佳实践 | 已禁用功能仍可访问 |
| ✅ 良好 | 正确实施的防护措施 | Rate Limit、TRACE 禁用 |

---

### 防护方案速查表

#### Nginx 通用加固

```nginx
server {
    # 隐藏服务器指纹
    server_tokens off;
    proxy_hide_header X-Powered-By;
    proxy_hide_header Server;

    # 6 项核心安全头
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;

    # 精确 CORS
    set $cors_origin "";
    if ($http_origin ~* "^https://(api\.yourdomain\.cn)$") {
        set $cors_origin $http_origin;
    }
    add_header Access-Control-Allow-Origin $cors_origin;

    # 屏蔽敏感路径
    location ~ ^/(\.git|\.env|admin|console|swagger|graphql|debug|wp-admin|backup|actuator|phpinfo) {
        return 404;
    }

    # API Rate Limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    location /api/ {
        limit_req zone=api burst=20 nodelay;
        proxy_pass http://backend;
    }
}
```

#### Go/Gin 常见修复

```go
// 区分认证/未认证的 API 响应
func GetStatus(c *gin.Context) {
    userId := c.GetInt("id")
    data := buildStatusData()
    if userId == 0 {
        // 仅返回公开信息，脱敏敏感字段
        data.GithubClientId = ""
        data.TurnstileSiteKey = ""
    }
    c.JSON(200, gin.H{"data": data, "success": true})
}

// 移除框架指纹头
func RemoveFingerprintHeaders() gin.HandlerFunc {
    return func(c *gin.Context) {
        c.Header("X-New-Api-Version", "")
        c.Header("X-Oneapi-Request-Id", "")
        c.Next()
    }
}
```

---

### 实战经验教训

#### 教训 1：`/api/status` 是最常见的信息泄露点

New-API/OneAPI 类 AI 网关的 `/api/status` 端点默认未认证返回完整系统配置。
**每次审计此类系统必须检查此端点。**

#### 教训 2：CORS `*` ≠ 安全

即使浏览器会因 `* + credentials: true` 而拒绝请求，非浏览器环境（curl/脚本/SDK）
完全不检查 CORS。`Allow-Headers: *` 让它们可携带任意认证头。

#### 教训 3：安全响应头缺失 = 极低成本修复点

6 个安全头的 Nginx 配置总计不到 10 行，但能防御 XSS/Clickjacking/SSL stripping 等。
**每个审计报告都必须优先指出此项。**

#### 教训 4：Rate Limit 存在 = 好信号

429 响应的存在意味着后端已有基本防护。应作为正面发现列入报告。

#### 教训 5：SPA 全 200 增加了审计难度

前端路由的 catch-all 行为让路径扫描结果"全是 200"，需对比 Content-Length 来区分。
应在报告中建议 Nginx 层做路由白名单。

---

## 法律与道德

- **仅对授权目标进行逆向工程与安全测试**（CTF、自己的程序、书面授权的渗透测试）
- 对他人网站/API 进行未授权的安全测试属于**违法行为**
- 逆向 DRM 保护的软件可能违反当地法律
- 不要将逆向得到的代码用于盗版分发
- 安全评估报告中的凭证/密钥必须脱敏
