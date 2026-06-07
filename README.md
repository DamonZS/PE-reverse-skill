# pe-reverse-analyzer

> 通用全平台逆向分析工具 —— 从二进制到可编译源码的完整链路

[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Android%20%7C%20iOS-blue)]()
[![Language](https://img.shields.io/badge/language-Python%203.10%2B-green)]()
[![License](https://img.shields.io/badge/license-MIT-orange)]()

覆盖 **Windows PE/EXE/DLL**、**Web**、**Android APK**、**iOS IPA** 三大平台，以及 **API 接口逆向**。支持从静态分析 → 加壳检测 → 脱壳 → 反编译到源码 → 修改源码 → 重构建完整链路。

适用于 **CTF 逆向题**、**恶意软件分析**、**APP 安全审计**、**API 逆向工程**。

---

## 核心理念

**报告只是中间产物，真实可编译可运行的源码才是终极目标。**

```
二进制文件 → 静态分析 → 脱壳(如需) → 反编译 → 源码重构 → 可编译项目
    │              │            │            │            │
    │              ↓            ↓            ↓            ↓
    │         analysis.json  dump.exe    .c/.java      CMakeLists.txt
    │         (中间产物)    (中间产物)  (终极产出)    build.gradle
    │                                              Makefile
    └→ 如果只出报告 = 失败                            (终极产出)
```

---

## 快速开始

### 安装

```bash
# 核心依赖（必须）
pip install pefile capstone

# 可选依赖
pip install unicorn  # 模拟器脱壳（仅无反模拟的壳）
```

### 使用

```bash
# PE → C/C++ 可编译项目（核心命令）
python scripts/reconstruct.py <target.exe> --output ./reconstructed/

# PE → 分析 + 重构一步到位
python scripts/pe_analyze.py <target.exe> --reconstruct --output report.txt

# 脱壳后 PE → 深度反编译
python scripts/deep_decompile.py <unpacked.exe> --output ./deep_analysis/

# 深度反编译结果 → 模块化源码整合
python scripts/integrate_v2.py

# APK → Android Studio 项目
python scripts/reconstruct.py <target.apk> --output ./reconstructed/

# API → Python/Go SDK
python scripts/reconstruct.py <flow.xml> --platform api --output ./sdk/
```

---

## 支持的壳类型

| 壳类型 | 脱壳策略 | 可靠性 |
|--------|---------|--------|
| UPX | `upx -d` 直接脱壳 | ✅ 可靠 |
| ASPack | ESP 定律脱壳 (x32dbg) | ✅ 可靠 |
| CNM 私有壳 | 挂起转储法 (`suspend_dump.py`) | ✅ 已验证 |
| 私有壳(通用) | 挂起转储法优先 | ✅ 推荐 |
| VMProtect | 无法完全脱壳 | ⚠️ 基于侧面信息推断 |
| Themida | 无法完全脱壳 | ⚠️ 同上 |

---

## 项目结构

```
pe-reverse-analyzer/
├── SKILL.md              # WorkBuddy Skill 定义（完整文档）
├── README.md             # 项目说明
├── .gitignore
├── scripts/
│   ├── reconstruct.py         # 主力：PE/APK/API → 可编译源码项目
│   ├── pe_analyze.py          # PE 静态分析 + 重构
│   ├── deep_decompile.py      # 函数级伪代码 + IAT 重建
│   ├── suspend_dump.py        # 挂起转储脱壳（推荐）
│   ├── integrate_v2.py        # 模块化源码整合（推荐）
│   ├── deep_extract.py        # 深度字符串/URL 提取
│   ├── apk_analyze.py         # APK → Android Studio 项目
│   ├── ipa_analyze.py         # IPA → Xcode 项目 (macOS)
│   ├── api_reverse.py         # API → Python/Go SDK + OpenAPI
│   ├── auto_evolve.py         # 自动进化引擎
│   ├── common.py              # 共享工具函数
│   ├── ghidra_headless_decompile.py  # Ghidra Headless 集成
│   ├── integrate_final.py     # 最终整合
│   ├── integrate_sources.py   # v1 整合 (已废弃)
│   ├── auto_unpack.py         # Unicorn 模拟器脱壳 (已废弃)
│   └── debug_unpack.py        # Windows 调试 API 脱壳 (已废弃)
└── evolution/                  # 自动进化数据库
    ├── detection_db.json
    ├── knowledge_base.json
    ├── sessions.json
    └── evolution_report.txt
```

---

## 产出示例

### PE → C/C++ 项目

```
reconstructed_<name>/
├── CMakeLists.txt / Makefile
├── OVERVIEW.md
├── src/
│   ├── main.c            # WinMain 重构
│   ├── network.c         # 网络通信 (WinHTTP/QQ API)
│   ├── ui.c              # UI 控件
│   ├── runtime.c         # 运行时分发
│   ├── crypto.c          # 加密 (TEA/XXTEA)
│   ├── registry.c        # 注册表操作
│   └── business.c        # 业务逻辑
├── include/
│   ├── common.h          # IAT 映射 + thunk 定义
│   └── strings.h         # 提取的字符串常量
└── pseudocode/           # 200 个函数的伪代码
```

### APK → Android Studio 项目

```
reconstructed_<name>/
├── build.gradle / settings.gradle
└── app/src/main/
    ├── java/             # jadx 反编译的 Java 源码
    ├── AndroidManifest.xml
    ├── res/              # 资源文件
    └── smali/            # Smali 代码（可直接编辑重打包）
```

---

## 专题文档

完整的技术细节请查看 [SKILL.md](./SKILL.md)，涵盖：

- **CNM 私有壳专题** — 特征识别、脱壳方案、IAT 修复
- **易语言程序逆向** — 运行时 VM 分发器、thunk 表解析
- **Ghidra Headless 集成** — 脚本陷阱、CNM VM 代码限制
- **导入表推断协议** — 从 DLL 导入组合反推通信协议
- **DLL 字符串 → COM 接口** — C++ mangled name 反推接口定义
- **结构体格式逆向** — struct 格式 debug 循环
- **NSIS+7z BCJ2 安装包** — 提取流程与陷阱
- **x64 .node 文件分析** — QQ NT/Electron 原生插件

---

## 工具链

### PE 逆向
- [Ghidra](https://ghidra-sre.org/) — 免费反编译器（需 JDK 17+）
- [x64dbg](https://x64dbg.com/) — Windows 调试器
- [7-Zip](https://www.7-zip.org/) — NSIS 安装包解压（py7zr 不支持 BCJ2）

### APK 逆向
- [apktool](https://ibotpeaches.github.io/Apktool/) — APK 解包/重打包
- [jadx](https://github.com/skylot/jadx) — DEX → Java 反编译

### iOS 逆向 (macOS)
- [class-dump](http://stevenygard.com/projects/class-dump/)
- [Frida](https://frida.re/)

---

## 法律声明

- 仅对授权目标进行逆向工程（CTF、自己的程序、书面授权的渗透测试）
- 逆向 DRM 保护的软件可能违反当地法律
- 不要将逆向得到的代码用于盗版分发
