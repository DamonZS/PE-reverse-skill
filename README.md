# pe-reverse-analyzer — 全平台逆向分析 + AI 安全技能路由平台

> 从二进制到可编译源码 | 从暴露面到安全加固 | 从静态分析到 AI 深度解读 | 20+ 安全技能模块路由 | 40+ CTF 专项子技能

![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Android%20%7C%20iOS%20%7C%20Web-blue)
![Language](https://img.shields.io/badge/language-Python%203.10%2B-green)
![License](https://img.shields.io/badge/license-CNF--NC%20%E9%9D%9E%E5%95%86%E4%B8%9A%E5%8D%81%E4%BF%AE-red)

本项目整合了两套成熟工具链：

- **pe-reverse-analyzer** — PE/APK/IPA/Web 全平台逆向引擎（静态分析→脱壳→反编译→源码重构完整链路）
- **[reverse-skills](./reverse-skills/)** — 面向 AI Agent 的网络安全技能路由系统（20 核心模块 + 40+ CTF 专项子技能）

另有 `scripts/codex-instruct.py` Codex CLI 指令注入工具和 [game-hacking-techniques](./docs/game-hacking-techniques-SKILL.md) 游戏安全研究文档。

---

## 平台覆盖

覆盖 **Windows PE/EXE/DLL**、**Web**、**Android APK**、**iOS IPA** 四大平台，以及 **API 接口逆向** 与 **Web API 安全审计**。支持从静态分析 → 加壳检测 → 脱壳 → 反编译到源码 → 修改源码 → 重构建完整链路，并在关键分析节点引入AI 辅助深度解读。

适用于 **CTF 逆向题**、**恶意软件分析**、**APP 安全审计**、**Web 安全评估**、**API 逆向工程**。

---

## 核心理念

**报告只是中间产物，真实可编译可运行的源码才是终极目标。**

```
二进制文件 → 静态分析 → 脱壳(如需) → 反编译 → 源码重构 → 可编译项目
    │              │            │            │
    │              ↓            ↓            ↓
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
python scripts/codex_helper.py deploy


# 交互式向导（推荐新手）
python scripts/codex_helper.py interactive

# ─── PE 逆向 ───
# PE → C/C++ 可编译项目（核心命令）
python scripts/reconstruct.py <target.exe> --output ./reconstructed/

# PE → 分析 + 重构一步到位
python scripts/pe_analyze.py <target.exe> --reconstruct --output report.txt

# 脱壳后 PE → 深度反编译
python scripts/deep_decompile.py <unpacked.exe> --output ./deep_analysis/

# 深度反编译结果 → 模块化源码整合
python scripts/integrate_v2.py

# ─── 移动端逆向 ───
# APK → Android Studio 项目
python scripts/reconstruct.py <target.apk> --output ./reconstructed/

# ─── API 逆向 ───
# API → Python/Go SDK
python scripts/reconstruct.py <flow.xml> --platform api --output ./sdk/

# 静态分析 → AI 深度解读
python scripts/codex_helper.py prompt --type pe-analyze --target target.exe --analysis analysis.json
```

---

## Web 端攻击逆向工具与方法

> Web 安全审计和 API 逆向也是逆向工程的重要分支——逆向的是系统暴露面、通信协议和安全配置，而非二进制。

### 适用场景

| 场景 | 说明 |
|------|------|
| 自有 Web/API 安全审计 | 对自己的服务进行渗透测试，产出修复方案 |
| CTF Web 题 | 分析 Web 题目逻辑、找 flag、绕过鉴权 |
| API 接口逆向 | 还原未文档化的 API 请求格式、签名算法、鉴权流程 |
| 配置安全评估 | 检测安全响应头、CORS、Rate Limit 等基础设施配置 |

**前提：仅对授权目标执行。CTF 题目、自己的系统、书面授权的渗透测试。**

---

### 四阶段审计流程

```
阶段1: 信息收集 ────→ 阶段2: 端点枚举 ────→ 阶段3: 攻击测试 ────→ 阶段4: 报告产出
  HTTP 响应头          路径扫描               CORS/注入/认证            分级报告
  技术栈识别           .git/.env 探测        危险方法测试              修复代码
  Server/框架指纹      API 端点发现           Rate Limit 验证            优先级排序
```

---

### 核心工具链

#### 信息收集

| 工具 | 用途 | 命令示例 |
|------|------|----------|
| **curl** | HTTP 响应头抓取、请求重放 | `curl -sI https://target.com -A "Mozilla/5.0"` |
| **httpx** (projectdiscovery) | 批量 URL 存活探测、响应头提取 | `echo "https://target.com" \| httpx -title -status-code -content-length` |
| **whatweb** | 技术栈指纹识别 | `whatweb https://target.com -v` |
| **wappalyzer** (CLI) | 前端框架/JS 库识别 | `wappalyzer https://target.com` |
| **nmap** | 端口扫描、服务识别 | `nmap -sV -p 80,443,8080 target.com` |
| **shodan** (CLI) | 公网资产搜索 | `shodan search "X-Powered-By:Express"` |
| **dnsx** (projectdiscovery) | 子域名解析与验证 | `echo "target.com" \| dnsx -a -aaaa -cname` |
| **mapcidr** (projectdiscovery) | IP 段展开 | `mapcidr -cidr 192.168.1.0/24` |

#### 端点枚举与路径扫描

| 工具 | 用途 | 命令示例 |
|------|------|----------|
| **ffuf** | 高速目录/参数 Fuzz | `ffuf -u https://target.com/FUZZ -w wordlist.txt -mc 200,204,301,302,403` |
| **gobuster** | 目录爆破 | `gobuster dir -u https://target.com -w wordlist.txt` |
| **dirsearch** | 综合目录扫描 | `dirsearch -u https://target.com -e php,html,js` |
| **arjun** | 参数发现（GET/POST） | `arjun -u https://target.com/api/test` |
| **katana** (projectdiscovery) | 爬虫 + 端点提取 | `katana -u https://target.com -d 3 -jc -jsl` |
| **waybackurls** | 从历史快照提取旧路径 | `echo "target.com" \| waybackurls` |
| **uro** | 去重 URL 列表 | `cat urls.txt \| uro \| tee clean_urls.txt` |
| **gau** (projectdiscovery) | 从 Wayback Machine 提取 URL | `gau target.com -b pdf,jpg,png` |
| **hakrawler** | 快速 Web 爬虫 | `echo "https://target.com" \| hakrawler -subs -u` |

#### 漏洞扫描与攻击测试

| 工具 | 用途 | 命令示例 |
|------|------|----------|
| **nuclei** (projectdiscovery) | 综合漏洞扫描（CVE/配置/Web 漏洞） | `nuclei -u https://target.com -t cves/,misconfiguration/,vulnerabilities/` |
| **OWASP ZAP** | 主动/被动扫描、API 测试 | `zap-cli quick-scan -s all https://target.com` |
| **Burp Suite** | 流量拦截、重放、Intruder 爆破 | GUI 操作，配置代理 `127.0.0.1:8080` |
| **sqlmap** | SQL 注入自动化利用 | `sqlmap -u "https://target.com/api?id=1" --batch --dbs` |
| **commix** | 命令注入检测 | `commix -u "https://target.com/search?q=test"` |
| **xsstrike** | XSS 检测与利用 | `xsstrike -u "https://target.com/search?q=test"` |
| **ssrf-king** | SSRF 测试 | `ssrf-king -u "https://target.com/api/fetch?url=XXX"` |
| **kadabra** | 自动 XSS/LFI/SQLi 检测 | `kadabra -u https://target.com/page?id=1` |
| **feroxbuster** | 多线程目录爆破 | `feroxbuster -u https://target.com -w wordlist.txt` |
| **nikto** | Web 服务器漏洞扫描 | `nikto -h https://target.com` |

#### API 专项测试

| 工具 | 用途 | 命令示例 |
|------|------|----------|
| **Postman / Bruno** | API 请求构造与测试 | GUI 操作，支持环境变量、脚本 |
| **httpie** | 人性化 HTTP 客户端 | `http POST https://target.com/api/login user=admin pass=123` |
| **curl** | 最灵活的 API 测试工具 | `curl -X POST https://target.com/api -H "Content-Type:application/json" -d '{"a":1}'` |
| **kiterunner** | API 路径发现（支持 OpenAPI spec） | `kr scan https://target.com -w routes-large.kite` |
| **OpenAPI-Tools** | Swagger/OpenAPI 文档解析 | `npx @openapitools/swagger-cli validate openapi.yaml` |
| **Hoppscotch** | 轻量级 Web API 测试 | 浏览器直接访问 https://hoppscotch.io |
| **insomnia** | 开源 API 客户端 | GUI，支持 gRPC/GraphQL/WebSocket |

#### CORS 专项测试

```bash
# 手动 CORS 测试
curl -H "Origin: https://evil.com" \
     -H "Access-Control-Request-Method: POST" \
     -X OPTIONS \
     -v https://target.com/api/endpoint

# 检查响应头
# Access-Control-Allow-Origin: *        ← 危险
# Access-Control-Allow-Credentials: true ← 如果 Origin=* 则无意义
# Access-Control-Allow-Headers: *       ← 危险
```

#### 子域名枚举（Web 攻击前置）

| 工具 | 用途 | 命令示例 |
|------|------|----------|
| **subfinder** (projectdiscovery) | 被动子域名枚举 | `subfinder -d target.com -o subdomains.txt` |
| **amass** | 主动+被动子域名枚举 | `amass enum -d target.com -o amass.txt` |
| **puredns** | 高速 DNS 解析与枚举 | `puredns resolve subdomains.txt -r resolvers.txt` |
| **shuffledns** | 高性能子域名爆破 | `shuffledns bruteforce sub.txt -d target.com -w wordlist.txt` |

---

### 方法与实战技巧

#### 方法 1：信息收集最大化

```bash
# 1. 完整响应头抓取（PowerShell）
(Invoke-WebRequest -Uri "https://target.com" -Method GET -UseBasicParsing).Headers

# 2. 技术栈指纹
whatweb -v https://target.com
wappalyzer https://target.com

# 3. 检查 6 项安全响应头
curl -sI https://target.com | grep -E "Strict-Transport|Content-Security|X-Frame|X-Content-Type|Referrer|Permissions"

# 4. 提取 Server/X-Powered-By（版本暴露）
curl -sI https://target.com | grep -E "Server:|X-Powered-By:|X-AspNet-Version:"

# 5. 全端口快速扫描
nmap -p- --open -T4 target.com

# 6. 子域名枚举 + HTTP 探测一键式
subfinder -d target.com | httpx -title -status-code -content-length -tech-detect
```

#### 方法 2：敏感路径枚举策略

优先扫描的路径清单（按优先级）：

```
# P0：配置泄露（最高优先级）
/.env
/.git/HEAD
/.git/config
/.svn/entries
/.DS_Store
/.aws/credentials
/.ssh/id_rsa
/.npmrc
/.dockerignore
/docker-compose.yml
/.kube/config

# P1：管理后台
/admin
/admin/
/console
/login
/dashboard
/phpmyadmin
/debug
/manager
/administrator

# P2：API 文档泄露
/swagger
/swagger/index.html
/swagger-ui.html
/docs
/api-docs
/openapi.json
/graphql
/graphiql
/v2/api-docs

# P3：监控/调试端点
/actuator
/actuator/env
/actuator/mappings
/health
/status
/metrics
/debug/pprof/
/__pycache__/
/.well-known/

# P4：备份/旧版本
/backup
/backup.sql
/db.sql
/.env.backup
/config.old
/.git/config
```

#### 方法 3：CORS 绕过测试

```
正常请求 → 检查 Access-Control-Allow-Origin
           ↓ (如果是 *)
尝试带凭据的请求 → 检查是否真的生效
           ↓
尝试 Origin 反射（有些后端会反射请求中的 Origin）
           ↓
尝试 null origins、子域名绕过、协议绕过（http:// vs https://）
           ↓
尝试通过 XSS 绕过 CORS（利用可信子域）
```

#### 方法 4：未认证数据暴露检测

```bash
# 对常见未认证端点发 GET 请求，观察响应体长度
# 如果 > 1000 字节，可能泄露配置数据

endpoints=(
  "/api/status"
  "/api/setup"
  "/api/version"
  "/api/config"
  "/api/health"
  "/actuator/env"
  "/v1/models"
  "/api/users"
  "/api/keys"
)

for ep in "${endpoints[@]}"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com$ep")
  len=$(curl -s "https://target.com$ep" | wc -c)
  echo "[$code] $ep → $len bytes"
done
```

#### 方法 5：Rate Limit 验证

```bash
# 快速发送 20 个请求，观察是否返回 429
for i in {1..20}; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/api/chat")
  echo "[$i] $code"
  sleep 0.1
done
# 如果有 429 → 好信号（有 Rate Limit）
# 如果全部 200 → 无 Rate Limit（风险）
```

#### 方法 6：JWT / Session 攻击

```bash
# 1. 检查 JWT 是否可未签名访问
# 把 alg 改为 none，删除签名部分，观察是否仍被接受

# 2. 检查 Session Fixation
# 登录前后 Session ID 是否变化

# 3. 检查 JWT 密钥暴力破解
# 使用 john 或 hashcat 对弱密钥进行破解
hashcat -m 16500 jwt_hash.txt rockyou.txt

# 4. 检查 Token 泄露在 URL 中
# 搜索 Response Headers / JS 文件中的 Token
```

#### 方法 7：SSRF 检测

```bash
# 常见 SSRF 参数名
url=
redirect=
uri=
path=
continue=
window=
next=
data=
reference=
site=
html=
val=
validate=
domain=

# 测试 payload
http://169.254.169.254/  # AWS 元数据
http://localhost:80/
http://127.0.0.1:8080/
file:///etc/passwd
```

---

### 实战案例：API 安全审计报告产出

完整流程见 [SKILL.md - Web API 安全审计与逆向](./SKILL.md) 章节。

**报告结构：**

```markdown
# [服务名] 外部安全评估报告

## 一、执行概要
- 测试时间、范围、授权情况
- 发现数量统计（按严重性分级）

## 二、发现详情
| ID | 严重性 | 问题 | 修复量 | 状态 |
|----|--------|------|--------|------|
| F1 | 🔴 严重 | /api/status 未认证泄露配置 | 10 行 | Open |
| F2 | 🔴 高危 | CORS Allow-Origin:* + Credentials | 15 行 | Open |

每个发现包含：
- 攻击场景描述
- 实际请求/响应（脱敏）
- 风险评级依据
- 完整修复代码（Nginx/Go/Python/Java）

## 三、修复优先级
- 立即（< 1 小时）：Nginx 配置修改
- 本周：代码层修复
- 下月：架构级改进

## 四、已具备的防护（正面发现）
- Rate Limit ✅
- SQL 注入防护 ✅
- XSS 过滤 ✅

## 五、服务器端自查清单
（需要登录服务器执行）
```

---

### 推荐学习资源

| 资源 | 类型 | 链接 |
|------|------|------|
| **OWASP Top 10** | 标准 | https://owasp.org/www-project-top-ten/ |
| **PortSwigger Web Security Academy** | 免费实战练习 | https://portswigger.net/web-security |
| **HackTheBox** | CTF 靶场 | https://www.hackthebox.com/ |
| **VulnHub** | 漏洞靶机 | https://www.vulnhub.com/ |
| **API Security Checklist** | Checklist | https://github.com/shieldfy/API-Security-Checklist |
| **OWASP API Security Top 10** | 标准 | https://apisecurity.io/ |
| **CTF Web Challenges** | 练习平台 | https://ctftime.org/ |

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
├── LICENSE               # CNF-NC 非商业许可协议
├── .gitignore
├── scripts/
│   ├── codex_helper.py        # AI 辅助逆向引擎（指令注入 + Prompt 生成 + 交互向导）
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
│   ├── debug_unpack.py        # Windows 调试 API 脱壳 (已废弃)
│   └── web_attack.py          # Web 主动攻击引擎（12 模块）
├── reverse-skills/           # ⭐ AI 安全技能路由系统（20 模块 + 40+ CTF 子技能）
├── docs/
│   └── game-hacking-techniques-SKILL.md  # 游戏安全研究全链路文档
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
- **Web API 安全审计** — 四阶段流程、Nginx 加固、CORS 检测

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

### Web 安全审计
> 详见上方「Web 端攻击逆向工具与方法」章节，工具链已完整列出。

**浏览器开发者工具（内置，无需安装）：**
- **Network 面板** — 抓取 XHR/Fetch 请求、Headers、Payload、Response
- **Application 面板** — 查看 Cookie、LocalStorage、SessionStorage、IndexedDB
- **Console 面板** — 执行 JavaScript、测试 XSS payload
- **Sources 面板** — 调试 JS、下断点、修改 JS 变量

---

## reverse-skills — AI 安全技能路由系统

本项目集成了 **[reverse-skills](./reverse-skills/)**，这是一个专为 AI Agent（Claude Code / Codex CLI / Cursor 等）设计的网络安全技能路由平台。

### 核心能力

- **20 个核心技能模块**：APK 逆向、IDA Pro（72 MCP 工具）、JS 逆向、渗透测试工具链、漏洞利用（pwn）、固件渗透、EDR 绕过、恶意软件分析、LLM 安全、供应链安全等
- **40+ CTF 专项子技能**：Web 运行时、Kerberos 委派、DPAPI 凭据链、容器逃逸、JWT 混淆、SSRF 元数据枢轴等
- **技能路由引擎**：基于 600+ 关键词自动路由到正确的技能模块和执行命令
- **工具自举**：Windows/Linux/macOS 一键安装所有依赖工具
- **经验自动积累**：完成任务后自动回写经验日志，形成知识自增长

### 与 pe-reverse-analyzer 的关系

- pe-reverse-analyzer 专注**二进制逆向**（PE/APK/IPA → 可编译源码）
- reverse-skills 覆盖**安全测试全链路**（渗透测试、漏洞利用、CTF 竞赛）
- 两者互补：逆向结果可喂入技能路由系统进行进一步的攻击链构造或安全加固

### 快速开始

```bash
# 查看 reverse-skills 完整文档
cat reverse-skills/README.md

# 在 AI Agent 中使用（Claude Code / Codex CLI / Cursor）
# Agent 会自动读取 RULES.md 完成技能路由
```

---

## codex-instruct — Codex CLI 指令注入工具

位于 `scripts/codex-instruct.py`，轻量级 Codex CLI 指令注入工具：

- 自动扫描系统中的 `.codex` 安装目录
- 通过 `model_instructions_file` 注入自定义系统指令
- 内置 CTF 沙盒和 GPT-5.5 无限制模式指令集
- 支持 `--dry-run` 预览和配置回滚

```bash
# 部署内置指令
python scripts/codex-instruct.py

# 预览模式
python scripts/codex-instruct.py --dry-run
```

---

## 许可协议

本项目采用 **CNF-NC 非商业许可协议**（详见 [LICENSE](./LICENSE)）。

### 允许

- 阅读、学习、研究源代码
- 在非商业目的下运行
- Fork 用于个人学习（副本仍受本协议约束）

### 禁止

- **禁止商业使用** — 不得直接或间接用于任何商业目的
- **禁止修改源代码** — 包括人工修改和 AI 自动修改，任何形式的变更均被禁止
- **禁止再分发** — 未经书面许可不得发布到任何平台
- **禁止用于非法目的** — 未经授权的逆向工程、破解 DRM、攻击未授权目标等


---

## 免责声明

1. 本项目按"现状"提供，不附带任何明示或暗示的保证
2. 版权持有人不对因使用本项目而产生的任何直接、间接、附带或后果性损害承担责任
3. 使用者应自行评估法律风险和技术风险，确保使用行为符合当地法律法规
4. 使用者必须确保在合法授权的前提下使用（CTF 竞赛、自己的程序、书面授权的渗透测试、法律允许的安全研究）
5. 本项目不提供任何技术支持保证
6. **使用者对使用本项目的一切行为负全部责任**

---

## 法律声明

- 仅对授权目标进行逆向工程（CTF、自己的程序、书面授权的渗透测试）
- 逆向 DRM 保护的软件可能违反当地法律
- 不要将逆向得到的代码用于盗版分发
- Web 安全审计需确认目标所有权后方可执行


---

## PentAGI 架构迁移后的使用指南

本项目已加入 PentAGI 风格的可恢复逆向分析运行时：用 `ReverseSession` 记录分析会话，用 `Flow / Task / Subtask` 拆分流程，用 `AgentLoop` 按“分析 → 调工具 → 记录 → 下一步”的循环推进，用 `ToolExecutor` 统一封装逆向工具，用 `Provider` 适配规则引擎或模型能力，并用 `ReportBuilder` 输出报告。

### 1. 本地准备

```powershell
cd D:\Project\pe-reverse-analyzer-main
python -m pip install -r requirements.txt
```

当前 `requirements.txt` 包含：

- `pefile`：PE 头、节区和导入表解析。
- `capstone`：反汇编能力，缺失时对应工具会以 `unavailable` 状态返回。
- `requests`：为后续 provider / API 集成预留。

`yara-python` 等扩展能力是可选依赖；未安装时工具不会让整体流程崩溃，而是返回结构化的 `unavailable` 结果。

### 2. CLI 快速开始

```powershell
# 查看命令
python -m reverse_analyzer --help

# 查看当前可用运行时组件
python -m reverse_analyzer list-tools
python -m reverse_analyzer list-tools --json

# 初始化本地知识库
python -m reverse_analyzer init-knowledge

# 查看知识库清单；不存在时自动创建
python -m reverse_analyzer show-knowledge --init-if-missing

# 分析一个样本
python -m reverse_analyzer analyze .\samples\app.exe --out .\reports\app --max-iterations 8
```

`analyze` 命令会输出一段 JSON，包含 `session_id`、输出目录、AgentLoop 结果和生成的报告路径。

### 3. `analyze` 会生成什么

假设执行：

```powershell
python -m reverse_analyzer analyze .\samples\app.exe --out .\reports\app --max-iterations 8
```

输出目录通常包含：

```text
reports/app/
├─ report.json                  # 机器可读报告
├─ report.md                    # 人类可读报告
├─ trace.jsonl                  # 每一步 provider/tool/event 追踪日志
├─ sessions/
│  └─ <session_id>.json          # 可恢复的 ReverseSession 状态
└─ artifacts/                   # 预留给后续工具产物
```

默认规则 Provider 会按顺序尝试以下内置工具：

1. `file_info`：读取路径、文件名、大小和后缀。
2. `hash`：计算 `md5 / sha1 / sha256`。
3. `strings_extract`：提取 ASCII / UTF-16LE 可打印字符串。
4. `packer_detect`：基于节名、熵和可疑 API 字符串做壳迹象判断。
5. `section_entropy_scan`：计算节区或文件块熵。
6. `pe_header_scan`：使用 `pefile` 解析 PE 元数据和导入表。

工具异常会被 `ToolExecutor` 归一化为 `ToolResult`，不会直接打断整个分析链路。

### 4. 架构对应关系

| PentAGI 思路 | 本项目实现 | 位置 |
|---|---|---|
| Flow / Task / Subtask 编排 | 可序列化的会话、流程、任务模型 | `reverse_analyzer/core/models.py` |
| Agent tool-call loop | Provider 决策、Tool 执行、Observation 记录循环 | `reverse_analyzer/agent/loop.py` |
| Tool Executor 抽象 | 统一注册、执行、异常归一化 | `reverse_analyzer/tools/executor.py` |
| 静态逆向工具 | 文件信息、哈希、字符串、PE、熵、壳检测、YARA stub | `reverse_analyzer/tools/static_tools.py` |
| Provider 抽象 | `BaseProvider`、规则 Provider、OpenAI-compatible stub | `reverse_analyzer/providers/` |
| Knowledge / 记忆 | 本地 JSON 知识库与相似特征查询 | `reverse_analyzer/knowledge/base.py` |
| Observability / Logs | JSONL trace 与 session 持久化 | `reverse_analyzer/runtime/` |
| Report | Markdown / JSON 报告 | `reverse_analyzer/report/builder.py` |
| Docker Compose | CLI 容器和后续 Dashboard 端口预留 | `Dockerfile`、`docker-compose.yml` |

### 5. Docker / Compose 用法

> 在 Windows 上不要输入 `Docker Desktop` 作为命令。应先从开始菜单启动 Docker Desktop，等 Docker Engine 运行后，再在 PowerShell 里执行下面的 `docker compose ...` 命令。

```powershell
# 构建镜像
docker compose build

# 查看 CLI 帮助
docker compose run --rm reverse-analyzer --help

# 初始化挂载工作区中的知识库
docker compose run --rm reverse-analyzer init-knowledge

# 分析挂载到 /workspace 的样本
docker compose run --rm reverse-analyzer analyze /workspace/samples/app.exe --out /workspace/reports/app --max-iterations 8
```

`docker-compose.yml` 预留了 `8088:8088` 端口，以及 `.reverse_analyzer`、`samples`、`reports` volume。当前主要用于 CLI 分析环境；后续可以在同一 compose 文件里接入 Web UI / Dashboard。



### Ghidra Headless decompilation

`analyze` can optionally run Ghidra Headless and include decompiler status in
`report.json` and `report.md`.

```powershell
# Print the local setup guide
python -m reverse_analyzer --install-guide ghidra

# Run normal analysis plus Ghidra decompilation when Ghidra is configured
python -m reverse_analyzer analyze .\samples\app.exe --out .\reports\app --max-iterations 8 --decompile

# Override automatic discovery for one run
python -m reverse_analyzer analyze .\samples\app.exe --out .\reports\app --decompile --ghidra-home C:\Tools\ghidra_<version>_PUBLIC
```

Discovery order:

1. `--ghidra-home`
2. `GHIDRA_HEADLESS`
3. `GHIDRA_HOME\support\analyzeHeadless.bat`
4. Common Windows paths such as `C:\Tools\ghidra_*`, `C:\Program Files\Ghidra\ghidra_*`, and `D:\Tools\ghidra_*`

If Ghidra is not installed, analysis still succeeds. The report records
`decompiler.status = "unavailable"` and includes a setup hint. Install Ghidra by
following `python -m reverse_analyzer --install-guide ghidra`.

When available, Ghidra artifacts are written under:

```text
<out>/decompiled/ghidra/
  functions.json
  call_graph.json
  strings_xrefs.json
  imports_xrefs.json
  summary.json
  pseudocode/*.c
  disassembly/*.asm
  ghidra.log
```

### Frida dynamic runtime tracing

`analyze --dynamic` now adds a real dynamic-reversing pass instead of relying
only on static imports and strings. The built-in hook plan covers loader APIs,
memory/protection APIs, process creation, file/registry activity, WinHTTP /
WinINet, raw Winsock traffic, and common anti-debug checks.

```powershell
# Print setup instructions
python -m reverse_analyzer --install-guide frida

# Static analysis + Frida instrumentation
python -m reverse_analyzer analyze .\samples\app.exe --out .\reports\app --dynamic --dynamic-duration 15

# Pass arguments to a spawned target
python -m reverse_analyzer analyze .\samples\app.exe --out .\reports\app --dynamic --dynamic-arg "--help"

# Attach to an already running PID
python -m reverse_analyzer analyze .\samples\app.exe --out .\reports\app --dynamic --attach-pid 1234

# Use a target-specific hook plan
python -m reverse_analyzer analyze .\samples\app.exe --out .\reports\app --dynamic --dynamic-hook-file .\hooks.json
```


Built-in Frida hook profiles:

| Profile | Use case |
| --- | --- |
| `auto` | Choose a profile from static signals such as packer score, imports, and strings. |\n| `behavior` | Broad default coverage across loader, memory, process, file, registry, and network APIs. |
| `quick` | Small high-signal smoke-test set for lower overhead. |
| `unpacking` | Loader, memory, anti-debug, and injection hooks for unpacking/runtime API resolution. |
| `network` | Dynamic resolver + network hooks for protocol/API reconstruction. |
| `persistence` | Loader, file, registry, and process hooks for installation/persistence behavior. |
Custom hook plans are JSON lists, or an object with a `hooks` list:

```json
{
  "hooks": [
    {
      "module": "kernel32.dll",
      "name": "CreateFileW",
      "category": "file",
      "capture_return": true,
      "args": [
        {"index": 0, "name": "path", "type": "wide"},
        {"index": 4, "name": "creation_disposition", "type": "u32"}
      ]
    }
  ]
}
```

Dynamic artifacts are written under:

```text
<out>/dynamic/frida/
  agent.js       # generated instrumentation script
  events.jsonl   # raw call / return / hook lifecycle events
  trace.json     # calls, returns, installed/missing hooks, module snapshot
  summary.json   # compact counts for reports
```


### Procmon OS behavior capture

Frida is precise for API-level instrumentation, but protected samples may block
or distort injected instrumentation. `--dynamic-backend procmon` adds a second
backend based on Microsoft Sysinternals Process Monitor: it records OS-level
file, registry, process/thread, image-load, TCP, and UDP events into a PML trace
and optionally converts the trace to CSV for report summaries.

```powershell
# Print setup instructions
python -m reverse_analyzer --install-guide procmon

# Procmon-only behavioral capture
python -m reverse_analyzer analyze .\samples\app.exe --out .\reports\app --dynamic --dynamic-backend procmon --dynamic-duration 15

# Run both Frida and Procmon in the same analysis session
python -m reverse_analyzer analyze .\samples\app.exe --out .\reports\app --dynamic --dynamic-backend all

# Use a Procmon executable that is not on PATH
python -m reverse_analyzer analyze .\samples\app.exe --out .\reports\app --dynamic --dynamic-backend procmon --procmon-path C:\Tools\Procmon64.exe
```

Procmon artifacts are written under:

```text
<out>/dynamic/procmon/
  trace.pml      # native Procmon backing file
  events.csv     # converted event table when /OpenLog /SaveAs succeeds
  summary.json   # operation/category/path counts for reports
  manifest.json  # capture metadata
```

### Dynamic evidence → reconstruction planning

When `--dynamic` is combined with `--reconstruct`, Frida and Procmon results are
normalized into `dynamic_evidence` and written into the generated project:

```text
<out>/reconstructed_<sample>/analysis/dynamic_evidence.json
```

The reconstruction engine uses this evidence to:

- create module files even when static decompilation has no recovered functions yet;
- boost module priorities from observed behavior such as `connect`, `WinHttpSendRequest`,
  `CreateRemoteThread`, `Process Create`, or registry/file activity;
- add `dynamic_correlation` subtasks to `analysis/reconstruction_plan.json` so the next
  reconstruction pass starts from behavior proven at runtime.

Example:

```powershell
python -m reverse_analyzer analyze .\samples\app.exe --out .\reports\app --dynamic --dynamic-backend all --reconstruct
```

### Dynamic behavior knowledge memory

Dynamic behavior is now persisted into the local knowledge base alongside static
features. After an analysis run, `KnowledgeBase` sample features include:

- dynamic backend status and backend list;
- event and return-event counts;
- category counts such as `network`, `process`, `file`, and `registry`;
- top Frida API names, Procmon operation names, and high-frequency paths;
- reconstruction dynamic-evidence count and prioritized modules.

Observations also include `dynamic_behavior` and `dynamic_summary` records. This
lets later sessions compare samples by runtime behavior, not only by static PE
metadata or strings.

### Dynamic profile outcome statistics

Each completed analysis can update `dynamic_profiles.json` in the knowledge
directory. The file accumulates per-profile outcomes such as:

- runs / successes / failures / unavailable counts;
- total and average dynamic event counts;
- return-event counts;
- planned hook counts;
- category counts and recent samples.

`KnowledgeBase.recommend_dynamic_profile()` uses these historical outcomes to
return the currently best-performing profile. This gives the platform a feedback
loop for future auto-profile tuning instead of treating every dynamic run as an
isolated event.

When `analyze --dynamic --dynamic-profile auto` has no strong static signal for
unpacking, network, or persistence behavior, the CLI now falls back to this
historical recommendation before using the conservative `quick` profile.

### GUI 技术栈识别与最优还原路径

`analyze --gui` 会启动 GUI 还原 pipeline：先识别 GUI 技术栈，再提取资源、
融合可用的运行时/视觉证据，并选择按原技术栈优先的重构策略。当前内置识别器覆盖
Windows PE（WPF、WinForms、Qt、Electron、MFC、Win32 Dialog、Delphi/VCL、
PyInstaller/PySide、自绘 GUI）、Android APK（XML、Compose、Flutter、React Native、
Unity、WebView）与 iOS IPA（UIKit、SwiftUI、Flutter、React Native、Unity）。

```powershell
# 静态 fingerprint + 资源目录 + 策略选择
python -m reverse_analyzer analyze .\samples\app.exe --out .\reports\app --gui

# 附加运行时 UI 树、截图视觉解析与 GUI 项目骨架生成
python -m reverse_analyzer analyze .\samples\app.exe --out .\reports\app --gui --gui-runtime --gui-visual --gui-screenshot-dir .\screenshots --reconstruct-gui

# 对已启动的 Windows 程序采集 Win32 顶层窗口与子控件树
python -m reverse_analyzer analyze .\samples\app.exe --out .\reports\app --gui --gui-runtime --attach-pid 1234

# 对 Android APK 从连接的模拟器/设备采集 uiautomator hierarchy
python -m reverse_analyzer analyze .\samples\app.apk --out .\reports\app --gui --gui-runtime --adb-path C:\Android\platform-tools\adb.exe --android-serial emulator-5554

# 无法保留原技术栈时，显式指定生成目标；默认值为 auto
python -m reverse_analyzer analyze .\samples\app.exe --out .\reports\app --gui --reconstruct-gui --gui-target pyside6
```

输出会保存在：

```text
<out>/gui/
  fingerprint.json
  xaml_evidence.json
  evidence_graph.json
  strategy.json
  resources/manifest.json
  resources/extracted/
  runtime_tree.json
  visual_parse.json
  regression.json

<out>/reconstructed_gui/
  README.md
  analysis/gui_fingerprint.json
  analysis/gui_strategy.json
  analysis/xaml_evidence.json
  analysis/evidence_graph.json
  analysis/ui_tree.json
  analysis/visual_parse.json
  assets/
  src/
```

对于可提取的 WPF XAML，pipeline 会解析控件、布局属性和事件处理器，并将其与运行时
控件树、视觉控件和反编译函数合并到 `evidence_graph.json`。当策略输出为 WPF 且图中
存在控件节点时，`--reconstruct-gui` 会生成实际的 `Button`、`TextBox`、`CheckBox`、
`ComboBox`、`ListView` 等控件；带完整坐标的节点放入 `Canvas`，其余节点落入
`StackPanel`，同时生成可编译的 C# 事件处理器 stub。

`report.json` 新增 `gui_analysis`，`report.md` 新增 **GUI Analysis**、
**GUI Reconstruction Strategy** 与 **GUI Visual Regression** 章节；GUI Analysis 会显示
XAML 静态节点数、Evidence Graph 节点/边数及事件处理器关联数。没有可用
UIAutomation、OCR、VLM、Android/iOS 工具链时，相应阶段记录为 `unavailable`，不会
阻断静态 fingerprint、资源提取或工程骨架生成。

### GUI 行为证据与交互轨迹

启用统一的 Behavior Evidence Graph、GUI State Machine 与交互轨迹融合：

```powershell
python -m reverse_analyzer analyze sample.exe --out out --gui --reconstruct-gui --gui-interaction-trace interaction_trace.json
```

`--gui-interaction-trace` 用于将外部提供的被动交互轨迹归一化并融合为证据；它不会
自动启动样本，也不会自动执行样本 UI 点击。

相关产物包括：

```text
out/analysis_graph.json                              # 统一 Behavior Evidence Graph
out/gui/state_machine.json                           # GUI 状态机
out/gui/interaction_trace.json                       # 归一化后的交互轨迹
out/reconstructed_gui/analysis/behavior_graph.json   # 重构项目使用的行为图
out/reconstructed_gui/analysis/state_machine.json    # 重构项目使用的状态机
```

Behavior Evidence Graph 以可解释证据链联结 `function`、`API`、`dynamic event`、
`UI control`、`handler`、`resource`、`state` 与 `action` 节点，保留来源、关联关系和
证据强度，便于从 UI 操作追溯到处理器、函数调用、API 或动态事件，并进一步关联资源
与状态变化。GUI State Machine 则描述可观测的 `state` 节点，以及由用户操作、控件
事件或运行时证据触发的 `transition`，用于解释界面流程和支持 GUI 重构。

GUI 策略结果会累计到知识目录中的 `gui_strategies.json`，包括 runs、success/failure
计数、平均视觉相似度、控件匹配率、文本匹配率和最近样本。可通过：

```python
KnowledgeBase(...).recommend_gui_strategy(framework="wpf")
```

为同一技术栈选择历史上表现更好的还原策略；该推荐也会写入 session summary。

### 实验编排与可视化指挥台

平台新增了一个可持久化的实验控制面，用于将样本、动态 profile、GUI 策略和重构选项
固化为可重放的 experiment job；创建和规划不会执行样本。

```powershell
# 创建实验：只记录分析计划，并返回 experiment ID 与确定性的 analyze 命令
python -m reverse_analyzer experiment create .\samples\app.exe --workspace .\lab `
  --dynamic --dynamic-backend procmon --dynamic-profile network `
  --gui-runtime --reconstruct-gui --gui-interaction-trace .\trace.json

# 查看或输出计划；dry-run 永远不会执行样本
python -m reverse_analyzer experiment plan <experiment-id> --workspace .\lab
python -m reverse_analyzer experiment run <experiment-id> --workspace .\lab --dry-run

# 仅在隔离的本地分析环境中，显式调用本机 CLI adapter
python -m reverse_analyzer experiment run <experiment-id> --workspace .\lab --execute-local --timeout 900

# 生成离线可打开的 Reverse Lab Command Deck，并可选以 loopback HTTP 服务预览
python -m reverse_analyzer dashboard --workspace .\lab
python -m reverse_analyzer dashboard --workspace .\lab --serve
```

实验记录位于：

```text
<workspace>/experiments/<experiment-id>.json
<workspace>/experiments/<experiment-id>/analysis/
```

每条记录保留状态流转、计划命令、运行摘要、产物链接和错误信息。初步可视化平台输出：

```text
<workspace>/dashboard/index.html   # 可离线直接打开的深色实验指挥台
<workspace>/dashboard/data.json    # 同一份可供后续 API / dashboard 消费的数据
```

指挥台汇总实验队列、状态 KPI、动态 profile 推荐、GUI strategy 推荐、顶层和实验内的
运行 session，并提供搜索与状态筛选。它只使用本地静态资源；`--serve` 默认绑定
`127.0.0.1`，且创建/计划实验不会自动启动目标样本。

新增的第 5 个 **Source Reconstruction** 工作区会自动发现本地已生成的
`reconstructed_*` / `reconstructed_gui` 工程，并将以下信息写入
`dashboard/data.json` 的 `source_reconstruction` 节点并可视化展示：

- 项目路径、目标语言 / 输出技术栈、README 与构建入口；
- 可浏览的恢复源文件清单和受限文本预览；
- 函数、模块、动态证据、资源数量与下一还原任务；
- 缺失或损坏还原元数据的本地诊断。

该页面只读取已经生成的产物，不会执行样本或重构工程。可通过下列命令先生成源代码还原骨架：

```powershell
python -m reverse_analyzer analyze .\samples\app.exe --out .\lab\reports\app --reconstruct
python -m reverse_analyzer dashboard --workspace .\lab
```

### 语义 IR 与静态重构验证

每次 `analyze` 都会在已有静态、动态、GUI 和行为证据之上生成确定性的
`semantic_ir.json`。它把函数、API、动态事件、UI 控件、事件处理器、状态与资源归一为
实体、关系和保守的 capability 分类，供报告、重构和后续策略学习共同消费：

```text
<out>/semantic_ir.json
<out>/report.json -> semantic_ir
```

当使用 `--reconstruct` 时，IR 会随工程写入：

```text
<out>/reconstructed_<sample>/analysis/semantic_ir.json
<out>/reconstructed_<sample>/analysis/reconstruction_verification.json
```

验证器只做静态检查：README、可读源码、构建入口、重构计划、IR 实体映射与模块覆盖率；
它**不会**启动原始样本、构建生成工程、调用外部命令或访问网络。结果会出现在
`report.json` 的 `reconstruction_verification`、`report.md` 的 **Reconstruction Verification**
章节，以及 Dashboard 的 Source Reconstruction 工作区。

### 6. 开发验证

修改运行时或工具后，建议至少执行：

```powershell
python -m compileall reverse_analyzer tests
python -m unittest discover -s tests -v
python -m reverse_analyzer list-tools
```

如果要做一次完整 smoke test：

```powershell
New-Item -ItemType Directory -Force tmp | Out-Null
Set-Content -Path tmp\sample.bin -Value "MZ hello VirtualAlloc UPX0 CreateRemoteThread"
python -m reverse_analyzer analyze tmp\sample.bin --out tmp\analysis --max-iterations 6
Get-Content tmp\analysis\report.md
```

`tmp/`、`.reverse_analyzer/` 和 `reports/` 已加入 `.gitignore`，默认不会提交运行时产物。

### 7. 下一步扩展建议

- 把 `pe_header_scan` 的导入表、节区和入口点结果转成更丰富的 finding。
- 接入真实 `yara-python` 规则目录，并在报告中展示命中规则。
- 为 `OpenAICompatibleProvider` 增加显式配置项，支持本地模型或 OpenAI-compatible endpoint。
- 在 Dashboard 中读取 `sessions/*.json`、`trace.jsonl` 和 `report.json`，做可视化分析工作台。
- 将 installer 作为独立命令加入 CLI，例如 `python -m reverse_analyzer install-tools`。

### Reverse analyzer updates (2026-07-09)

The current `reverse_analyzer` runtime now integrates the remaining static
reverse-analysis pieces directly into the CLI flow:

- `pe_deep_scan`
  - imports / exports / resources / TLS callbacks
  - overlay / Rich header
  - section anomalies / IAT anomalies
  - shell score + verdict
- `yara_scan`
  - bundled rules under `rules/yara/`
  - automatic recursive loading of `.yar` / `.yara`
  - matched rule metadata and string evidence in `report.json` / `report.md`
- `reconstruct_project`
  - optional compilable stub project output with `--reconstruct`

#### New CLI examples

```powershell
# Standard analysis with PE deep scan + bundled YARA rules
python -m reverse_analyzer analyze .\samples\app.exe --out .\reports\app --max-iterations 8

# Use a custom YARA rules directory
python -m reverse_analyzer analyze .\samples\app.exe --out .\reports\app --yara-rules .\custom-rules

# Generate a reconstruction scaffold
python -m reverse_analyzer analyze .\samples\app.exe --out .\reports\app --reconstruct

# Combine reconstruction and Ghidra decompilation
python -m reverse_analyzer analyze .\samples\app.exe --out .\reports\app --decompile --reconstruct
```

#### Additional output

`report.json` / `report.md` now include:

- `pe_analysis`
- `yara`
- `decompiler`
- `reconstruction`
- normalized `findings` with:
  - `severity`
  - `confidence`
  - `evidence`
  - `recommendation`
