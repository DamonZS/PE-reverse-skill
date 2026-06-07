# pe-reverse-analyzer

> 通用全平台逆向分析工具 —— 从二进制到可编译源码 | 从暴露面到安全加固

![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Android%20%7C%20iOS%20%7C%20Web-blue)
![Language](https://img.shields.io/badge/language-Python%203.10%2B-green)
![License](https://img.shields.io/badge/license-MIT-orange)

覆盖 **Windows PE/EXE/DLL**、**Web**、**Android APK**、**iOS IPA** 三大平台，以及 **API 接口逆向** 与 **Web API 安全审计**。支持从静态分析 → 加壳检测 → 脱壳 → 反编译到源码 → 修改源码 → 重构建完整链路，以及对外暴露的 Web 服务进行安全评估、配置审计、漏洞发现与修复方案输出。

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

## 法律声明

- 仅对授权目标进行逆向工程（CTF、自己的程序、书面授权的渗透测试）
- 逆向 DRM 保护的软件可能违反当地法律
- 不要将逆向得到的代码用于盗版分发
- Web 安全审计需确认目标所有权后方可执行
