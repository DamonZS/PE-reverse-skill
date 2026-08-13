# BurpSuite MCP Full Control Extension

通过 MCP 协议完整控制 BurpSuite 的所有核心功能。跨平台支持 Windows / Linux (Kali) / macOS。

## 快速开始

### 1. 编译扩展

**Windows**:
```cmd
cd burp-mcp-full
build.bat
```

**Linux / Kali / macOS**:
```bash
cd burp-mcp-full
chmod +x build.sh
./build.sh
```

构建脚本会自动：检测 JDK 21+、下载依赖（montoya-api 2025.5 / gson / nanohttpd）、编译、把扩展描述符（`META-INF/extensions/burp-extension.properties`）打入 jar、打包 fat jar。无需 Gradle。

输出：`build/libs/burp-mcp-full.jar`。

### 2. 加载到 Burp

```
Burp Suite → Extensions → Add → Java → 选择 build/libs/burp-mcp-full.jar
```

加载后在 Output 看到：
```
[MCP] Server started on http://127.0.0.1:9876
```

### 3. 鉴权（v2 起默认启用）

扩展启动时自动生成随机 token 并写入 `~/.burp-mcp-token`。`mcp-bridge.js` 会自动读取该文件并在每个请求携带 `Authorization: Bearer <token>` 头，无需手动配置。

需要固定 token 时（例如多个客户端共享），可用：
- JVM 参数：`-Dburp.mcp.token=<token>`
- 环境变量：`BURP_MCP_TOKEN=<token>`（同时用于 bridge 侧）

所有 `/health`、`/tools`、`/`（POST）请求均要求携带该头，否则返回 403。CORS 已收敛为仅允许 `http://127.0.0.1` 来源。

### 4. 配置 MCP 客户端

在任何 MCP 客户端（Claude Code / Kiro / Cursor / Cline / Windsurf）中添加（stdio 模式）：

```json
{
  "mcpServers": {
    "burpsuite": {
      "command": "node",
      "args": ["<本目录路径>/mcp-bridge.js"]
    }
  }
}
```

### 5. 开始使用

对 AI 说："分析 Burp 代理历史中的请求，找出安全漏洞"

## 功能列表

扩展暴露 78 个工具。常用分类如下（完整列表见 `src/main/java/com/burpmcp/McpHttpServer.java` 的 `getToolList()`，或访问 `GET http://127.0.0.1:9876/tools`，需携带 Authorization 头）：

| 分类 | 工具 |
|------|------|
| Proxy 历史 | `proxy_history`, `proxy_detail`, `proxy_history_filtered`, `proxy_websocket`, `proxy_clear`, `search_history`, `highlight`, `annotate`, `compare` |
| 发送请求 | `send_request`, `send_to_repeater`, `repeater_send`, `repeater_modify_send`, `send_to_intruder` |
| Intruder 攻击 | `intruder_attack`, `intruder_attack_async`, `intruder_attack_wordlist`, `intruder_pitchfork`, `intruder_cluster_bomb`, `intruder_battering_ram`, `intruder_with_options`, `payload_process` |
| 扫描 / 爬取 | `scan`(主动/被动), `scan_active`, `scan_results`, `scan_issue_detail`, `crawl`, `sequencer` |
| Scope / Sitemap | `sitemap`, `target_info`, `get_scope`, `add_to_scope`, `remove_from_scope`, `add_issue` |
| 拦截 / 规则 | `intercept_toggle`, `register_http_handler`, `remove_http_handler`, `register_proxy_rule`, `remove_proxy_rule` |
| 编解码 | `encode`, `decode`, `convert_request`, `export_request`, `generate_csrf_poc`, `extract_from_response`, `token_analysis` |
| Collaborator | `collaborator_generate`, `collaborator_poll` |
| 配置 | `export_config`, `import_config`, `set_upstream_proxy`, `set_dns_override`, `set_http2`, `cookie_jar`, `save_project`, `burp_version`, `extensions_list`, `log` |

> 扫描/爬取（`scan`、`scan_active`、`crawl`）需要 **Burp Professional**。Community 版会返回明确的许可证错误。手动添加的 issue（`add_issue`）会写入 Site map。

## 关键工具参数

### `intruder_attack` — 自动化枚举攻击

| 参数 | 说明 |
|------|------|
| `url_template` | URL 模板，占位符默认 `@@` |
| `placeholder` | 占位符字符串（默认 `@@`） |
| `from` / `to` | 枚举起止值 |
| `pad_digits` | 补零位数（0 不补） |
| `method` | HTTP 方法（默认 GET） |
| `body_template` | 请求体模板（含占位符） |
| `headers` | 请求头对象 |
| `success_length_not` | 命中条件：响应长度 ≠ 此值 |
| `success_contains` | 命中条件：响应体包含此字符串 |

### `scan` — 启动审计

| 参数 | 说明 |
|------|------|
| `url` | 目标 URL（必填，自动加入 scope） |
| `mode` | `active`（默认）或 `passive` |

启动后用 `scan_results` 轮询 issues 与活动审计状态（请求数、错误数、插入点数）。

### `register_proxy_rule` — 代理请求拦截规则

| 参数 | 说明 |
|------|------|
| `url_contains` | 命中条件：URL 包含此串 |
| `intercept` | `true` 拦截 / `false` 放行不拦截（默认 true） |

通过 `remove_proxy_rule` 注销规则（基于 `Registration.deregister()`，真正从 Burp 卸载）。

## 调用示例

### 查看代理历史
```json
POST http://127.0.0.1:9876
{"tool": "proxy_history", "params": {"limit": 10, "url_filter": "personalblog"}}
```

### 发送请求
```json
POST http://127.0.0.1:9876
{"tool": "send_request", "params": {"method": "GET", "url": "https://example.com/api/test"}}
```

### 自动化枚举攻击（核心功能）
```json
POST http://127.0.0.1:9876
{
  "tool": "intruder_attack",
  "params": {
    "url_template": "https://target.com/api/verify?code=@@",
    "method": "POST",
    "from": 0,
    "to": 999999,
    "pad_digits": 6,
    "success_length_not": 176,
    "headers": {"User-Agent": "Mozilla/5.0"}
  }
}
```

### 开关拦截
```json
POST http://127.0.0.1:9876
{"tool": "intercept_toggle", "params": {"enable": false}}
```

## 端口配置

默认监听 `127.0.0.1:9876`。如需更改（例如与 PortSwigger 官方 MCP 扩展同端口冲突）：

1. **Burp 侧**：启动 Burp 时传 JVM 参数 `-Dburp.mcp.port=9877`，或设环境变量 `BURP_MCP_PORT=9877`。
2. **桥接侧**：MCP 客户端配置里设环境变量 `BURP_MCP_PORT=9877` 与 `BURP_MCP_HOST=127.0.0.1`。

两侧端口必须一致。若 Burp 未运行或端口不通，桥接会在 `tools/list` 与 `tools/call` 返回明确的连接错误指引。

## 故障排查

| 现象 | 排查 |
|------|------|
| Burp Output 无 "[MCP] Server started" | 端口被占用或扩展加载失败，查 Burp Errors 面板 |
| MCP 客户端报 "Burp MCP not connected" | 确认 Burp 已运行且扩展已加载；确认两侧端口一致 |
| 扫描返回 "requires Burp Professional" | 正常，Community 版不支持 Scanner API |
| `remove_http_handler` / `remove_proxy_rule` 无效 | 确认之前 `register_*` 返回 success=true |

## 源码构建（Gradle 可选）

```bash
cd burp-mcp-full
gradle jar      # 需本机已装 Gradle 8.7+
# 输出: build/libs/burp-mcp-full.jar
```

> 推荐使用 `build.bat` / `build.sh`（零依赖，自动下载 jar）。Gradle 路径仅作备选。
