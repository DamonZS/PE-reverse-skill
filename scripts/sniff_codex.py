#!/usr/bin/env python3
"""临时嗅探：截获一次 Codex 请求，验证 instructions 是否来自指令文件"""
import json, sys, http.server, urllib.request, urllib.error

LISTEN = ("127.0.0.1", 8081)
UPSTREAM = "https://api.toporeduce.cn/v1"

class Sniffer(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(body_len)

        try:
            payload = json.loads(body)
            instructions = payload.get("instructions", "")
        except:
            instructions = "(非 JSON)"

        # 判断是否命中指令文件
        if "UNRESTRICTED" in str(instructions) or "sandbox" in str(instructions).lower():
            verdict = "✅ 指令文件已加载 — 命中 UNRESTRICTED/SANDBOX"
        elif "helpful coding assistant" in str(instructions).lower():
            verdict = "❌ 默认指令 — 指令文件未生效"
        elif len(str(instructions)) < 20:
            verdict = "❌ 指令为空/过短 — 未加载"
        else:
            verdict = f"⚠️ 未知指令内容 ({len(str(instructions))} chars)"

        print(f"\n{'='*60}")
        print(f"PATH: {self.path}")
        print(f"INSTRUCTIONS ({len(str(instructions))} chars):")
        print(f"  {str(instructions)[:300]}...")
        print(f"VERDICT: {verdict}")
        print(f"{'='*60}\n")
        sys.stdout.flush()

        # 转发到上游
        url = UPSTREAM + self.path
        req = urllib.request.Request(url, data=body, method="POST")
        for k, v in self.headers.items():
            if k.lower() in ("host", "content-length"):
                continue
            req.add_header(k, v)

        try:
            resp = urllib.request.urlopen(req, timeout=60)
            resp_body = resp.read()
            self.send_response(resp.status)
            for k, v in resp.headers.items():
                if k.lower() in ("transfer-encoding", "connection"):
                    continue
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(resp_body)))
            self.end_headers()
            self.wfile.write(resp_body)
        except Exception as e:
            self.send_error(502, str(e))

        # 截获一次后就退出
        print("截获完成，退出嗅探。修改 config.toml base_url 回原地址。")
        import os, signal
        os.kill(os.getpid(), signal.SIGTERM)

    def log_message(self, format, *args):
        pass  # 静默


if __name__ == "__main__":
    print(f"嗅探代理启动: http://{LISTEN[0]}:{LISTEN[1]}")
    print(f"上游: {UPSTREAM}")
    print(f"\n请修改 Codex config.toml base_url 为 http://{LISTEN[0]}:{LISTEN[1]}/v1")
    print(f"然后对 Codex 发一条消息，代理会自动截获并退出。\n")
    httpd = http.server.HTTPServer(LISTEN, Sniffer)
    httpd.serve_forever()
