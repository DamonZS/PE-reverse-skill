#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
API 接口逆向分析脚本
支持从 Burp Suite / ZAP / mitmproxy / PCAP 导出的流量中
提取 API 端点、请求/响应结构，生成 OpenAPI 3.0 文档和调用示例。

用法:
  python api_reverse.py --burp-log burp.xml --output api_docs.md
  python api_reverse.py --mitm-log flowfile --output api_docs.md
  python api_reverse.py --pcap capture.pcap --output api_docs.md
  python api_reverse.py --live-proxy 8080 --output api_docs.md
"""

import re
import json
import sys
import argparse
import html
from pathlib import Path
from collections import defaultdict, Counter
from xml.etree import ElementTree as ET

# ─── 工具函数 ───────────────────────────────────────────────────────

def load_burp_xml(path):
    """解析 Burp Suite XML 导出文件"""
    items = []
    try:
        tree = ET.parse(path)
        root = tree.getroot()
        for item in root.iter('item'):
            req_raw = item.findtext('request', '')
            resp_raw = item.findtext('response', '')
            url = item.findtext('url', '')
            method = item.findtext('method', 'GET')
            status = item.findtext('status', '0')
            items.append({
                'url': url,
                'method': method,
                'status': int(status) if status.isdigit() else 0,
                'request': req_raw,
                'response': resp_raw,
            })
    except Exception as e:
        print('[!] 解析 Burp XML 失败: %s' % e)
    return items


def load_mitmproxy(path):
    """解析 mitmproxy flow 文件（二进制格式需 mitmproxy 工具）"""
    items = []
    try:
        from mitmproxy import io as mitm_io
        with open(path, 'rb') as f:
            freader = mitm_io.FlowReader(f)
            for flow in freader.stream():
                if hasattr(flow, 'request'):
                    req = flow.request
                    resp = getattr(flow, 'response', None)
                    items.append({
                        'url': '%s://%s%s' % (req.scheme, req.host, req.path),
                        'method': req.method,
                        'status': resp.status_code if resp else 0,
                        'request': req.text if hasattr(req, 'text') else '',
                        'response': resp.text if resp and hasattr(resp, 'text') else '',
                        'req_headers': dict(req.headers) if hasattr(req, 'headers') else {},
                        'resp_headers': dict(resp.headers) if resp and hasattr(resp, 'headers') else {},
                    })
    except ImportError:
        print('[!] mitmproxy 未安装，请运行: pip install mitmproxy')
    except Exception as e:
        print('[!] 解析 mitmproxy 文件失败: %s' % e)
    return items


def parse_request(req_text):
    """解析 HTTP 请求文本，提取方法、路径、头、体"""
    if not req_text:
        return {}
    lines = req_text.split('\r\n') if '\r\n' in req_text else req_text.split('\n')
    result = {'method': '', 'path': '', 'headers': {}, 'body': '', 'content_type': ''}
    if not lines:
        return result
    # 请求行
    first = lines[0]
    m = re.match(r'^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)', first)
    if m:
        result['method'] = m.group(1)
        result['path'] = m.group(2)
    # 头
    idx = 1
    while idx < len(lines) and lines[idx].strip():
        line = lines[idx]
        if ':' in line:
            k, _, v = line.partition(':')
            result['headers'][k.strip()] = v.strip()
        idx += 1
    # Body
    if idx + 1 < len(lines):
        result['body'] = '\n'.join(lines[idx + 1:])
    ct = result['headers'].get('Content-Type', '')
    result['content_type'] = ct.split(';')[0] if ct else ''
    return result


def parse_response(resp_text):
    """解析 HTTP 响应文本"""
    if not resp_text:
        return {}
    lines = resp_text.split('\r\n') if '\r\n' in resp_text else resp_text.split('\n')
    result = {'status': 0, 'headers': {}, 'body': ''}
    if not lines:
        return result
    m = re.match(r'^HTTP/\d\.\d\s+(\d+)', lines[0])
    if m:
        result['status'] = int(m.group(1))
    idx = 1
    while idx < len(lines) and lines[idx].strip():
        line = lines[idx]
        if ':' in line:
            k, _, v = line.partition(':')
            result['headers'][k.strip()] = v.strip()
        idx += 1
    if idx + 1 < len(lines):
        result['body'] = '\n'.join(lines[idx + 1:])
    return result


def infer_json_type(val):
    """推断 JSON 值的类型"""
    if val is None:
        return 'null'
    if isinstance(val, bool):
        return 'boolean'
    if isinstance(val, int):
        return 'integer'
    if isinstance(val, float):
        return 'number'
    if isinstance(val, str):
        return 'string'
    if isinstance(val, list):
        return 'array'
    if isinstance(val, dict):
        return 'object'
    return 'string'


def infer_json_schema(data, depth=0):
    """从 JSON 数据推断 OpenAPI schema"""
    if depth > 5:
        return {'type': 'object'}
    if isinstance(data, dict):
        props = {}
        required = []
        for k, v in data.items():
            props[k] = infer_json_schema(v, depth + 1)
            required.append(k)
        return {
            'type': 'object',
            'properties': props,
            'required': required,
        }
    elif isinstance(data, list) and data:
        return {
            'type': 'array',
            'items': infer_json_schema(data[0], depth + 1),
        }
    else:
        return {'type': infer_json_type(data)}


def try_parse_json(text):
    """尝试解析 JSON，返回 (success, data)"""
    text = text.strip()
    if not text:
        return False, None
    try:
        return True, json.loads(text)
    except:
        return False, None


def extract_endpoints(items):
    """从流量条目中提取唯一端点，聚合请求/响应"""
    endpoints = defaultdict(lambda: {
        'methods': set(),
        'statuses': set(),
        'req_samples': [],
        'resp_samples': [],
        'req_headers_samples': [],
        'resp_headers_samples': [],
        'content_types': set(),
        'auth_headers': set(),
    })

    for item in items:
        url = item.get('url', '')
        if not url:
            continue
        # 规范化路径（去除 query 参数用于聚合）
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url)
        base_url = '%s://%s' % (parsed.scheme, parsed.netloc)
        path = parsed.path
        # 尝试将路径中的数字 ID 替换为 {id}
        norm_path = re.sub(r'/\d+', '/{id}', path)

        ep = endpoints[norm_path]
        ep['full_url'] = base_url + path
        ep['base_url'] = base_url
        ep['methods'].add(item.get('method', 'GET'))
        ep['statuses'].add(str(item.get('status', 0)))
        ep['content_types'].add(item.get('content_type', ''))

        req = item.get('request', '')
        if req:
            ep['req_samples'].append(req)
        resp = item.get('response', '')
        if resp:
            ep['resp_samples'].append(resp)

        # 提取认证头
        for h in ['Authorization', 'X-API-Key', 'X-Auth-Token', 'Token']:
            v = item.get('req_headers', {}).get(h, '')
            if v:
                ep['auth_headers'].add('%s: %s...' % (h, v[:20]))

    return endpoints


# ─── 主分析函数 ─────────────────────────────────────────────────────

def analyze_api(items, output_path=None):
    """主分析函数，生成 API 逆向报告"""
    lines = []
    def out(s=''):
        lines.append(str(s))
        print(s)

    sep = '=' * 70
    out(sep)
    out('  API 接口逆向分析报告')
    out('  共分析 %d 条流量记录' % len(items))
    out(sep)

    if not items:
        out('\n[!] 无有效流量数据')
        return '\n'.join(lines)

    # 1. 概览
    out('\n[1] API 端点概览')
    endpoints = extract_endpoints(items)
    out('  发现 %d 个唯一端点:' % len(endpoints))
    for path in sorted(endpoints.keys())[:30]:
        ep = endpoints[path]
        methods = ', '.join(sorted(ep['methods']))
        out('    %-40s [%s]' % (path[:40], methods))
    if len(endpoints) > 30:
        out('    ... 共 %d 个端点' % len(endpoints))

    # 2. 认证机制分析
    out('\n[2] 认证机制分析')
    all_auth = set()
    for ep in endpoints.values():
        all_auth |= ep['auth_headers']
    if all_auth:
        out('  [!] 发现认证头:')
        for a in sorted(all_auth):
            out('    - %s' % a)
    else:
        # 检查是否有 token/key 在 query 或 body 中
        token_patterns = []
        for ep in endpoints.values():
            for req in ep['req_samples'][:3]:
                if 'token' in req.lower() or 'api_key' in req.lower() or 'authorization' in req.lower():
                    token_patterns.append('可能在请求体中传递 token')
                    break
        if token_patterns:
            for t in set(token_patterns):
                out('  [?] %s' % t)
        else:
            out('  [?] 未发现明显认证头，可能：')
            out('    - 使用 Cookie/Session 认证')
            out('    - 无认证（公开 API）')
            out('    - 认证在 WebSocket/自定义协议中')

    # 3. 请求/响应结构分析
    out('\n[3] 请求/响应结构分析')
    for path in sorted(endpoints.keys())[:15]:
        ep = endpoints[path]
        out('\n  --- %s ---' % path)
        out('    方法: %s' % ', '.join(sorted(ep['methods'])))
        out('    基础 URL: %s' % ep.get('base_url', '未知'))

        # 分析请求体
        for req_text in ep['req_samples'][:3]:
            parsed = parse_request(req_text)
            if parsed.get('body'):
                body = parsed['body']
                ok, data = try_parse_json(body)
                if ok:
                    out('    请求体 (JSON):')
                    schema = infer_json_schema(data)
                    for k, v in schema.get('properties', {}).items():
                        out('      - %s: %s' % (k, v.get('type', 'unknown')))
                else:
                    out('    请求体 (非 JSON，前 100 字符): %s' % body[:100])
            # 检查 Content-Type
            ct = parsed.get('content_type', '')
            if ct:
                out('    Content-Type: %s' % ct)

        # 分析响应体
        for resp_text in ep['resp_samples'][:3]:
            parsed = parse_response(resp_text)
            if parsed.get('status'):
                out('    响应状态码: %s' % parsed['status'])
            if parsed.get('body'):
                body = parsed['body']
                ok, data = try_parse_json(body)
                if ok:
                    out('    响应体 (JSON):')
                    if isinstance(data, dict):
                        schema = infer_json_schema(data)
                        for k, v in list(schema.get('properties', {}).items())[:10]:
                            out('      - %s: %s' % (k, v.get('type', 'unknown')))
                    elif isinstance(data, list) and data:
                        out('    响应体: 数组，首项结构:')
                        schema = infer_json_schema(data[0])
                        for k, v in list(schema.get('properties', {}).items())[:10]:
                            out('      - %s: %s' % (k, v.get('type', 'unknown')))
                else:
                    out('    响应体 (非 JSON，前 100 字符): %s' % body[:100])

    # 4. 生成 OpenAPI 3.0 文档
    out('\n[4] OpenAPI 3.0 规范文档（摘要）')
    openapi_paths = {}
    for path, ep in endpoints.items():
        methods_spec = {}
        for method in sorted(ep['methods']):
            spec = {
                'summary': '%s %s' % (method, path),
                'responses': {
                    '200': {'description': '成功响应'}
                }
            }
            # 从样本中推断请求参数
            if method in ('POST', 'PUT', 'PATCH'):
                for req_text in ep['req_samples'][:1]:
                    parsed = parse_request(req_text)
                    if parsed.get('body'):
                        ok, data = try_parse_json(parsed['body'])
                        if ok:
                            spec['requestBody'] = {
                                'content': {
                                    'application/json': {
                                        'schema': infer_json_schema(data)
                                    }
                                }
                            }
            methods_spec[method.lower()] = spec
        openapi_paths[path] = methods_spec

    openapi_doc = {
        'openapi': '3.0.0',
        'info': {
            'title': '逆向生成的 API 文档',
            'version': '1.0.0',
            'description': '由 api_reverse.py 自动生成',
        },
        'servers': [{'url': ep.get('base_url', 'https://api.example.com')}
                     for ep in [next(iter(endpoints.values()))] if ep.get('base_url')],
        'paths': openapi_paths,
    }
    # 简化 servers（只取第一个）
    first_ep = next(iter(endpoints.values()), {})
    if first_ep.get('base_url'):
        openapi_doc['servers'] = [{'url': first_ep['base_url']}]
    else:
        openapi_doc['servers'] = [{'url': 'https://api.example.com'}]

    out('  已生成 OpenAPI 3.0 规范文档')
    out('  端点数量: %d' % len(openapi_paths))

    # 5. 生成调用示例（Python/JavaScript）
    out('\n[5] API 调用示例')
    for path in sorted(endpoints.keys())[:5]:
        ep = endpoints[path]
        method = sorted(ep['methods'])[0] if ep['methods'] else 'GET'
        url = ep.get('full_url', 'https://api.example.com' + path)

        out('\n  -- %s %s --' % (method, path))
        out('  Python (requests):')
        if method == 'GET':
            out("    import requests")
            out("    r = requests.get('%s')" % url)
            out("    print(r.json())")
        else:
            out("    import requests")
            # 尝试从样本中找请求体
            body_example = '{}'
            for req_text in ep['req_samples'][:1]:
                parsed = parse_request(req_text)
                if parsed.get('body'):
                    ok, data = try_parse_json(parsed['body'])
                    if ok:
                        body_example = json.dumps(data, ensure_ascii=False)
            out("    r = requests.%s('%s'," % (method.lower(), url))
            out("        json=%s)" % body_example)
            out("    print(r.json())")

        out('\n  JavaScript (fetch):')
        if method == 'GET':
            out("    fetch('%s').then(r => r.json()).then(console.log);" % url)
        else:
            out("    fetch('%s', { method: '%s'," % (url, method))
            out("      headers: { 'Content-Type': 'application/json' },")
            out("      body: JSON.stringify({}) })")
            out("      .then(r => r.json()).then(console.log);")

    # 6. 安全建议
    out('\n[6] API 安全分析')
    issues = []
    for path, ep in endpoints.items():
        for resp_text in ep['resp_samples'][:3]:
            parsed = parse_response(resp_text)
            body = parsed.get('body', '')
            ok, data = try_parse_json(body)
            if ok and isinstance(data, dict):
                # 检查是否返回敏感信息
                sensitive = ['password', 'token', 'secret', 'api_key', 'private_key']
                for s in sensitive:
                    if s in body.lower():
                        issues.append('端点 %s 响应中包含敏感字段: %s' % (path, s))
    if issues:
        out('  [!] 发现潜在安全问题:')
        for i in issues[:10]:
            out('    - %s' % i)
    else:
        out('  [?] 未发现明显安全问题（仍需人工审查）')

    # 7. 保存 OpenAPI 文档到文件
    if output_path:
        openapi_path = Path(output_path).with_suffix('.openapi.json')
        try:
            openapi_path.write_text(
                json.dumps(openapi_doc, ensure_ascii=False, indent=2),
                encoding='utf-8'
            )
            out('\n[+] OpenAPI 文档已保存: %s' % openapi_path)
        except Exception as e:
            out('\n[!] 保存 OpenAPI 文档失败: %s' % e)

    out('\n' + sep)
    out('  分析完成')
    out(sep)
    return '\n'.join(lines)


# ─── 实时代理模式 ─────────────────────────────────────────────────────

def live_proxy_mode(port=8080):
    """实时代理模式：启动 HTTP 代理，拦截并分析流量"""
    try:
        from mitmproxy.tools.main import mitmdump
        import sys
        script_path = Path(__file__).parent / 'mitm_intercept.py'
        print('[*] 启动 mitmproxy 实时拦截，端口: %d' % port)
        print('[*] 拦截脚本: %s' % script_path)
        print('[*] 手机/模拟器设置代理为 PC IP:%d' % port)
        sys.argv = ['mitmdump', '-p', str(port), '-s', str(script_path)]
        mitmdump()
    except ImportError:
        print('[!] mitmproxy 未安装，请运行: pip install mitmproxy')
        print('[*] 或者手动配置: mitmweb -p %d -s scripts/mitm_intercept.py' % port)


# ─── 主入口 ─────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='API 接口逆向分析工具 - 从流量日志生成 API 文档'
    )
    parser.add_argument('--burp-log', '-b', help='Burp Suite XML 导出文件')
    parser.add_argument('--mitm-log', '-m', help='mitmproxy flow 文件')
    parser.add_argument('--pcap', '-p', help='Wireshark PCAP 文件（需要 scapy）')
    parser.add_argument('--live-proxy', '-l', type=int,
                        help='实时代理模式，指定端口（需要 mitmproxy）')
    parser.add_argument('--output', '-o', help='输出报告文件路径')
    parser.add_argument('--openapi-out', help='OpenAPI 文档输出路径（默认与 output 同名）')

    args = parser.parse_args()

    items = []

    if args.live_proxy:
        live_proxy_mode(args.live_proxy)
        return

    if args.burp_log:
        print('[*] 加载 Burp Suite 日志: %s' % args.burp_log)
        items = load_burp_xml(args.burp_log)

    elif args.mitm_log:
        print('[*] 加载 mitmproxy 日志: %s' % args.mitm_log)
        items = load_mitmproxy(args.mitm_log)

    elif args.pcap:
        print("[!] PCAP mode is experimental: HTTP parsing is basic, results will have 'unknown' URLs")
        print('[*] 加载 PCAP 文件: %s' % args.pcap)
        try:
            import scapy.all as scapy
            pkts = scapy.rdpcap(args.pcap)
            for pkt in pkts:
                if pkt.haslayer(scapy.Raw):
                    payload = pkt[scapy.Raw].load
                    if b'HTTP' in payload or b'GET ' in payload or b'POST ' in payload:
                        try:
                            items.append({
                                'url': 'unknown',
                                'method': 'UNKNOWN',
                                'status': 0,
                                'request': payload.decode('utf-8', errors='ignore'),
                                'response': '',
                            })
                        except:
                            pass
        except ImportError:
            print('[!] scapy 未安装，请运行: pip install scapy')

    else:
        parser.print_help()
        return

    if not items:
        print('[!] 未能从 input 中提取有效流量数据')
        return

    print('[*] 共加载 %d 条流量记录，开始分析...' % len(items))
    report = analyze_api(items, output_path=args.output)

    if args.output:
        Path(args.output).write_text(report, encoding='utf-8')
        print('[+] 报告已保存到: %s' % args.output)


if __name__ == '__main__':
    main()
