#!/usr/bin/env python3
"""
deep_extract.py - 深度字符串和代码特征提取
从加壳PE二进制中最大化提取可用于重构源码的信息
"""
import re
import sys
import os
import json
import struct
import argparse

# 确保依赖可用
try:
    import pefile
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'pefile', '-q'])
    import pefile

try:
    import capstone
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False


def extract_all_strings(data, min_len=5):
    """提取所有 ASCII 和 UTF-16LE 字符串"""
    results = {'ascii': [], 'utf16': [], 'chinese': []}
    seen = set()

    # ASCII
    for m in re.findall(rb'[\x20-\x7e]{' + str(min_len).encode() + b',}', data):
        try:
            s = m.decode('ascii')
            if s not in seen:
                seen.add(s)
                results['ascii'].append(s)
        except:
            pass

    # UTF-16LE
    seen2 = set()
    for m in re.findall(rb'(?:[\x20-\x7e]\x00){4,}', data):
        try:
            s = m.decode('utf-16-le', errors='ignore').rstrip('\x00')
            if s not in seen2 and len(s) >= 4:
                seen2.add(s)
                results['utf16'].append(s)
                # 检测中文
                if any('\u4e00' <= c <= '\u9fff' for c in s):
                    results['chinese'].append(s)
        except:
            pass

    # GBK 中文字符串（常见于老旧中文软件）
    gbk_pattern = re.findall(rb'(?:[\xa1-\xfe][\xa1-\xfe]){2,}', data)
    for m in gbk_pattern:
        try:
            s = m.decode('gbk', errors='ignore')
            if len(s) >= 3 and s not in seen2:
                seen2.add(s)
                results['chinese'].append(s)
        except:
            pass

    return results


def categorize_strings(strings_dict):
    """将字符串分类"""
    all_strs = strings_dict.get('ascii', []) + strings_dict.get('utf16', [])
    
    categories = {
        'urls': [],
        'api_endpoints': [],
        'file_paths': [],
        'registry_keys': [],
        'error_messages': [],
        'ui_strings': [],
        'crypto_related': [],
        'network_related': [],
        'class_names_delphi': [],
        'function_names': [],
        'format_strings': [],
        'config_keys': [],
        'version_info': [],
    }

    for s in all_strs:
        sl = s.lower()

        # URL
        if re.match(r'https?://', s, re.IGNORECASE):
            categories['urls'].append(s)
        elif re.match(r'www\.', s, re.IGNORECASE):
            categories['urls'].append(s)

        # API 端点
        if re.match(r'(https?://|/).*\.(php|asp|aspx|jsp|do|action)', s, re.IGNORECASE):
            categories['api_endpoints'].append(s)

        # 文件路径
        if re.search(r'[A-Za-z]:[/\\]', s) or s.endswith(('.dll', '.exe', '.ini', '.dat', '.cfg', '.xml', '.log')):
            categories['file_paths'].append(s)

        # 注册表
        if any(k in s for k in ['HKEY_', 'SOFTWARE\\', 'CurrentVersion\\', 'Windows\\', 'Run\\', 'SYSTEM\\']):
            categories['registry_keys'].append(s)

        # 错误消息
        if any(k in sl for k in ['error', 'fail', 'success', 'invalid', 'wrong', 'not found', 'timeout',
                                   '失败', '成功', '错误', '无效', '超时', '不存在']):
            categories['error_messages'].append(s)

        # UI/界面字符串
        if any(k in s for k in ['Form', 'Dialog', 'Window', 'Button', 'Panel', 'Label', 'Edit',
                                  'Memo', 'List', 'Tree', 'Grid', 'Image', 'Frame']):
            categories['ui_strings'].append(s)

        # Delphi 类名（TXxx）
        if re.match(r'^T[A-Z][a-zA-Z0-9_]{2,}$', s):
            categories['class_names_delphi'].append(s)

        # 加密相关
        if any(k in sl for k in ['encrypt', 'decrypt', 'md5', 'sha', 'aes', 'des', 'rsa',
                                   'base64', 'crc', 'hash', 'hmac', 'key', 'cipher']):
            categories['crypto_related'].append(s)

        # 网络相关
        if any(k in sl for k in ['socket', 'connect', 'send', 'recv', 'http', 'tcp', 'udp',
                                   'port', 'host', 'ip', 'proxy', 'ssl', 'tls']):
            categories['network_related'].append(s)

        # 格式字符串
        if '%s' in s or '%d' in s or '%x' in s or '%f' in s:
            categories['format_strings'].append(s)

        # 配置键
        if re.match(r'^[A-Za-z][A-Za-z0-9_]{2,30}$', s) and '_' in s:
            categories['config_keys'].append(s)

        # 版本信息
        if re.search(r'[Vv]ersion|版本|v\d+\.\d+', s):
            categories['version_info'].append(s)

    # 去重
    for k in categories:
        categories[k] = list(dict.fromkeys(categories[k]))

    return categories


def detect_algorithms(data):
    """检测常见算法特征"""
    findings = []

    # MD5 常量
    if b'\x67\x45\x23\x01\xef\xcd\xab\x89' in data:
        findings.append(('MD5', '检测到 MD5 初始化常量 (0x67452301)'))
    
    # SHA1 常量
    if b'\x01\x23\x45\x67' in data and b'\x89\xab\xcd\xef' in data:
        findings.append(('SHA1', '检测到疑似 SHA1 常量'))

    # AES S-box 特征 (前8字节)
    if b'\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5' in data:
        findings.append(('AES', '检测到 AES S-box 常量'))

    # CRC32 多项式
    if b'\x77\x07\x30\x96' in data or b'\xB7\x7C\x4A\xCE' in data:
        findings.append(('CRC32', '检测到 CRC32 多项式常量'))

    # Base64 字符表
    if b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/' in data:
        findings.append(('Base64', '检测到完整 Base64 字符表'))

    # TEA/XXTEA 特征（delta = 0x9E3779B9）
    if b'\xb9\x79\x37\x9e' in data or b'\x9e\x37\x79\xb9' in data:
        findings.append(('TEA/XXTEA', '检测到 TEA delta 常量 (0x9E3779B9)'))

    # RC4 特征（0x100 字节查找表）
    rc4_pattern = bytes(range(256))
    if rc4_pattern[:16] in data:
        findings.append(('RC4 (possible)', '检测到 256 字节序列，可能是 RC4 S-box 初始化'))

    # XOR 加密（高频单字节 XOR）
    xor_byte_counts = {}
    for byte in data[::100]:  # 采样
        xor_byte_counts[byte] = xor_byte_counts.get(byte, 0) + 1
    common_xor = sorted(xor_byte_counts.items(), key=lambda x: -x[1])[:3]
    if common_xor[0][1] > len(data) // 1000:
        findings.append(('XOR (possible)', f'高频字节 0x{common_xor[0][0]:02X}，可能是 XOR 加密'))

    return findings


def find_embedded_files(data):
    """搜索嵌入的其他文件"""
    findings = []

    # PE 文件
    offsets = [m.start() for m in re.finditer(b'MZ', data)]
    for off in offsets[1:]:  # 跳过文件本身
        if off + 0x40 < len(data):
            e_lfanew_bytes = data[off+0x3c:off+0x40]
            if len(e_lfanew_bytes) == 4:
                e_lfanew = struct.unpack('<I', e_lfanew_bytes)[0]
                if e_lfanew < 0x1000 and off + e_lfanew + 4 < len(data):
                    pe_sig = data[off+e_lfanew:off+e_lfanew+4]
                    if pe_sig == b'PE\x00\x00':
                        findings.append({'type': 'PE', 'offset': hex(off), 'note': '嵌入的 PE 文件'})

    # ZIP
    for m in re.finditer(b'PK\x03\x04', data):
        findings.append({'type': 'ZIP', 'offset': hex(m.start()), 'note': '嵌入的 ZIP 数据'})
    
    # SQLite
    if b'SQLite format 3' in data:
        off = data.index(b'SQLite format 3')
        findings.append({'type': 'SQLite', 'offset': hex(off), 'note': '嵌入的 SQLite 数据库'})

    # Lua
    if b'\x1bLua' in data:
        off = data.index(b'\x1bLua')
        findings.append({'type': 'Lua bytecode', 'offset': hex(off), 'note': '嵌入的 Lua 字节码'})

    # Python
    if b'PYTHONPATH' in data or b'python27.dll' in data.lower() or b'python3' in data.lower():
        findings.append({'type': 'Python', 'offset': 'N/A', 'note': '可能内嵌 Python 运行时'})

    return findings


def identify_framework(pe, data, strings_dict):
    """识别开发框架"""
    all_strs = ' '.join(strings_dict.get('ascii', []) + strings_dict.get('utf16', []))
    all_bytes = data
    
    results = []

    # Delphi 特征
    delphi_classes = [s for s in strings_dict.get('ascii', []) if re.match(r'^T[A-Z][a-zA-Z0-9]+$', s)]
    if len(delphi_classes) > 5 or 'TForm' in all_strs or 'TButton' in all_strs:
        results.append(('Delphi/Pascal', f'检测到 {len(delphi_classes)} 个 Delphi 类名'))

    # MFC/ATL
    if 'AfxWinMain' in all_strs or 'CWinApp' in all_strs or b'ATL' in all_bytes[:1024]:
        results.append(('MFC/ATL (C++)', '检测到 MFC 特征'))

    # .NET
    if b'mscoree.dll' in all_bytes[:1024] or b'_CorExeMain' in all_bytes[:1024]:
        results.append(('.NET CLR', '检测到 .NET 运行时'))

    # AutoIt
    if b'AU3!' in all_bytes or 'AutoIt' in all_strs:
        results.append(('AutoIt', '检测到 AutoIt 脚本特征'))

    # NSIS Installer
    if b'Nullsoft Install System' in all_bytes or 'NSIS Error' in all_strs:
        results.append(('NSIS Installer', '检测到 NSIS 安装包'))

    # Qt
    if b'QApplication' in all_bytes or 'QMainWindow' in all_strs:
        results.append(('Qt', '检测到 Qt 框架'))

    # Visual Basic 6
    if b'MSVBVM60.dll' in all_bytes or b'MSVBVM50.dll' in all_bytes:
        results.append(('Visual Basic 6', '检测到 VB6 运行时'))

    # Electron/Node.js
    if b'node.dll' in all_bytes or 'electron' in all_strs.lower():
        results.append(('Electron', '检测到 Electron 框架'))

    # 无框架识别时默认判断
    if not results:
        # 检查链接器版本
        linker_major = pe.OPTIONAL_HEADER.MajorLinkerVersion
        linker_minor = pe.OPTIONAL_HEADER.MinorLinkerVersion
        if linker_major == 6:
            results.append(('Visual C++ 6.0 (MFC可能)', f'链接器版本 {linker_major}.{linker_minor}'))
        elif linker_major >= 14:
            results.append(('Visual C++ 2015+', f'链接器版本 {linker_major}.{linker_minor}'))
        else:
            results.append(('Unknown C/C++', f'链接器版本 {linker_major}.{linker_minor}'))

    return results


def main():
    parser = argparse.ArgumentParser(description='深度字符串和代码特征提取')
    parser.add_argument('target', help='目标 PE 文件')
    parser.add_argument('--output', '-o', help='JSON 输出文件', default=None)
    parser.add_argument('--min-len', type=int, default=5, help='最短字符串长度')
    args = parser.parse_args()

    if not os.path.isfile(args.target):
        print(f'[!] 文件不存在: {args.target}')
        sys.exit(1)

    print(f'[*] 深度提取: {args.target}')

    with open(args.target, 'rb') as f:
        data = f.read()

    pe = pefile.PE(args.target)

    # 1. 字符串提取
    print('[*] 提取字符串...')
    strings = extract_all_strings(data, args.min_len)
    categories = categorize_strings(strings)

    total = len(strings['ascii']) + len(strings['utf16'])
    print(f'    ASCII: {len(strings["ascii"])} | UTF-16LE: {len(strings["utf16"])} | 中文: {len(strings["chinese"])}')

    # 2. 算法检测
    print('[*] 检测加密算法...')
    algos = detect_algorithms(data)

    # 3. 嵌入文件
    print('[*] 搜索嵌入文件...')
    embedded = find_embedded_files(data)

    # 4. 框架识别
    print('[*] 识别开发框架...')
    frameworks = identify_framework(pe, data, strings)

    # 5. 汇总输出
    result = {
        'file': args.target,
        'total_strings': total,
        'strings': {
            'ascii_count': len(strings['ascii']),
            'utf16_count': len(strings['utf16']),
            'chinese': strings['chinese'][:100],
            'categories': {k: v[:50] for k, v in categories.items() if v},
        },
        'algorithms': algos,
        'embedded_files': embedded,
        'frameworks': frameworks,
    }

    # 打印摘要
    print('\n' + '='*60)
    print('深度提取结果摘要')
    print('='*60)

    print(f'\n[框架识别]:')
    for fw, desc in frameworks:
        print(f'  ★ {fw}: {desc}')

    print(f'\n[加密算法]:')
    if algos:
        for algo, desc in algos:
            print(f'  ! {algo}: {desc}')
    else:
        print('  未检测到已知加密算法常量')

    print(f'\n[嵌入文件]:')
    if embedded:
        for e in embedded:
            print(f'  ! {e["type"]} @ {e["offset"]}: {e["note"]}')
    else:
        print('  未发现嵌入文件')

    print(f'\n[分类字符串]:')
    for cat, strs in categories.items():
        if strs:
            print(f'\n  [{cat}] ({len(strs)} 条):')
            for s in strs[:8]:
                print(f'    {s[:100]}')

    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        print(f'\n[+] 完整结果已保存: {args.output}')

    pe.close()
    return result


if __name__ == '__main__':
    main()
