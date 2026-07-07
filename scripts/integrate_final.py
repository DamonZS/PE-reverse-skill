#!/usr/bin/env python3
"""
Final Integration — 将 Ghidra C 级伪代码 + reconstruct.py 骨架合并为可构建项目

输入:
  - Ghidra 输出: ghidra_output/ghidra_analysis.json + functions/*.c
  - reconstruct.py 输出: reconstructed_engine/src/*, include/*
  - deep_analysis 输出: deep_analysis.json (字符串/HAT 映射)

输出:
  - 完整可构建 C 项目，每个函数有真实类型签名
  - 替换汇编级伪代码为 Ghidra C 级伪代码
  - 补充 IAT 映射、字符串常量、协议结构体
"""

import os
import sys
import json
import re
import shutil
import argparse
from pathlib import Path
from collections import defaultdict
from datetime import datetime


def load_ghidra_output(ghidra_dir):
    """Load Ghidra decompilation results"""
    ghidra_dir = Path(ghidra_dir)
    summary_file = ghidra_dir / "ghidra_analysis.json"
    func_dir = ghidra_dir / "functions"

    if not summary_file.exists():
        print("[!] ghidra_analysis.json not found")
        return None, {}

    with open(summary_file, 'r', encoding='utf-8') as f:
        summary = json.load(f)

    functions = {}
    for func_info in summary.get('functions', []):
        addr = func_info['address']
        # Read the .c file
        func_file = func_dir / func_info.get('file', '')
        if func_file.exists():
            with open(func_file, 'r', encoding='utf-8', errors='replace') as f:
                func_info['pseudocode'] = f.read()
        else:
            func_info['pseudocode'] = ''

        # Normalize address to 8-hex-digit format
        if addr.startswith('0x') or addr.startswith('0X'):
            addr_int = int(addr, 16)
        else:
            addr_int = int(addr, 16)
        addr_key = "%08X" % addr_int
        functions[addr_key] = func_info

    return summary, functions


def load_deep_analysis(deep_dir):
    """Load deep_analysis strings and IAT references"""
    deep_dir = Path(deep_dir)
    analysis_file = deep_dir / "deep_analysis.json"
    strings_file = deep_dir / "ascii_strings_unpacked.txt"
    gbk_file = deep_dir / "gbk_strings_unpacked.txt"
    urls_file = deep_dir / "urls_unpacked.txt"

    result = {'strings': [], 'gbk': [], 'urls': [], 'iat': {}}

    if analysis_file.exists():
        with open(analysis_file, 'r', encoding='utf-8') as f:
            da = json.load(f)
        result['iat'] = da.get('iat', {})

    for fname, key in [(strings_file, 'strings'), (gbk_file, 'gbk'), (urls_file, 'urls')]:
        if fname.exists():
            with open(fname, 'r', encoding='utf-8', errors='replace') as f:
                result[key] = [l.strip() for l in f if l.strip() and not l.startswith('#')]

    return result


def load_engine_skeleton(engine_dir):
    """Load reconstruct.py skeleton files"""
    engine_dir = Path(engine_dir)
    result = {}

    for subdir in ['src', 'include']:
        sd = engine_dir / subdir
        if sd.exists():
            for f in sd.glob('*.c'):
                with open(f, 'r', encoding='utf-8', errors='replace') as fh:
                    result["src/%s" % f.name] = fh.read()
            for f in sd.glob('*.h'):
                with open(f, 'r', encoding='utf-8', errors='replace') as fh:
                    result["include/%s" % f.name] = fh.read()

    # Also grab README, CMakeLists, Makefile
    for fname in ['README.md', 'CMakeLists.txt', 'Makefile', 'analysis.json']:
        f = engine_dir / fname
        if f.exists():
            with open(f, 'r', encoding='utf-8', errors='replace') as fh:
                result[fname] = fh.read()

    return result


def classify_function(func_info, deep_data):
    """Classify a function based on Ghidra's signature and pseudocode content"""
    sig = func_info.get('signature', '')
    pseudo = func_info.get('pseudocode', '')
    name = func_info.get('name', '')
    combined = (sig + " " + pseudo + " " + name).lower()

    # Category detection patterns
    patterns = {
        'network': [
            'winhttp', 'wininet', 'socket', 'connect', 'send', 'recv',
            'winsock', 'http', 'url', 'dns', 'gethostbyname',
            'internetopen', 'httpopenrequest', 'httpsendrequest',
            'ws2_32', 'wsastartup', 'inet_addr', 'htons'
        ],
        'crypto': [
            'tea', 'xxtea', 'encrypt', 'decrypt', 'cipher', 'hash',
            'md5', 'sha', 'aes', 'rc4', 'base64', 'crypt',
            'random', 'key', 'xor'
        ],
        'registry': [
            'regcreate', 'regopen', 'regset', 'regget', 'regdelete',
            'regquery', 'regclose', 'regkey', 'hkey_', 'advapi32'
        ],
        'ui': [
            'window', 'dialog', 'button', 'control', 'hwnd', 'wndproc',
            'createwindow', 'messagebox', 'setwindow', 'getwindow',
            'skin', 'skin_h', 'skinh_el', 'draw', 'paint', 'render',
            'wm_', 'lresult', 'wparam', 'lparam', 'defwindowproc'
        ],
        'business': [
            'qq', 'qun', 'group', 'rank', '排名', 'score', 'points',
            'poi', 'location', 'city', 'region', 'category',
            'login', 'auth', 'token', 'cookie', 'verify'
        ],
        'file_io': [
            'file', 'read', 'write', 'open', 'close', 'fopen', 'fwrite',
            'fread', 'createfile', 'readfile', 'writefile',
            'ini', 'config', 'save', 'load'
        ],
        'threading': [
            'thread', 'mutex', 'semaphore', 'event', 'wait',
            'createthread', 'waitforsingle', 'criticalsection'
        ],
        'string_util': [
            'strcpy', 'strcat', 'strlen', 'strcmp', 'sprintf',
            'memcpy', 'memset', 'malloc', 'free', 'alloc',
            'gbk', 'utf8', 'unicode', 'widechar', 'multibyte'
        ],
    }

    scores = defaultdict(int)
    for category, keywords in patterns.items():
        for kw in keywords:
            if kw in combined:
                scores[category] += 1

    if scores:
        best = max(scores, key=scores.get)
        if scores[best] >= 2:
            return best

    # Fallback: check call count and xrefs
    if func_info.get('callCount', 0) > 10:
        return 'coordinator'
    if func_info.get('xrefCount', 0) > 5:
        return 'shared_util'

    # Default based on size
    if func_info.get('bodySize', 0) > 500:
        return 'large_unknown'
    return 'small_unknown'


def extract_fn_signature(ghidra_sig):
    """Normalize Ghidra function signature for C header"""
    # Ghidra signatures look like: "void __cdecl FUN_004010a1(int param_1)"
    # Clean up calling convention and make it a proper declaration
    sig = ghidra_sig.strip()
    # Remove calling conventions if present
    for cc in ['__cdecl ', '__stdcall ', '__fastcall ', '__thiscall ']:
        sig = sig.replace(cc, '')
    # Remove FUN_ prefix from names
    sig = re.sub(r'\bFUN_(\w+)', r'func_\1', sig)
    return sig


def generate_project(output_dir, ghidra_funcs, engine_skeleton, deep_data):
    """Generate the final integrated C project"""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    src_dir = output_dir / "src"
    inc_dir = output_dir / "include"
    src_dir.mkdir(exist_ok=True)
    inc_dir.mkdir(exist_ok=True)

    # Classify all functions
    modules = defaultdict(list)
    for addr, func_info in ghidra_funcs.items():
        category = classify_function(func_info, deep_data)
        modules[category].append((addr, func_info))

    print("[*] Function classification:")
    for cat in sorted(modules.keys(), key=lambda k: -len(modules[k])):
        print("    %-20s: %d functions" % (cat, len(modules[cat])))

    # Generate module source files
    written_funcs = 0
    total_funcs = len(ghidra_funcs)

    for category, funcs in sorted(modules.items()):
        module_file = src_dir / ("%s.c" % category)
        header_file = inc_dir / ("%s.h" % category)

        # Sort by address
        funcs.sort(key=lambda x: x[0])

        # Write header
        with open(header_file, 'w', encoding='utf-8') as hf:
            guard = "%s_H" % category.upper()
            hf.write("/* %s.h - Auto-generated from Ghidra decompilation */\n" % category)
            hf.write("/* Category: %s, %d functions */\n" % (category, len(funcs)))
            hf.write("\n#ifndef %s\n" % guard)
            hf.write("#define %s\n\n" % guard)
            hf.write('#include "common.h"\n')
            hf.write('#include "ghidra_types.h"\n\n')

            for addr, fi in funcs:
                sig = extract_fn_signature(fi.get('signature', 'int func_%s(void)' % addr))
                hf.write("/* 0x%s */\n" % addr)
                hf.write("extern %s;\n\n" % sig)

            hf.write("#endif /* %s */\n" % guard)

        # Write source
        with open(module_file, 'w', encoding='utf-8') as sf:
            sf.write("/* %s.c - Auto-generated from Ghidra decompilation */\n" % category)
            sf.write("/* %d functions, Ghidra 12.1 decompiler */\n" % len(funcs))
            sf.write("\n#include \"%s.h\"\n" % category)
            sf.write('#include "common.h"\n')
            sf.write('#include "ghidra_types.h"\n\n')

            for addr, fi in funcs:
                sig = extract_fn_signature(fi.get('signature', 'int func_%s(void)' % addr))
                pseudo = fi.get('pseudocode', '/* No decompilation available */\n')

                sf.write("/* ============================================================ */\n")
                sf.write("/* Function: %s */\n" % fi.get('name', '?'))
                sf.write("/* Address: 0x%s */\n" % addr)
                sf.write("/* Calls: %d | Xrefs: %d | Body: %d bytes */\n" % (
                    fi.get('callCount', 0), fi.get('xrefCount', 0), fi.get('bodySize', 0)))
                sf.write("/* ============================================================ */\n")
                sf.write("%s {\n" % sig)
                sf.write(pseudo)
                sf.write("}\n\n")

        written_funcs += len(funcs)

    # Copy skeleton files (main.c, network.c, registry.c, etc.)
    for path, content in engine_skeleton.items():
        if path.startswith('src/') or path.startswith('include/'):
            dest = output_dir / path
            # Don't overwrite generated module files
            if not dest.exists():
                dest.parent.mkdir(parents=True, exist_ok=True)
                with open(dest, 'w', encoding='utf-8') as f:
                    f.write(content)

    # Generate ghidra_types.h — common types inferred by Ghidra
    with open(inc_dir / "ghidra_types.h", 'w', encoding='utf-8') as f:
        f.write("/* ghidra_types.h — Inferred type definitions */\n\n")
        f.write("#ifndef GHIDRA_TYPES_H\n")
        f.write("#define GHIDRA_TYPES_H\n\n")
        f.write("#include <windows.h>\n")
        f.write("#include <stdint.h>\n")
        f.write("#include <stdbool.h>\n\n")

        # Collect unique types from signatures
        types_seen = set()
        for addr, fi in ghidra_funcs.items():
            sig = fi.get('signature', '')
            # Extract param types
            params = sig.split('(')[-1].split(')')[0] if '(' in sig else ''
            for param in params.split(','):
                param = param.strip()
                if not param:
                    continue
                parts = param.split()
                if parts:
                    types_seen.add(parts[0])

        f.write("/* Ghidra-inferred type aliases */\n")
        f.write("typedef unsigned char byte;\n")
        f.write("typedef unsigned short ushort;\n")
        f.write("typedef unsigned int uint;\n")
        f.write("typedef unsigned long ulong;\n")
        f.write("typedef long long longlong;\n")
        f.write("typedef unsigned long long ulonglong;\n\n")
        f.write("#endif /* GHIDRA_TYPES_H */\n")

    # Generate common.h — shared include with IAT mappings
    with open(inc_dir / "common.h", 'w', encoding='utf-8') as f:
        f.write("/* common.h — Shared definitions */\n\n")
        f.write("#ifndef COMMON_H\n")
        f.write("#define COMMON_H\n\n")
        f.write("#include <windows.h>\n")
        f.write("#include <winsock2.h>\n")
        f.write("#include <winhttp.h>\n")
        f.write("#include <stdio.h>\n")
        f.write("#include <stdlib.h>\n")
        f.write("#include <string.h>\n\n")
        f.write("/* IAT function pointers (runtime loaded) */\n")

        iat_funcs = deep_data.get('iat', {}).get('func_imports', {}).get('unknown', [])
        for imp in iat_funcs[:50]:
            name = imp.get('name', '?')
            f.write("// extern void* %s;  /* runtime IAT */\n" % name)

        f.write("\n/* QQ API endpoints */\n")
        for url in deep_data.get('urls', [])[:20]:
            f.write("// #define QQ_API \"%s\"\n" % url[:60])

        f.write("\n#endif /* COMMON_H */\n")

    # Copy CMakeLists.txt from skeleton
    cmake_content = engine_skeleton.get('CMakeLists.txt', '')
    if cmake_content:
        # Update to include new module files
        with open(output_dir / "CMakeLists.txt", 'w', encoding='utf-8') as f:
            f.write(cmake_content)

    # Write OVERVIEW.md
    with open(output_dir / "OVERVIEW.md", 'w', encoding='utf-8') as f:
        f.write("# QQ群排名优化软件 — Ghidra 重构项目\n\n")
        f.write("**反编译时间**: %s\n\n" % datetime.now().strftime("%Y-%m-%d %H:%M"))
        f.write("## 反编译流程\n\n")
        f.write("1. **脱壳**: suspend_dump.py（CNM 壳挂起转储法）\n")
        f.write("2. **引擎重构**: reconstruct.py（易语言框架识别 + 项目骨架）\n")
        f.write("3. **Ghidra 反编译**: analyzeHeadless + DecompileToC.java（C 级伪代码）\n")
        f.write("4. **源码整合**: integrate_final.py（合并所有产出）\n\n")
        f.write("## 函数分类统计\n\n")
        f.write("| 类别 | 数量 |\n")
        f.write("|------|------|\n")
        for cat in sorted(modules.keys(), key=lambda k: -len(modules[k])):
            f.write("| %s | %d |\n" % (cat, len(modules[cat])))
        f.write("| **总计** | **%d** |\n\n" % written_funcs)
        f.write("## 构建\n\n")
        f.write("```bash\nmkdir build && cd build\ncmake .. -G \"MinGW Makefiles\"\nmake\n```\n")
        f.write("\n**注意**: 伪代码来自 Ghidra 反编译，需要手动修正类型和逻辑才能编译通过。\n")

    print("\n[+] Project generated: %s" % output_dir)
    print("[+] Modules: %d source files, %d header files" % (
        len(modules), len(modules) + 3))
    print("[+] Total functions written: %d/%d" % (written_funcs, total_funcs))


def main():
    parser = argparse.ArgumentParser(
        description='Final Integration — Ghidra C pseudocode + reconstruct.py skeleton'
    )
    parser.add_argument('--ghidra-dir', required=True, help='Ghidra output directory')
    parser.add_argument('--engine-dir', required=True, help='reconstruct.py output directory')
    parser.add_argument('--deep-dir', default=None, help='deep_analysis directory')
    parser.add_argument('--output', '-o', default=None, help='Output project directory')

    args = parser.parse_args()

    # Load all sources
    print("[*] Loading Ghidra output from: %s" % args.ghidra_dir)
    summary, ghidra_funcs = load_ghidra_output(args.ghidra_dir)
    if not ghidra_funcs:
        print("[!] No functions loaded from Ghidra output")
        sys.exit(1)
    print("[+] Loaded %d functions" % len(ghidra_funcs))

    print("[*] Loading deep analysis from: %s" % (args.deep_dir or 'N/A'))
    deep_data = load_deep_analysis(args.deep_dir) if args.deep_dir else {}

    print("[*] Loading engine skeleton from: %s" % args.engine_dir)
    engine_skeleton = load_engine_skeleton(args.engine_dir)
    print("[+] Loaded %d skeleton files" % len(engine_skeleton))

    # Generate
    output_dir = args.output or str(
        Path(args.ghidra_dir).parent / "final_project"
    )
    generate_project(output_dir, ghidra_funcs, engine_skeleton, deep_data)


if __name__ == '__main__':
    main()
