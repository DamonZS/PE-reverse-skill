#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
reconstruct.py - 源码重构核心引擎 v3

终极目标：从二进制文件生成可修改、可编译、可运行的源码项目。

支持平台：
  - PE/EXE → C/C++ 项目（CMake/Makefile），含易语言专项识别
  - APK → Android Studio 项目（Gradle）+ jadx Java 源码
  - IPA → Xcode 项目骨架（需 macOS 完整执行）
  - API → Python/Go/Java SDK + OpenAPI 文档

v3 更新：
  - 易语言程序专项识别和重构
  - 框架自动检测（Delphi/MFC/Qt/VB6/AutoIt/.NET/易语言）
  - 更完整的函数框架生成
  - analysis.json 扩展，记录框架信息

用法:
  python reconstruct.py <target.exe> --output ./reconstructed/
  python reconstruct.py <target.apk> --output ./reconstructed/
  python reconstruct.py <flow.xml> --platform api --output ./sdk/
"""

import re
import os
import sys
import json
import shutil
import struct
import argparse
import importlib.util
from pathlib import Path
from datetime import datetime

# 确保能导入同目录的 common.py
sys.path.insert(0, str(Path(__file__).parent))
from common import (
    disassemble, find_functions, find_xrefs,
    extract_ascii_strings, extract_unicode_strings, extract_chinese_strings,
    extract_urls, extract_registry_keys, file_hashes, human_size,
    ensure_package, which, run_cmd
)


# ============================================================
# 框架检测
# ============================================================

def detect_framework(pe, data):
    """检测程序开发框架，返回 (framework_name, confidence, details)"""
    ensure_package('pefile')

    ascii_strs = extract_ascii_strings(data, min_len=4)
    all_text = ' '.join(ascii_strs)
    all_bytes = data

    # 易语言（最高优先级——是中国最常见的特殊框架）
    elang_signs = [b'\xe6\x98\x93\xe8\xaf\xad\xe8\xa8\x80', b'ELanguage',
                   b'e_kernel', b'\xce\xd7\xd3\xef\xd1\xd4', b'dywt.com']
    # 版本资源检查
    version_info = _get_version_info(pe)
    if ('易语言' in version_info.get('FileDescription', '') or
        '易语言' in version_info.get('ProductName', '') or
        'dywt.com' in version_info.get('Comments', '') or
        any(sign in all_bytes for sign in elang_signs)):
        comments = version_info.get('Comments', '')
        return ('易语言 (E-Language)', 'HIGH', {
            'version_info': version_info,
            'note': '中国本土可视化编程语言，编译为原生 PE，运行时库内嵌'
        })

    # Delphi/VCL 特征
    delphi_classes = [s for s in ascii_strs if re.match(r'^T[A-Z][a-zA-Z0-9]{3,}$', s)]
    if (len(delphi_classes) > 5 or 'TApplication' in all_text or
        'TForm1' in all_text or b'Borland' in all_bytes or b'Delphi' in all_bytes):
        return ('Delphi/Pascal', 'HIGH', {
            'delphi_classes': delphi_classes[:20],
            'note': 'Borland/Embarcadero Delphi VCL 框架'
        })

    # .NET CLR
    if b'mscoree.dll' in all_bytes or b'_CorExeMain' in all_bytes:
        return ('.NET CLR', 'HIGH', {'note': 'Microsoft .NET 托管代码，推荐用 dnSpy/ILSpy 反编译'})

    # AutoIt
    if b'AU3!' in all_bytes or 'AutoIt' in all_text:
        return ('AutoIt', 'HIGH', {'note': '可用 myAutToExe 或 Exe2Aut 提取原始脚本'})

    # VB6
    if b'MSVBVM60.dll' in all_bytes or b'MSVBVM50.dll' in all_bytes:
        return ('Visual Basic 6', 'HIGH', {'note': 'P-Code 或 Native 编译，用 VB Decompiler 逆向'})

    # Qt
    if b'Qt5Core.dll' in all_bytes or b'Qt6Core.dll' in all_bytes or 'QApplication' in all_text:
        return ('Qt C++', 'MEDIUM', {'note': 'Qt 框架，信号/槽机制'})

    # MFC/ATL
    if 'AfxWinMain' in all_text or 'CWinApp' in all_text:
        return ('MFC C++ (VC++)', 'MEDIUM', {'note': 'Microsoft MFC 框架'})

    # NSIS
    if b'Nullsoft Install System' in all_bytes or 'NSIS Error' in all_text:
        return ('NSIS Installer', 'HIGH', {'note': '安装包，可用 7-Zip 解包'})

    # Electron
    if b'electron.exe' in all_bytes.lower() or 'electron' in all_text.lower():
        return ('Electron (Node.js)', 'MEDIUM', {'note': 'Electron/Node.js 应用'})

    # 默认 C/C++
    linker_ver = pe.OPTIONAL_HEADER.MajorLinkerVersion
    if linker_ver == 6:
        return ('Visual C++ 6.0', 'LOW', {'linker': '6.0', 'note': 'VC6 编译，无运行时'})
    elif linker_ver >= 14:
        return ('Visual C++ 2015+', 'LOW', {'linker': str(linker_ver), 'note': 'MSVC 现代版本'})
    else:
        return ('C/C++ (Unknown Compiler)', 'LOW', {'linker': str(linker_ver)})


def _get_version_info(pe):
    """提取 PE 版本信息"""
    info = {}
    try:
        if hasattr(pe, 'FileInfo'):
            for fi in pe.FileInfo:
                if hasattr(fi, '__iter__'):
                    for fii in fi:
                        if hasattr(fii, 'StringTable'):
                            for st in fii.StringTable:
                                for k, v in st.entries.items():
                                    key = k.decode('utf-8', errors='ignore') if isinstance(k, bytes) else k
                                    val = v.decode('utf-8', errors='ignore') if isinstance(v, bytes) else v
                                    info[key] = val
    except Exception:
        pass
    return info


# ============================================================
# 易语言专项重构
# ============================================================

def reconstruct_elang(exe_path, output_dir, pe, data, version_info, packer_info=None):
    """
    易语言程序专项重构
    
    易语言特点：
    - 中文标识符（变量名、函数名、类名全是中文）
    - 编译为原生 Win32 PE，内嵌运行时（e_kernel 等）
    - GUI 用内置窗体控件（类似 Delphi VCL）
    - 支持调用 DLL 和 Windows API
    
    重构策略：
    - 无法直接还原中文标识符，但可以重构程序结构骨架
    - 生成等效的 C 项目（手动还原）或建议用 Delphi/C++ Builder 重构
    - 提取所有可见的中文字符串、UI 结构、网络逻辑
    """
    exe_path = Path(exe_path)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    src_dir = output_dir / "src"
    include_dir = output_dir / "include"
    elang_dir = output_dir / "elang_analysis"
    src_dir.mkdir(exist_ok=True)
    include_dir.mkdir(exist_ok=True)
    elang_dir.mkdir(exist_ok=True)

    bits = 32 if pe.OPTIONAL_HEADER.Magic == 0x10b else 64
    image_base = pe.OPTIONAL_HEADER.ImageBase
    ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint

    # 提取信息
    ascii_strs = extract_ascii_strings(data, min_len=5)
    utf16_strs = extract_unicode_strings(data, min_len=3)
    cn_strs = extract_chinese_strings(data, min_len=2)
    urls = extract_urls(data)
    reg_keys = extract_registry_keys(data)
    imports = {}
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode('utf-8', errors='ignore')
            funcs = []
            for imp in entry.imports:
                fname = imp.name.decode('utf-8', errors='ignore') if imp.name else ("Ordinal_%d" % imp.ordinal)
                funcs.append(fname)
            imports[dll] = funcs

    ep_data = data[pe.get_offset_from_rva(ep_rva):pe.get_offset_from_rva(ep_rva) + 512]
    ep_disasm = disassemble(ep_data, image_base + ep_rva, 'x86', 32, count=40)

    # ── 生成易语言分析报告 ──
    _write_elang_analysis(elang_dir, exe_path, pe, data, version_info, packer_info,
                          cn_strs, ascii_strs, urls, reg_keys, imports, ep_disasm)

    # ── 生成 C 重构项目（骨架） ──
    _write_elang_c_skeleton(src_dir, include_dir, exe_path, pe, packer_info,
                             imports, urls, cn_strs, ep_disasm, version_info)

    # ── 构建系统 ──
    _write_cmake(output_dir, exe_path.stem, bits)
    _write_makefile(output_dir, exe_path.stem, bits)

    # ── README ──
    _write_elang_readme(output_dir, exe_path.name, version_info, packer_info,
                         imports, cn_strs, urls)

    # ── analysis.json ──
    analysis = {
        'file': str(exe_path),
        'hashes': file_hashes(str(exe_path)),
        'bits': bits,
        'framework': '易语言 (E-Language)',
        'framework_confidence': 'HIGH',
        'version_info': version_info,
        'packer': packer_info,
        'imports': imports,
        'urls': urls,
        'registry_keys': reg_keys,
        'chinese_strings': cn_strs[:200],
        'ascii_strings_count': len(ascii_strs),
        'reconstruct_time': datetime.now().isoformat(),
    }
    with open(output_dir / "analysis.json", 'w', encoding='utf-8') as f:
        json.dump(analysis, f, ensure_ascii=False, indent=2)

    print("\n[+] 易语言程序重构完成!")
    _print_tree(output_dir)
    print("\n[!] 重要提示：")
    print("    易语言编译的程序无法完全还原为原始易语言源码。")
    print("    已生成等效 C 项目骨架 + 详细分析报告。")
    print("    建议阅读: %s" % (output_dir / "elang_analysis" / "ANALYSIS.md"))


def _write_elang_analysis(out_dir, exe_path, pe, data, version_info, packer_info,
                           cn_strs, ascii_strs, urls, reg_keys, imports, ep_disasm):
    """生成详细的易语言分析报告"""
    lines = [
        "# 易语言程序逆向分析报告",
        "",
        "## 基本信息",
        "",
        "| 项目 | 值 |",
        "|------|-----|",
        "| 文件 | `%s` |" % exe_path.name,
        "| 框架 | 易语言 (E-Language) |",
        "| 官网 | http://www.dywt.com.cn |",
    ]
    for k, v in version_info.items():
        lines.append("| %s | %s |" % (k, v))

    if packer_info:
        lines.append("| 加壳 | %s |" % packer_info)

    lines.extend([
        "",
        "## 易语言程序特征说明",
        "",
        "易语言是中国开发的可视化编程语言（类似 Delphi），其程序特点：",
        "",
        "1. **中文标识符**：所有变量名、函数名、类名均为中文",
        "2. **内嵌运行时**：不依赖外部 DLL，运行时代码编译进 EXE",
        "3. **私有 GUI 控件**：使用易语言内置窗体/按钮/标签等控件",
        "4. **加壳保护**：很多易语言程序会加壳（CNM 壳等私有壳）",
        "",
        "## 逆向策略",
        "",
        "### 方案 1（推荐）：动态脱壳 + 静态分析",
        "",
        "```",
        "1. x32dbg 加载程序，ESP 定律法脱壳",
        "2. 用 Ghidra/IDA 分析脱壳后的 PE",
        "3. 找到易语言 WinMain 入口（通常是 TApplication.Initialize → TApplication.Run）",
        "4. 分析窗体事件处理函数",
        "5. 用 GBK 编码解码所有 char* 字符串（显示中文）",
        "```",
        "",
        "### 方案 2：字符串追踪法",
        "",
        "```",
        "1. 程序中的中文字符串以 GBK 编码存储",
        "2. x32dbg → 搜索字符串 → 找到关键提示（如「激活成功」「注册码」等）",
        "3. 从这些字符串反向追踪到验证逻辑",
        "4. 找到 patch 点（jmp/je/jne 跳转）即可绕过验证",
        "```",
        "",
        "### 方案 3（CTF 专用）：内存断点法",
        "",
        "```",
        "1. 运行程序，出现注册/激活界面",
        "2. x32dbg → 内存映射 → 找到输入框对应的内存区域",
        "3. 设硬件访问断点",
        "4. 输入内容后断下，追踪到验证函数",
        "```",
        "",
        "## 导入函数分析",
        "",
        "| DLL | 函数 | 行为推断 |",
        "|-----|------|---------|",
    ])

    behavior_map = {
        'ShellExecuteA': '执行外部命令/打开文件',
        'RegCreateKeyExA': '创建/写入注册表（保存激活状态？）',
        'RegOpenKeyExA': '读取注册表（检查激活状态）',
        'gethostbyname': 'DNS 解析（远程验证？）',
        'connect': '建立 TCP 连接（远程验证）',
        'send': '发送数据',
        'recv': '接收数据',
        'GetModuleHandleA': '获取模块句柄',
        'LoadLibraryA': '动态加载 DLL',
        'GetProcAddress': '动态解析函数地址',
        'CreateFileA': '文件操作',
        'WriteFile': '写文件',
        'ReadFile': '读文件',
        'GetVersionExA': '获取系统版本（反沙箱？）',
        'IsDebuggerPresent': '检测调试器（反调试！）',
        'CheckRemoteDebuggerPresent': '远程调试检测（反调试！）',
        'CreateProcessA': '创建子进程',
        'OpenProcess': '打开进程句柄',
    }

    for dll, funcs in sorted(imports.items()):
        for f in funcs:
            behavior = behavior_map.get(f, '-')
            flag = ' ⚠️' if '反调试' in behavior or '验证' in behavior else ''
            lines.append("| %s | `%s` | %s%s |" % (dll, f, behavior, flag))

    lines.extend([
        "",
        "## 提取的 URL / 网络端点",
        "",
    ])
    if urls:
        for u in sorted(set(urls)):
            lines.append("- `%s`" % u)
    else:
        lines.append("（未直接提取到 URL，可能在壳内加密存储）")

    lines.extend([
        "",
        "## 注册表相关",
        "",
    ])
    if reg_keys:
        for rk in sorted(set(reg_keys)):
            lines.append("- `%s`" % rk)
    else:
        lines.append("（需要动态分析获取实际注册表键）")

    lines.extend([
        "",
        "## 中文字符串（GBK 解码，前 100 条）",
        "",
        "注：部分乱码是加壳加密导致的，脱壳后字符串才会可读。",
        "",
        "```",
    ])
    # 过滤明显乱码（过滤掉2个字符以下的以及乱码字符）
    real_cn = [s for s in cn_strs if len(s) > 2 and not all(
        '\u4e00' <= c <= '\u9fff' and ord(c) % 10 == 0 for c in s if c.isalpha()
    )]
    for s in real_cn[:100]:
        lines.append(s)
    lines.extend([
        "```",
        "",
        "## 入口点反汇编",
        "",
        "```asm",
    ])
    for addr, size, mn, op, raw in ep_disasm:
        lines.append("%08X: %-10s %s" % (addr, mn, op))
    lines.extend([
        "```",
        "",
        "## 下一步建议",
        "",
        "1. **脱壳**（最重要）：用 x32dbg ESP 定律法脱壳，获取真正的代码段",
        "2. **字符串解码**：脱壳后搜索 GBK 编码的中文字符串",
        "3. **找注册/激活逻辑**：搜索「激活」「成功」「注册」等字符串",
        "4. **动态分析**：在 `RegCreateKeyExA` / `gethostbyname` 处设断",
        "5. **API 监控**：用 ProcMon 记录所有注册表和文件操作",
    ])

    with open(out_dir / "ANALYSIS.md", 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))

    # 同时写 GBK 解码尝试结果
    _write_gbk_strings(out_dir, data, packer_info, pe)


def _write_gbk_strings(out_dir, data, packer_info=None, pe=None):
    """尝试 GBK 解码所有可能的中文字符串"""
    lines = ["# GBK 字符串提取结果", "",
             "这些是从程序中提取的 GBK 编码字符串。", ""]

    if packer_info:
        lines.extend([
            "> ⚠️ **此程序加壳（%s），加壳段的数据会伪匹配 GBK 模式。**" % packer_info,
            "> 已自动过滤高熵段（加密段），仅从低熵/资源段提取。",
            "> 脱壳后重新运行重构引擎可提取更完整的字符串。",
            "",
        ])

    # 确定可搜索的偏移范围（避免搜索加壳段）
    search_data = data
    if packer_info and pe is not None:
        # 只从低熵段和资源段提取
        safe_ranges = []
        for sec in pe.sections:
            name = sec.Name.decode('utf-8', errors='ignore').rstrip('\x00')
            sec_entropy = sec.get_entropy() if hasattr(sec, 'get_entropy') else 0
            sec_offset = sec.PointerToRawData
            sec_size = min(sec.SizeOfRawData, len(data) - sec_offset) if sec.SizeOfRawData > 0 else 0
            # 资源段、低熵段（< 6.5）才安全
            is_resource = name in ('.rsrc', '.idata', '.edata')
            is_low_entropy = sec_entropy < 6.5
            if is_resource or is_low_entropy:
                if sec_size > 0 and sec_offset + sec_size <= len(data):
                    safe_ranges.append((sec_offset, sec_offset + sec_size, name, sec_entropy))

        if safe_ranges:
            lines.append("搜索的段：%s" % ', '.join(
                '%s(entropy=%.1f)' % (n, e) for _, _, n, e in safe_ranges))
            lines.append("")
            # 拼接安全段的数据
            safe_data = bytearray()
            for start, end, _, _ in safe_ranges:
                safe_data.extend(data[start:end])
            search_data = bytes(safe_data)
        else:
            lines.append("所有段均为高熵（加密），无法提取 GBK 字符串。")
            lines.append("")
            lines.append("**需要先脱壳才能提取到有效的中文字符串。**")
            lines.append("脱壳方法：x32dbg → ESP 定律法 → Scylla dump")
            with open(out_dir / "gbk_strings.md", 'w', encoding='utf-8') as f:
                f.write('\n'.join(lines))
            return

    # GBK 双字节匹配：首字节 0x81-0xFE，次字节 0x40-0xFE
    gbk_pattern = re.findall(rb'(?:[\x81-\xfe][\x40-\x7e\x80-\xfe]){2,}', search_data)
    decoded = set()
    for m in gbk_pattern:
        try:
            s = m.decode('gbk', errors='strict').strip()
            if len(s) < 2 or s in decoded:
                continue
            # 可读性检测：至少 40% 的字符是常用中文字符
            cn_chars = sum(1 for c in s if '\u4e00' <= c <= '\u9fff')
            total_chars = len(s.replace(' ', ''))
            if total_chars == 0:
                continue
            cn_ratio = cn_chars / total_chars
            if cn_ratio < 0.3:
                continue
            # 排除纯重复字符
            if len(set(s)) <= 2:
                continue
            decoded.add(s)
        except (UnicodeDecodeError, ValueError):
            pass

    if decoded:
        # 可读性排序函数
        def readability(s):
            cn = sum(1 for c in s if '\u4e00' <= c <= '\u9fff')
            return cn / max(len(s), 1)

        # 最终质量检查：过滤掉不含常用汉字的字符串
        # 常用汉字范围：U+4E00-U+53FF（覆盖最常用的 ~2000 字）
        def has_consecutive_common(s):
            """检查是否含有至少2个连续常用汉字"""
            consecutive = 0
            for c in s:
                if '\u4e00' <= c <= '\u53ff':
                    consecutive += 1
                    if consecutive >= 2:
                        return True
                else:
                    consecutive = 0
            return False

        readable_strs = [s for s in sorted(decoded, key=readability, reverse=True)
                         if has_consecutive_common(s)]

        if readable_strs:
            lines.append("共提取到 %d 条有效 GBK 字符串（按可读性排序）：" % len(readable_strs))
            lines.append("")
            lines.append("```")
            for s in readable_strs[:200]:
                lines.append(s)
            lines.append("```")
        else:
            lines.append("低熵段中未发现可读的中文字符串。")
            lines.append("（资源段中提取到的候选字符串均为乱码，说明有效字符串在加密段中）")
            lines.append("")
            lines.append("**需要先脱壳才能提取到有效的中文字符串。**")
            lines.append("脱壳方法：x32dbg → ESP 定律法 → Scylla dump")
            lines.append("脱壳后重新运行重构引擎即可提取。")
    else:
        lines.append("未能提取到有效 GBK 字符串（程序可能加壳加密了字符串）")
        lines.append("")
        lines.append("**需要先脱壳才能提取到有效的中文字符串。**")
        lines.append("脱壳方法：x32dbg → ESP 定律法 → Scylla dump")
        lines.append("脱壳后重新运行重构引擎即可提取。")

    with open(out_dir / "gbk_strings.md", 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))


def _write_elang_c_skeleton(src_dir, include_dir, exe_path, pe, packer_info,
                              imports, urls, cn_strs, ep_disasm, version_info=None):
    """生成等效 C 项目骨架"""
    bits = 32 if pe.OPTIONAL_HEADER.Magic == 0x10b else 64

    # ── imports.h ──
    _write_imports_h(include_dir, imports, bits)

    # ── strings.h ──（包含中文字符串作为 L"" 宽字符定义）
    with open(include_dir / "strings.h", 'w', encoding='utf-8') as f:
        f.write('/*\n * strings.h - 字符串常量\n * 易语言中文字符串以 GBK 存储，这里转为 Unicode\n */\n\n')
        f.write('#ifndef STRINGS_H\n#define STRINGS_H\n\n')
        f.write('/* ── 网络端点 ── */\n')
        for i, u in enumerate(sorted(set(urls))[:20]):
            f.write('#define URL_%d "%s"\n' % (i, u.replace('"', '\\"')))
        f.write('\n/* ── 中文界面字符串（估计值，脱壳后可验证）── */\n')
        for i, s in enumerate(cn_strs[:30]):
            escaped = s.replace('"', '\\"')[:80]
            f.write('/* CNSTR_%d: %s */\n' % (i, escaped))
        f.write('\n#endif /* STRINGS_H */\n')

    # ── protocol.h ──
    _write_protocol_h(include_dir, urls, imports, [])

    # ── windows_compat.h ──
    _write_windows_compat_h(include_dir)

    # ── main.c ──（易语言风格的等效框架）
    all_func_names = [f.lower() for funcs in imports.values() for f in funcs]
    has_network = any(k in all_func_names for k in ['gethostbyname', 'connect', 'send', 'recv'])
    has_registry = any('regcreate' in f or 'regopen' in f or 'regset' in f for f in all_func_names)
    has_shell = any('shellexecute' in f for f in all_func_names)

    # 窗口标题：优先用 ProductName/FileDescription，否则用文件名
    window_title = (version_info.get('ProductName') or
                    version_info.get('FileDescription') or
                    exe_path.stem)
    # 移除「易语言程序」这类通用描述
    if window_title in ('易语言程序', 'E-Language Program', ''):
        window_title = exe_path.stem

    main_lines = [
        "/*",
        " * main.c - 易语言程序等效 C 重构",
        " *",
        " * 原程序: %s" % exe_path.name,
        " * 框架: 易语言 (E-Language)",
        " * 说明: 易语言 GUI 程序，中文变量名/函数名无法还原",
        " *       此文件是等效的 Win32 C 程序骨架",
        " *",
    ]
    if packer_info:
        main_lines.extend([
            " * 加壳: %s（需脱壳后补充完整逻辑）" % packer_info,
        ])
    main_lines.extend([
        " */",
        "",
        '#include <windows.h>',
        '#include <winsock2.h>',
        '#include <stdio.h>',
        '#include <stdlib.h>',
        '#include <string.h>',
        '#include "imports.h"',
        '#include "strings.h"',
        '#include "protocol.h"',
        "",
        "/* ══════════════════════════════════════════════════════════",
        " * 易语言等效结构定义",
        " * 易语言使用内置窗体控件，等效为以下 Win32 结构",
        " * ══════════════════════════════════════════════════════════ */",
        "",
        "typedef struct {",
        "    HWND hWnd;",
        "    HINSTANCE hInstance;",
        "    /* TODO: 添加窗体控件句柄 */",
        "} MainForm;",
        "",
        "/* 全局变量（易语言全局变量） */",
        "static MainForm g_MainForm = {0};",
        "",
    ])

    # 生成窗体回调
    main_lines.extend([
        "/* ── 窗体消息处理 ── */",
        "LRESULT CALLBACK MainFormProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {",
        "    switch (msg) {",
        "    case WM_CREATE:",
        "        /* TODO: 窗体初始化（等效易语言「窗口_创建」事件） */",
    ])
    if has_registry:
        main_lines.extend([
            "        /* 读取注册表配置 */",
            "        /* registry_read_config(&g_config); */",
        ])
    if has_network:
        main_lines.extend([
            "        /* 初始化网络 */",
            "        /* WSAStartup(MAKEWORD(2,2), &wsaData); */",
        ])
    main_lines.extend([
        "        return 0;",
        "",
        "    case WM_COMMAND:",
        "        /* TODO: 按钮点击等控件事件（等效易语言「按钮_被单击」事件） */",
        "        switch (LOWORD(wParam)) {",
        "            /* case IDC_BUTTON1: handle_button1_click(); break; */",
        "        }",
        "        return 0;",
        "",
        "    case WM_DESTROY:",
        "        /* TODO: 窗体关闭清理 */",
    ])
    if has_network:
        main_lines.append("        /* WSACleanup(); */")
    main_lines.extend([
        "        PostQuitMessage(0);",
        "        return 0;",
        "",
        "    default:",
        "        return DefWindowProcA(hWnd, msg, wParam, lParam);",
        "    }",
        "}",
        "",
        "/* ── 主函数 ── */",
        "int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,",
        "                   LPSTR lpCmdLine, int nCmdShow) {",
        "    /* 初始化 */",
        "    g_MainForm.hInstance = hInstance;",
        "",
    ])
    if has_network:
        main_lines.extend([
            "    /* 网络初始化 */",
            "    WSADATA wsaData;",
            "    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {",
            "        MessageBoxA(NULL, \"网络初始化失败\", \"错误\", MB_OK | MB_ICONERROR);",
            "        return 1;",
            "    }",
            "",
        ])
    main_lines.extend([
        "    /* 注册窗体类 */",
        "    WNDCLASSA wc = {0};",
        "    wc.lpfnWndProc = MainFormProc;",
        "    wc.hInstance = hInstance;",
        '    wc.lpszClassName = "MainForm";',
        "    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);",
        "    wc.hCursor = LoadCursorA(NULL, IDC_ARROW);",
        "    RegisterClassA(&wc);",
        "",
        "    /* 创建主窗口 */",
        "    g_MainForm.hWnd = CreateWindowExA(",
        "        0,",
        '        "MainForm",',
        '        "%s",  /* 窗口标题 */' % window_title,
        "        WS_OVERLAPPEDWINDOW,",
        "        CW_USEDEFAULT, CW_USEDEFAULT, 800, 600,",
        "        NULL, NULL, hInstance, NULL",
        "    );",
        "",
        "    if (!g_MainForm.hWnd) return 1;",
        "",
        "    ShowWindow(g_MainForm.hWnd, nCmdShow);",
        "    UpdateWindow(g_MainForm.hWnd);",
        "",
        "    /* 消息循环 */",
        "    MSG msg = {0};",
        "    while (GetMessageA(&msg, NULL, 0, 0)) {",
        "        TranslateMessage(&msg);",
        "        DispatchMessageA(&msg);",
        "    }",
        "",
    ])
    if has_network:
        main_lines.append("    WSACleanup();")
    main_lines.extend([
        "    return (int)msg.wParam;",
        "}",
        "",
        "/*",
        " * ════════════════════════════════════════════════════════",
        " * 入口点反汇编（供参考）：",
    ])
    for addr, size, mn, op, raw in ep_disasm[:20]:
        main_lines.append(" *   %08X: %-8s %s" % (addr, mn, op))
    main_lines.extend([
        " * ════════════════════════════════════════════════════════",
        " */",
    ])

    with open(src_dir / "main.c", 'w', encoding='utf-8') as f:
        f.write('\n'.join(main_lines))

    # ── network.c（如果有网络功能）──
    if has_network:
        net_code = """/*
 * network.c - 网络通信实现
 * 基于 WS2_32.dll 导入推断
 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include "protocol.h"

BOOL network_init(NetworkConnection* conn, const char* host, int port) {
    if (!conn || !host) return FALSE;
    memset(conn, 0, sizeof(NetworkConnection));

    struct hostent* he = gethostbyname(host);
    if (!he) return FALSE;

    conn->sock = socket(AF_INET, SOCK_STREAM, 0);
    if (conn->sock == INVALID_SOCKET) return FALSE;

    conn->server_addr.sin_family = AF_INET;
    conn->server_addr.sin_port = htons((u_short)port);
    conn->server_addr.sin_addr = *(struct in_addr*)he->h_addr;

    if (connect(conn->sock, (struct sockaddr*)&conn->server_addr,
                sizeof(conn->server_addr)) == SOCKET_ERROR) {
        closesocket(conn->sock);
        return FALSE;
    }

    conn->connected = TRUE;
    return TRUE;
}

int network_send(NetworkConnection* conn, const char* data, int len) {
    if (!conn || !conn->connected) return -1;
    return send(conn->sock, data, len, 0);
}

int network_recv(NetworkConnection* conn, char* buffer, int buf_size) {
    if (!conn || !conn->connected) return -1;
    return recv(conn->sock, buffer, buf_size, 0);
}

void network_close(NetworkConnection* conn) {
    if (conn && conn->sock != INVALID_SOCKET) {
        closesocket(conn->sock);
        conn->sock = INVALID_SOCKET;
        conn->connected = FALSE;
    }
}
"""
        with open(src_dir / "network.c", 'w', encoding='utf-8') as f:
            f.write(net_code)

    # ── registry.c（如果有注册表）──
    if has_registry:
        reg_code = """/*
 * registry.c - 注册表操作实现
 * 基于 ADVAPI32.dll 导入推断（可能用于保存激活状态）
 */
#include <windows.h>
#include "protocol.h"

/* 注册表根键 */
#define REG_BASE_KEY HKEY_CURRENT_USER
/* TODO: 替换为实际路径（用 ProcMon 监控 RegCreateKeyExA 获取） */
#define REG_SUB_KEY "SOFTWARE\\\\QQRank"

BOOL registry_read_config(RegistryConfig* config) {
    if (!config) return FALSE;

    HKEY hKey;
    LONG result = RegOpenKeyExA(
        REG_BASE_KEY,
        REG_SUB_KEY,
        0,
        KEY_READ,
        &hKey
    );

    if (result != ERROR_SUCCESS) return FALSE;
    config->hKey = hKey;
    strncpy_s(config->subkey, sizeof(config->subkey), REG_SUB_KEY, _TRUNCATE);
    return TRUE;
}

BOOL registry_write_config(RegistryConfig* config, const char* value_name,
                             DWORD type, const BYTE* data, DWORD data_size) {
    if (!config) {
        /* 如果没有打开的键，先创建 */
        HKEY hKey;
        DWORD disposition;
        LONG result = RegCreateKeyExA(
            REG_BASE_KEY,
            REG_SUB_KEY,
            0, NULL,
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            NULL,
            &hKey,
            &disposition
        );
        if (result != ERROR_SUCCESS) return FALSE;
        result = RegSetValueExA(hKey, value_name, 0, type, data, data_size);
        RegCloseKey(hKey);
        return result == ERROR_SUCCESS;
    }

    LONG result = RegSetValueExA(config->hKey, value_name, 0, type, data, data_size);
    return result == ERROR_SUCCESS;
}
"""
        with open(src_dir / "registry.c", 'w', encoding='utf-8') as f:
            f.write(reg_code)


def _write_elang_readme(output_dir, exe_name, version_info, packer_info, imports, cn_strs, urls):
    lines = [
        "# %s - 易语言程序逆向重构" % exe_name,
        "",
        "## 程序信息",
        "",
        "| 项目 | 值 |",
        "|------|-----|",
        "| 文件 | `%s` |" % exe_name,
        "| 框架 | **易语言 (E-Language)** - 中国本土可视化编程语言 |",
        "| 官网 | http://www.dywt.com.cn |",
    ]
    for k, v in version_info.items():
        lines.append("| %s | `%s` |" % (k, v))
    if packer_info:
        lines.append("| 加壳 | `%s` |" % packer_info)

    lines.extend([
        "",
        "## 项目结构",
        "",
        "```",
        "src/",
        "├── main.c          - 等效 Win32 C 程序骨架（含窗体框架）",
        "├── network.c       - 网络通信实现（如果程序有网络功能）",
        "├── registry.c      - 注册表操作（激活状态保存/读取）",
        "include/",
        "├── imports.h       - 所有导入函数声明",
        "├── strings.h       - 字符串和 URL 常量",
        "├── protocol.h      - 网络/注册表结构定义",
        "└── windows_compat.h",
        "elang_analysis/",
        "├── ANALYSIS.md     - 详细逆向分析报告",
        "└── gbk_strings.md  - GBK 编码字符串提取",
        "CMakeLists.txt",
        "Makefile",
        "analysis.json       - 结构化分析数据",
        "```",
        "",
        "## 构建",
        "",
        "```bash",
        "mkdir build && cd build",
        "cmake .. -G \"MinGW Makefiles\"",
        "make",
        "```",
        "",
        "## 逆向指南（重要）",
        "",
        "因为是易语言程序且有壳，**完整源码还原需要以下步骤**：",
        "",
        "### 步骤 1：脱壳",
        "",
        "```",
        "1. x32dbg 加载 %s" % exe_name,
        "2. EP 处观察是否是 PUSHAD（私有壳典型开头）",
        "3. ESP 定律法：PUSHAD → 对 ESP 设硬件断点 → F9 → 找 OEP",
        "4. Scylla → Fix Dump → 保存脱壳后文件",
        "```",
        "",
        "### 步骤 2：分析脱壳后的程序",
        "",
        "```",
        "1. 用 Ghidra/IDA 打开脱壳文件",
        "2. 搜索 GBK 字符串（易语言中文字符串）",
        "3. 找到主窗体初始化函数",
        "4. 分析按钮点击/验证逻辑",
        "```",
        "",
        "### 步骤 3：找关键逻辑",
        "",
        "在脱壳后的内存中搜索这些中文字符串：",
        "",
    ])
    for s in cn_strs[:20]:
        if len(s) > 2 and len(s) < 30:
            lines.append("- `%s`" % s)

    lines.extend([
        "",
        "### 步骤 4：重构源码",
        "",
        "脱壳后重新运行重构引擎：",
        "```bash",
        "python scripts/reconstruct.py <脱壳后.exe> --output ./reconstructed_unpacked/",
        "```",
    ])

    with open(output_dir / "README.md", 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))


# ============================================================
# PE → C/C++ 源码重构（通用）
# ============================================================

def reconstruct_pe(exe_path, output_dir, packer_info=None):
    """从 PE 文件重构 C/C++ 源码项目（自动检测框架）"""
    ensure_package('pefile')
    ensure_package('capstone')
    import pefile as pefile_mod

    exe_path = Path(exe_path).resolve()
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    with open(exe_path, 'rb') as f:
        data = f.read()
    pe = pefile_mod.PE(str(exe_path))

    bits = 32 if pe.OPTIONAL_HEADER.Magic == 0x10b else 64
    arch = 'x86' if bits == 32 else 'x64'
    image_base = pe.OPTIONAL_HEADER.ImageBase
    ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint

    # 检测框架
    framework, confidence, fw_details = detect_framework(pe, data)
    version_info = _get_version_info(pe)

    print("[*] PE 源码重构: %s (%d-bit)" % (exe_path.name, bits))
    print("[*] 框架识别: %s (置信度: %s)" % (framework, confidence))
    print("[*] 输出目录: %s" % output_dir)

    # 易语言走专项流程
    if '易语言' in framework:
        return reconstruct_elang(exe_path, output_dir, pe, data, version_info, packer_info)

    # 通用 C/C++ 重构流程
    imports = {}
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode('utf-8', errors='ignore')
            funcs = []
            for imp in entry.imports:
                fname = imp.name.decode('utf-8', errors='ignore') if imp.name else ("Ordinal_%d" % imp.ordinal)
                funcs.append(fname)
            imports[dll] = funcs

    exports = []
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        exp = pe.DIRECTORY_ENTRY_EXPORT
        export_list = (exp.symbols if hasattr(exp, 'symbols') else
                       exp.exports if hasattr(exp, 'exports') else [])
        for e in export_list:
            fname = (e.name.decode('utf-8', errors='ignore') if hasattr(e, 'name') and e.name
                     else "Ordinal_%d" % (e.ordinal if hasattr(e, 'ordinal') else 0))
            addr = e.address if hasattr(e, 'address') else 0
            exports.append({'name': fname, 'address': addr})

    ascii_strings = extract_ascii_strings(data, min_len=6)
    utf16_strings = extract_unicode_strings(data, min_len=4)
    cn_strings = extract_chinese_strings(data, min_len=2)
    urls = extract_urls(data)
    reg_keys = extract_registry_keys(data)

    try:
        ep_offset = pe.get_offset_from_rva(ep_rva)
    except Exception:
        ep_offset = ep_rva
    ep_data = data[ep_offset:ep_offset + 512]
    ep_disasm = disassemble(ep_data, image_base + ep_rva, arch=arch, mode=bits, count=50)

    # 查找 .text 段
    disasm_results = []
    identified_functions = []
    text_section = None
    for sec in pe.sections:
        name = sec.Name.decode('utf-8', errors='ignore').rstrip('\x00')
        if name == '.text' and sec.SizeOfRawData > 0:
            text_section = sec
            break

    if text_section and text_section.SizeOfRawData > 0:
        text_data = data[text_section.PointerToRawData:
                         text_section.PointerToRawData + min(text_section.SizeOfRawData, 2 * 1024 * 1024)]
        text_va = image_base + text_section.VirtualAddress
        disasm_results = disassemble(text_data, text_va, arch=arch, mode=bits, count=10000)
        identified_functions = find_functions(text_data, text_va, arch=arch, mode=bits)

    src_dir = output_dir / "src"
    include_dir = output_dir / "include"
    src_dir.mkdir(exist_ok=True)
    include_dir.mkdir(exist_ok=True)

    _write_imports_h(include_dir, imports, bits)
    _write_imports_c(src_dir, imports, bits)
    _write_strings_h(include_dir, ascii_strings, utf16_strings, cn_strings, urls)
    _write_protocol_h(include_dir, urls, imports, reg_keys)
    _write_crypto_h(include_dir, data, imports)
    _write_resource_h(include_dir, pe)
    _write_main_c(src_dir, pe, ep_disasm, identified_functions, imports, packer_info)
    _write_functions_c(src_dir, identified_functions, disasm_results, image_base, bits)
    _write_windows_compat_h(include_dir)
    _write_cmake(output_dir, exe_path.stem, bits)
    _write_makefile(output_dir, exe_path.stem, bits)
    _write_readme(output_dir, exe_path.name, pe, packer_info, imports, exports,
                  identified_functions, urls, cn_strings)

    analysis_data = {
        'file': str(exe_path),
        'hashes': file_hashes(str(exe_path)),
        'bits': bits,
        'framework': framework,
        'framework_confidence': confidence,
        'framework_details': fw_details,
        'version_info': version_info,
        'image_base': image_base,
        'ep_rva': ep_rva,
        'packer': packer_info,
        'imports': {dll: funcs for dll, funcs in imports.items()},
        'exports': exports,
        'urls': urls,
        'registry_keys': reg_keys,
        'chinese_strings': cn_strings[:100],
        'functions_identified': len(identified_functions),
        'reconstruct_time': datetime.now().isoformat(),
    }
    with open(output_dir / "analysis.json", 'w', encoding='utf-8') as f:
        json.dump(analysis_data, f, indent=2, ensure_ascii=False)

    pe.close()

    print("\n[+] PE 源码重构完成!")
    _print_tree(output_dir)
    print("\n[+] 构建方法:")
    print("    cd %s" % output_dir)
    print("    mkdir build && cd build")
    print('    cmake .. -G "MinGW Makefiles"')
    print("    make")

    return str(output_dir)


# ============================================================
# 公共源码生成函数
# ============================================================

def _write_imports_h(dir_path, imports, bits):
    lines = [
        "/* imports.h - 导入函数声明（从 PE 导入表自动生成） */",
        "#ifndef IMPORTS_H", "#define IMPORTS_H",
        "", "#include <windows.h>", "#include <winsock2.h>", "",
    ]
    for dll, funcs in sorted(imports.items()):
        lines.append("/* ── %s ── */" % dll)
        for func in funcs:
            if func.startswith('Ordinal_'):
                continue
            decl = _infer_function_signature(func, dll)
            lines.append("extern %s;" % decl)
        lines.append("")
    lines.append("#endif /* IMPORTS_H */")
    with open(dir_path / "imports.h", 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))


def _infer_function_signature(func_name, dll):
    known_sigs = {
        'GetModuleHandleA': 'HMODULE WINAPI GetModuleHandleA(LPCSTR lpModuleName)',
        'LoadLibraryA': 'HMODULE WINAPI LoadLibraryA(LPCSTR lpLibFileName)',
        'GetProcAddress': 'FARPROC WINAPI GetProcAddress(HMODULE hModule, LPCSTR lpProcName)',
        'ExitProcess': 'VOID WINAPI ExitProcess(UINT uExitCode)',
        'GetModuleFileNameA': 'DWORD WINAPI GetModuleFileNameA(HMODULE hModule, LPSTR lpFilename, DWORD nSize)',
        'LocalAlloc': 'HLOCAL WINAPI LocalAlloc(UINT uFlags, SIZE_T uBytes)',
        'LocalFree': 'HLOCAL WINAPI LocalFree(HLOCAL hMem)',
        'ShellExecuteA': 'HINSTANCE WINAPI ShellExecuteA(HWND hwnd, LPCSTR op, LPCSTR file, LPCSTR params, LPCSTR dir, INT show)',
        'RegCreateKeyExA': 'LONG WINAPI RegCreateKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, LPSTR lpClass, DWORD dwOptions, REGSAM samDesired, LPSECURITY_ATTRIBUTES lpSA, PHKEY phkResult, LPDWORD lpdwDisposition)',
        'RegSetValueExA': 'LONG WINAPI RegSetValueExA(HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE* lpData, DWORD cbData)',
        'RegOpenKeyExA': 'LONG WINAPI RegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult)',
        'RegCloseKey': 'LONG WINAPI RegCloseKey(HKEY hKey)',
        'gethostbyname': 'struct hostent* WSAAPI gethostbyname(const char* name)',
        'SystemParametersInfoA': 'BOOL WINAPI SystemParametersInfoA(UINT uiAction, UINT uiParam, PVOID pvParam, UINT fWinIni)',
        'GetVersion': 'DWORD WINAPI GetVersion(void)',
        'GetVersionExA': 'BOOL WINAPI GetVersionExA(LPOSVERSIONINFOA lpVersionInformation)',
        'waveOutPrepareHeader': 'MMRESULT WINAPI waveOutPrepareHeader(HWAVEOUT hWaveOut, LPWAVEHDR lpWaveOutHdr, UINT cbWaveOutHdr)',
        'CoFreeUnusedLibraries': 'void WINAPI CoFreeUnusedLibraries(void)',
        'UnRegisterTypeLib': 'HRESULT WINAPI UnRegisterTypeLib(REFGUID libID, WORD wVerMajor, WORD wVerMinor, LCID lcid, SYSKIND syskind)',
        'ChooseColorA': 'BOOL WINAPI ChooseColorA(LPCHOOSECOLORA lpcc)',
        'GetWindowExtEx': 'BOOL WINAPI GetWindowExtEx(HDC hdc, LPSIZE lpsize)',
        'ClosePrinter': 'BOOL WINAPI ClosePrinter(HANDLE hPrinter)',
    }
    if func_name in known_sigs:
        return known_sigs[func_name]
    return "void* WINAPI %s(void)" % func_name


def _write_imports_c(dir_path, imports, bits):
    lines = [
        "/* imports.c - 导入函数动态加载实现 */",
        '#include "imports.h"', '#include <stdio.h>', "",
    ]
    for dll, funcs in sorted(imports.items()):
        safe_dll = re.sub(r'[^A-Za-z0-9_]', '_', dll)
        lines.append("static HMODULE h_%s = NULL;" % safe_dll)
    lines.extend(["", "BOOL imports_init(void) {", "    HMODULE h;", ""])
    for dll, funcs in sorted(imports.items()):
        safe_dll = re.sub(r'[^A-Za-z0-9_]', '_', dll)
        lines.append('    h_%s = LoadLibraryA("%s");' % (safe_dll, dll))
        for func in funcs:
            if not func.startswith('Ordinal_'):
                lines.append('    /* %s = GetProcAddress(h_%s, "%s"); */' % (func, safe_dll, func))
        lines.append("")
    lines.extend(["    return TRUE;", "}"])
    with open(dir_path / "imports.c", 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))


def _write_strings_h(dir_path, ascii_strings, utf16_strings, cn_strings, urls):
    lines = ["/* strings.h - 字符串常量 */", "#ifndef STRINGS_H", "#define STRINGS_H", ""]
    if urls:
        lines.append("/* ── URL ── */")
        for i, url in enumerate(sorted(set(urls))[:30]):
            lines.append('#define URL_%d "%s"' % (i, url.replace('"', '\\"')))
        lines.append("")
    interesting = [s for s in ascii_strings if any(
        k in s.lower() for k in ['http', 'api', 'key', 'pass', 'token', 'error', 'fail', 'success',
                                   'version', 'dll', 'exe', 'reg', 'config', '.cn', '.com'])]
    if interesting:
        lines.append("/* ── ASCII Strings ── */")
        for i, s in enumerate(interesting[:50]):
            esc = s.replace('\\', '\\\\').replace('"', '\\"')[:200]
            lines.append('#define STR_%d "%s"' % (i, esc))
        lines.append("")
    if cn_strings:
        lines.append("/* ── Chinese Strings ── */")
        for i, s in enumerate(cn_strings[:30]):
            lines.append('/* CNSTR_%d: %s */' % (i, s.replace('*/', '').replace('/*', '')[:80]))
        lines.append("")
    lines.append("#endif /* STRINGS_H */")
    with open(dir_path / "strings.h", 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))


def _write_protocol_h(dir_path, urls, imports, reg_keys):
    lines = [
        "/* protocol.h - 网络/注册表协议结构 */",
        "#ifndef PROTOCOL_H", "#define PROTOCOL_H",
        "", "#include <winsock2.h>", "#include <windows.h>", "",
    ]
    has_net = any('WS2_32' in dll or 'WININET' in dll for dll in imports)
    has_reg = any('ADVAPI32' in dll for dll in imports)
    if has_net or urls:
        lines.extend([
            "typedef struct {",
            "    SOCKET sock;",
            "    struct sockaddr_in server_addr;",
            "    BOOL connected;",
            "} NetworkConnection;",
            "",
            "BOOL network_init(NetworkConnection* conn, const char* host, int port);",
            "int network_send(NetworkConnection* conn, const char* data, int len);",
            "int network_recv(NetworkConnection* conn, char* buffer, int buf_size);",
            "void network_close(NetworkConnection* conn);",
            "",
        ])
    if has_reg:
        lines.extend([
            "typedef struct {",
            "    HKEY hKey;",
            "    char subkey[256];",
            "} RegistryConfig;",
            "",
            "BOOL registry_read_config(RegistryConfig* config);",
            "BOOL registry_write_config(RegistryConfig* config, const char* value_name,",
            "                            DWORD type, const BYTE* data, DWORD data_size);",
            "",
        ])
    lines.append("#endif /* PROTOCOL_H */")
    with open(dir_path / "protocol.h", 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))


def _write_crypto_h(dir_path, data, imports):
    content = """/* crypto.h - 加密函数声明 */
#ifndef CRYPTO_H
#define CRYPTO_H
#include <stdint.h>
#include <stddef.h>

/* TEA 加密 */
void tea_encrypt(uint32_t* v, const uint32_t* k);
void tea_decrypt(uint32_t* v, const uint32_t* k);

/* MD5 */
void md5_hash(const unsigned char* data, size_t len, unsigned char* digest);

/* Base64 */
int base64_encode(const unsigned char* src, size_t len, char* out, size_t out_size);
int base64_decode(const char* src, unsigned char* out, size_t out_size);

#endif /* CRYPTO_H */
"""
    with open(dir_path / "crypto.h", 'w', encoding='utf-8') as f:
        f.write(content)


def _write_resource_h(dir_path, pe):
    lines = ["/* resource.h - 资源 ID 定义 */", "#ifndef RESOURCE_H", "#define RESOURCE_H", ""]
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        for rt in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            rt_id = rt.id if rt.id is not None else -1
            rt_name = {
                1: 'CURSOR', 2: 'BITMAP', 3: 'ICON', 4: 'MENU',
                5: 'DIALOG', 6: 'STRING', 9: 'ACCELERATOR', 10: 'RCDATA',
                14: 'GROUP_ICON', 16: 'VERSION', 24: 'MANIFEST',
            }.get(rt_id, "UNKNOWN_%d" % rt_id)
            if hasattr(rt, 'directory'):
                for rid in rt.directory.entries:
                    res_id = rid.id if hasattr(rid, 'id') and rid.id is not None else 0
                    lines.append("#define IDR_%s_%d %d" % (rt_name, res_id, res_id))
    lines.extend(["", "#endif /* RESOURCE_H */"])
    with open(dir_path / "resource.h", 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))


def _write_main_c(dir_path, pe, ep_disasm, functions, imports, packer_info):
    func_names = [f.lower() for funcs in imports.values() for f in funcs]
    lines = [
        "/* main.c - 程序入口点重构 */",
        '#include <windows.h>',
        '#include "imports.h"', '#include "strings.h"',
        '#include "protocol.h"', '#include "crypto.h"', '#include "resource.h"', "",
    ]
    if packer_info:
        lines.extend([
            "/* 注意：原程序被 %s 加壳保护" % packer_info,
            " * 以下逻辑基于导入表推断，脱壳后需补充 */", "",
        ])
    if ep_disasm:
        lines.extend(["/* 原始入口点反汇编 (EP=0x%08X):" % pe.OPTIONAL_HEADER.AddressOfEntryPoint])
        for addr, size, mn, op, raw in ep_disasm:
            lines.append(" *   %08X: %-8s %s" % (addr, mn, op))
        lines.append(" */")
    lines.extend(["", "int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,",
                  "                   LPSTR lpCmdLine, int nCmdShow) {",
                  "    HMODULE hModule = GetModuleHandleA(NULL);", ""])
    if any('socket' in f or 'gethostbyname' in f for f in func_names):
        lines.extend(["    WSADATA wsaData;",
                      "    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) return 1;", ""])
    lines.extend(["    /* TODO: 主逻辑 */", "", "    return 0;", "}"])
    with open(dir_path / "main.c", 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))


def _write_functions_c(dir_path, functions, disasm_results, image_base, bits):
    lines = ["/* functions.c - 反汇编函数重构 */",
             '#include <windows.h>', '#include "imports.h"', '#include "strings.h"', ""]
    if not functions:
        lines.extend(["/* 未识别到函数（加壳或 .text 段为空） */",
                      "/* 脱壳后重新运行重构引擎 */"])
    else:
        for i, func in enumerate(functions[:50]):
            addr = func['addr']
            size = func['size']
            func_insns = [(a, s, mn, op, raw) for a, s, mn, op, raw in disasm_results
                          if addr <= a < addr + size]
            lines.extend(["", "/* func_%08X (size: %d bytes) */" % (addr, size)])
            if func_insns:
                lines.append("/*")
                for a, s, mn, op, raw in func_insns[:20]:
                    lines.append(" *  %08X: %-8s %s" % (a, mn, op))
                lines.append(" */")
            lines.extend(["void func_%08X(void) {" % addr,
                           "    /* TODO: 从反汇编重构此函数 */",
                           "}", ""])
    with open(dir_path / "functions.c", 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))


def _write_windows_compat_h(dir_path):
    content = """/* windows_compat.h - Windows API 兼容层 */
#ifndef WINDOWS_COMPAT_H
#define WINDOWS_COMPAT_H
#ifdef _WIN32
  #include <windows.h>
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "kernel32.lib")
  #pragma comment(lib, "user32.lib")
  #pragma comment(lib, "advapi32.lib")
  #pragma comment(lib, "ws2_32.lib")
  #pragma comment(lib, "shell32.lib")
  #pragma comment(lib, "winmm.lib")
#else
  #error "This project requires Windows."
#endif
#define SAFE_FREE(p) do { if (p) { free(p); p = NULL; } } while(0)
#define SAFE_CLOSE(h) do { if ((h) && (h) != INVALID_HANDLE_VALUE) { CloseHandle(h); (h) = NULL; } } while(0)
#endif /* WINDOWS_COMPAT_H */
"""
    with open(dir_path / "windows_compat.h", 'w', encoding='utf-8') as f:
        f.write(content)


def _write_cmake(output_dir, project_name, bits):
    # CMake 项目名必须是 ASCII，中文文件名转为拼音风格或用 reconstruct 前缀
    safe_name = re.sub(r'[^A-Za-z0-9_]', '_', project_name)
    # 如果全是下划线（纯中文文件名），使用 fallback 名
    if not re.search(r'[A-Za-z]', safe_name):
        safe_name = "reconstructed_target"
    # 清理连续下划线和首尾下划线
    safe_name = re.sub(r'_+', '_', safe_name).strip('_')
    content = """cmake_minimum_required(VERSION 3.15)
project(%s C)
set(CMAKE_C_STANDARD 11)

file(GLOB SOURCES "src/*.c")
add_executable(${PROJECT_NAME} WIN32 ${SOURCES})
target_include_directories(${PROJECT_NAME} PRIVATE include src)
target_link_libraries(${PROJECT_NAME} PRIVATE kernel32 user32 advapi32 ws2_32 shell32 winmm gdi32)

if(MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE /W3 /utf-8)
elseif(MINGW)
    target_compile_options(${PROJECT_NAME} PRIVATE -Wall -m%s)
    set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS "-m%s -mwindows")
endif()
""" % (safe_name, bits, bits)
    with open(output_dir / "CMakeLists.txt", 'w', encoding='utf-8') as f:
        f.write(content)


def _write_makefile(output_dir, project_name, bits):
    arch = "-m%d" % bits
    # Makefile TARGET 必须是 ASCII 安全的
    safe_name = re.sub(r'[^A-Za-z0-9_]', '_', project_name)
    if not re.search(r'[A-Za-z]', safe_name):
        safe_name = "target"
    safe_name = re.sub(r'_+', '_', safe_name).strip('_')
    content = f"""CC = gcc
CFLAGS = -Wall -O2 {arch} -DUNICODE -D_UNICODE
LDFLAGS = {arch} -mwindows
LIBS = -lkernel32 -luser32 -ladvapi32 -lws2_32 -lshell32 -lwinmm -lgdi32

SRC_DIR = src
INC_DIR = include
BUILD_DIR = build

SOURCES = $(wildcard $(SRC_DIR)/*.c)
OBJECTS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SOURCES))
TARGET = {safe_name}.exe

all: $(BUILD_DIR) $(TARGET)
$(BUILD_DIR):
\tmkdir -p $(BUILD_DIR)
$(TARGET): $(OBJECTS)
\t$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
\t$(CC) $(CFLAGS) -I$(INC_DIR) -c -o $@ $<
clean:
\trm -rf $(BUILD_DIR) $(TARGET)
.PHONY: all clean
"""
    with open(output_dir / "Makefile", 'w', encoding='utf-8') as f:
        f.write(content)


def _write_readme(output_dir, exe_name, pe, packer_info, imports, exports, functions, urls, cn_strings):
    bits = 32 if pe.OPTIONAL_HEADER.Magic == 0x10b else 64
    ts = pe.FILE_HEADER.TimeDateStamp
    dt = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "# %s - 逆向重构" % exe_name, "",
        "| 项目 | 值 |", "|------|-----|",
        "| 位数 | %d-bit |" % bits,
        "| 编译时间 | %s |" % dt,
        "| 镜像基址 | 0x%X |" % pe.OPTIONAL_HEADER.ImageBase,
        "| 入口点 | 0x%X |" % pe.OPTIONAL_HEADER.AddressOfEntryPoint,
    ]
    if packer_info:
        lines.append("| 加壳 | %s |" % packer_info)
    lines.extend([
        "", "## 构建", "",
        "```bash", "mkdir build && cd build",
        'cmake .. -G "MinGW Makefiles"', "make", "```",
    ])
    with open(output_dir / "README.md", 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))


def _print_tree(output_dir):
    print("[+] 项目结构:")
    for f in sorted(Path(output_dir).rglob("*")):
        if f.is_file():
            rel = f.relative_to(output_dir)
            size = f.stat().st_size
            print("    %-50s (%d 字节)" % (str(rel), size))


# ============================================================
# APK → Android Studio 项目
# ============================================================

def reconstruct_apk(apk_path, output_dir):
    apk_path = Path(apk_path).resolve()
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    print("[*] APK 源码重构: %s" % apk_path.name)

    decompiled_dir = output_dir / "app" / "src" / "main"
    if which('apktool'):
        code, out, err = run_cmd('apktool d -f "%s" -o "%s"' % (apk_path, decompiled_dir))
        if code != 0:
            print("[!] apktool 失败，尝试解压: %s" % err[:100])
    if not decompiled_dir.exists():
        import zipfile
        with zipfile.ZipFile(apk_path, 'r') as zf:
            zf.extractall(decompiled_dir)

    jadx_out = output_dir / "app" / "src" / "main" / "java_reconstructed"
    if which('jadx'):
        code, out, err = run_cmd('jadx -d "%s" --show-bad-code "%s"' % (jadx_out, apk_path), timeout=120)
        if code == 0:
            print("[+] jadx 反编译完成")
            java_dir = output_dir / "app" / "src" / "main" / "java"
            sources = jadx_out / "sources"
            if sources.exists():
                if java_dir.exists():
                    shutil.rmtree(java_dir)
                shutil.copytree(sources, java_dir)
    else:
        print("[!] jadx 未找到，跳过 Java 反编译")
        print("    安装: https://github.com/skylot/jadx/releases")

    _write_apk_build_gradle(output_dir / "app" / "build.gradle")
    _write_apk_root_build_gradle(output_dir / "build.gradle")
    _write_apk_settings_gradle(output_dir / "settings.gradle", apk_path.stem)

    with open(output_dir / "README.md", 'w', encoding='utf-8') as f:
        f.write("# %s - APK 逆向重构\n\n用 Android Studio 打开此目录。\n\n" % apk_path.name)
        f.write("Java 源码在: `app/src/main/java/`\n")
        f.write("Smali 代码在: `app/src/main/smali/` (可修改后重打包)\n")
    print("[+] APK 重构完成: %s" % output_dir)


def _write_apk_build_gradle(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w') as f:
        f.write("""plugins { id 'com.android.application' }
android {
    namespace 'com.reconstructed.app'
    compileSdk 34
    defaultConfig {
        applicationId "com.reconstructed.app"
        minSdk 21
        targetSdk 34
        versionCode 1
        versionName "1.0"
    }
    compileOptions {
        sourceCompatibility JavaVersion.VERSION_1_8
        targetCompatibility JavaVersion.VERSION_1_8
    }
}
dependencies {
    implementation 'androidx.appcompat:appcompat:1.6.1'
}
""")


def _write_apk_root_build_gradle(path):
    with open(path, 'w') as f:
        f.write("plugins { id 'com.android.application' version '8.1.0' apply false }\n")


def _write_apk_settings_gradle(path, name):
    with open(path, 'w') as f:
        f.write("""pluginManagement {
    repositories { google(); mavenCentral(); gradlePluginPortal() }
}
dependencyResolutionManagement {
    repositories { google(); mavenCentral() }
}
rootProject.name = '%s'
include ':app'
""" % name)


# ============================================================
# 主入口
# ============================================================

def main():
    parser = argparse.ArgumentParser(description='源码重构引擎 v3 - 从二进制生成可编译源码项目')
    parser.add_argument('target', help='目标文件（.exe/.dll/.apk/.ipa）')
    parser.add_argument('--platform', '-p', default='auto',
                        choices=['auto', 'pe', 'apk', 'ipa', 'api'])
    parser.add_argument('--output', '-o', default=None, help='输出目录')
    parser.add_argument('--packer', default=None, help='已知加壳类型')
    parser.add_argument('--flow-file', default=None, help='API 流量文件')
    parser.add_argument('--flow-type', default='burp', choices=['burp', 'mitm', 'pcap'])
    args = parser.parse_args()

    target = Path(args.target)
    if not target.exists():
        print("[!] 文件不存在: %s" % args.target)
        sys.exit(1)

    platform = args.platform
    if platform == 'auto':
        ext = target.suffix.lower()
        if ext in ('.exe', '.dll', '.sys', '.ocx'):
            platform = 'pe'
        elif ext == '.apk':
            platform = 'apk'
        elif ext == '.ipa':
            platform = 'ipa'
        else:
            print("[!] 无法自动检测平台，请用 --platform 指定")
            sys.exit(1)

    output_dir = args.output or str(target.parent / ("reconstructed_" + target.stem))

    if platform == 'pe':
        reconstruct_pe(args.target, output_dir, packer_info=args.packer)
    elif platform == 'apk':
        reconstruct_apk(args.target, output_dir)
    elif platform == 'ipa':
        print("[!] IPA 重构需要 macOS 环境（class-dump / Ghidra）")
    elif platform == 'api':
        if not args.flow_file:
            print("[!] API 模式需要 --flow-file 参数")
            sys.exit(1)


if __name__ == '__main__':
    main()
