#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
deep_decompile.py - 脱壳后 PE 深度反编译分析

核心能力：
  1. 从脱壳后的 .text/.rdata 段提取 GBK 字符串（不过滤高熵段）
  2. 从 .text 段识别所有函数边界
  3. 对每个函数生成接近 C 的伪代码
  4. 从 .rdata 段重建 IAT（导入地址表）
  5. 搜索真正的 OEP
  6. 生成完整的分析报告
"""

import re
import os
import sys
import json
import struct
import argparse
from pathlib import Path
from collections import defaultdict, OrderedDict

# 依赖
try:
    import pefile
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'pefile', '-q'])
    import pefile

try:
    import capstone
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'capstone', '-q'])
    import capstone


# ============================================================
# GBK 字符串提取（脱壳后专用，不过滤高熵段）
# ============================================================

def extract_gbk_strings_unpacked(data, min_chars=3, min_cn_ratio=0.3):
    """
    从脱壳后的数据中提取 GBK 中文字符串
    不做高熵过滤，因为脱壳后的段数据是真实的
    """
    results = []
    seen = set()

    # GBK 双字节匹配：首字节 0x81-0xFE，次字节 0x40-0xFE
    # 匹配至少 4 字节（2 个汉字）的连续 GBK 序列
    gbk_pattern = re.findall(rb'(?:[\x81-\xfe][\x40-\x7e\x80-\xfe]){' + str(min_chars).encode() + b',}', data)

    for m in gbk_pattern:
        try:
            s = m.decode('gbk', errors='strict').strip()
            if len(s) < min_chars or s in seen:
                continue
            # 可读性检测
            cn_chars = sum(1 for c in s if '\u4e00' <= c <= '\u9fff')
            total_chars = len(s.replace(' ', ''))
            if total_chars == 0:
                continue
            cn_ratio = cn_chars / total_chars
            if cn_ratio < min_cn_ratio:
                continue
            # 排除纯重复字符
            if len(set(s)) <= 2:
                continue
            seen.add(s)
            results.append(s)
        except (UnicodeDecodeError, ValueError):
            pass

    return results


def extract_ascii_strings(data, min_len=6):
    """提取 ASCII 可打印字符串"""
    pattern = rb'[\x20-\x7e]{' + str(min_len).encode() + b',}'
    return [m.decode('ascii') for m in re.findall(pattern, data)]


def extract_utf16_strings(data, min_len=4):
    """提取 UTF-16LE 字符串（含中文）"""
    pattern = rb'(?:[\x20-\x7e\u4e00-\u9fff]\x00){' + str(min_len).encode() + b',}'
    # 简化：搜索 UTF-16LE 可打印序列
    pattern2 = rb'(?:[\x20-\x7e]\x00){' + str(min_len).encode() + b',}'
    results = []
    seen = set()
    for m in re.findall(pattern2, data):
        try:
            s = m.decode('utf-16-le', errors='ignore').rstrip('\x00')
            if s and s not in seen and len(s) >= min_len:
                seen.add(s)
                results.append(s)
        except:
            pass
    return results


def extract_urls(data):
    """提取 HTTP/HTTPS URL"""
    urls = re.findall(rb'https?://[^\x00-\x1f\x7f-\xff]{5,250}', data)
    return list(set(u.decode('utf-8', errors='ignore') for u in urls))


# ============================================================
# 函数识别与伪代码生成
# ============================================================

def find_all_functions(text_data, base_addr, mode=32):
    """
    从 .text 段识别所有函数边界
    使用多种启发式方法：
    1. 经典函数序言（push ebp; mov ebp, esp / sub esp, imm）
    2. CALL 目标地址
    3. INT3 填充后的代码
    4. RET 后的代码
    """
    cs = capstone.Cs(capstone.CS_ARCH_X86,
                      capstone.CS_MODE_32 if mode == 32 else capstone.CS_MODE_64)
    cs.detail = True

    all_insns = list(cs.disasm(text_data, base_addr))
    call_targets = set()

    # 第一遍：收集 CALL 目标
    for insn in all_insns:
        if insn.mnemonic == 'call':
            try:
                target = int(insn.op_str, 16)
                if base_addr <= target < base_addr + len(text_data):
                    call_targets.add(target)
            except:
                pass

    # 第二遍：识别函数入口
    func_starts = set()
    for i, insn in enumerate(all_insns):
        # 规则 1: PUSH EBP; MOV EBP, ESP
        if (insn.mnemonic == 'push' and insn.op_str == 'ebp' and
            i + 1 < len(all_insns) and
            all_insns[i+1].mnemonic == 'mov' and 'ebp' in all_insns[i+1].op_str and 'esp' in all_insns[i+1].op_str):
            func_starts.add(insn.address)

        # 规则 2: SUB ESP, imm (独立栈帧分配)
        if (insn.mnemonic == 'sub' and insn.op_str.startswith('esp,') and
            i > 0 and all_insns[i-1].mnemonic == 'push'):
            func_starts.add(all_insns[i-1].address)

        # 规则 3: CALL 的目标地址
        if insn.address in call_targets:
            func_starts.add(insn.address)

        # 规则 4: INT3 填充后的代码
        if (insn.mnemonic == 'int3' and
            i + 1 < len(all_insns) and
            all_insns[i+1].mnemonic not in ('int3', 'nop', '')):
            func_starts.add(all_insns[i+1].address)

        # 规则 5: RET 后的非 INT3 代码
        if (insn.mnemonic in ('ret', 'retn') and
            i + 1 < len(all_insns) and
            all_insns[i+1].mnemonic not in ('int3', 'nop', '')):
            func_starts.add(all_insns[i+1].address)

    # 构建函数列表
    sorted_starts = sorted(func_starts)
    functions = []
    for idx, start in enumerate(sorted_starts):
        end = sorted_starts[idx + 1] if idx + 1 < len(sorted_starts) else base_addr + len(text_data)
        size = end - start
        if size >= 8:  # 最小函数大小
            functions.append({
                'addr': start,
                'size': size,
                'end': end,
            })

    return functions, call_targets


def decompile_function(func_addr, func_size, text_data, base_addr, mode=32):
    """
    将一个函数反汇编并生成接近 C 的伪代码
    
    策略：
    - 识别栈帧操作 → 推断局部变量
    - 识别 CALL → 生成函数调用
    - 识别条件跳转 → 生成 if/else
    - 识别循环 → 生成 while/for
    - 识别返回值 → 推断函数签名
    """
    cs = capstone.Cs(capstone.CS_ARCH_X86,
                      capstone.CS_MODE_32 if mode == 32 else capstone.CS_MODE_64)
    cs.detail = True

    offset = func_addr - base_addr
    func_data = text_data[offset:offset + func_size]
    insns = list(cs.disasm(func_data, func_addr))

    if not insns:
        return None

    # 分析函数特征
    has_ebp_frame = False
    local_var_size = 0
    calls = []
    returns_value = False
    params_count = 0
    conditionals = 0
    loops = 0
    string_refs = []
    is_stdcall = False

    # 检查参数数量（stdcall 通过 RET imm16 判断）
    for insn in insns:
        if insn.mnemonic == 'retn' and insn.op_str and insn.op_str != '':
            try:
                ret_bytes = int(insn.op_str, 16)
                params_count = ret_bytes // 4
                is_stdcall = True
            except:
                pass

    for i, insn in enumerate(insns):
        # 函数序言
        if (insn.mnemonic == 'push' and insn.op_str == 'ebp' and
            i + 1 < len(insns) and insns[i+1].mnemonic == 'mov' and 'esp' in insns[i+1].op_str and 'ebp' in insns[i+1].op_str):
            has_ebp_frame = True

        # 栈帧分配
        if insn.mnemonic == 'sub' and insn.op_str.startswith('esp,'):
            try:
                local_var_size = int(insn.op_str.split(',')[1].strip(), 16)
            except:
                pass

        # 函数调用
        if insn.mnemonic == 'call':
            calls.append(insn.op_str)

        # 返回值
        if insn.mnemonic in ('mov', 'xor', 'lea') and insn.op_str.startswith('eax'):
            returns_value = True

        # 条件跳转
        if insn.mnemonic in ('je', 'jne', 'jz', 'jnz', 'jl', 'jg', 'jle', 'jge', 'jb', 'ja', 'jbe', 'jae'):
            conditionals += 1

        # 循环（向后跳转）
        if insn.mnemonic in ('jmp', 'jne', 'jnz', 'je', 'jz') and insn.op_str.startswith('0x'):
            try:
                target = int(insn.op_str, 16)
                if target < insn.address:
                    loops += 1
            except:
                pass

    # 生成伪代码
    lines = []
    func_name = "func_%08X" % func_addr

    # 函数签名推断
    ret_type = "void" if not returns_value else "int"
    if is_stdcall and params_count > 0:
        params = ", ".join(["int arg%d" % i for i in range(params_count)])
        signature = "%s __stdcall %s(%s)" % (ret_type, func_name, params)
    elif params_count > 0:
        params = ", ".join(["int arg%d" % i for i in range(params_count)])
        signature = "%s %s(%s)" % (ret_type, func_name, params)
    else:
        signature = "%s %s(void)" % (ret_type, func_name)

    lines.append(signature + " {")

    # 局部变量
    if local_var_size > 0:
        num_vars = local_var_size // 4
        for v in range(num_vars):
            lines.append("    int var_%d; /* [ebp-0x%X] */" % (v, (v + 1) * 4))
        lines.append("")

    # 反汇编 → 伪代码转换（使用字符串拼接避免 %s 冲突）
    asm_lines = []
    indent = "    "
    for insn in insns:
        addr = insn.address
        mn = insn.mnemonic
        op = insn.op_str

        if mn == 'push' and op == 'ebp':
            asm_lines.append(indent + "/* push ebp */")
        elif mn == 'mov' and 'ebp' in op and 'esp' in op:
            asm_lines.append(indent + "/* mov ebp, esp */")
        elif mn == 'sub' and op.startswith('esp,'):
            val = op.split(',')[1].strip() if ',' in op else '?'
            asm_lines.append(indent + "/* sub esp, " + val + " - allocate stack frame */")
        elif mn == 'push' and op in ('ebx', 'esi', 'edi'):
            asm_lines.append(indent + "/* save " + op + " */")
        elif mn == 'pop' and op in ('ebx', 'esi', 'edi'):
            asm_lines.append(indent + "/* restore " + op + " */")
        elif mn == 'call':
            asm_lines.append(indent + "CALL(" + op + ");")
        elif mn == 'ret' or mn == 'retn':
            if op and op != '':
                asm_lines.append(indent + "return; /* retn " + op + " - stdcall */")
            else:
                asm_lines.append(indent + "return;")
        elif mn == 'jmp':
            asm_lines.append(indent + "goto " + op + ";")
        elif mn in ('je', 'jne', 'jz', 'jnz'):
            cond = {'je': '==', 'jne': '!=', 'jz': '==', 'jnz': '!='}[mn]
            asm_lines.append(indent + "if (flag" + cond + ") goto " + op + ";")
        elif mn in ('jl', 'jg', 'jle', 'jge', 'jb', 'ja', 'jbe', 'jae'):
            cond_map = {'jl': '<', 'jg': '>', 'jle': '<=', 'jge': '>=',
                        'jb': '< unsigned', 'ja': '> unsigned', 'jbe': '<= unsigned', 'jae': '>= unsigned'}
            asm_lines.append(indent + "if (cmp " + cond_map.get(mn, '?') + " 0) goto " + op + ";")
        elif mn in ('cmp', 'test'):
            asm_lines.append(indent + "/* " + mn + " " + op + " */")
        elif mn == 'mov':
            asm_lines.append(indent + _simplify_mov(op) + "; /* mov */")
        elif mn == 'lea':
            parts = op.split(',', 1)
            if len(parts) == 2:
                asm_lines.append(indent + parts[0].strip() + " = &(" + parts[1].strip() + ");")
            else:
                asm_lines.append(indent + "lea(" + op + ");")
        elif mn == 'xor' and len(op.split(',')) == 2:
            p0 = op.split(',')[0].strip()
            p1 = op.split(',')[1].strip()
            if p0 == p1:
                asm_lines.append(indent + p0 + " = 0; /* xor zero */")
            else:
                asm_lines.append(indent + p0 + " ^= " + p1 + ";")
        elif mn == 'push':
            asm_lines.append(indent + "PUSH(" + op + ");")
        elif mn == 'pop':
            asm_lines.append(indent + "POP(" + op + ");")
        elif mn == 'add':
            parts = op.split(',', 1)
            if len(parts) == 2:
                asm_lines.append(indent + parts[0].strip() + " += " + parts[1].strip() + ";")
            else:
                asm_lines.append(indent + "add(" + op + ");")
        elif mn == 'sub':
            parts = op.split(',', 1)
            if len(parts) == 2:
                asm_lines.append(indent + parts[0].strip() + " -= " + parts[1].strip() + ";")
            else:
                asm_lines.append(indent + "sub(" + op + ");")
        elif mn == 'inc':
            asm_lines.append(indent + op + "++;")
        elif mn == 'dec':
            asm_lines.append(indent + op + "--;")
        elif mn == 'and':
            parts = op.split(',', 1)
            if len(parts) == 2:
                asm_lines.append(indent + parts[0].strip() + " &= " + parts[1].strip() + ";")
            else:
                asm_lines.append(indent + "and(" + op + ");")
        elif mn == 'or':
            parts = op.split(',', 1)
            if len(parts) == 2:
                asm_lines.append(indent + parts[0].strip() + " |= " + parts[1].strip() + ";")
            else:
                asm_lines.append(indent + "or(" + op + ");")
        elif mn == 'xor':
            parts = op.split(',', 1)
            if len(parts) == 2:
                asm_lines.append(indent + parts[0].strip() + " ^= " + parts[1].strip() + ";")
            else:
                asm_lines.append(indent + "xor(" + op + ");")
        elif mn == 'shl':
            parts = op.split(',', 1)
            if len(parts) == 2:
                asm_lines.append(indent + parts[0].strip() + " <<= " + parts[1].strip() + ";")
            else:
                asm_lines.append(indent + "shl(" + op + ");")
        elif mn == 'shr':
            parts = op.split(',', 1)
            if len(parts) == 2:
                asm_lines.append(indent + parts[0].strip() + " >>= " + parts[1].strip() + ";")
            else:
                asm_lines.append(indent + "shr(" + op + ");")
        elif mn == 'nop':
            continue
        elif mn == 'int3':
            continue
        elif mn in ('movsx', 'movzx'):
            parts = op.split(',', 1)
            ext_type = 'sign_ext' if mn == 'movsx' else 'zero_ext'
            if len(parts) == 2:
                asm_lines.append(indent + parts[0].strip() + " = (" + ext_type + ")" + parts[1].strip() + ";")
            else:
                asm_lines.append(indent + mn + "(" + op + ");")
        else:
            asm_lines.append(indent + mn + " " + op + ";")

    lines.extend(asm_lines)
    lines.append("}")

    return {
        'name': func_name,
        'addr': func_addr,
        'size': func_size,
        'signature': signature,
        'has_ebp_frame': has_ebp_frame,
        'local_var_size': local_var_size,
        'calls': calls,
        'returns_value': returns_value,
        'params_count': params_count,
        'is_stdcall': is_stdcall,
        'conditionals': conditionals,
        'loops': loops,
        'pseudocode': '\n'.join(lines),
    }


def _simplify_mov(op):
    """简化 MOV 指令为伪代码"""
    parts = op.split(',', 1)
    if len(parts) == 2:
        return "%s = %s" % (parts[0].strip(), parts[1].strip())
    return "mov(%s)" % op


# ============================================================
# IAT 重建（从 .rdata 段）
# ============================================================

def rebuild_iat_from_rdata(rdata_data, rdata_va, image_base, text_data, text_va):
    """
    从 .rdata 段重建导入地址表
    
    策略：
    1. 在 .rdata 中搜索 DLL 名称字符串
    2. 在 .rdata 中搜索函数名称字符串
    3. 在 .text 中搜索 CALL [addr] 模式，推断 IAT 引用
    """
    dll_names = []
    func_imports = defaultdict(list)  # dll -> [func_name]

    # 搜索 DLL 名称（xxx.dll 模式）
    dll_pattern = re.findall(rb'[A-Za-z0-9_]+\.dll', rdata_data)
    seen_dlls = set()
    for m in dll_pattern:
        name = m.decode('ascii', errors='ignore')
        if name.lower() not in seen_dlls:
            seen_dlls.add(name.lower())
            # 在 .rdata 中找到这个 DLL 名称的偏移
            offset = rdata_data.find(m)
            dll_names.append({
                'name': name,
                'rva': rdata_va + offset,
                'va': image_base + rdata_va + offset,
            })

    # 搜索函数名称（在 DLL 名称附近，有 Hint 编号的 API 名称）
    # 常见 Windows API 名称模式
    api_pattern = re.findall(rb'[\x00]([A-Z][A-Za-z0-9]{4,40})[\x00]', rdata_data)
    seen_funcs = set()
    for m in api_pattern:
        name = m.decode('ascii', errors='ignore')
        if name not in seen_funcs and not name.startswith('_'):
            seen_funcs.add(name)
            # 找偏移
            offset = rdata_data.find(b'\x00' + m + b'\x00')
            if offset < 0:
                offset = rdata_data.find(m)
            func_imports['unknown'].append({
                'name': name,
                'offset_in_rdata': offset,
            })

    # 搜索 CALL [addr] 模式推断 IAT slot
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    cs.detail = True

    iat_refs = defaultdict(int)  # addr -> 引用次数
    for insn in cs.disasm(text_data, text_va):
        if insn.mnemonic == 'call' and insn.op_str.startswith('dword ptr [0x'):
            try:
                target = int(insn.op_str.replace('dword ptr [', '').replace(']', ''), 16)
                iat_refs[target] += 1
            except:
                pass
        elif insn.mnemonic == 'jmp' and insn.op_str.startswith('dword ptr [0x'):
            try:
                target = int(insn.op_str.replace('dword ptr [', '').replace(']', ''), 16)
                iat_refs[target] += 1
            except:
                pass

    return {
        'dll_names': dll_names,
        'func_imports': dict(func_imports),
        'iat_refs': {hex(k): v for k, v in sorted(iat_refs.items(), key=lambda x: -x[1])[:100]},
    }


# ============================================================
# OEP 搜索（真正的程序入口点）
# ============================================================

def find_real_oep(text_data, base_addr, image_base, ep_rva):
    """
    在脱壳后的 .text 段中搜索真正的 OEP
    
    搜索策略：
    1. 经典 C 运行时入口（_WinMainCRTStartup / WinMain）
    2. push ebp; mov ebp, esp 序言
    3. 对 PE 头中的 EP RVA 进行验证
    """
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    cs.detail = True

    candidates = []

    # 策略 1: 搜索标准函数序言
    prologue_bytes = [b'\x55\x8b\xec',       # push ebp; mov ebp, esp
                      b'\x55\x8b\xec\x83\xec',  # push ebp; mov ebp, esp; sub esp, imm
                      b'\x55\x8b\xec\xe8',      # push ebp; mov ebp, esp; call xxx
                      ]

    for pattern in prologue_bytes:
        offset = 0
        while True:
            idx = text_data.find(pattern, offset)
            if idx < 0:
                break
            va = base_addr + idx
            # 反汇编这个位置的代码，验证是否像入口点
            func_insns = list(cs.disasm(text_data[idx:idx+64], va))
            if len(func_insns) >= 5:
                # 检查是否有 GetModuleHandleA 调用（WinMain 的特征）
                has_getmodule = False
                for fi in func_insns:
                    if fi.mnemonic == 'call':
                        has_getmodule = True
                candidates.append({
                    'va': hex(va),
                    'rva': hex(va - image_base),
                    'offset': idx,
                    'pattern': pattern.hex(),
                    'first_insns': [(fi.mnemonic + ' ' + fi.op_str) for fi in func_insns[:5]],
                    'likely_entry': has_getmodule,
                })
            offset = idx + 1

    # 策略 2: 验证 PE 头中的 EP RVA
    ep_offset = ep_rva - (base_addr - image_base)
    if 0 <= ep_offset < len(text_data):
        ep_insns = list(cs.disasm(text_data[ep_offset:ep_offset+64], image_base + ep_rva))
        # 检查 EP 处的代码是否合理
        is_valid = len(ep_insns) > 0 and ep_insns[0].mnemonic not in ('int3', 'nop', '')
        candidates.insert(0, {
            'va': hex(image_base + ep_rva),
            'rva': hex(ep_rva),
            'offset': ep_offset,
            'pattern': 'PE Header EP',
            'first_insns': [(fi.mnemonic + ' ' + fi.op_str) for fi in ep_insns[:5]],
            'likely_entry': is_valid,
        })

    # 按可能程度排序
    candidates.sort(key=lambda c: (c.get('likely_entry', False), -len(c.get('first_insns', []))), reverse=True)

    return candidates


# ============================================================
# 主分析流程
# ============================================================

def deep_analyze(exe_path, output_dir, sections_dir=None):
    """深度分析脱壳后的 PE"""
    exe_path = Path(exe_path).resolve()
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    print("[*] 深度反编译分析: %s" % exe_path.name)

    with open(exe_path, 'rb') as f:
        data = f.read()

    pe = pefile.PE(str(exe_path))
    bits = 32 if pe.OPTIONAL_HEADER.Magic == 0x10b else 64
    image_base = pe.OPTIONAL_HEADER.ImageBase
    ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint

    # 获取段信息
    sections = {}
    for sec in pe.sections:
        name = sec.Name.decode('utf-8', errors='ignore').rstrip('\x00')
        sections[name] = {
            'va': sec.VirtualAddress,
            'size': sec.Misc_VirtualSize,
            'raw_size': sec.SizeOfRawData,
            'entropy': sec.get_entropy() if hasattr(sec, 'get_entropy') else 0,
        }

    print("[*] 段信息:")
    for name, info in sections.items():
        print("    %-10s VA=0x%06X Size=%d Entropy=%.2f" % (
            name, info['va'], info['size'], info['entropy']))

    # ── 1. 从段数据文件直接读取（更可靠）──
    text_data = None
    rdata_data = None
    text_va = image_base
    rdata_va = image_base

    for sec in pe.sections:
        name = sec.Name.decode('utf-8', errors='ignore').rstrip('\x00')
        if name == '.text':
            text_va = image_base + sec.VirtualAddress
            raw_off = sec.PointerToRawData
            raw_size = sec.SizeOfRawData
            if raw_size > 0 and raw_off + raw_size <= len(data):
                text_data = data[raw_off:raw_off + raw_size]
            # 尝试从 sections 目录读取
            if sections_dir:
                sec_file = Path(sections_dir) / ".text.bin"
                if sec_file.exists():
                    with open(sec_file, 'rb') as f:
                        text_data = f.read()
                    print("    [.text] 从段文件加载: %d 字节" % len(text_data))
        elif name == '.rdata':
            rdata_va = image_base + sec.VirtualAddress
            raw_off = sec.PointerToRawData
            raw_size = sec.SizeOfRawData
            if raw_size > 0 and raw_off + raw_size <= len(data):
                rdata_data = data[raw_off:raw_off + raw_size]
            if sections_dir:
                sec_file = Path(sections_dir) / ".rdata.bin"
                if sec_file.exists():
                    with open(sec_file, 'rb') as f:
                        rdata_data = f.read()
                    print("    [.rdata] 从段文件加载: %d 字节" % len(rdata_data))

    if text_data is None:
        print("[!] 无法获取 .text 段数据")
        return

    # ── 2. GBK 字符串提取（从 .text + .rdata）──
    print("\n[*] 提取 GBK 字符串...")
    all_search_data = text_data
    if rdata_data:
        all_search_data = text_data + rdata_data

    gbk_strings = extract_gbk_strings_unpacked(all_search_data, min_chars=2, min_cn_ratio=0.3)
    # 质量过滤：至少 2 个连续常用汉字
    def has_common_cn(s, min_consecutive=2):
        consecutive = 0
        for c in s:
            if '\u4e00' <= c <= '\u53ff':
                consecutive += 1
                if consecutive >= min_consecutive:
                    return True
            else:
                consecutive = 0
        return False

    quality_gbk = [s for s in gbk_strings if has_common_cn(s)]
    print("    GBK 候选: %d 条 → 质量过滤后: %d 条" % (len(gbk_strings), len(quality_gbk)))

    # ── 3. ASCII/UTF-16 字符串提取 ──
    print("[*] 提取 ASCII/UTF-16 字符串...")
    ascii_strs = extract_ascii_strings(all_search_data, min_len=6)
    utf16_strs = extract_utf16_strings(all_search_data, min_len=4)
    urls = extract_urls(all_search_data)
    print("    ASCII: %d | UTF-16: %d | URL: %d" % (len(ascii_strs), len(utf16_strs), len(urls)))

    # ── 4. 函数识别 ──
    print("[*] 识别函数...")
    functions, call_targets = find_all_functions(text_data, text_va, mode=bits)
    print("    识别到 %d 个函数, %d 个 CALL 目标" % (len(functions), len(call_targets)))

    # ── 5. OEP 搜索 ──
    print("[*] 搜索真正的 OEP...")
    oep_candidates = find_real_oep(text_data, text_va, image_base, ep_rva)
    for i, c in enumerate(oep_candidates[:5]):
        print("    候选 %d: VA=%s %s" % (i+1, c['va'], '(可能)' if c.get('likely_entry') else ''))

    # ── 6. IAT 重建 ──
    print("[*] 重建 IAT...")
    iat_info = {}
    if rdata_data:
        iat_info = rebuild_iat_from_rdata(rdata_data, rdata_va - image_base, image_base,
                                           text_data, text_va)
        print("    DLL 名称: %d | 函数导入: %d | IAT 引用: %d" % (
            len(iat_info.get('dll_names', [])),
            sum(len(v) for v in iat_info.get('func_imports', {}).values()),
            len(iat_info.get('iat_refs', {}))))

    # ── 7. 函数级伪代码生成 ──
    print("[*] 生成函数伪代码（前 200 个）...")
    decompiled = []
    for func in functions[:200]:
        dc = decompile_function(func['addr'], func['size'], text_data, text_va, mode=bits)
        if dc:
            decompiled.append(dc)

    # ── 8. 算法检测 ──
    print("[*] 检测加密算法...")
    algo_findings = detect_algorithms(all_search_data)
    for algo, desc in algo_findings:
        print("    ! %s: %s" % (algo, desc))

    # ── 9. 生成输出 ──
    print("\n[*] 生成分析报告...")

    # 9a. 完整伪代码文件
    pseudo_dir = output_dir / "pseudocode"
    pseudo_dir.mkdir(exist_ok=True)

    for dc in decompiled:
        fname = "%s.c" % dc['name']
        with open(pseudo_dir / fname, 'w', encoding='utf-8') as f:
            f.write("/*\n * Pseudo-C decompilation of %s\n" % dc['name'])
            f.write(" * Address: 0x%08X, Size: %d bytes\n" % (dc['addr'], dc['size']))
            f.write(" * Signature: %s\n" % dc['signature'])
            f.write(" * Calls: %s\n" % ', '.join(dc['calls'][:10]))
            f.write(" * Params: %d, Locals: %d bytes\n" % (dc['params_count'], dc['local_var_size']))
            if dc['conditionals'] > 0:
                f.write(" * Conditionals: %d\n" % dc['conditionals'])
            if dc['loops'] > 0:
                f.write(" * Loops: %d\n" % dc['loops'])
            f.write(" */\n\n")
            f.write(dc['pseudocode'])
            f.write("\n")

    # 9b. GBK 字符串文件
    with open(output_dir / "gbk_strings_unpacked.txt", 'w', encoding='utf-8') as f:
        for s in quality_gbk:
            f.write(s + '\n')

    # 9c. ASCII 字符串文件
    with open(output_dir / "ascii_strings_unpacked.txt", 'w', encoding='utf-8') as f:
        for s in ascii_strs:
            f.write(s + '\n')

    # 9d. URL 列表
    with open(output_dir / "urls_unpacked.txt", 'w', encoding='utf-8') as f:
        for u in sorted(set(urls)):
            f.write(u + '\n')

    # 9e. 完整分析 JSON
    analysis = {
        'file': str(exe_path),
        'bits': bits,
        'image_base': image_base,
        'ep_rva': ep_rva,
        'sections': {k: {kk: (hex(vv) if isinstance(vv, int) and kk in ('va',) else vv)
                         for kk, vv in v.items()} for k, v in sections.items()},
        'oep_candidates': oep_candidates[:10],
        'functions': {
            'total': len(functions),
            'decompiled': len(decompiled),
            'call_targets': len(call_targets),
        },
        'strings': {
            'gbk_quality': len(quality_gbk),
            'ascii': len(ascii_strs),
            'utf16': len(utf16_strs),
            'urls': len(urls),
        },
        'iat': iat_info,
        'algorithms': algo_findings,
        'function_list': [{
            'name': dc['name'],
            'addr': hex(dc['addr']),
            'size': dc['size'],
            'signature': dc['signature'],
            'calls_count': len(dc['calls']),
            'params': dc['params_count'],
            'locals': dc['local_var_size'],
            'conditionals': dc['conditionals'],
            'loops': dc['loops'],
        } for dc in decompiled],
    }

    with open(output_dir / "deep_analysis.json", 'w', encoding='utf-8') as f:
        json.dump(analysis, f, indent=2, ensure_ascii=False)

    # 9f. 生成分析报告
    _write_report(output_dir, analysis, quality_gbk, urls, decompiled, oep_candidates, iat_info, algo_findings)

    pe.close()

    print("\n[+] 深度分析完成!")
    print("    函数: %d (伪代码: %d)" % (len(functions), len(decompiled)))
    print("    GBK 字符串: %d 条" % len(quality_gbk))
    print("    URL: %d 条" % len(urls))
    print("    输出目录: %s" % output_dir)

    return analysis


def detect_algorithms(data):
    """检测常见加密算法特征"""
    findings = []

    # MD5 常量
    if b'\x67\x45\x23\x01\xef\xcd\xab\x89' in data:
        findings.append(('MD5', '检测到 MD5 初始化常量 (0x67452301)'))

    # TEA/XXTEA delta 常量
    if b'\xb9\x79\x37\x9e' in data or b'\x9e\x37\x79\xb9' in data:
        findings.append(('TEA/XXTEA', '检测到 TEA delta 常量 (0x9E3779B9)'))

    # AES S-box
    if b'\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5' in data:
        findings.append(('AES', '检测到 AES S-box 常量'))

    # Base64
    if b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/' in data:
        findings.append(('Base64', '检测到完整 Base64 字符表'))

    # CRC32
    if b'\x77\x07\x30\x96' in data or b'\xB7\x7C\x4A\xCE' in data:
        findings.append(('CRC32', '检测到 CRC32 多项式常量'))

    return findings


def _write_report(output_dir, analysis, gbk_strings, urls, decompiled, oep_candidates, iat_info, algo_findings):
    """生成完整的 Markdown 分析报告"""
    lines = [
        "# 脱壳后深度反编译分析报告",
        "",
        "## 基本信息",
        "",
        "| 项目 | 值 |",
        "|------|-----|",
        "| 文件 | `%s` |" % analysis['file'],
        "| 位数 | %d-bit |" % analysis['bits'],
        "| 镜像基址 | 0x%X |" % analysis['image_base'],
        "| PE 入口点 RVA | 0x%X |" % analysis['ep_rva'],
        "",
        "## 段信息",
        "",
        "| 段名 | VA | 大小 | 熵 |",
        "|------|-----|------|-----|",
    ]
    for name, info in analysis['sections'].items():
        lines.append("| %s | %s | %s | %.2f |" % (name, info.get('va', '?'), info.get('size', '?'), info.get('entropy', 0)))

    # OEP 候选
    lines.extend([
        "", "## OEP（原始入口点）候选", "",
    ])
    for i, c in enumerate(oep_candidates[:5]):
        mark = " ⭐ 可能的真正入口" if c.get('likely_entry') else ""
        lines.append("### 候选 %d: VA=%s (RVA=%s)%s" % (i+1, c['va'], c['rva'], mark))
        lines.append("")
        lines.append("前几条指令：")
        lines.append("```asm")
        for ins in c.get('first_insns', []):
            lines.append("  %s" % ins)
        lines.append("```")
        lines.append("")

    # GBK 字符串
    lines.extend([
        "## GBK 中文字符串（%d 条）" % len(gbk_strings), "",
    ])
    if gbk_strings:
        lines.append("```")
        for s in gbk_strings[:200]:
            lines.append(s)
        lines.append("```")
    else:
        lines.append("（未提取到有效的 GBK 字符串）")

    # URL
    lines.extend([
        "", "## 网络端点（%d 条）" % len(urls), "",
    ])
    if urls:
        for u in sorted(set(urls)):
            lines.append("- `%s`" % u)
    else:
        lines.append("（未提取到 URL）")

    # IAT
    if iat_info:
        lines.extend(["", "## IAT（导入地址表）重建", ""])
        if iat_info.get('dll_names'):
            lines.append("### 检测到的 DLL")
            lines.append("")
            for dll in iat_info['dll_names']:
                lines.append("- `%s` (RVA: %s)" % (dll['name'], hex(dll['rva'])))
        if iat_info.get('iat_refs'):
            lines.extend(["", "### 高频 IAT 引用（可能是关键 API）", ""])
            for addr, count in list(iat_info['iat_refs'].items())[:20]:
                lines.append("- IAT slot %s: %d 次引用" % (addr, count))

    # 算法
    if algo_findings:
        lines.extend(["", "## 加密算法检测", ""])
        for algo, desc in algo_findings:
            lines.append("- **%s**: %s" % (algo, desc))

    # 函数列表
    lines.extend([
        "", "## 识别的函数（%d 个）" % analysis['functions']['total'], "",
        "| 地址 | 大小 | 签名 | 调用数 | 条件数 | 循环数 |",
        "|------|------|------|--------|--------|--------|",
    ])
    for f in analysis.get('function_list', [])[:100]:
        lines.append("| %s | %d | `%s` | %d | %d | %d |" % (
            f['addr'], f['size'], f['signature'], f['calls_count'],
            f['conditionals'], f['loops']))

    # 重点函数
    important = [f for f in analysis.get('function_list', []) if f['calls_count'] > 5 or f['conditionals'] > 3]
    if important:
        lines.extend(["", "## 重点函数（调用数>5 或 条件数>3）", ""])
        for f in important[:30]:
            lines.append("### %s" % f['name'])
            lines.append("- 地址: %s, 大小: %d 字节" % (f['addr'], f['size']))
            lines.append("- 签名: `%s`" % f['signature'])
            lines.append("- 调用数: %d, 条件: %d, 循环: %d" % (f['calls_count'], f['conditionals'], f['loops']))
            lines.append("")

    with open(output_dir / "DEEP_ANALYSIS.md", 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))


def main():
    parser = argparse.ArgumentParser(description='脱壳后 PE 深度反编译分析')
    parser.add_argument('target', help='脱壳后的 PE 文件')
    parser.add_argument('--output', '-o', default=None, help='输出目录')
    parser.add_argument('--sections-dir', default=None, help='段数据目录（.text.bin 等）')
    args = parser.parse_args()

    target = Path(args.target)
    if not target.exists():
        print("[!] 文件不存在: %s" % args.target)
        sys.exit(1)

    # 自动检测 sections 目录
    sections_dir = args.sections_dir
    if not sections_dir:
        candidate = target.parent / (target.stem + "_sections")
        if candidate.exists():
            sections_dir = str(candidate)
            print("[*] 自动检测到段数据目录: %s" % sections_dir)

    output_dir = args.output or str(target.parent / (target.stem + "_deep"))
    deep_analyze(args.target, output_dir, sections_dir)


if __name__ == '__main__':
    main()
