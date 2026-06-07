#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
common.py - 逆向分析通用工具函数（v2 - 源码重构导向）

核心能力：
  - capstone 反汇编引擎（x86/x64/ARM/AArch64/Thumb）
  - 函数边界识别 + 交叉引用分析
  - 字符串提取（ASCII/UTF-16/CJK）
  - 文件哈希、命令执行、依赖管理
"""

import os
import re
import sys
import json
import hashlib
import subprocess
from pathlib import Path
from collections import defaultdict

# ============================================================
# capstone 反汇编引擎
# ============================================================

def get_capstone():
    """获取 capstone 模块（自动安装）"""
    try:
        import capstone
        return capstone
    except ImportError:
        print("[*] capstone 未安装，正在安装...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "capstone", "-q"])
        import capstone
        return capstone


def disassemble(data, base_addr=0, arch='x86', mode=32, count=0):
    """
    使用 capstone 反汇编二进制数据

    Args:
        data: 字节数据
        base_addr: 基地址
        arch: 'x86', 'x64', 'arm', 'arm64', 'thumb'
        mode: 16/32/64 位模式
        count: 反汇编指令数量（0=全部）

    Returns:
        list of (address, size, mnemonic, op_str, bytes)
    """
    cs = get_capstone()
    arch_map = {
        'x86': (cs.CS_ARCH_X86, cs.CS_MODE_32),
        'x64': (cs.CS_ARCH_X86, cs.CS_MODE_64),
        'arm': (cs.CS_ARCH_ARM, cs.CS_MODE_ARM),
        'arm64': (cs.CS_ARCH_ARM64, cs.CS_MODE_ARM),
        'thumb': (cs.CS_ARCH_ARM, cs.CS_MODE_THUMB),
    }
    cs_arch, cs_mode = arch_map.get(arch, (cs.CS_ARCH_X86, cs.CS_MODE_32))
    md = cs.Cs(cs_arch, cs_mode)
    md.detail = True

    results = []
    for insn in md.disasm(data, base_addr):
        results.append((
            insn.address,
            insn.size,
            insn.mnemonic,
            insn.op_str,
            bytes(insn.bytes)
        ))
        if count > 0 and len(results) >= count:
            break
    return results


def disassemble_function(data, offset, base_addr=0, arch='x86', mode=32, max_insns=500):
    """
    反汇编一个函数（直到遇到 RET/INT3/无条件跳转返回）

    Returns:
        list of (address, size, mnemonic, op_str, bytes)
    """
    cs = get_capstone()
    arch_map = {
        'x86': (cs.CS_ARCH_X86, cs.CS_MODE_32),
        'x64': (cs.CS_ARCH_X86, cs.CS_MODE_64),
    }
    cs_arch, cs_mode = arch_map.get(arch, (cs.CS_ARCH_X86, cs.CS_MODE_32))
    md = cs.Cs(cs_arch, cs_mode)
    md.detail = True

    results = []
    for insn in md.disasm(data[offset:], base_addr + offset):
        results.append((
            insn.address,
            insn.size,
            insn.mnemonic,
            insn.op_str,
            bytes(insn.bytes)
        ))
        # 函数结束标志
        if insn.mnemonic in ('ret', 'retn', 'int3'):
            break
        if len(results) >= max_insns:
            break
    return results


# ============================================================
# 函数边界识别
# ============================================================

def find_functions(data, base_addr=0, arch='x86', mode=32, min_func_size=16):
    """
    通过模式匹配和启发式方法识别函数边界

    识别规则：
    1. PUSH EBP; MOV EBP, ESP（经典函数序言）
    2. SUB ESP, imm（栈帧分配）
    3. CALL 前的目标地址
    4. CC CC CC... 填充区域后的代码

    Returns:
        list of { 'addr': int, 'size': int, 'type': str }
    """
    cs = get_capstone()
    cs_arch = cs.CS_ARCH_X86
    cs_mode = cs.CS_MODE_32 if mode == 32 else cs.CS_MODE_64
    md = cs.Cs(cs_arch, cs_mode)

    functions = []
    call_targets = set()
    all_insns = []

    # 第一遍：收集所有指令和 CALL 目标
    for insn in md.disasm(data, base_addr):
        all_insns.append(insn)
        if insn.mnemonic == 'call':
            # 解析立即数调用目标
            try:
                target = int(insn.op_str, 16)
                call_targets.add(target)
            except:
                pass

    # 第二遍：识别函数入口点
    func_starts = set()
    for i, insn in enumerate(all_insns):
        # 规则 1: PUSH EBP; MOV EBP, ESP
        if (insn.mnemonic == 'push' and insn.op_str == 'ebp' and
            i + 1 < len(all_insns) and
            all_insns[i+1].mnemonic == 'mov' and 'esp' in all_insns[i+1].op_str):
            func_starts.add(insn.address)

        # 规则 2: CALL 的目标地址
        if insn.address in call_targets:
            func_starts.add(insn.address)

        # 规则 3: INT3 填充后的代码
        if (insn.mnemonic == 'int3' and
            i + 1 < len(all_insns) and
            all_insns[i+1].mnemonic not in ('int3', 'nop', '')):
            func_starts.add(all_insns[i+1].address)

    # 构建函数列表
    sorted_starts = sorted(func_starts)
    for idx, start in enumerate(sorted_starts):
        end = sorted_starts[idx + 1] if idx + 1 < len(sorted_starts) else base_addr + len(data)
        size = end - start
        if size >= min_func_size:
            functions.append({
                'addr': start,
                'size': size,
                'type': 'identified',
            })

    return functions


# ============================================================
# 交叉引用分析
# ============================================================

def find_xrefs(data, base_addr=0, arch='x86', mode=32):
    """
    构建交叉引用表（谁调用了谁，谁引用了什么地址）

    Returns:
        { target_addr: [source_addr, ...] }
    """
    cs = get_capstone()
    cs_arch = cs.CS_ARCH_X86
    cs_mode = cs.CS_MODE_32 if mode == 32 else cs.CS_MODE_64
    md = cs.Cs(cs_arch, cs_mode)

    xrefs = defaultdict(list)

    for insn in md.disasm(data, base_addr):
        if insn.mnemonic == 'call':
            try:
                target = int(insn.op_str, 16)
                xrefs[target].append(insn.address)
            except:
                pass
        elif insn.mnemonic == 'jmp' and insn.op_str.startswith('0x'):
            try:
                target = int(insn.op_str, 16)
                xrefs[target].append(insn.address)
            except:
                pass
        elif insn.mnemonic in ('mov', 'lea', 'push'):
            # 检查是否引用了绝对地址
            m = re.match(r'0x[0-9a-fA-F]+', insn.op_str)
            if m:
                try:
                    target = int(m.group(), 16)
                    if base_addr <= target < base_addr + len(data):
                        xrefs[target].append(insn.address)
                except:
                    pass

    return dict(xrefs)


# ============================================================
# 文件与哈希工具
# ============================================================

def file_hash(filepath, algo='sha256'):
    """计算文件哈希"""
    h = hashlib.new(algo)
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()

def file_hashes(filepath):
    """返回文件 MD5/SHA1/SHA256 哈希字典"""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {'md5': md5.hexdigest(), 'sha1': sha1.hexdigest(), 'sha256': sha256.hexdigest()}

def human_size(size_bytes):
    """字节数转人类可读格式"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return "%.2f %s" % (size_bytes, unit)
        size_bytes /= 1024.0
    return "%.2f PB" % size_bytes


# ============================================================
# 命令执行工具
# ============================================================

def run_cmd(cmd, timeout=60, capture=True):
    """运行 shell 命令"""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=capture,
            timeout=timeout, text=True, errors='ignore'
        )
        return result.returncode, result.stdout or '', result.stderr or ''
    except subprocess.TimeoutExpired:
        return -1, '', 'TIMEOUT'
    except Exception as e:
        return -1, '', str(e)

def which(program):
    """检查命令是否可用"""
    result = subprocess.run(
        'where %s' % program if os.name == 'nt' else 'which %s' % program,
        shell=True, capture_output=True, text=True
    )
    if result.returncode == 0:
        return result.stdout.strip().split('\n')[0]
    return None


# ============================================================
# 字符串提取工具
# ============================================================

def extract_ascii_strings(data, min_len=6):
    """从字节数据中提取 ASCII 可打印字符串"""
    pattern = rb'[\x20-\x7e]{%d,}' % min_len
    return [m.decode('ascii') for m in re.findall(pattern, data)]

def extract_unicode_strings(data, min_len=4):
    """从字节数据中提取 UTF-16LE 字符串"""
    pattern = rb'(?:[\x20-\x7e]\x00){%d,}' % min_len
    results = []
    for m in re.findall(pattern, data):
        try:
            s = m.decode('utf-16-le', errors='ignore').rstrip('\x00')
            if s:
                results.append(s)
        except:
            pass
    return results

def extract_chinese_strings(data, min_len=2):
    """提取包含中文字符的 UTF-16LE 字符串"""
    pattern = rb'(?:[\x20-\x7e]\x00){%d,}' % min_len
    results = []
    for m in re.findall(pattern, data):
        try:
            s = m.decode('utf-16-le', errors='ignore').rstrip('\x00')
            if any('\u4e00' <= c <= '\u9fff' for c in s):
                results.append(s)
        except:
            pass
    return results

def extract_urls(data):
    """提取所有 HTTP/HTTPS URL"""
    urls = re.findall(rb'https?://[^\x00-\x1f\x7f-\xff]{5,200}', data)
    return list(set(u.decode('utf-8', errors='ignore') for u in urls))

def extract_registry_keys(data):
    """提取注册表键路径"""
    regs = re.findall(rb'HKEY_[A-Za-z_\\]+\\[^\x00-\x1f]{0,100}', data)
    return list(set(r.decode('utf-8', errors='ignore') for r in regs))


# ============================================================
# 依赖管理
# ============================================================

def ensure_package(package, import_name=None):
    """检查 Python 包是否可用，不可用则自动安装"""
    if import_name is None:
        import_name = package
    try:
        __import__(import_name)
        return True
    except ImportError:
        print("[*] 正在安装 %s..." % package)
        code = run_cmd('"%s" -m pip install %s -q' % (sys.executable, package))[0]
        if code == 0:
            print("[+] %s 安装成功" % package)
            return True
        else:
            print("[-] %s 安装失败" % package)
            return False


# ============================================================
# 配置文件读写
# ============================================================

def load_json(path):
    """加载 JSON 配置文件"""
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except:
        return None

def save_json(path, data):
    """保存 JSON 配置文件"""
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


# ============================================================
# 主入口（测试）
# ============================================================

if __name__ == '__main__':
    print("common.py v2 - 源码重构导向")
    print("  capstone: %s" % ("OK" if ensure_package('capstone') else "FAIL"))
    print("  file_hash: %s" % file_hash(__file__))
    print("  which python: %s" % which('python'))

    # 测试 capstone 反汇编
    test_code = b'\x55\x89\xe5\x83\xec\x10\xc7\x45\xfc\x01\x00\x00\x00\xb8\x00\x00\x00\x00\xc9\xc3'
    insns = disassemble(test_code, 0x401000, 'x86', 32)
    print("\n  反汇编测试:")
    for addr, size, mn, op, raw in insns:
        print("    %08X: %-8s %s" % (addr, mn, op))
