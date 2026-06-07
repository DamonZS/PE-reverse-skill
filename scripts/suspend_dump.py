#!/usr/bin/env python3
"""
自动脱壳脚本 v6 — 挂起转储法 (Suspend & Dump)

绕过所有反调试检测：
1. 正常启动进程（非调试模式），让壳自行解压
2. 等待足够时间让程序完全加载
3. 挂起所有线程
4. 使用 ReadProcessMemory 读取脱壳后的内存
5. 重建 PE 文件

这是最可靠的自动化脱壳方法之一。
"""

import sys
import os
import struct
import argparse
import time
import traceback
from pathlib import Path

import ctypes
from ctypes import wintypes as wt

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

# 常量
PROCESS_ALL_ACCESS = 0x001F0FFF
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_SUSPEND_RESUME = 0x0800
THREAD_SUSPEND_RESUME = 0x0002
TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPTHREAD = 0x00000004
MAX_PATH = 260


class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ('dwSize', wt.DWORD), ('cntUsage', wt.DWORD), ('th32ProcessID', wt.DWORD),
        ('th32DefaultHeapID', ctypes.c_void_p), ('th32ModuleID', wt.DWORD),
        ('cntThreads', wt.DWORD), ('th32ParentProcessID', wt.DWORD),
        ('pcPriClassBase', ctypes.c_long), ('dwFlags', wt.DWORD),
        ('szExeFile', wt.CHAR * MAX_PATH),
    ]


class THREADENTRY32(ctypes.Structure):
    _fields_ = [
        ('dwSize', wt.DWORD), ('cntUsage', wt.DWORD), ('th32ThreadID', wt.DWORD),
        ('th32OwnerProcessID', wt.DWORD), ('tpBasePri', ctypes.c_long),
        ('tpDeltaPri', ctypes.c_long), ('dwFlags', wt.DWORD),
    ]


class MODULEENTRY32(ctypes.Structure):
    _fields_ = [
        ('dwSize', wt.DWORD), ('th32ModuleID', wt.DWORD), ('th32ProcessID', wt.DWORD),
        ('GlblcntUsage', wt.DWORD), ('ProccntUsage', wt.DWORD),
        ('modBaseAddr', ctypes.c_void_p), ('modBaseSize', wt.DWORD),
        ('hModule', wt.HMODULE), ('szModule', wt.CHAR * 256),
        ('szExePath', wt.CHAR * MAX_PATH),
    ]


class STARTUPINFO(ctypes.Structure):
    _fields_ = [
        ('cb', wt.DWORD), ('lpReserved', wt.LPWSTR), ('lpDesktop', wt.LPWSTR),
        ('lpTitle', wt.LPWSTR), ('dwX', wt.DWORD), ('dwY', wt.DWORD),
        ('dwXSize', wt.DWORD), ('dwYSize', wt.DWORD), ('dwXCountChars', wt.DWORD),
        ('dwYCountChars', wt.DWORD), ('dwFillAttribute', wt.DWORD),
        ('dwFlags', wt.DWORD), ('wShowWindow', wt.WORD), ('cbReserved2', wt.WORD),
        ('lpReserved2', ctypes.POINTER(ctypes.c_byte)),
        ('hStdInput', wt.HANDLE), ('hStdOutput', wt.HANDLE), ('hStdError', wt.HANDLE),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('hProcess', wt.HANDLE), ('hThread', wt.HANDLE),
        ('dwProcessId', wt.DWORD), ('dwThreadId', wt.DWORD),
    ]


def read_mem(h_process, address, size):
    buf = ctypes.create_string_buffer(size)
    read = ctypes.c_size_t()
    if kernel32.ReadProcessMemory(h_process, ctypes.c_void_p(address), buf, size, ctypes.byref(read)):
        return buf.raw[:read.value]
    return None


def suspend_process(pid):
    """挂起进程的所有线程"""
    h_snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    if h_snap == -1:
        return 0

    count = 0
    te = THREADENTRY32()
    te.dwSize = ctypes.sizeof(THREADENTRY32)

    if kernel32.Thread32First(h_snap, ctypes.byref(te)):
        while True:
            if te.th32OwnerProcessID == pid:
                h_thread = kernel32.OpenThread(THREAD_SUSPEND_RESUME, False, te.th32ThreadID)
                if h_thread:
                    kernel32.SuspendThread(h_thread)
                    kernel32.CloseHandle(h_thread)
                    count += 1
            if not kernel32.Thread32Next(h_snap, ctypes.byref(te)):
                break

    kernel32.CloseHandle(h_snap)
    return count


def get_module_base(pid):
    """获取主模块基址"""
    h_snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if h_snap == -1:
        return 0

    pe = PROCESSENTRY32()
    pe.dwSize = ctypes.sizeof(PROCESSENTRY32)

    if kernel32.Process32First(h_snap, ctypes.byref(pe)):
        while True:
            if pe.th32ProcessID == pid:
                kernel32.CloseHandle(h_snap)
                # 用 Module32First 获取模块基址
                h_mod_snap = kernel32.CreateToolhelp32Snapshot(0x00000008, pid)  # TH32CS_SNAPMODULE
                if h_mod_snap == -1:
                    return 0
                me = MODULEENTRY32()
                me.dwSize = ctypes.sizeof(MODULEENTRY32)
                if kernel32.Module32First(h_mod_snap, ctypes.byref(me)):
                    base = me.modBaseAddr
                    kernel32.CloseHandle(h_mod_snap)
                    return base or 0
                kernel32.CloseHandle(h_mod_snap)
                return 0
            if not kernel32.Process32Next(h_snap, ctypes.byref(pe)):
                break

    kernel32.CloseHandle(h_snap)
    return 0


def main():
    parser = argparse.ArgumentParser(description='挂起转储法脱壳')
    parser.add_argument('input', help='加壳 EXE')
    parser.add_argument('--output', '-o', help='输出 PE')
    parser.add_argument('--wait', '-w', type=float, default=3.0, help='等待秒数（让壳完成解压）')
    parser.add_argument('--try-ep', type=int, default=0, help='尝试指定 EP RVA (十六进制)')
    args = parser.parse_args()

    exe_path = Path(args.input)
    output_path = args.output or str(exe_path.with_name(exe_path.stem + '_unpacked.exe'))

    print(f"[*] 目标: {exe_path}")
    print(f"[*] 输出: {output_path}")
    print(f"[*] 等待时间: {args.wait}s")

    import pefile
    pe = pefile.PE(str(exe_path))
    image_base = pe.OPTIONAL_HEADER.ImageBase
    ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    print(f"[*] ImageBase=0x{image_base:08X}, EP RVA=0x{ep_rva:08X}")

    sections = []
    for sec in pe.sections:
        name = sec.Name.decode('utf-8', errors='ignore').rstrip('\x00')
        sections.append({
            'name': name,
            'vaddr': image_base + sec.VirtualAddress,
            'vsize': sec.Misc_VirtualSize,
            'raw_offset': sec.PointerToRawData,
            'raw_size': sec.SizeOfRawData,
        })

    # 1. 正常启动进程
    print(f"\n[1] 正常启动进程（非调试模式）...")
    si = STARTUPINFO()
    si.cb = ctypes.sizeof(STARTUPINFO)
    # SW_HIDE = 0 (隐藏窗口，避免弹出窗口)
    si.wShowWindow = 0
    si.dwFlags = 0x01  # STARTF_USESHOWWINDOW

    pi = PROCESS_INFORMATION()

    if not kernel32.CreateProcessW(
        None, ctypes.create_unicode_buffer(str(exe_path)),
        None, None, False, 0,  # 正常启动，不挂起
        None, None, ctypes.byref(si), ctypes.byref(pi)):
        print(f"[!] CreateProcess 失败: {ctypes.get_last_error()}")
        sys.exit(1)

    pid = pi.dwProcessId
    h_process = pi.hProcess
    print(f"[+] 进程已启动: PID={pid}")

    # 关闭不需要的句柄
    kernel32.CloseHandle(pi.hThread)

    # 2. 等待进程自解压
    print(f"\n[2] 等待 {args.wait}s 让壳完成解压...")
    time.sleep(args.wait)

    # 3. 挂起进程
    print(f"\n[3] 挂起进程...")
    suspended = suspend_process(pid)
    print(f"[+] 已挂起 {suspended} 个线程")

    # 4. 读取进程内存
    print(f"\n[4] 读取进程内存...")

    # 先用 ReadProcessMemory 读取 PE Header 确定模块基址
    mod_base = get_module_base(pid)
    if not mod_base:
        mod_base = image_base
    print(f"  模块基址: 0x{mod_base:08X}")

    # 读取 PE Header
    pe_header = read_mem(h_process, mod_base, 0x1000)  # 4KB to handle large headers
    if not pe_header:
        print(f"[!] 无法读取 PE Header")
        kernel32.TerminateProcess(h_process, 0)
        sys.exit(1)

    # 解析段信息
    e_lfanew = struct.unpack_from('<I', pe_header, 0x3C)[0]
    num_sections = struct.unpack_from('<H', pe_header, e_lfanew + 6)[0]
    opt_header_size = struct.unpack_from('<H', pe_header, e_lfanew + 20)[0]
    sec_offset = e_lfanew + 24 + opt_header_size

    live_sections = []
    for i in range(num_sections):
        off = sec_offset + i * 40
        if off + 40 <= len(pe_header):
            name = pe_header[off:off+8].decode('ascii', errors='ignore').rstrip('\x00')
            vaddr = struct.unpack_from('<I', pe_header, off + 12)[0] + mod_base
            vsize = struct.unpack_from('<I', pe_header, off + 8)[0]
            raw_offset = struct.unpack_from('<I', pe_header, off + 20)[0]
            raw_size = struct.unpack_from('<I', pe_header, off + 16)[0]
            live_sections.append({
                'name': name,
                'vaddr': vaddr,
                'vsize': vsize,
                'raw_offset': raw_offset,
                'raw_size': raw_size,
            })

    # 读取各段
    sections_data = {}
    for sec in live_sections:
        vsize = sec['vsize']
        if vsize > 10 * 1024 * 1024:  # 限制 10MB
            vsize = 10 * 1024 * 1024
        data = read_mem(h_process, sec['vaddr'], vsize)
        if data:
            non_zero = sum(1 for b in data if b != 0)
            sections_data[sec['name']] = data
            print(f"  {sec['name']:10s}: {len(data):>8d} 字节, 非零: {non_zero:>8d} ({non_zero/max(len(data),1)*100:.1f}%)")
        else:
            print(f"  {sec['name']:10s}: 读取失败")

    # 5. 搜索 OEP
    print(f"\n[5] 搜索 OEP...")
    text_data = sections_data.get('.text', b'')
    text_non_zero = sum(1 for b in text_data if b != 0) if text_data else 0
    print(f"  .text 非零: {text_non_zero}")

    if text_non_zero > 100:
        print(f"  ✅ .text 段有实质代码！")

        # 反汇编搜索入口
        import capstone
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        text_va = next((s['vaddr'] for s in live_sections if s['name'] == '.text'), mod_base + 0x1000)

        # 搜索典型入口模式: push ebp; mov ebp, esp 或 sub esp
        oep_rva = 0
        for i in md.disasm(text_data, text_va):
            if i.mnemonic == 'push' and i.op_str == 'ebp':
                # 检查下一条是否是 mov ebp, esp
                next_bytes = text_data[i.address - text_va + len(i.bytes):i.address - text_va + len(i.bytes) + 3]
                if len(next_bytes) >= 2 and next_bytes[0] == 0x8B and next_bytes[1] in (0xEC, 0xE5):
                    oep_rva = i.address - mod_base
                    print(f"  OEP 候选: 0x{i.address:08X} (RVA=0x{oep_rva:08X})")
                    break

        # 6. 重建 PE
        print(f"\n[6] 重建脱壳 PE...")

        with open(exe_path, 'rb') as f:
            new_pe = bytearray(f.read())

        # 更新入口点
        if oep_rva:
            opt_off = e_lfanew + 24 + 16
            struct.pack_into('<I', new_pe, opt_off, oep_rva)
            print(f"  新 EP RVA: 0x{oep_rva:08X}")

        # 写入段数据
        for sec in live_sections:
            if sec['name'] not in sections_data:
                continue
            data = sections_data[sec['name']]
            raw_off = sec['raw_offset']
            raw_size = sec['raw_size']

            if raw_size > 0 and raw_off > 0:
                write_len = min(len(data), raw_size, len(new_pe) - raw_off)
                if write_len > 0:
                    new_pe[raw_off:raw_off + write_len] = data[:write_len]
            elif sum(1 for b in data if b != 0) > 0:
                # 追加
                aligned = (len(new_pe) + 0x1FF) & ~0x1FF
                new_pe.extend(b'\x00' * (aligned - len(new_pe)))
                new_pe.extend(data)

        with open(output_path, 'wb') as f:
            f.write(new_pe)
        print(f"\n[+] ✅ 脱壳 PE: {output_path}")

        # 保存段数据
        sec_dir = Path(output_path).with_name(Path(output_path).stem + '_sections')
        sec_dir.mkdir(exist_ok=True)
        for name, data in sections_data.items():
            with open(sec_dir / f"{name}.bin", 'wb') as f:
                f.write(data)

        # GBK 字符串
        gbk_strs = []
        import re
        for m in re.finditer(rb'(?:[\x81-\xfe][\x40-\x7e\x80-\xfe]){2,}', text_data):
            try:
                s = m.group().decode('gbk', errors='strict').strip()
                cn = sum(1 for c in s if '\u4e00' <= c <= '\u9fff')
                if cn >= 2 and len(set(s)) > 2:
                    gbk_strs.append(s)
            except:
                pass

        if gbk_strs:
            print(f"\n[*] GBK 字符串: {len(gbk_strs)} 条")
            for s in sorted(gbk_strs, key=len, reverse=True)[:30]:
                print(f"  {s}")

        # 反汇编 .text 前 40 条
        print(f"\n[*] .text 反汇编:")
        count = 0
        for i in md.disasm(text_data[:0x400], text_va):
            print(f"  0x{i.address:08X}: {i.mnemonic:8s} {i.op_str}")
            count += 1
            if count >= 40:
                break

    else:
        print(f"  ⚠️ .text 段无实质代码，可能需要更长的等待时间")
        # 仍然保存段数据供分析
        sec_dir = Path(output_path).with_name(Path(output_path).stem + '_sections')
        sec_dir.mkdir(exist_ok=True)
        for name, data in sections_data.items():
            with open(sec_dir / f"{name}.bin", 'wb') as f:
                f.write(data)
        print(f"  段数据已保存: {sec_dir}")

    # 清理
    kernel32.TerminateProcess(h_process, 0)
    kernel32.CloseHandle(h_process)
    print(f"\n[*] 进程已终止")


if __name__ == '__main__':
    main()
