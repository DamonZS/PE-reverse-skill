#!/usr/bin/env python3
"""
⚠️ DEPRECATED — 此脚本在 CNM 私有壳上失败（反调试检测，EP 断点不触发）
保留供参考，新项目请使用 suspend_dump.py（挂起转储法）

自动脱壳脚本 v5 — Windows 调试 API (Wow64 兼容)

修复：在 64 位 Windows 上正确调试 32 位进程
策略：直接在 EP 设 INT3 断点，然后 ESP 定律法
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
DEBUG_PROCESS = 0x00000001
CREATE_SUSPENDED = 0x00000004
INFINITE = 0xFFFFFFFF
DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001

EXCEPTION_DEBUG_EVENT = 1
CREATE_THREAD_DEBUG_EVENT = 2
CREATE_PROCESS_DEBUG_EVENT = 3
EXIT_THREAD_DEBUG_EVENT = 4
EXIT_PROCESS_DEBUG_EVENT = 5
LOAD_DLL_DEBUG_EVENT = 6
UNLOAD_DLL_DEBUG_EVENT = 7
OUTPUT_DEBUG_STRING_EVENT = 8

EXCEPTION_BREAKPOINT = 0x80000003
EXCEPTION_SINGLE_STEP = 0x80000004

CONTEXT_FULL = 0x10007
CONTEXT_DEBUG_REGISTERS = 0x00010000
CONTEXT_CONTROL = 0x00010001
CONTEXT_INTEGER = 0x00010002


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


class FLOATING_SAVE_AREA(ctypes.Structure):
    _fields_ = [
        ('ControlWord', wt.DWORD), ('StatusWord', wt.DWORD),
        ('TagWord', wt.DWORD), ('ErrorOffset', wt.DWORD),
        ('ErrorSelector', wt.DWORD), ('DataOffset', wt.DWORD),
        ('DataSelector', wt.DWORD), ('RegisterArea', wt.BYTE * 80),
        ('Cr0NpxState', wt.DWORD),
    ]


class CONTEXT32(ctypes.Structure):
    _fields_ = [
        ('ContextFlags', wt.DWORD),
        ('Dr0', wt.DWORD), ('Dr1', wt.DWORD), ('Dr2', wt.DWORD),
        ('Dr3', wt.DWORD), ('Dr6', wt.DWORD), ('Dr7', wt.DWORD),
        ('FloatSave', FLOATING_SAVE_AREA),
        ('SegGs', wt.DWORD), ('SegFs', wt.DWORD), ('SegEs', wt.DWORD), ('SegDs', wt.DWORD),
        ('Edi', wt.DWORD), ('Esi', wt.DWORD), ('Ebx', wt.DWORD),
        ('Edx', wt.DWORD), ('Ecx', wt.DWORD), ('Eax', wt.DWORD),
        ('Ebp', wt.DWORD), ('Eip', wt.DWORD), ('SegCs', wt.DWORD),
        ('EFlags', wt.DWORD), ('Esp', wt.DWORD), ('SegSs', wt.DWORD),
        ('ExtendedRegisters', wt.BYTE * 512),
    ]


class EXCEPTION_RECORD(ctypes.Structure):
    pass


EXCEPTION_RECORD._fields_ = [
    ('ExceptionCode', wt.DWORD), ('ExceptionFlags', wt.DWORD),
    ('ExceptionRecord', ctypes.POINTER(EXCEPTION_RECORD)),
    ('ExceptionAddress', ctypes.c_void_p),
    ('NumberParameters', wt.DWORD), ('ExceptionInformation', ctypes.c_void_p * 15),
]


class EXCEPTION_DEBUG_INFO(ctypes.Structure):
    _fields_ = [('ExceptionRecord', EXCEPTION_RECORD), ('dwFirstChance', wt.DWORD)]


class CREATE_PROCESS_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ('hFile', wt.HANDLE), ('hProcess', wt.HANDLE), ('hThread', wt.HANDLE),
        ('lpBaseOfImage', ctypes.c_void_p), ('dwDebugInfoFileOffset', wt.DWORD),
        ('nDebugInfoSize', wt.DWORD), ('lpThreadLocalBase', ctypes.c_void_p),
        ('lpStartAddress', ctypes.c_void_p), ('lpImageName', ctypes.c_void_p),
        ('fUnicode', wt.WORD),
    ]


class DEBUG_EVENT(ctypes.Structure):
    class _U(ctypes.Union):
        _fields_ = [
            ('Exception', EXCEPTION_DEBUG_INFO),
            ('CreateProcessInfo', CREATE_PROCESS_DEBUG_INFO),
        ]
    _fields_ = [
        ('dwDebugEventCode', wt.DWORD), ('dwProcessId', wt.DWORD),
        ('dwThreadId', wt.DWORD), ('u', _U),
    ]


def read_mem(h_process, address, size):
    buf = ctypes.create_string_buffer(size)
    read = ctypes.c_size_t()
    if kernel32.ReadProcessMemory(h_process, ctypes.c_void_p(address), buf, size, ctypes.byref(read)):
        return buf.raw[:read.value]
    return None


def write_mem(h_process, address, data):
    buf = ctypes.create_string_buffer(data)
    written = ctypes.c_size_t()
    return kernel32.WriteProcessMemory(h_process, ctypes.c_void_p(address), buf, len(data), ctypes.byref(written))


def get_context(h_thread):
    ctx = CONTEXT32()
    ctx.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS
    if kernel32.GetThreadContext(h_thread, ctypes.byref(ctx)):
        return ctx
    return None


def set_context(h_thread, ctx):
    return kernel32.SetThreadContext(h_thread, ctypes.byref(ctx))


def set_hw_bp(ctx, dr_index, address, mode='w', length=4):
    """设置硬件断点"""
    setattr(ctx, f'Dr{dr_index}', address)
    enable_bit = 1 << (dr_index * 2)
    type_shift = 16 + dr_index * 4
    len_shift = 18 + dr_index * 4
    mode_val = 0x01 if mode == 'w' else 0x00
    len_val = {1: 0x00, 2: 0x01, 4: 0x03}.get(length, 0x03)
    ctx.Dr7 |= enable_bit | (mode_val << type_shift) | (len_val << len_shift)
    return ctx


def main():
    parser = argparse.ArgumentParser(description='Windows 调试 API 自动脱壳')
    parser.add_argument('input', help='加壳 EXE')
    parser.add_argument('--output', '-o', help='输出 PE')
    parser.add_argument('--max-wait', type=int, default=30, help='最大等待秒数')
    args = parser.parse_args()

    exe_path = Path(args.input)
    output_path = args.output or str(exe_path.with_name(exe_path.stem + '_unpacked.exe'))

    print(f"[*] 目标: {exe_path}")
    print(f"[*] 输出: {output_path}")

    # 读取 PE 信息
    import pefile
    pe = pefile.PE(str(exe_path))
    image_base = pe.OPTIONAL_HEADER.ImageBase
    ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    ep_va = image_base + ep_rva
    print(f"[*] ImageBase=0x{image_base:08X}, EP=0x{ep_va:08X}")

    # 段信息
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
        print(f"  {name:10s}: VA=0x{image_base + sec.VirtualAddress:08X} VSize=0x{sec.Misc_VirtualSize:08X}")

    # 启动进程
    si = STARTUPINFO()
    si.cb = ctypes.sizeof(STARTUPINFO)
    pi = PROCESS_INFORMATION()

    print(f"\n[1] 启动调试进程...")
    if not kernel32.CreateProcessW(
        None, ctypes.create_unicode_buffer(str(exe_path)),
        None, None, False, DEBUG_PROCESS | CREATE_SUSPENDED,
        None, None, ctypes.byref(si), ctypes.byref(pi)):
        print(f"[!] CreateProcess 失败: {ctypes.get_last_error()}")
        sys.exit(1)

    h_process, h_thread = pi.hProcess, pi.hThread
    pid, tid = pi.dwProcessId, pi.dwThreadId
    print(f"[+] PID={pid}, TID={tid}")

    # 在 EP 处写 INT3 (0xCC) 断点
    # 先用 VirtualProtectEx 确保页面可写
    PAGE_EXECUTE_READWRITE = 0x40
    old_protect = wt.DWORD()
    kernel32.VirtualProtectEx(h_process, ctypes.c_void_p(ep_va), 4,
                              PAGE_EXECUTE_READWRITE, ctypes.byref(old_protect))

    ep_byte = read_mem(h_process, ep_va, 1)
    if ep_byte:
        print(f"[*] EP 处原字节: 0x{ep_byte[0]:02X}")
        saved_ep_byte = ep_byte[0]
    else:
        print(f"[!] 无法读取 EP 内存")
        saved_ep_byte = 0x90

    if write_mem(h_process, ep_va, b'\xCC'):
        print(f"[+] INT3 断点已设置 @ 0x{ep_va:08X}")
        # 验证写入
        verify = read_mem(h_process, ep_va, 1)
        if verify and verify[0] == 0xCC:
            print(f"[+] 验证: INT3 写入成功")
        else:
            print(f"[!] 验证失败: 写入后字节 = {verify.hex() if verify else 'None'}")

    # 恢复线程
    kernel32.ResumeThread(h_thread)

    # 调试事件循环
    print(f"\n[2] 等待调试事件...")
    event = DEBUG_EVENT()
    bp_count = 0
    dll_count = 0
    ep_hit = False
    esp_hw_bp_set = False
    oep_found = False
    oep_address = 0
    saved_ep_byte = ep_byte[0] if ep_byte else 0x90
    start_time = time.time()

    try:
        while True:
            if time.time() - start_time > args.max_wait:
                print(f"[!] 超时 ({args.max_wait}s)")
                break

            if not kernel32.WaitForDebugEvent(ctypes.byref(event), 3000):
                continue

            code = event.dwDebugEventCode
            evt_pid = event.dwProcessId
            evt_tid = event.dwThreadId

            if code == EXCEPTION_DEBUG_EVENT:
                exc = event.u.Exception
                exc_code = exc.ExceptionRecord.ExceptionCode
                exc_addr = exc.ExceptionRecord.ExceptionAddress or 0

                if exc_code == EXCEPTION_BREAKPOINT:
                    bp_count += 1
                    first_chance = exc.dwFirstChance

                    if exc_addr == ep_va and not ep_hit:
                        # EP 断点命中！
                        print(f"\n  🔥 EP 断点命中！@ 0x{exc_addr:08X}")

                        # 恢复原字节
                        write_mem(h_process, ep_va, bytes([saved_ep_byte]))

                        # 获取上下文
                        ctx = get_context(h_thread)
                        if ctx:
                            eip = ctx.Eip
                            esp = ctx.Esp
                            print(f"  EIP=0x{eip:08X}, ESP=0x{esp:08X}")

                            if esp != 0:
                                # ESP 定律法：对 ESP 设硬件写入断点
                                ctx = set_hw_bp(ctx, 0, esp, mode='w', length=4)
                                # 单步执行以跳过 INT3
                                ctx.Eip = ep_va  # 确保 EIP 在 EP
                                ctx.EFlags |= 0x100  # TF (Trap Flag) - 单步
                                if set_context(h_thread, ctx):
                                    esp_hw_bp_set = True
                                    print(f"  ✅ ESP 硬件断点: DR0=0x{esp:08X}")
                                ep_hit = True
                            else:
                                print(f"  ❌ ESP=0，上下文读取可能失败")
                                ctx.Eip = ep_va
                                set_context(h_thread, ctx)
                                ep_hit = True
                        else:
                            print(f"  ❌ 无法读取上下文")
                    else:
                        print(f"  断点 #{bp_count} @ 0x{exc_addr:08X} (EP=0x{ep_va:08X})")

                elif exc_code == EXCEPTION_SINGLE_STEP:
                    ctx = get_context(h_thread)
                    if ctx:
                        eip = ctx.Eip
                        esp = ctx.Esp
                        print(f"  单步/硬件断点 @ EIP=0x{eip:08X}, ESP=0x{esp:08X}")

                        if ep_hit and esp_hw_bp_set and not oep_found:
                            # 检查是否在 .text 段
                            in_text = False
                            for sec in sections:
                                if sec['name'] == '.text' and sec['vaddr'] <= eip < sec['vaddr'] + sec['vsize']:
                                    in_text = True
                                    break

                            if in_text:
                                # 检查 .text 是否有内容
                                text_sec = next((s for s in sections if s['name'] == '.text'), None)
                                if text_sec:
                                    sample = read_mem(h_process, text_sec['vaddr'], 0x1000) or b'\x00' * 0x1000
                                    non_zero = sum(1 for b in sample if b != 0)
                                    if non_zero > 100:
                                        print(f"\n  ✅ OEP 找到！0x{eip:08X} [.text, 非零={non_zero}]")
                                        oep_found = True
                                        oep_address = eip
                                        # 清除硬件断点
                                        ctx.Dr7 = 0
                                        ctx.Dr0 = 0
                                        set_context(h_thread, ctx)
                                    else:
                                        print(f"  .text 非零={non_zero}，继续...")
                                        # 重设 ESP 断点
                                        ctx = set_hw_bp(ctx, 0, esp, mode='w', length=4)
                                        set_context(h_thread, ctx)
                            else:
                                sec_name = "unknown"
                                for sec in sections:
                                    if sec['vaddr'] <= eip < sec['vaddr'] + sec['vsize']:
                                        sec_name = sec['name']
                                        break
                                print(f"  在 {sec_name} 段，继续...")
                                # 重设 ESP 断点
                                ctx = set_hw_bp(ctx, 0, esp, mode='w', length=4)
                                set_context(h_thread, ctx)

            elif code == EXIT_PROCESS_DEBUG_EVENT:
                print(f"\n[!] 进程已退出")
                break

            elif code == LOAD_DLL_DEBUG_EVENT:
                dll_count += 1
                if dll_count <= 5 or dll_count % 10 == 0:
                    print(f"  DLL 加载 #{dll_count}")

            elif code == CREATE_PROCESS_DEBUG_EVENT:
                pass  # 已在前面处理

            elif code == CREATE_THREAD_DEBUG_EVENT:
                pass  # 线程创建

            else:
                if time.time() - start_time < 5:
                    print(f"  事件: code={code}")

            # 继续调试
            if oep_found:
                kernel32.ContinueDebugEvent(evt_pid, evt_tid, DBG_CONTINUE)
                break
            else:
                cont = DBG_EXCEPTION_NOT_HANDLED
                if code == EXCEPTION_DEBUG_EVENT:
                    cont = DBG_CONTINUE
                kernel32.ContinueDebugEvent(evt_pid, evt_tid, cont)

    except Exception as e:
        print(f"[!] 异常: {e}")
        traceback.print_exc()

    # Dump 内存
    if oep_found:
        print(f"\n[3] Dump 内存...")
        # 读取各段
        sections_data = {}
        for sec in sections:
            data = read_mem(h_process, sec['vaddr'], sec['vsize'])
            if data:
                non_zero = sum(1 for b in data if b != 0)
                sections_data[sec['name']] = data
                print(f"  {sec['name']:10s}: {len(data):>8d} 字节, 非零: {non_zero:>8d}")

        # 重建 PE
        with open(exe_path, 'rb') as f:
            new_pe = bytearray(f.read())

        # 更新入口点
        oep_rva = oep_address - image_base
        e_lfanew = struct.unpack_from('<I', new_pe, 0x3C)[0]
        opt_off = e_lfanew + 24 + 16  # AddressOfEntryPoint offset
        struct.pack_into('<I', new_pe, opt_off, oep_rva)
        print(f"  新 EP RVA: 0x{oep_rva:08X}")

        # 写入段数据
        for sec in sections:
            if sec['name'] not in sections_data:
                continue
            data = sections_data[sec['name']]
            raw_off = sec['raw_offset']
            raw_size = sec['raw_size']

            if raw_size > 0 and raw_off > 0:
                write_len = min(len(data), raw_size, len(new_pe) - raw_off)
                new_pe[raw_off:raw_off + write_len] = data[:write_len]

        with open(output_path, 'wb') as f:
            f.write(new_pe)
        print(f"\n[+] ✅ 脱壳 PE 已保存: {output_path}")

        # 保存段 bin 文件
        sections_dir = Path(output_path).with_name(Path(output_path).stem + '_sections')
        sections_dir.mkdir(exist_ok=True)
        for name, data in sections_data.items():
            sf = sections_dir / f"{name}.bin"
            with open(sf, 'wb') as f:
                f.write(data)
        print(f"[+] 段数据: {sections_dir}")

        # 反汇编 .text 前 30 条
        text_data = sections_data.get('.text', b'')
        if text_data:
            import capstone
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            text_va = next((s['vaddr'] for s in sections if s['name'] == '.text'), 0x401000)
            print(f"\n[*] .text 反汇编 (前 30 条):")
            count = 0
            for i in md.disasm(text_data, text_va):
                print(f"  0x{i.address:08X}: {i.mnemonic:8s} {i.op_str}")
                count += 1
                if count >= 30:
                    break

        # GBK 字符串提取
        if text_data:
            gbk_strings = []
            import re
            for m in re.finditer(rb'(?:[\x81-\xfe][\x40-\x7e\x80-\xfe]){2,}', text_data):
                try:
                    s = m.group().decode('gbk', errors='strict').strip()
                    cn = sum(1 for c in s if '\u4e00' <= c <= '\u9fff')
                    if cn >= 2 and len(set(s)) > 2:
                        gbk_strings.append(s)
                except:
                    pass
            if gbk_strings:
                print(f"\n[*] GBK 字符串 (脱壳后): {len(gbk_strings)} 条")
                for s in sorted(gbk_strings, key=len, reverse=True)[:20]:
                    print(f"  {s}")
    else:
        print(f"\n[!] 未找到 OEP")

    # 清理
    kernel32.TerminateProcess(h_process, 0)
    kernel32.CloseHandle(h_thread)
    kernel32.CloseHandle(h_process)


if __name__ == '__main__':
    main()
