#!/usr/bin/env python3
"""
⚠️ DEPRECATED — 此脚本在 CNM 私有壳上失败（反模拟检测导致 ExitProcess）
保留供参考，新项目请使用 suspend_dump.py（挂起转储法）

自动脱壳脚本 v3 — 带 API 模拟的 Unicorn 脱壳引擎

核心改进：
1. 模拟 VirtualAlloc → 在 Unicorn 中实际分配内存并返回地址
2. 模拟 VirtualProtect → 更改内存权限（Unicorn 中为 no-op）
3. 模拟 GetModuleHandleA → 返回镜像基址
4. 模拟 GetProcAddress → 返回 API 存根地址
5. 模拟 LoadLibraryA → 返回假模块句柄
6. 内存写入跟踪：在脱壳完成后从 Unicorn 内存读取所有段数据

这样 CNM 壳的解压代码就能正确运行：
壳调用 VirtualAlloc → 我们分配内存 → 壳写入解压数据 → 我们从内存中读取
"""

import sys
import os
import struct
import argparse
import time
import traceback
from pathlib import Path
from collections import defaultdict

try:
    import pefile
except ImportError:
    print("[!] pip install pefile"); sys.exit(1)
try:
    import unicorn
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
    from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_UNMAPPED, UC_HOOK_INTR
    from unicorn.x86_const import (
        UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX,
        UC_X86_REG_ESP, UC_X86_REG_EBP, UC_X86_REG_ESI, UC_X86_REG_EDI,
        UC_X86_REG_EIP, UC_X86_REG_EFLAGS,
    )
except ImportError:
    print("[!] pip install unicorn"); sys.exit(1)

import capstone

def log(msg):
    print(f"  [*] {msg}")

def align_up(value, alignment):
    return (value + alignment - 1) & ~(alignment - 1)


class APIEmulator:
    """Windows API 模拟器"""

    def __init__(self, uc, image_base, api_stub_base):
        self.uc = uc
        self.image_base = image_base
        self.api_stub_base = api_stub_base
        self.next_alloc_addr = 0x10000000  # 分配内存的起始地址
        self.alloc_regions = {}  # addr -> size
        self.module_handles = {  # 模块名 -> 假句柄
            b'kernel32.dll': 0x7C800000,
            b'user32.dll': 0x7E450000,
            b'advapi32.dll': 0x7DD90000,
            b'ws2_32.dll': 0x71AB0000,
            b'shell32.dll': 0x7CA00000,
            b'winmm.dll': 0x76B40000,
            b'gdi32.dll': 0x77F10000,
        }
        self.api_stub_map = {}  # stub_addr -> (api_name, handler_func)
        self.next_stub_offset = 0x20
        self.string_buffer_base = 0x20000000
        self.string_buffer_offset = 0

    def _alloc_unicorn_mem(self, size, prot=7):
        """在 Unicorn 中分配内存"""
        addr = self.next_alloc_addr
        aligned_size = align_up(size, 0x1000)
        try:
            self.uc.mem_map(addr, aligned_size, prot)
            self.alloc_regions[addr] = aligned_size
            self.next_alloc_addr += aligned_size + 0x10000
            return addr
        except Exception as e:
            log(f"内存分配失败 @ 0x{addr:08X}: {e}")
            return 0

    def _get_stub_addr(self, api_name):
        """获取或创建 API 存根地址"""
        for addr, (name, _) in self.api_stub_map.items():
            if name == api_name:
                return addr
        # 创建新存根
        stub_addr = self.api_stub_base + self.next_stub_offset
        self.next_stub_offset += 0x20
        if self.next_stub_offset >= 0xFFF0:
            self.next_stub_offset = 0x20
        # 写入 ret 指令
        self.uc.mem_write(stub_addr, b'\xC3')
        self.api_stub_map[stub_addr] = (api_name, None)
        return stub_addr

    def _write_string(self, s, encoding='ascii'):
        """将字符串写入内存缓冲区"""
        if isinstance(s, str):
            s = s.encode(encoding)
        addr = self.string_buffer_base + self.string_buffer_offset
        # 确保内存已映射
        try:
            self.uc.mem_read(addr, 1)
        except:
            self._alloc_unicorn_mem(0x10000)
            self.string_buffer_base = max(self.string_buffer_base, addr)
        self.uc.mem_write(addr, s + b'\x00')
        self.string_buffer_offset += len(s) + 1
        return addr

    def _read_string(self, addr, max_len=256):
        """从内存读取字符串"""
        try:
            data = bytes(self.uc.mem_read(addr, max_len))
            null_idx = data.find(b'\x00')
            if null_idx >= 0:
                data = data[:null_idx]
            return data
        except:
            return b''

    # ── API 处理函数 ──

    def handle_VirtualAlloc(self, esp):
        """LPVOID VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)"""
        ret_addr = struct.unpack('<I', bytes(self.uc.mem_read(esp, 4)))[0]
        lpAddress = struct.unpack('<I', bytes(self.uc.mem_read(esp + 4, 4)))[0]
        dwSize = struct.unpack('<I', bytes(self.uc.mem_read(esp + 8, 4)))[0]
        flAllocType = struct.unpack('<I', bytes(self.uc.mem_read(esp + 12, 4)))[0]
        flProtect = struct.unpack('<I', bytes(self.uc.mem_read(esp + 16, 4)))[0]

        if dwSize == 0:
            result = 0
        elif lpAddress != 0:
            # 在指定地址分配
            try:
                self.uc.mem_map(lpAddress, align_up(dwSize, 0x1000),
                                unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE | unicorn.UC_PROT_EXEC)
                self.alloc_regions[lpAddress] = align_up(dwSize, 0x1000)
                result = lpAddress
            except:
                # 可能已映射，尝试直接返回
                result = lpAddress
        else:
            result = self._alloc_unicorn_mem(dwSize)

        self.uc.reg_write(UC_X86_REG_EAX, result)
        # 从栈上弹出参数并返回
        self.uc.reg_write(UC_X86_REG_ESP, esp + 20)  # 4 params * 4 + ret
        self.uc.reg_write(UC_X86_REG_EIP, ret_addr)
        return True

    def handle_VirtualProtect(self, esp):
        """BOOL VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)"""
        ret_addr = struct.unpack('<I', bytes(self.uc.mem_read(esp, 4)))[0]
        # 返回 TRUE (1)
        self.uc.reg_write(UC_X86_REG_EAX, 1)
        self.uc.reg_write(UC_X86_REG_ESP, esp + 20)
        self.uc.reg_write(UC_X86_REG_EIP, ret_addr)
        return True

    def handle_GetModuleHandleA(self, esp):
        ret_addr = struct.unpack('<I', bytes(self.uc.mem_read(esp, 4)))[0]
        lpModuleName = struct.unpack('<I', bytes(self.uc.mem_read(esp + 4, 4)))[0]

        if lpModuleName == 0:
            result = self.image_base
        else:
            name = self._read_string(lpModuleName).lower()
            result = self.module_handles.get(name, self.image_base)

        self.uc.reg_write(UC_X86_REG_EAX, result)
        self.uc.reg_write(UC_X86_REG_ESP, esp + 8)
        self.uc.reg_write(UC_X86_REG_EIP, ret_addr)
        return True

    def handle_GetProcAddress(self, esp):
        ret_addr = struct.unpack('<I', bytes(self.uc.mem_read(esp, 4)))[0]
        hModule = struct.unpack('<I', bytes(self.uc.mem_read(esp + 4, 4)))[0]
        lpProcName = struct.unpack('<I', bytes(self.uc.mem_read(esp + 8, 4)))[0]

        if lpProcName > 0xFFFF:
            func_name = self._read_string(lpProcName).decode('ascii', errors='ignore')
        else:
            func_name = f"ord_{lpProcName}"

        result = self._get_stub_addr(f"dynamic_{func_name}")
        self.uc.reg_write(UC_X86_REG_EAX, result)
        self.uc.reg_write(UC_X86_REG_ESP, esp + 12)
        self.uc.reg_write(UC_X86_REG_EIP, ret_addr)
        return True

    def handle_LoadLibraryA(self, esp):
        ret_addr = struct.unpack('<I', bytes(self.uc.mem_read(esp, 4)))[0]
        lpLibFileName = struct.unpack('<I', bytes(self.uc.mem_read(esp + 4, 4)))[0]

        if lpLibFileName:
            name = self._read_string(lpLibFileName).lower()
            result = self.module_handles.get(name, self.next_alloc_addr)
            if result not in self.module_handles.values():
                self.module_handles[name] = result
        else:
            result = 0

        self.uc.reg_write(UC_X86_REG_EAX, result)
        self.uc.reg_write(UC_X86_REG_ESP, esp + 8)
        self.uc.reg_write(UC_X86_REG_EIP, ret_addr)
        return True

    def handle_GetVersion(self, esp):
        ret_addr = struct.unpack('<I', bytes(self.uc.mem_read(esp, 4)))[0]
        # Windows XP SP3: 0x00000A28
        self.uc.reg_write(UC_X86_REG_EAX, 0x00000A28)
        self.uc.reg_write(UC_X86_REG_ESP, esp + 4)
        self.uc.reg_write(UC_X86_REG_EIP, ret_addr)
        return True

    def handle_GetCurrentProcessId(self, esp):
        ret_addr = struct.unpack('<I', bytes(self.uc.mem_read(esp, 4)))[0]
        self.uc.reg_write(UC_X86_REG_EAX, 1234)
        self.uc.reg_write(UC_X86_REG_ESP, esp + 4)
        self.uc.reg_write(UC_X86_REG_EIP, ret_addr)
        return True

    def handle_GetLastError(self, esp):
        ret_addr = struct.unpack('<I', bytes(self.uc.mem_read(esp, 4)))[0]
        self.uc.reg_write(UC_X86_REG_EAX, 0)
        self.uc.reg_write(UC_X86_REG_ESP, esp + 4)
        self.uc.reg_write(UC_X86_REG_EIP, ret_addr)
        return True

    # 默认处理：返回 0
    def handle_default(self, esp, name="unknown"):
        ret_addr = struct.unpack('<I', bytes(self.uc.mem_read(esp, 4)))[0]
        self.uc.reg_write(UC_X86_REG_EAX, 0)
        self.uc.reg_write(UC_X86_REG_ESP, esp + 4)  # 假设 0 个参数（最小）
        self.uc.reg_write(UC_X86_REG_EIP, ret_addr)
        return True

    # API 名称 -> 处理函数 映射
    API_HANDLERS = {
        'VirtualAlloc': 'handle_VirtualAlloc',
        'VirtualAllocEx': 'handle_VirtualAlloc',
        'VirtualProtect': 'handle_VirtualProtect',
        'VirtualProtectEx': 'handle_VirtualProtect',
        'GetModuleHandleA': 'handle_GetModuleHandleA',
        'GetModuleHandleW': 'handle_GetModuleHandleA',
        'GetProcAddress': 'handle_GetProcAddress',
        'LoadLibraryA': 'handle_LoadLibraryA',
        'LoadLibraryW': 'handle_LoadLibraryA',
        'GetVersion': 'handle_GetVersion',
        'GetCurrentProcessId': 'handle_GetCurrentProcessId',
        'GetLastError': 'handle_GetLastError',
    }


class AutoUnpackerV3:
    """带 API 模拟的自动脱壳引擎"""

    def __init__(self, exe_path, verbose=True):
        self.exe_path = Path(exe_path)
        self.pe = pefile.PE(str(exe_path))
        self.image_base = self.pe.OPTIONAL_HEADER.ImageBase
        self.image_size = self.pe.OPTIONAL_HEADER.SizeOfImage
        self.entry_point = self.image_base + self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        self.section_alignment = self.pe.OPTIONAL_HEADER.SectionAlignment
        self.file_alignment = self.pe.OPTIONAL_HEADER.FileAlignment

        self.sections = []
        for sec in self.pe.sections:
            name = sec.Name.decode('utf-8', errors='ignore').rstrip('\x00')
            self.sections.append({
                'name': name,
                'vaddr': self.image_base + sec.VirtualAddress,
                'vsize': align_up(max(sec.Misc_VirtualSize, 0x1000), self.section_alignment),
                'raw_offset': sec.PointerToRawData,
                'raw_size': sec.SizeOfRawData,
                'entropy': sec.get_entropy() if hasattr(sec, 'get_entropy') else 0,
            })

        self.uc = None
        self.api_emulator = None
        self.mapped_regions = []
        self.step_count = 0
        self.write_count = 0
        self.write_log = defaultdict(int)  # section_name -> write_count
        self.api_call_log = defaultdict(int)  # api_name -> call_count
        self.oep_found = False
        self.oep_address = 0
        self.iat_map = {}  # iat_addr -> api_name

    def _get_section_name(self, addr):
        for sec in self.sections:
            if sec['vaddr'] <= addr < sec['vaddr'] + sec['vsize']:
                return sec['name']
        # 检查 API 模拟分配的区域
        if self.api_emulator:
            for alloc_addr, alloc_size in self.api_emulator.alloc_regions.items():
                if alloc_addr <= addr < alloc_addr + alloc_size:
                    return f"VA_{alloc_addr:08X}"
        return "unknown"

    def initialize(self):
        """初始化 Unicorn 模拟器和 API 仿真"""
        log(f"镜像基址: 0x{self.image_base:08X}")
        log(f"入口点:   0x{self.entry_point:08X}")

        self.uc = Uc(UC_ARCH_X86, UC_MODE_32)

        # 映射 PE Header
        header_size = align_up(self.pe.OPTIONAL_HEADER.SizeOfHeaders, 0x1000)
        self.uc.mem_map(self.image_base, header_size, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
        self.uc.mem_write(self.image_base, self.pe.__data__[:header_size])
        self.mapped_regions.append((self.image_base, header_size))

        # 映射各段
        for sec in self.sections:
            vaddr = sec['vaddr']
            vsize = sec['vsize']
            raw_size = sec['raw_size']
            raw_offset = sec['raw_offset']

            if raw_size > 0 and raw_offset > 0:
                data = self.pe.__data__[raw_offset:raw_offset + raw_size]
            else:
                data = b'\x00' * vsize
            if len(data) < vsize:
                data = data + b'\x00' * (vsize - len(data))
            data = data[:vsize]

            self.uc.mem_map(vaddr, vsize,
                            unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE | unicorn.UC_PROT_EXEC)
            self.uc.mem_write(vaddr, data)
            self.mapped_regions.append((vaddr, vsize))
            log(f"映射: {sec['name']:10s} @ 0x{vaddr:08X}, 0x{vsize:08X} bytes")

        # 栈 (2MB)
        stack_base = 0x00C00000
        stack_size = 0x200000
        self.uc.mem_map(stack_base, stack_size, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
        esp = stack_base + stack_size - 0x2000
        self.uc.reg_write(UC_X86_REG_ESP, esp)
        self.uc.reg_write(UC_X86_REG_EBP, esp)

        # API 存根区
        api_stub_base = 0x00F00000
        self.uc.mem_map(api_stub_base, 0x10000, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE | unicorn.UC_PROT_EXEC)
        self.uc.mem_write(api_stub_base, b'\xC3' * 0x10000)

        # 字符串缓冲区
        str_buf_base = 0x20000000
        try:
            self.uc.mem_map(str_buf_base, 0x100000, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
        except:
            pass

        # PEB
        peb_addr = 0x7FFDF000
        try:
            self.uc.mem_map(peb_addr, 0x1000, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
            self.uc.mem_write(peb_addr + 2, b'\x00')
        except:
            pass

        # 创建 API 模拟器
        self.api_emulator = APIEmulator(self.uc, self.image_base, api_stub_base)

        # 设置 IAT hooks
        self._setup_iat_hooks()

        log(f"栈: 0x{stack_base:08X}, ESP: 0x{esp:08X}")
        log(f"API 存根: 0x{api_stub_base:08X}")
        log(f"IAT hooks: {len(self.iat_map)} 个函数")
        return True

    def _setup_iat_hooks(self):
        """设置 IAT hook"""
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            return

        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.address and imp.name:
                    func_name = imp.name.decode('utf-8', errors='ignore') if isinstance(imp.name, bytes) else str(imp.name)
                    iat_addr = imp.address

                    # 对已知 API，设置专门的存根
                    handler_name = APIEmulator.API_HANDLERS.get(func_name)
                    if handler_name:
                        # 重要 API：创建调用存根（push esp相关参数，然后跳到处理器）
                        stub_addr = self.api_emulator._get_stub_addr(func_name)
                    else:
                        stub_addr = self.api_emulator._get_stub_addr(func_name)

                    self.iat_map[iat_addr] = func_name

                    # 重写 IAT：让 call [IAT] 跳到我们的存根
                    try:
                        self.uc.mem_write(iat_addr, struct.pack('<I', stub_addr))
                    except:
                        pass

    def _hook_code(self, uc, address, size, user_data):
        """指令执行钩子 — 检测 API 调用和 OEP"""
        self.step_count += 1

        # 检测是否调用了 API 存根（ret 指令）
        if self.api_emulator and self.api_emulator.api_stub_base <= address < self.api_emulator.api_stub_base + 0x10000:
            esp = uc.reg_read(UC_X86_REG_ESP)
            api_name = self.api_emulator.api_stub_map.get(address, (f"api_{address:08X}", None))[0]

            self.api_call_log[api_name] += 1
            if self.api_call_log[api_name] <= 3:
                log(f"API 调用: {api_name} @ ESP=0x{esp:08X}")

            # 查找处理函数
            handler_name = APIEmulator.API_HANDLERS.get(api_name)
            if handler_name:
                handler = getattr(self.api_emulator, handler_name)
                handler(esp)
                return
            else:
                # 默认处理
                self.api_emulator.handle_default(esp, api_name)
                return

        # 每 5M 步输出进度
        if self.step_count % 5_000_000 == 0:
            eip = uc.reg_read(UC_X86_REG_EIP)
            esp = uc.reg_read(UC_X86_REG_ESP)
            sec = self._get_section_name(eip)
            log(f"步骤 {self.step_count // 1_000_000}M: EIP=0x{eip:08X} [{sec}] 写入={self.write_count}")

        # OEP 检测
        sec_name = self._get_section_name(address)
        if sec_name == '.text':
            # 检查 .text 段是否有实质代码
            text_sec = next((s for s in self.sections if s['name'] == '.text'), None)
            if text_sec:
                try:
                    sample = bytes(uc.mem_read(text_sec['vaddr'], min(0x1000, text_sec['vsize'])))
                    non_zero = sum(1 for b in sample if b != 0)
                    if non_zero > 500:
                        if not hasattr(self, '_text_consec'):
                            self._text_consec = 0
                        self._text_consec += 1
                        if self._text_consec >= 200 and not self.oep_found:
                            self.oep_found = True
                            self.oep_address = address
                            log(f"\n[+] ✅ OEP: 0x{address:08X} [.text]")
                            log(f"[+] 写入: {self.write_count}, 步骤: {self.step_count:,}")
                            uc.emu_stop()
                            return
                except:
                    pass
        else:
            if hasattr(self, '_text_consec'):
                self._text_consec = 0

    def _hook_mem_write(self, uc, access, address, size, value, user_data):
        """内存写入钩子"""
        self.write_count += 1
        sec_name = self._get_section_name(address)
        self.write_log[sec_name] += 1

    def _hook_unmapped(self, uc, access, address, size, value, user_data):
        """未映射内存 → 动态分配"""
        page_addr = address & ~0xFFF
        try:
            uc.mem_map(page_addr, 0x1000,
                       unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE | unicorn.UC_PROT_EXEC)
            self.mapped_regions.append((page_addr, 0x1000))
            return True
        except:
            return False

    def run(self, timeout_seconds=120, max_steps=500_000_000):
        """运行脱壳模拟"""
        print(f"\n[*] 开始脱壳 (超时: {timeout_seconds}s)")

        self.uc.hook_add(UC_HOOK_CODE, self._hook_code)
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self._hook_mem_write)
        self.uc.hook_add(UC_HOOK_MEM_UNMAPPED, self._hook_unmapped)

        start_time = time.time()
        try:
            self.uc.emu_start(self.entry_point, 0,
                              timeout=timeout_seconds * 1_000_000,
                              count=max_steps)
        except unicorn.UcError as e:
            eip = self.uc.reg_read(UC_X86_REG_EIP)
            log(f"模拟器异常 @ 0x{eip:08X}: {e}")
        except Exception as e:
            log(f"未知异常: {e}")

        elapsed = time.time() - start_time
        print(f"\n[*] 模拟完成: {elapsed:.1f}s, {self.step_count:,} 步, {self.write_count:,} 写入")

        # 打印 API 调用统计
        if self.api_call_log:
            print(f"\n[*] API 调用统计:")
            for name, count in sorted(self.api_call_log.items(), key=lambda x: -x[1])[:20]:
                print(f"  {name:30s}: {count}")

        # 打印写入统计
        if self.write_log:
            print(f"\n[*] 写入分布:")
            for name, count in sorted(self.write_log.items(), key=lambda x: -x[1]):
                print(f"  {name:20s}: {count:,}")

        return self.oep_found or self.write_count > 1000

    def dump_all_memory(self, output_dir):
        """dump 所有内存区域"""
        output_dir = Path(output_dir)
        output_dir.mkdir(exist_ok=True, parents=True)

        print(f"\n[*] Dump 所有内存...")

        # 1. 原始段
        for sec in self.sections:
            try:
                data = bytes(self.uc.mem_read(sec['vaddr'], sec['vsize']))
                non_zero = sum(1 for b in data if b != 0)
                sec_file = output_dir / f"{sec['name']}.bin"
                with open(sec_file, 'wb') as f:
                    f.write(data)
                print(f"  {sec['name']:10s}: {non_zero:>8d}/{len(data)} 非零 ({non_zero/max(len(data),1)*100:.1f}%)")
            except Exception as e:
                print(f"  {sec['name']:10s}: 失败 - {e}")

        # 2. 动态分配区域
        if self.api_emulator:
            for addr, size in sorted(self.api_emulator.alloc_regions.items()):
                try:
                    data = bytes(self.uc.mem_read(addr, size))
                    non_zero = sum(1 for b in data if b != 0)
                    if non_zero > 0:
                        sec_file = output_dir / f"VA_0x{addr:08X}.bin"
                        with open(sec_file, 'wb') as f:
                            f.write(data)
                        print(f"  VA_0x{addr:08X}: {non_zero:>8d}/{len(data)} 非零 ({non_zero/max(len(data),1)*100:.1f}%)")
                except:
                    pass

        # 3. 其他映射区域
        for vaddr, vsize in self.mapped_regions:
            name = self._get_section_name(vaddr)
            if name.startswith("dynamic") or name == "unknown":
                try:
                    data = bytes(self.uc.mem_read(vaddr, vsize))
                    non_zero = sum(1 for b in data if b != 0)
                    if non_zero > 100:
                        sec_file = output_dir / f"mem_0x{vaddr:08X}.bin"
                        with open(sec_file, 'wb') as f:
                            f.write(data)
                        print(f"  mem_0x{vaddr:08X}: {non_zero:>8d}/{len(data)} 非零")
                except:
                    pass

    def analyze_text_section(self):
        """分析 .text 段"""
        text_sec = next((s for s in self.sections if s['name'] == '.text'), None)
        if not text_sec:
            return
        try:
            data = bytes(self.uc.mem_read(text_sec['vaddr'], text_sec['vsize']))
        except:
            return

        non_zero = sum(1 for b in data if b != 0)
        print(f"\n[*] .text 段: {len(data)} 字节, 非零 {non_zero} ({non_zero/max(len(data),1)*100:.1f}%)")

        if non_zero < 100:
            print(f"  ⚠️ .text 几乎全零 — 解压未完成")
            return

        # 反汇编
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        count = 0
        for i in md.disasm(data[:0x400], text_sec['vaddr']):
            if count < 20:
                print(f"  0x{i.address:08X}: {i.mnemonic:8s} {i.op_str}")
            count += 1
        print(f"  前 0x400 字节: {count} 条指令")

    def build_unpacked_pe(self, output_path):
        """重建脱壳 PE"""
        output_path = Path(output_path)
        print(f"\n[*] 重建 PE: {output_path}")

        # 读取原始 PE
        with open(self.exe_path, 'rb') as f:
            new_pe = bytearray(f.read())

        # 更新入口点
        if self.oep_found:
            oep_rva = self.oep_address - self.image_base
            # AddressOfEntryPoint 在 Optional Header 中偏移 16 字节
            opt_offset = self.pe.DOS_HEADER.e_lfanew + 4 + 20 + 16
            struct.pack_into('<I', new_pe, opt_offset, oep_rva)
            print(f"  新入口点 RVA: 0x{oep_rva:08X}")

        # 更新段数据
        for sec in self.sections:
            try:
                mem_data = bytes(self.uc.mem_read(sec['vaddr'], sec['vsize']))
            except:
                continue

            raw_offset = sec['raw_offset']
            raw_size = sec['raw_size']
            non_zero = sum(1 for b in mem_data if b != 0)

            if raw_size > 0 and raw_offset > 0:
                write_len = min(len(mem_data), raw_size, len(new_pe) - raw_offset)
                if write_len > 0:
                    new_pe[raw_offset:raw_offset + write_len] = mem_data[:write_len]
                    print(f"  {sec['name']:10s}: {non_zero} 非零, 写入 {write_len} 字节")
            elif non_zero > 0:
                # 追加到末尾
                aligned = align_up(len(new_pe), self.file_alignment)
                new_pe.extend(b'\x00' * (aligned - len(new_pe)))
                new_pe.extend(mem_data)
                print(f"  {sec['name']:10s}: 追加 {len(mem_data)} 字节 (非零: {non_zero})")

        with open(output_path, 'wb') as f:
            f.write(new_pe)
        print(f"[+] 脱壳 PE 已保存: {output_path}")


def generate_x32dbg_script(output_path, exe_path):
    """生成 x32dbg 脱壳脚本"""
    lines = [
        "// CNM 壳自动脱壳脚本 — ESP 定律法",
        "// 目标: %s" % exe_path,
        'log "开始 ESP 定律脱壳..."',
        "$esp_init = esp",
        'log "初始 ESP: {$esp_init}"',
        "sti", "sti",  # skip PUSHAD
        "bphws esp",
        'log "ESP 硬件断点已设"',
        "run",
        'log "断点命中！"',
        'cmp mod.name(eip), "CNM0"', "je continue_run",
        'cmp mod.name(eip), "CNM1"', "je continue_run",
        'log "===== OEP 找到！====="',
        "// 使用 Scylla dump: Plugins → Scylla → Dump",
        "ret",
        "continue_run:",
        'log "还在壳段，继续..."',
        "bphws esp", "run", "ret",
    ]
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))
    print(f"[+] x32dbg 脚本: {output_path}")


def main():
    parser = argparse.ArgumentParser(description='自动脱壳 v3 — API 模拟')
    parser.add_argument('input', help='加壳 EXE')
    parser.add_argument('--output', '-o', help='输出 PE')
    parser.add_argument('--timeout', '-t', type=int, default=120)
    parser.add_argument('--max-steps', type=int, default=500_000_000)
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"[!] 文件不存在: {input_path}"); sys.exit(1)

    output_path = args.output or str(input_path.with_name(input_path.stem + '_unpacked.exe'))

    print(f"[*] 目标: {input_path}")
    print(f"[*] 输出: {output_path}")

    unpacker = AutoUnpackerV3(input_path)

    print(f"\n[*] 段信息:")
    for sec in unpacker.sections:
        print(f"  {sec['name']:10s} VA=0x{sec['vaddr']:08X} VSize=0x{sec['vsize']:08X} "
              f"RawSize=0x{sec['raw_size']:08X} 熵={sec['entropy']:.2f}")

    # 生成 x32dbg 脚本（备用）
    generate_x32dbg_script(str(input_path.with_name(input_path.stem + '_unpack_script.txt')),
                            str(input_path))

    print(f"\n{'='*60}")
    print(f"[*] Unicorn 脱壳 v3 — API 模拟版")
    print(f"{'='*60}")

    try:
        unpacker.initialize()
    except Exception as e:
        print(f"[!] 初始化失败: {e}")
        traceback.print_exc()
        sys.exit(1)

    success = unpacker.run(timeout_seconds=args.timeout, max_steps=args.max_steps)

    # 分析 .text
    unpacker.analyze_text_section()

    # dump 所有内存
    mem_dir = str(input_path.with_name(input_path.stem + '_unpacked_mem'))
    unpacker.dump_all_memory(mem_dir)

    if success:
        print(f"\n[+] ✅ 脱壳完成！")
        if unpacker.oep_found:
            print(f"[+] OEP: 0x{unpacker.oep_address:08X}")

        # 重建 PE
        try:
            unpacker.build_unpacked_pe(output_path)
        except Exception as e:
            print(f"[!] PE 重建失败: {e}")

        print(f"\n[*] 下一步: 运行 reconstruct.py {output_path}")
    else:
        print(f"\n[!] 脱壳可能不完整")
        print(f"[*] 内存数据已保存在: {mem_dir}")
        print(f"[*] 建议用 x32dbg 手动脱壳")

    # 检查动态分配的内存
    if unpacker.api_emulator and unpacker.api_emulator.alloc_regions:
        print(f"\n[*] VirtualAlloc 分配的区域:")
        for addr, size in sorted(unpacker.api_emulator.alloc_regions.items()):
            try:
                data = bytes(unpacker.uc.mem_read(addr, min(size, 0x1000)))
                non_zero = sum(1 for b in data if b != 0)
                print(f"  0x{addr:08X}: {size} 字节, 前4K非零={non_zero}")
            except:
                pass


if __name__ == '__main__':
    main()
