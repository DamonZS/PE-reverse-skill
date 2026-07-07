#!/usr/bin/env python3
"""
PE Reverse Analyzer - 通用 PE/EXE 逆向分析脚本
用法: python pe_analyze.py <target.exe> [--output report.txt] [--deep]
"""

import re
import sys
import struct
import hashlib
import argparse
import subprocess
import importlib.util

def ensure_pefile():
    """自动安装 pefile 如果不存在"""
    if importlib.util.find_spec("pefile") is None:
        print("[*] pefile 未安装，正在自动安装...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pefile", "-q"])
        print("[+] pefile 安装完成")
    import pefile
    return pefile

def analyze_pe(exe_path, deep=False):
    pefile = ensure_pefile()

    with open(exe_path, 'rb') as f:
        data = f.read()

    pe = pefile.PE(exe_path)

    lines = []
    def out(s=""):
        lines.append(s)
        print(s)

    title = "PE 逆向分析报告 - %s" % exe_path.split("/")[-1].split("\\")[-1]
    sep = "=" * 65
    out(sep)
    out("  " + title)
    out("  文件大小: %d bytes (%.2f MB)" % (len(data), len(data)/1024/1024))
    out(sep)

    # 1. 文件哈希
    out("\n[1] 文件哈希 (取证标识)")
    out("  MD5:    %s" % hashlib.md5(data).hexdigest())
    out("  SHA1:   %s" % hashlib.sha1(data).hexdigest())
    out("  SHA256: %s" % hashlib.sha256(data).hexdigest())

    # 2. PE 基本信息
    out("\n[2] PE 基本信息")
    oh = pe.OPTIONAL_HEADER
    bits = "32" if oh.Magic == 0x10b else "64"
    sub_sys = {2: "Windows GUI", 3: "CUI (Console)", 9: "Windows CE", 10: "EFI"} .get(oh.Subsystem, "Other(%d)" % oh.Subsystem)
    from datetime import datetime, timezone
    ts = pe.FILE_HEADER.TimeDateStamp
    dt_str = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S") + " UTC"

    out("  文件类型:     PE32 (%s-bit)" % bits)
    out("  链接器版本:   %d.%d" % (oh.MajorLinkerVersion, oh.MinorLinkerVersion))
    out("  入口点 RVA:  %s" % hex(oh.AddressOfEntryPoint))
    out("  镜像基址:     %s" % hex(oh.ImageBase))
    out("  子系统:       %d (%s)" % (oh.Subsystem, sub_sys))
    out("  DLL 特征:    %s" % hex(oh.DllCharacteristics))
    out("  编译时间戳:   %s (%s)" % (dt_str, hex(ts)))
    out("  Image Size:   %s (%d bytes)" % (hex(oh.SizeOfImage), oh.SizeOfImage))

    # 3. 段分析 + 加壳检测
    out("\n[3] 段 (Sections) 分析")
    out("  %-12s %-12s %-12s %-12s %-8s %s" % ("Name", "VirtAddr", "VirtSize", "RawAddr", "Entropy", "Flags"))
    suspect_sections = []
    packing_evidence = []
    for sec in pe.sections:
        name = sec.Name.decode('utf-8', errors='ignore').rstrip('\x00')
        va = sec.VirtualAddress
        vs = sec.Misc_VirtualSize
        ra = sec.PointerToRawData
        rs = sec.SizeOfRawData
        ent = sec.get_entropy()
        flags = []
        if sec.Characteristics & 0x20000000: flags.append("X")
        if sec.Characteristics & 0x40000000: flags.append("R")
        if sec.Characteristics & 0x80000000: flags.append("W")
        out("  %-12s %-12s %-12s %-12s %-8.2f %s" % (
            name, hex(va), hex(vs), hex(ra) if ra else "0", ent, ",".join(flags)))
        if ent > 7.0:
            suspect_sections.append((name, ent))
        # 检测异常段
        if name.lower() not in ('.text', '.data', '.rdata', '.rsrc', '.reloc',
                                 '.idata', '.edata', '.pdata', '.xdata', '.bss',
                                 '.tls', '.cormeta', '.sdata', '.sbss'):
            packing_evidence.append("非常规段名: %s" % name)
        if ra == 0 and rs == 0 and sec.Misc_VirtualSize > 0:
            packing_evidence.append("%s 段仅在内存中存在 (RawSize=0)" % name)

    out("\n  [加壳检测]")
    # 基于段名的壳识别
    section_packers = {
        '.vmp0': 'VMProtect', '.vmp1': 'VMProtect', '.vmp2': 'VMProtect', '.vmp3': 'VMProtect',
        '.vmp4': 'VMProtect', '.vmp5': 'VMProtect',
        'CNM0': 'CNM Packer (私有壳)', 'CNM1': 'CNM Packer (私有壳)',
        'UPX0': 'UPX', 'UPX1': 'UPX', 'UPX2': 'UPX',
        '.themida': 'Themida', '.winlicense': 'WinLicense',
        '.enigma1': 'Enigma Protector', '.enigma2': 'Enigma Protector',
        '.aspack': 'ASPack',
        '.perplex': 'Perplex PE Protector',
        '.np0': 'NoProtect', '.np1': 'NoProtect',
        '.shrink': 'Shrinker',
        '.yp': 'yoda Protector',
        '.petite': 'Petite',
        '.mpress1': 'MPRESS', '.mpress2': 'MPRESS',
        '.rlpack': 'RLPack',
        '.pebundle': 'PEBundle',
        '.ndata': 'NSIS Installer',
    }
    detected_packer_by_section = None
    for sec in pe.sections:
        sec_name = sec.Name.decode('utf-8', errors='ignore').rstrip('\x00')
        if sec_name in section_packers:
            detected_packer_by_section = section_packers[sec_name]
            packing_evidence.append("段名 %s → %s (确定性识别)" % (sec_name, detected_packer_by_section))
    if suspect_sections:
        out("    [!] 高熵值段 (可能加密/压缩):")
        for name, ent in suspect_sections:
            out("        %s: entropy=%.4f" % (name, ent))
    if detected_packer_by_section:
        out("    [!] 基于段名的壳识别: %s (确定性)" % detected_packer_by_section)
    if len(pe.sections) <= 3:
        packing_evidence.append("段数量极少 (%d 个)，可能加壳" % len(pe.sections))
    if packing_evidence:
        for e in packing_evidence:
            out("    [?] %s" % e)
    else:
        out("    [?] 未发现明显加壳特征（但无法排除自定义壳）")

    # 4. CNM / 可疑段详细分析
    out("\n[4] 可疑段详细分析")
    found_suspicious = False
    for sec in pe.sections:
        name = sec.Name.decode('utf-8', errors='ignore').rstrip('\x00')
        if sec.get_entropy() > 6.5 or name.lower() not in ('.text', '.data', '.rdata', '.rsrc'):
            found_suspicious = True
            out("\n  --- %s (熵值: %.4f) ---" % (name, sec.get_entropy()))
            out("    VirtualAddr:  %s" % hex(sec.VirtualAddress))
            out("    VirtualSize:  %s (%d bytes)" % (hex(sec.Misc_VirtualSize), sec.Misc_VirtualSize))
            out("    RawAddr:      %s" % (hex(sec.PointerToRawData) if sec.PointerToRawData else "0 (内存中分配)"))
            out("    RawSize:      %s" % (hex(sec.SizeOfRawData) if sec.SizeOfRawData else "0"))
            out("    Entropy:      %.4f" % sec.get_entropy())
            out("    Characteristics: %s" % hex(sec.Characteristics))
            if sec.PointerToRawData > 0 and sec.SizeOfRawData > 0:
                offset = sec.PointerToRawData
                size = min(sec.SizeOfRawData, 256)
                chunk = data[offset:offset+size]
                packers = {
                    b'UPX': 'UPX Packer',
                    b'PETITE': 'Petite Packer',
                    b'ASPack': 'ASPack Packer',
                    b'FSG': 'FSG Packer',
                    b'MEW': 'MEW Packer',
                    b'PECompact': 'PECompact Packer',
                    b'Themida': 'Themida Protector',
                    b'VMProtect': 'VMProtect Protector',
                    b'Enigma': 'Enigma Protector',
                    b'UPX!': 'UPX! variant',
                    b'Yoda': 'Yoda Protector',
                    b'PELock': 'PELock Protector',
                    b'Armadillo': 'Armadillo Protector',
                    b'ASProtect': 'ASProtect',
                }
                found = [desc for sig, desc in packers.items() if sig in chunk]
                if found:
                    out("    [!] 检测到已知壳特征: %s" % ', '.join(found))
                else:
                    out("    [?] 未在已知壳数据库中匹配 (可能是私有壳/自定义保护)")

    if not found_suspicious:
        out("  所有段熵值正常，未发现明显可疑段")

    # 5. 导入表分析
    out("\n[5] 导入表 (Import Table) 分析")
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        all_funcs = []
        dll_count = 0
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode('utf-8', errors='ignore')
            dll_count += 1
            funcs = []
            for imp in entry.imports:
                fname = imp.name.decode('utf-8', errors='ignore') if imp.name else ("Ordinal_%d" % imp.ordinal)
                funcs.append(fname)
                all_funcs.append((dll, fname))
            out("\n  DLL: %s (%d functions)" % (dll, len(funcs)))
            for f in funcs[:8]:
                out("      - %s" % f)
            if len(funcs) > 8:
                out("      ... 共 %d 个函数" % len(funcs))

        out("\n  [统计] DLL 数量: %d, 导入函数总数: %d" % (dll_count, len(all_funcs)))
        if len(all_funcs) < 50:
            out("  [!] 导入函数数量极少 (%d 个)，高度疑似加壳 (IAT 加密)" % len(all_funcs))

        # 行为推断
        out("\n  [行为推断] 基于导入 API:")
        behaviors = []
        func_names = [f[1].lower() for f in all_funcs]
        dll_names = [f[0].lower() for f in all_funcs]

        if any('shellexecute' in f or 'winexec' in f or 'system' in f or 'createprocess' in f for f in func_names):
            behaviors.append("[!] 可执行系统命令/进程 (ShellExecuteA/WinExec/CreateProcess)")
        if any('regcreate' in f or 'regset' in f or 'regopen' in f or 'regsave' in f for f in func_names):
            behaviors.append("[!] 注册表操作 (可能保存激活信息/配置/反分析)")
        if any('socket' in f or 'connect' in f or 'gethostbyname' in f or 'send' in f or 'recv' in f or 'internetconnect' in f for f in func_names):
            behaviors.append("[!] 网络通信 (可能连接 C2 服务器/远程验证/数据外泄)")
        if any('virtualalloc' in f or 'virtualprotect' in f or 'virtualfree' in f for f in func_names):
            behaviors.append("[!] 内存操作 (可能执行 shellcode/反调试/注入)")
        if any('setwindowshookex' in f or 'getkeystate' in f or 'getasynckeystate' in f for f in func_names):
            behaviors.append("[!] 键盘钩子 (可能记录按键)")
        if any('createdesktop' in f or 'switchdesktop' in f for f in func_names):
            behaviors.append("[!] 桌面操作 (可能创建隐藏桌面/反沙箱)")
        if any('wave' in f or 'midi' in f or 'play' in f for f in func_names):
            behaviors.append("[?] 音频功能 (程序可能播放提示音)")

        if not behaviors:
            behaviors.append("[*] 未识别出明显行为特征 (可能导入表被破坏/加密)")

        for b in behaviors:
            out("    %s" % b)
    else:
        out("  [!] 无导入表 (可能完全静态链接或严重加壳，IAT 被加密)")

    # 6. 导出表
    out("\n[6] 导出表 (Export Table)")
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        exp = pe.DIRECTORY_ENTRY_EXPORT
        name = exp.name.decode('utf-8', errors='ignore') if exp.name else 'N/A'
        out("  DLL Name: %s" % name)
        export_list = exp.symbols if hasattr(exp, 'symbols') else (exp.exports if hasattr(exp, 'exports') else [])
        out("  导出函数数: %d" % len(export_list))
        for i, e in enumerate(export_list[:15]):
            fname = e.name.decode('utf-8', errors='ignore') if hasattr(e, 'name') and e.name else ("Ordinal_%d" % e.ordinal if hasattr(e, 'ordinal') else "Unknown")
            addr = hex(e.address) if hasattr(e, 'address') else "N/A"
            out("    [%d] %s @ %s" % (i, fname, addr))
        if len(export_list) > 15:
            out("    ... 共 %d 个导出函数" % len(export_list))
    else:
        out("  无导出函数 (符合 GUI 可执行文件或纯 EXE 特征)")

    # 7. 资源分析
    out("\n[7] 资源 (.rsrc) 分析")
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        for rt in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            rt_id = rt.id if rt.id is not None else -1
            rt_name = pefile.RESOURCE_TYPE.get(rt_id, "Unknown_%d" % rt_id)
            count = 0
            if hasattr(rt, 'directory'):
                for rid in rt.directory.entries:
                    if hasattr(rid, 'directory'):
                        count += len(rid.directory.entries)
            out("  资源类型: %s (ID:%d) - %d 个资源" % (rt_name, rt_id, count))
    else:
        out("  无资源段")

    # 8. 字符串提取
    out("\n[8] 字符串提取 (感兴趣内容)")
    all_ascii = re.findall(rb'[\x20-\x7e]{6,}', data)
    decoded_ascii = []
    for s in all_ascii:
        try:
            decoded_ascii.append(s.decode('ascii'))
        except:
            pass

    # URL
    urls = re.findall(rb'https?://[^\x00-\x1f\x7f-\xff]{5,150}', data)
    if urls:
        out("\n  [URL] 发现的 URL:")
        seen_urls = set()
        for u in urls:
            us = u.decode('utf-8', errors='ignore')
            if us not in seen_urls:
                seen_urls.add(us)
                out("    %s" % us[:200])

    # 文件路径
    paths = re.findall(rb'[A-Za-z]:\\[^\x00-\x1f\x7f]{5,200}', data)
    if paths:
        out("\n  [PATH] 发现的文件路径:")
        seen_paths = set()
        for p in paths:
            ps = p.decode('utf-8', errors='ignore')
            if ps not in seen_paths:
                seen_paths.add(ps)
                out("    %s" % ps[:200])

    # 注册表键
    regs = re.findall(rb'HKEY_[A-Za-z_\\]+\\[^\x00-\x1f]{0,100}', data)
    if regs:
        out("\n  [REG] 发现的注册表键:")
        for r in sorted(set(regs)):
            out("    %s" % r.decode('utf-8', errors='ignore')[:200])

    # 中文 UTF-16LE 字符串
    utf16_strings = re.findall(rb'(?:[\x20-\x7e]\x00){4,}', data)
    cn_strings = []
    seen_cn = set()
    for m in utf16_strings:
        try:
            s = m.decode('utf-16-le', errors='ignore').rstrip('\x00')
            if s not in seen_cn and any('\u4e00' <= c <= '\u9fff' for c in s):
                seen_cn.add(s)
                cn_strings.append(s)
        except:
            pass
    if cn_strings:
        out("\n  [CN] 中文 UTF-16LE 字符串 (样本):")
        for s in cn_strings[:20]:
            out("    %s" % s[:150])

    # 可能的序列号/密钥格式
    serial_pat = re.compile(rb'[A-Za-z0-9]{16,}(?:-[A-Za-z0-9]{4,}){2,}')
    serials = serial_pat.findall(data)
    if serials:
        out("\n  [SERIAL] 可能的序列号格式:")
        for s in serials[:5]:
            out("    %s" % s.decode('utf-8', errors='ignore'))

    # 9. 入口点反汇编
    out("\n[9] 入口点 (OEP) 简易反汇编")
    ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    try:
        ep_offset = pe.get_offset_from_rva(ep_rva)
    except:
        ep_offset = ep_rva  # 估算
    ep_bytes = data[ep_offset:ep_offset+80]
    out("  EP RVA: %s, EP Offset: %s" % (hex(ep_rva), hex(ep_offset)))
    out("\n  地址       指令")
    out("  " + "-" * 60)

    addr = ep_offset
    idx = 0
    while idx < len(ep_bytes) and addr < ep_offset + 64:
        b = ep_bytes[idx]
        line = "  %08X: " % addr
        if b == 0x90:
            line += "NOP"; idx += 1; addr += 1
        elif b == 0xCC:
            line += "INT3 (调试断点)"; idx += 1; addr += 1
        elif b == 0x55:
            line += "PUSH EBP"; idx += 1; addr += 1
        elif b == 0x89 and idx+1 < len(ep_bytes) and ep_bytes[idx+1] == 0xE5:
            line += "MOV EBP, ESP"; idx += 2; addr += 2
        elif b == 0xE8 and idx+4 < len(ep_bytes):
            rel = struct.unpack('<i', ep_bytes[idx+1:idx+5])[0]
            target = ep_rva + idx + 5 + rel
            line += "CALL near -> %s" % hex(target); idx += 5; addr += 5
        elif b == 0xE9 and idx+4 < len(ep_bytes):
            rel = struct.unpack('<i', ep_bytes[idx+1:idx+5])[0]
            target = ep_rva + idx + 5 + rel
            line += "JMP near -> %s" % hex(target); idx += 5; addr += 5
        elif b == 0xEB and idx+1 < len(ep_bytes):
            rel = ep_bytes[idx+1]
            line += "JMP short -> %s" % hex(ep_rva + idx + 2 + (rel if rel < 128 else rel - 256)); idx += 2; addr += 2
        elif b == 0xC3:
            line += "RET"; idx += 1; addr += 1
        elif b == 0x68 and idx+4 < len(ep_bytes):
            val = struct.unpack('<I', ep_bytes[idx+1:idx+5])[0]
            line += "PUSH %s" % hex(val); idx += 5; addr += 5
        elif b == 0xB8 and idx+4 < len(ep_bytes):
            val = struct.unpack('<I', ep_bytes[idx+1:idx+5])[0]
            line += "MOV EAX, %s" % hex(val); idx += 5; addr += 5
        elif b == 0xFF:
            line += "JMP/CALL r/m32"; idx += 1; addr += 1
        elif b == 0x33:
            line += "XOR r32, r/m32"; idx += 1; addr += 1
        elif b == 0x85:
            line += "TEST r/m32, r32"; idx += 1; addr += 1
        elif b == 0x60:
            line += "PUSHAD (壳特征!)"; idx += 1; addr += 1
        elif b == 0x61:
            line += "POPAD (壳特征!)"; idx += 1; addr += 1
        elif b == 0xE2:
            line += "LOOP (短循环)"; idx += 1; addr += 1
        else:
            line += "DB %02X" % b; idx += 1; addr += 1
        out(line)

    # 10. CTF 建议
    out("\n[10] CTF 逆向建议 - 下一步行动")
    out("\n  " + "═" * 60)
    out("  关键发现总结：")
    out("  " + "═" * 60)

    ep_in_suspicious = False
    for sec in pe.sections:
        name = sec.Name.decode('utf-8', errors='ignore').rstrip('\x00')
        sec_start = sec.VirtualAddress
        sec_end = sec_start + sec.Misc_VirtualSize
        if sec_start <= ep_rva < sec_end:
            if sec.get_entropy() > 7.0 or name.lower() not in ('.text',):
                ep_in_suspicious = True
                out("  [1] 入口点 (EP) 位于可疑段 %s (熵值=%.2f)" % (name, sec.get_entropy()))
                out("      → 这是壳的代码，不是原程序 OEP")

    if len(all_funcs) < 50:
        out("  [2] 导入函数仅 %d 个 → 极可能加壳 (IAT 加密)" % len(all_funcs))

    out("\n  " + "═" * 60)
    out("  推荐脱壳方法 (x32dbg / x64dbg / OD):")
    out("  " + "═" * 60)
    out("""
  方法 A - ESP 定律脱壳法 (推荐):
    1. x32dbg 加载目标程序
    2. 程序暂停在 EP (注意第一条指令是否是 PUSHAD / PUSHFD)
    3. 如果是 PUSHAD，单步 (F7) 执行它
    4. 在 ESP 寄存器值上 右键 → Breakpoint → Hardware, on access
    5. F9 运行，硬件断点触发时通常已接近 OEP
    6. 在断点处查看反汇编，识别原程序入口特征
    7. 用 Scylla 插件 dump 内存中的脱壳程序
    8. 用 Scylla 修复 IAT (导入地址表)

  方法 B - 在关键 API 设断跟踪:
    1. x32dbg 中 Ctrl+G → 输入 ShellExecuteA (在 kernel32.dll 中)
    2. 在函数开头 F2 设断
    3. F9 运行程序，调用时断下
    4. Alt+K 查看调用栈，找到调用来源
    5. 回到调用代码，分析其参数

  方法 C - 内存字符串搜索 (脱壳后):
    1. 壳解包完成后 (或手动脱壳后)，在 x32dbg 中用搜索
    2. 搜索字符串 "flag" "key" "password" "serial" "激活" "注册"
    3. 找到后，在引用这些字符串的代码处设断
""")

    out("\n  " + "═" * 60)
    out("  静态分析备选 (如不想动态调试):")
    out("  " + "═" * 60)
    out("""
  1. 用 PEiD / RDG Packer Detector / Detect It Easy 识别壳类型
  2. 如果是 UPX → 直接用 upx -d 脱壳
  3. 如果是 Themida/VMProtect → 需要动态调试或找 OEP
  4. 用 strings 工具提取所有字符串，搜索关键关键词
  5. 用 Pestudio / CFF Explorer 查看导入表、资源、字符串
  6. 用 Die (Detect It Easy) 查看编译器特征、段信息
""")

    pe.close()
    out("\n" + sep)
    out("  分析完成")
    out(sep)

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="PE 逆向分析工具 - 通用 EXE 分析 + 源码重构")
    parser.add_argument("target", help="目标 EXE/PE 文件路径")
    parser.add_argument("--output", "-o", help="输出报告到文件", default=None)
    parser.add_argument("--deep", action="store_true", help="深度分析模式 (更详细的字符串提取)")
    parser.add_argument("--reconstruct", "-r", action="store_true",
                        help="源码重构模式：生成可编译的 C/C++ 项目（而非仅报告）")
    parser.add_argument("--reconstruct-dir", default=None,
                        help="重构输出目录（默认 ./reconstructed_<filename>/）")
    args = parser.parse_args()

    import os
    if not os.path.isfile(args.target):
        print("[!] 文件不存在: %s" % args.target)
        sys.exit(1)

    print("[*] 开始分析: %s" % args.target)

    if args.reconstruct:
        # 源码重构模式 - 最终产出是可编译项目
        from reconstruct import reconstruct_pe
        import pefile
        pe_tmp = pefile.PE(args.target)
        # 检测壳类型
        packer = None
        section_packers = {
            '.vmp0': 'VMProtect', '.vmp1': 'VMProtect', '.vmp2': 'VMProtect',
            'CNM0': 'CNM Packer', 'CNM1': 'CNM Packer',
            'UPX0': 'UPX', 'UPX1': 'UPX',
            '.themida': 'Themida',
        }
        for sec in pe_tmp.sections:
            sn = sec.Name.decode('utf-8', errors='ignore').rstrip('\x00')
            if sn in section_packers:
                packer = section_packers[sn]
                break
        pe_tmp.close()

        output_dir = args.reconstruct_dir or os.path.join(
            os.path.dirname(args.target) or '.',
            "reconstructed_" + os.path.splitext(os.path.basename(args.target))[0]
        )
        reconstruct_pe(args.target, output_dir, packer_info=packer)

        # 同时生成分析报告作为参考
        report = analyze_pe(args.target, deep=args.deep)
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(report)
            print("[+] 分析报告已保存到: %s" % args.output)
    else:
        # 传统分析模式 - 产出报告
        report = analyze_pe(args.target, deep=args.deep)

        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(report)
            print("[+] 报告已保存到: %s" % args.output)


if __name__ == '__main__':
    main()
