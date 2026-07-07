#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IPA 逆向分析 + 反编译 + 重签名 完整链路脚本
用法:
  python ipa_analyze.py <target.ipa> [--output report.txt] [--deep] [--extract-macho]
"""

import re
import sys
import json
import shutil
import hashlib
import argparse
import subprocess
import importlib.util
from pathlib import Path
from collections import Counter

def ensure_deps():
    """检查依赖工具"""
    deps = {}
    for tool in ['class-dump', 'otool', 'lipo', 'codesign', 'xattr']:
        r = subprocess.run(['which', tool], capture_output=True)
        deps[tool] = r.returncode == 0
    # class-dump 可能通过 brew 安装为 class-dump
    if not deps.get('class-dump'):
        r = subprocess.run(['which', 'class-dump'], capture_output=True)
        deps['class-dump'] = r.returncode == 0
    return deps

def get_macho_info(macho_path):
    """用 otool 分析 Mach-O 头信息"""
    info = {}
    r = subprocess.run(['otool', '-h', str(macho_path)],
                      capture_output=True, text=True)
    if r.returncode == 0:
        lines = r.stdout.strip().splitlines()
        for line in lines[1:]:
            parts = line.split()
            if len(parts) >= 4:
                info['magic'] = parts[0] if len(parts) > 4 else None
                info['cputype'] = parts[-3] if len(parts) > 4 else parts[0]
                info['cpusubtype'] = parts[-2] if len(parts) > 4 else parts[1]
                info['caps'] = parts[-1] if len(parts) > 4 else parts[2]
    # 检查架构
    r2 = subprocess.run(['lipo', '-info', str(macho_path)],
                       capture_output=True, text=True)
    if r2.returncode == 0:
        info['architectures'] = r2.stdout.strip()
    # 检查是否加密
    r3 = subprocess.run(['otool', '-l', str(macho_path)],
                       capture_output=True, text=True)
    if r3.returncode == 0:
        for line in r3.stdout.splitlines():
            if 'cryptoff' in line or 'cryptid' in line:
                info['encrypted'] = True
                break
        else:
            info['encrypted'] = False
    return info

def analyze_ipa(ipa_path, deep=False, extract_macho=False, output=None):
    """主分析函数"""
    lines = []
    def out(s=""):
        lines.append(str(s))
        print(s)

    ipa_path = Path(ipa_path).resolve()
    if not ipa_path.exists():
        out("[!] IPA 文件不存在: %s" % ipa_path)
        return "\n".join(lines)

    sep = "=" * 65
    out(sep)
    out("  IPA 逆向分析报告 - %s" % ipa_path.name)
    out("  文件大小: %.2f MB" % (ipa_path.stat().st_size / 1024 / 1024))
    out(sep)

    # 1. 文件哈希
    data = ipa_path.read_bytes()
    out("\n[1] 文件哈希")
    out("  MD5:    %s" % hashlib.md5(data).hexdigest())
    out("  SHA1:   %s" % hashlib.sha1(data).hexdigest())
    out("  SHA256: %s" % hashlib.sha256(data).hexdigest())

    # 2. 解包
    out("\n[2] IPA 解包")
    extract_dir = ipa_path.parent / (ipa_path.stem + "_extracted")
    app_dir = None

    if extract_dir.exists() and not extract_macho:
        out("  解包目录已存在: %s" % extract_dir)
        # 查找 .app 目录
        for p in extract_dir.rglob("*.app"):
            app_dir = p
            break
    else:
        out("  正在解包 IPA...")
        import zipfile
        try:
            with zipfile.ZipFile(ipa_path, 'r') as zf:
                zf.extractall(extract_dir)
            out("  [+] 解包完成: %s" % extract_dir)
        except Exception as e:
            out("  [!] 解包失败: %s" % e)
            return "\n".join(lines)

    # 查找 .app 目录和主二进制
    if not app_dir:
        for p in extract_dir.rglob("*.app"):
            app_dir = p
            break
        if not app_dir:
            # 尝试查找 Payload 目录
            payload = extract_dir / "Payload"
            if payload.exists():
                for p in payload.iterdir():
                    if p.suffix == ".app" or (p.is_dir() and any(p.glob("*.plist"))):
                        app_dir = p
                        break

    if not app_dir or not app_dir.exists():
        out("  [!] 无法找到 .app 目录")
        return "\n".join(lines)

    out("  应用目录: %s" % app_dir)

    # 查找主二进制
    app_name = app_dir.stem
    main_binary = app_dir / app_name
    if not main_binary.exists():
        # 尝试查找可执行文件
        for f in app_dir.iterdir():
            if f.is_file() and os.access(str(f), os.X_OK):
                main_binary = f
                break

    out("  主二进制: %s" % main_binary.name if main_binary.exists() else "未找到")

    # 3. Info.plist 分析
    out("\n[3] Info.plist 分析")
    plist_path = app_dir / "Info.plist"
    if plist_path.exists():
        try:
            import plistlib
            with open(plist_path, 'rb') as f:
                plist = plistlib.load(f)
            key_map = {
                'CFBundleIdentifier': 'Bundle ID',
                'CFBundleDisplayName': '显示名称',
                'CFBundleVersion': '版本号',
                'CFBundleShortVersionString': '短版本号',
                'MinimumOSVersion': '最低 iOS 版本',
                'UIRequiredDeviceCapabilities': '设备要求',
                'UISupportedExternalScreenResolutions': '支持的分辨率',
            }
            for key, desc in key_map.items():
                if key in plist:
                    out("  %-30s %s" % (desc + ":", plist[key]))
            # 权限（键值对）
            if 'UIRequiredDeviceCapabilities' in plist:
                out("  设备能力: %s" % plist['UIRequiredDeviceCapabilities'])
        except Exception as e:
            out("  [!] 读取 Info.plist 失败: %s" % e)
    else:
        out("  [!] Info.plist 不存在")

    # 4. Mach-O 二进制分析
    out("\n[4] Mach-O 二进制分析")
    if main_binary.exists():
        macho_info = get_macho_info(main_binary)
        if macho_info:
            out("  架构信息: %s" % macho_info.get('architectures', '未知'))
            out("  CPU 类型: %s" % macho_info.get('cputype', '未知'))
            if macho_info.get('encrypted'):
                out("  [!] 二进制已加密（FairPlay DRM）")
                out("      → 需要从越狱设备 dum p 解密后的二进制")
            else:
                out("  [?] 二进制未加密或无法确定")

        # 用 class-dump 导出头文件
        out("\n  [class-dump] 导出 Objective-C 头文件...")
        headers_dir = extract_dir / "headers"
        if not headers_dir.exists() or extract_macho:
            r = subprocess.run(
                ['class-dump', str(main_binary), '-o', str(headers_dir)],
                capture_output=True, text=True
            )
            if r.returncode == 0:
                header_count = sum(1 for _ in headers_dir.rglob("*.h"))
                out("  [+] 导出完成，共 %d 个头文件" % header_count)
                out("  头文件目录: %s" % headers_dir)
            else:
                out("  [!] class-dump 失败: %s" % r.stderr[:200])
                out("     可能需要先提取指定架构: lipo -thin arm64 <binary> -output <output>")

    # 5. Frameworks 分析
    out("\n[5] Frameworks 分析")
    fw_dir = app_dir / "Frameworks"
    if fw_dir.exists():
        dylibs = list(fw_dir.glob("*.dylib")) + list(fw_dir.glob("*.framework/**/*.dylib"))
        out("  Frameworks 数量: %d" % len(list(fw_dir.iterdir())))
        for f in list(fw_dir.iterdir())[:10]:
            out("    - %s" % f.name)
        if len(list(fw_dir.iterdir())) > 10:
            out("    ... 共 %d 个" % len(list(fw_dir.iterdir())))
    else:
        out("  无 Frameworks 目录")

    # 6. 字符串提取
    out("\n[6] 字符串提取 (感兴趣内容)")
    if main_binary.exists() and main_binary.stat().st_size < 50 * 1024 * 1024:
        try:
            bin_data = main_binary.read_bytes()
            # URL
            urls = re.findall(rb'https?://[^\x00-\x1f\x7f-\xff]{5,200}', bin_data)
            if urls:
                out("\n  [URL] 发现的 URL:")
                for u in sorted(set(urls))[:15]:
                    out("    %s" % u.decode('utf-8', errors='ignore')[:200])
            # 中文 UTF-16LE
            utf16 = re.findall(rb'(?:[\x20-\x7e]\x00){4,}', bin_data)
            cn_strings = []
            seen = set()
            for m in utf16:
                try:
                    s = m.decode('utf-16-le', errors='ignore').rstrip('\x00')
                    if s not in seen and any('\u4e00' <= c <= '\u9fff' for c in s):
                        seen.add(s)
                        cn_strings.append(s)
                except:
                    pass
            if cn_strings:
                out("\n  [CN] 中文 UTF-16LE 字符串 (样本):")
                for s in cn_strings[:15]:
                    out("    %s" % s[:150])
        except Exception as e:
            out("  [!] 字符串提取失败: %s" % e)

    # 7. 签名分析
    out("\n[7] 代码签名分析")
    r = subprocess.run(
        ['codesign', '-dv', '--verbose=4', str(main_binary)],
        capture_output=True, text=True
    )
    if r.returncode == 0:
        out("  签名信息:")
        for line in r.stdout.splitlines()[:15]:
            out("    %s" % line)
    else:
        out("  [!] codesign 失败（可能在非 macOS 系统上运行）")
        out("     可在 macOS 上运行: codesign -dv --verbose=4 <binary>")

    # 8. CTF 建议
    out("\n[8] iOS 逆向建议 - 下一步行动")
    out("""
  ════════════════════════════════════════════════════════════
  关键发现总结：
  ════════════════════════════════════════════════════════════

  [1] 检查主二进制是否加密（FairPlay DRM）
  [2] 如果加密 → 需要从越狱设备 dum p 解密后的二进制
  [3] 用 class-dump 导出的头文件理解程序结构
  [4] 用 Ghidra 反编译 Mach-O（支持 ARM64）

  ════════════════════════════════════════════════════════════
  iOS 逆向完整链路：
  ════════════════════════════════════════════════════════════

  步骤 1：解密二进制（如在越狱设备上）
    # 在越狱 iOS 设备上：
    # 1. 安装 Frida 和 Frida 相关工具
    # 2. 用 Frida 注入 dum p 内存中的解密二进制
    # 或使用 Clutch / bfinject / dum pdecrypted 等工具

  步骤 2：用 Ghidra 反编译
    # 1. 打开 Ghidra → Import File → 选择解密后的二进制
    # 2. 处理器选择 AArch64（ARM64）
    # 3. 分析完成后按 F4 查看反编译 C 伪代码
    # 4. 重点关注 __text 段和 __objc 相关段

  步骤 3：Frida 动态分析
    # 在越狱设备上安装 Frida server
    # PC 上运行: frida -U -f com.bundle.id -l hook.js
    # hook.js 示例：
    #   ObjC.enumerateLoadedClasses(function(name) {
    #     console.log("[*] " + name);
    #   });

  步骤 4：修改并重签名
    # 修改 Mach-O 二进制（在 Ghidra 中 Patch）
    # 用 codesign 重签名：
    #   codesign -f -s "iPhone Developer: ..." target.app
    # 用 ios-deploy 安装到设备：
    #   ios-deploy --bundle target.app

  ════════════════════════════════════════════════════════════
  CTF 常见题型：
  ════════════════════════════════════════════════════════════

  - Objective-C/Swift 方法混淆：用 class-dump 恢复方法列表
  - 内嵌验证逻辑：在 - validateFlag: 或类似方法中设断
  - 网络验证：用 Burp Suite 拦截 HTTPS 流量（需绕过证书锁定）
  - 本地存储：检查 Library/Preferences/、Documents/ 中的 plist 文件
""")

    out("\n" + sep)
    out("  分析完成")
    out(sep)

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="IPA 逆向分析工具 - 完整链路（解包→分析→反编译→重签名）")
    parser.add_argument("target", help="目标 IPA 文件路径")
    parser.add_argument("--output", "-o", help="输出报告到文件", default=None)
    parser.add_argument("--deep", action="store_true", help="深度分析（更多字符串提取）")
    parser.add_argument("--extract-macho", "-e", action="store_true",
                        help="强制重新提取 Mach-O 并导出头文件")
    args = parser.parse_args()

    import os
    if not os.path.isfile(args.target):
        print("[!] 文件不存在: %s" % args.target)
        sys.exit(1)

    print("[*] 开始分析 IPA: %s" % args.target)
    deps = ensure_deps()
    missing = [k for k, v in deps.items() if not v]
    if missing and sys.platform == "darwin":
        print("[!] 以下工具未安装: %s" % ', '.join(missing))
        print("    建议安装: brew install class-dump")

    report = analyze_ipa(
        args.target,
        deep=args.deep,
        extract_macho=args.extract_macho,
        output=args.output
    )

    if args.output:
        Path(args.output).write_text(report, encoding='utf-8')
        print("[+] 报告已保存到: %s" % args.output)


if __name__ == '__main__':
    main()
