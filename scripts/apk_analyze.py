#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
APK 逆向分析 + 反编译 + 重打包 完整链路脚本
用法:
  python apk_analyze.py <target.apk> [--output report.txt] [--deep] [--decompile] [--rebuild] [--sign]
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
    """检查并提示安装依赖工具"""
    deps = {}
    # 检查 apktool
    result = subprocess.run(['where', 'apktool.bat'], capture_output=True, shell=True)
    if result.returncode != 0:
        result = subprocess.run(['which', 'apktool'], capture_output=True, shell=True)
    deps['apktool'] = result.returncode == 0

    # 检查 jadx
    result = subprocess.run(['where', 'jadx.bat'], capture_output=True, shell=True)
    if result.returncode != 0:
        result = subprocess.run(['which', 'jadx'], capture_output=True, shell=True)
    deps['jadx'] = result.returncode == 0

    # 检查 apksigner
    result = subprocess.run(['where', 'apksigner.bat'], capture_output=True, shell=True)
    if result.returncode != 0:
        result = subprocess.run(['which', 'apksigner'], capture_output=True, shell=True)
    deps['apksigner'] = result.returncode == 0

    # 检查 keytool
    result = subprocess.run(['where', 'keytool.exe'], capture_output=True, shell=True)
    if result.returncode != 0:
        result = subprocess.run(['which', 'keytool'], capture_output=True, shell=True)
    deps['keytool'] = result.returncode == 0

    return deps

def get_apk_info(apk_path):
    """用 aapt 或 unzip 获取 APK 基本信息"""
    info = {}
    # 尝试用 aapt
    r = subprocess.run(['aapt', 'dump', 'badging', str(apk_path)],
                      capture_output=True, text=True, shell=True)
    if r.returncode == 0:
        for line in r.stdout.splitlines():
            if line.startswith('package:'):
                m = re.search(r"name='([^']+)'", line)
                if m: info['package'] = m.group(1)
                m = re.search(r"versionCode='([^']+)'", line)
                if m: info['version_code'] = m.group(1)
                m = re.search(r"versionName='([^']+)'", line)
                if m: info['version_name'] = m.group(1)
            if line.startswith('sdkVersion:'):
                info['min_sdk'] = line.split(':')[1].strip()
            if line.startswith('targetSdkVersion:'):
                info['target_sdk'] = line.split(':')[1].strip()
    return info

def analyze_apk(apk_path, deep=False, decompile=False,
                 rebuild=False, sign=False, output=None):
    """主分析函数"""
    lines = []
    def out(s=""):
        lines.append(str(s))
        print(s)

    apk_path = Path(apk_path).resolve()
    if not apk_path.exists():
        out("[!] APK 文件不存在: %s" % apk_path)
        return "\n".join(lines)

    sep = "=" * 65
    out(sep)
    out("  APK 逆向分析报告 - %s" % apk_path.name)
    out("  文件大小: %.2f MB" % (apk_path.stat().st_size / 1024 / 1024))
    out(sep)

    # 1. 文件哈希
    data = apk_path.read_bytes()
    out("\n[1] 文件哈希")
    out("  MD5:    %s" % hashlib.md5(data).hexdigest())
    out("  SHA1:   %s" % hashlib.sha1(data).hexdigest())
    out("  SHA256: %s" % hashlib.sha256(data).hexdigest())

    # 2. APK 基本信息
    out("\n[2] APK 基本信息")
    info = get_apk_info(apk_path)
    if info:
        for k, v in info.items():
            out("  %-20s %s" % (k + ":", v))
    else:
        out("  [!] 无法用 aapt 获取信息，尝试用 unzip 解包...")

    # 3. 解包分析 AndroidManifest.xml
    out("\n[3] 解包分析")
    work_dir = apk_path.parent / (apk_path.stem + "_decompiled")
    manifest_path = work_dir / "AndroidManifest.xml"

    if not work_dir.exists() or rebuild:
        out("  正在用 apktool 解包...")
        r = subprocess.run(
            ['apktool', 'd', '-f', str(apk_path), '-o', str(work_dir)],
            capture_output=True, text=True, shell=True
        )
        if r.returncode != 0:
            # 尝试直接用 jar
            apktool_jar = shutil.which("apktool.jar")
            if apktool_jar:
                r = subprocess.run(
                    ['java', '-jar', apktool_jar, 'd', '-f',
                     str(apk_path), '-o', str(work_dir)],
                    capture_output=True, text=True
                )
            if r.returncode != 0:
                out("  [!] apktool 执行失败: %s" % r.stderr[:200])
                out("  [!] 请确保 apktool 已安装并在 PATH 中")
                out("      安装方法: https://ibotpeaches.github.io/Apktool/")
                # 尝试用 unzip 解包
                out("  [+] 尝试用 unzip 解包（无 Smali 反编译）...")
                work_dir.mkdir(exist_ok=True)
                subprocess.run(['unzip', '-o', str(apk_path), '-d', str(work_dir)],
                             capture_output=True)

    if manifest_path.exists():
        manifest = manifest_path.read_text(encoding='utf-8', errors='ignore')
        out("\n  [AndroidManifest.xml 分析]")
        # 提取包名
        m = re.search(r'package="([^"]+)"', manifest)
        if m: out("  包名: %s" % m.group(1))
        # 提取权限
        perms = re.findall(r'android:name="([^"]+)"', manifest)
        if perms:
            out("  权限数量: %d" % len(perms))
            dangerous = [p for p in perms if any(k in p for k in
                         ['READ_', 'WRITE_', 'ACCESS_', 'CAMERA', 'RECORD_',
                          'PROCESS_', 'SYSTEM_'])]
            if dangerous:
                out("  [!] 危险权限:")
                for p in dangerous[:10]:
                    out("      - %s" % p)
        # 提取入口 Activity
        activities = re.findall(r'<activity[^>]*>.*?</activity>', manifest, re.DOTALL)
        for act in activities:
            if 'android.intent.action.MAIN' in act and 'android.intent.category.LAUNCHER' in act:
                m = re.search(r'android:name="([^"]+)"', act)
                if m:
                    out("  入口 Activity: %s" % m.group(1))
        # 提取所有 Activity
        all_acts = re.findall(r'android:name="([^"]+)"', manifest)
        if all_acts:
            out("  所有 Activity (%d 个):" % len(all_acts))
            for a in all_acts[:15]:
                out("      - %s" % a)
            if len(all_acts) > 15:
                out("      ... 共 %d 个" % len(all_acts))

    # 4. DEX 文件分析
    out("\n[4] DEX 文件分析")
    dex_files = list(work_dir.glob("*.dex")) + list(work_dir.glob("smali*/**/*.smali"))
    if not dex_files:
        # 查找原始 DEX
        dex_in_zip = []
        try:
            import zipfile
            with zipfile.ZipFile(apk_path, 'r') as zf:
                dex_in_zip = [f for f in zf.namelist() if f.endswith('.dex')]
                out("  APK 内 DEX 文件: %s" % ', '.join(dex_in_zip))
        except:
            pass
    else:
        smali_dir = work_dir / "smali"
        if smali_dir.exists():
            smali_count = sum(1 for _ in smali_dir.rglob("*.smali"))
            out("  Smali 文件数量: %d" % smali_count)

    # 5. 字符串提取
    out("\n[5] 字符串提取 (感兴趣内容)")
    if work_dir.exists():
        all_files = list(work_dir.rglob("*.smali")) + list(work_dir.rglob("*.xml"))
        all_files = [f for f in all_files if f.stat().st_size < 500000][:200]

        urls = []
        secrets = []
        api_endpoints = []
        crypto_keywords = []

        for fpath in all_files:
            try:
                content = fpath.read_text(encoding='utf-8', errors='ignore')
                # URL
                found = re.findall(r'"(https?://[^"\s]+)"', content)
                urls.extend(found)
                # 可能的密钥/Token
                if re.search(r'(key|token|secret|password|pwd|api[_-]?key)',
                             content, re.IGNORECASE):
                    secrets.append(str(fpath.relative_to(work_dir)))
                # API 端点
                found_api = re.findall(r'"(/api/[^"\s]{0,100})"', content)
                api_endpoints.extend(found_api)
                # 加密关键词
                if re.search(r'(AES|RSA|DES|MD5|SHA|HMAC|encrypt|decrypt|cipher)',
                             content, re.IGNORECASE):
                    crypto_keywords.append(str(fpath.relative_to(work_dir)))
            except:
                pass

        if urls:
            out("\n  [URL] 发现的 URL:")
            for u in sorted(set(urls))[:20]:
                out("    %s" % u[:200])
        if api_endpoints:
            out("\n  [API] 可能的 API 端点:")
            for a in sorted(set(api_endpoints))[:15]:
                out("    %s" % a)
        if secrets:
            out("\n  [SECRET] 含密钥/Token 关键词的文件:")
            for s in secrets[:10]:
                out("    %s" % s)
        if crypto_keywords:
            out("\n  [CRYPTO] 含加密关键词的文件:")
            for c in crypto_keywords[:10]:
                out("    %s" % c)

    # 6. Native 库分析
    out("\n[6] Native 库 (.so) 分析")
    lib_dir = work_dir / "lib"
    if lib_dir.exists():
        so_files = list(lib_dir.rglob("*.so"))
        out("  Native 库数量: %d" % len(so_files))
        for so in so_files[:10]:
            out("    - %s" % str(so.relative_to(lib_dir)))
        if len(so_files) > 10:
            out("    ... 共 %d 个" % len(so_files))
        out("\n  [!] 可用 pe_analyze.py 进一步分析 .so 文件（ELF 格式）")
    else:
        out("  无 Native 库")

    # 7. 加壳检测
    out("\n[7] 加壳检测")
    shell_apis = []
    if work_dir.exists():
        # 检查已知壳特征
        known_shells = {
            'legu': '腾讯乐固 (LeGu)',
            'bangcle': '梆梆安全 (Bangcle)',
            'ijiami': '爱加密 (iJiami)',
            'qihoo': '360 加固 (Qihoo)',
            'aliprotect': '阿里聚安全 (AliProtect)',
            'tencent': '腾讯保护 (Tencent)',
            'libshella': '某壳 (libshella)',
            'libdexloader': 'DexLoader 壳',
        }
        for so in (list(work_dir.rglob("*.so")) if lib_dir.exists() else []):
            name = so.name.lower()
            for key, desc in known_shells.items():
                if key in name:
                    shell_apis.append(desc)
        # 检查 assets 中的壳特征
        assets_dir = work_dir / "assets"
        if assets_dir.exists():
            for f in assets_dir.iterdir():
                fname = f.name.lower()
                for key, desc in known_shells.items():
                    if key in fname:
                        shell_apis.append(desc)

        if shell_apis:
            out("  [!] 检测到可能的加壳: %s" % ', '.join(set(shell_apis)))
        else:
            out("  [?] 未发现已知壳特征（可能未加壳或使用未知壳）")

    # 8. Jadx 反编译
    if decompile:
        out("\n[8] Jadx 反编译")
        jadx_out = apk_path.parent / (apk_path.stem + "_jadx")
        if jadx_out.exists() and not rebuild:
            out("  Jadx 输出已存在: %s" % jadx_out)
        else:
            out("  正在用 jadx 反编译...")
            r = subprocess.run(
                ['jadx', '-d', str(jadx_out), '--show-bad-code', str(apk_path)],
                capture_output=True, text=True
            )
            if r.returncode == 0:
                out("  [+] Jadx 反编译完成: %s" % jadx_out)
                # 统计 Java 文件数量
                java_files = list(jadx_out.rglob("*.java"))
                out("  Java 源码文件数量: %d" % len(java_files))
            else:
                out("  [!] Jadx 执行失败: %s" % r.stderr[:200])

    # 9. 重打包建议
    out("\n[9] 重打包指引")
    out("""
  修改后重打包步骤：
  1. 修改 smali/ 中的 .smali 文件（文本格式，可直接编辑）
  2. 或用 jadx 输出的 .java 文件修改后，用 javac 编译成 .class，
     再用 dx 工具转成 .dex（较复杂，推荐直接改 smali）
  3. 重打包：
     apktool b %s -o rebuilt.apk
  4. 签名：
     apksigner sign --ks my.keystore rebuilt.apk
  5. 安装测试：
     adb install rebuilt.apk
""" % str(work_dir))

    if rebuild and work_dir.exists():
        out("[*] 正在重打包...")
        rebuilt_path = apk_path.parent / "rebuilt.apk"
        r = subprocess.run(
            ['apktool', 'b', str(work_dir), '-o', str(rebuilt_path)],
            capture_output=True, text=True, shell=True
        )
        if r.returncode == 0:
            out("  [+] 重打包完成: %s" % rebuilt_path)
            if sign:
                out("  [*] 正在签名...")
                r2 = subprocess.run(
                    ['apksigner', 'sign', '--ks', 'my-release-key.keystore',
                     str(rebuilt_path)],
                    capture_output=True, text=True, shell=True
                )
                if r2.returncode == 0:
                    out("  [+] 签名完成")
                else:
                    out("  [!] 签名失败（需要先创建密钥库）")
                    out("      创建密钥库: keytool -genkey -v -keystore my-release-key.keystore")
        else:
            out("  [!] 重打包失败: %s" % r.stderr[:300])

    # 10. CTF 建议
    out("\n[10] CTF 逆向建议")
    out("""
  ════════════════════════════════════════════════════════
  关键发现总结：
  ════════════════════════════════════════════════════════

  [1] 检查 AndroidManifest.xml 中的入口 Activity
  [2] 在 smali/ 中搜索 "flag", "key", "password", "secret"
  [3] 检查 strings.xml (res/values/strings.xml)
  [4] Hook 关键函数用 Frida（如果需要动态分析）

  ════════════════════════════════════════════════════════
  Smali 修改常用技巧：
  ════════════════════════════════════════════════════════

  1. 绕过登录验证：
     找到 if-eqz（等于 0 跳转），改成 if-nez（不等于 0 跳转）

  2. 修改字符串常量：
     搜索 const-string，直接修改后面的字符串

  3. 移除 Root 检测：
     找到 isRoot() 方法，让它返回 const/4 v0, 0x0（false）

  4. 修改网络端点：
     搜索 const-string 后面的 URL，直接替换

  ════════════════════════════════════════════════════════
  工具链推荐：
  ════════════════════════════════════════════════════════

  - apktool: 解包/重打包
  - jadx: 反编译 Java 源码（比 jadx-gui 更适合脚本化）
  - Frida: 动态 hook（需要越狱/root 或 Frida Gadget）
  - objection: 基于 Frida 的自动化分析框架
  - Mobsf: 静态分析框架（Web UI）
""")

    out("\n" + sep)
    out("  分析完成")
    out(sep)

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="APK 逆向分析工具 - 完整链路（解包→分析→反编译→重打包）")
    parser.add_argument("target", help="目标 APK 文件路径")
    parser.add_argument("--output", "-o", help="输出报告到文件", default=None)
    parser.add_argument("--deep", action="store_true", help="深度分析（更多字符串提取）")
    parser.add_argument("--decompile", "-d", action="store_true",
                        help="用 jadx 反编译为 Java 源码")
    parser.add_argument("--rebuild", "-r", action="store_true",
                        help="修改后重打包（需要先修改 smali/ 目录）")
    parser.add_argument("--sign", "-s", action="store_true",
                        help="重打包后自动签名（需要密钥库）")
    args = parser.parse_args()

    import os
    if not os.path.isfile(args.target):
        print("[!] 文件不存在: %s" % args.target)
        sys.exit(1)

    print("[*] 开始分析 APK: %s" % args.target)
    deps = ensure_deps()
    missing = [k for k, v in deps.items() if not v]
    if missing:
        print("[!] 以下工具未安装: %s" % ', '.join(missing))
        print("    建议安装: sudo apt install apktool jadx (Linux) 或 brew install apktool jadx (macOS)")

    report = analyze_apk(
        args.target,
        deep=args.deep,
        decompile=args.decompile,
        rebuild=args.rebuild,
        sign=args.sign,
        output=args.output
    )

    if args.output:
        Path(args.output).write_text(report, encoding='utf-8')
        print("[+] 报告已保存到: %s" % args.output)


if __name__ == '__main__':
    main()
