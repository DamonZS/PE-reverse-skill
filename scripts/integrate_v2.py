#!/usr/bin/env python3
"""
Integrate decompiled pseudocode into a structured project (v2).

Fixes from v1:
- Classify functions by string references + call patterns, not IAT address matching
- Replace CALL addresses with descriptive names where possible
- Fix address format matching (0x004010A1 vs 0x4010a1)
- Preserve existing source files (main.c, network.c, registry.c)
- Generate proper module structure with meaningful names

Usage:
  python integrate_v2.py --base-dir <project_dir> [--output-dir <output_dir>]

  If --output-dir is not specified, defaults to <project_dir>/reconstructed_v2/
"""

import os
import sys
import json
import re
import argparse
from collections import defaultdict

# === Parse arguments ===
parser = argparse.ArgumentParser(description='Integrate decompiled pseudocode v2')
parser.add_argument('--base-dir', required=True, help='Project base directory containing deep_analysis/')
parser.add_argument('--output-dir', help='Output directory (default: <base-dir>/reconstructed_v2/)')
parser.add_argument('--binary-name', default='unknown', help='Original binary name for documentation')
args = parser.parse_args()

BASE_DIR = args.base_dir
DEEP_ANALYSIS_DIR = os.path.join(BASE_DIR, "deep_analysis")
PSEUDOCODE_DIR = os.path.join(DEEP_ANALYSIS_DIR, "pseudocode")
OUTPUT_DIR = args.output_dir or os.path.join(BASE_DIR, "reconstructed_v2")

ANALYSIS_JSON = os.path.join(DEEP_ANALYSIS_DIR, "deep_analysis.json")
STRINGS_ASCII = os.path.join(DEEP_ANALYSIS_DIR, "ascii_strings_unpacked.txt")
STRINGS_GBK = os.path.join(DEEP_ANALYSIS_DIR, "gbk_strings_unpacked.txt")
URLS_FILE = os.path.join(DEEP_ANALYSIS_DIR, "urls_unpacked.txt")

# === Read analysis data ===
print("[1/7] Loading analysis data...")
with open(ANALYSIS_JSON, 'r', encoding='utf-8') as f:
    analysis = json.load(f)

function_list = analysis.get('function_list', [])
strings_data = analysis.get('strings', {})
iat_data = analysis.get('iat', {})
algo_data = analysis.get('algorithms', {})

# Build function info map with normalized addresses
func_info = {}
for fi in function_list:
    addr = fi.get('addr', '')
    # Normalize: ensure consistent 0x prefix + lowercase
    norm_addr = hex(int(addr, 16))
    func_info[norm_addr] = fi

print(f"  Functions: {len(function_list)}")
print(f"  GBK strings: {strings_data.get('gbk_quality', 0)}")
print(f"  ASCII strings: {strings_data.get('ascii', 0)}")

# === Read all pseudocode ===
print("[2/7] Reading pseudocode files...")
pseudocode_files = sorted([f for f in os.listdir(PSEUDOCODE_DIR) if f.endswith('.c')])
print(f"  Found {len(pseudocode_files)} pseudocode files")

# Read each pseudocode file
pseudocodes = {}
for fname in pseudocode_files:
    # Extract address from filename: func_00401004.c -> 0x401004
    match = re.match(r'func_([0-9A-Fa-f]+)\.c', fname)
    if not match:
        continue
    addr_int = int(match.group(1), 16)
    norm_addr = hex(addr_int)

    fpath = os.path.join(PSEUDOCODE_DIR, fname)
    with open(fpath, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()

    pseudocodes[norm_addr] = {
        'filename': fname,
        'content': content,
        'addr': norm_addr,
        'addr_int': addr_int,
        'size': len(content),
    }

print(f"  Loaded {len(pseudocodes)} pseudocode entries")

# === Read string files for classification ===
print("[3/7] Loading string references...")

# Read ASCII strings
ascii_strings = []
if os.path.exists(STRINGS_ASCII):
    with open(STRINGS_ASCII, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.strip()
            if line and len(line) >= 4:
                ascii_strings.append(line)

# Read GBK strings
gbk_strings = []
if os.path.exists(STRINGS_GBK):
    with open(STRINGS_GBK, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.strip()
            if line and len(line) >= 2:
                gbk_strings.append(line)

# Read URLs
urls = []
if os.path.exists(URLS_FILE):
    with open(URLS_FILE, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.strip()
            if line:
                urls.append(line)

print(f"  ASCII strings: {len(ascii_strings)}")
print(f"  GBK strings: {len(gbk_strings)}")
print(f"  URLs: {len(urls)}")

# === IAT mapping ===
# Build API name -> category mapping from the 186 runtime imports
api_categories = {
    'network': ['WinHttp', 'Internet', 'Http', 'WSA', 'gethostbyname', 'WSAGetLastError',
                'WSACleanup', 'WSASet', 'HttpOpen', 'HttpSend', 'HttpQuery', 'WinHttpOpen',
                'WinHttpSend', 'WinHttpQuery', 'WinHttpSet', 'WinHttpCheck',
                'InternetRead', 'InternetGet', 'InternetClose',
                'getsockname', 'connect', 'send', 'recv', 'socket'],
    'crypto': ['Crypt', 'TEA', 'XXTEA', 'encrypt', 'decrypt', 'hash', 'MD5', 'SHA',
               'CRC32', 'base64', 'A512548E'],
    'registry': ['RegCreate', 'RegOpen', 'RegQuery', 'RegSet', 'RegClose', 'RegDelete'],
    'ui': ['CreateWindow', 'ShowWindow', 'MessageBox', 'DialogBox', 'SetWindowText',
           'GetWindowText', 'SendMessage', 'PostMessage', 'DefWindowProc',
           'SkinH', 'EditBox', 'PicBox', 'GroupBox', 'Label', 'Button',
           'CheckBox', 'RadioBox', 'ComboBox', 'Timer', 'ListView', 'StatusBar',
           'TransLabel', 'HtmlViewer', 'DrawDib', 'BitBlt', 'TransparentBlt'],
    'file_io': ['CreateFile', 'ReadFile', 'WriteFile', 'CloseHandle', 'DeleteFile',
                'FindFirst', 'FindNext', 'GetModuleFileName', 'LoadLibrary',
                'GetProcAddress', 'GetModuleHandle', 'VirtualAlloc', 'VirtualFree',
                'VirtualProtect', 'LocalAlloc', 'LocalFree', 'GetFileSize',
                'SetFilePointer', 'FlushFileBuffers'],
    'system': ['GetVersion', 'GetSystemInfo', 'GetSystemTime', 'GetTickCount',
               'Sleep', 'CreateProcess', 'ShellExecute', 'CoInitialize',
               'CoUninitialize', 'GetActiveWindow', 'GetLastActivePopup',
               'MultiByteToWideChar', 'WideCharToMultiByte', 'ExitProcess',
               'GetVersionEx', 'FileTimeToSystemTime', 'LocalFileTimeToFileTime',
               'CreateWaitableTimer', 'SetWaitableTimer', 'MsgWaitForMultipleObjects',
               'SystemParametersInfo', 'EnumDisplayMonitors', 'MonitorFromRect',
               'InitCommonControlsEx'],
}

# Map API name to category
api_to_category = {}
for cat, apis in api_categories.items():
    for api in apis:
        api_to_category[api.lower()] = cat

# Read the 186 runtime imports from the analysis
func_imports = iat_data.get('func_imports', {})
runtime_apis = []
for cat_name, items in func_imports.items():
    for item in items:
        name = item.get('name', '')
        offset = item.get('offset_in_rdata', 0)
        # Determine category
        best_cat = 'utility'
        for api_pattern, cat in api_to_category.items():
            if api_pattern in name.lower():
                best_cat = cat
                break
        runtime_apis.append({'name': name, 'offset': offset, 'category': best_cat})

# Build DLL name list
dll_names = iat_data.get('dll_names', [])
dll_name_map = {}
for d in dll_names:
    dll_name_map[d.get('name', '').lower()] = d.get('name', '')

# === Classify functions ===
print("[4/7] Classifying functions...")

# Build string address -> string content mapping
# (we'll use heuristics based on content patterns in pseudocode)

# Category keywords found in pseudocode content
category_keywords = {
    'network': [
        r'WinHttp', r'Internet', r'http://', r'https://', r'socket', r'WSA',
        r'gethostbyname', r'send\(', r'recv\(', r'connect\(',
        r'0x46e0e8', r'0x46e0ee',  # Thunks that we identified
        r'WinHttpOpen', r'WinHttpSend', r'WinHttpQuery',
        r'InternetRead', r'HttpOpen', r'HttpSend',
        r'qq\.com', r'qzone', r'GetTroopList', r'ModifyGroupInfo',
        r'ReqBatchProcess', r'OnlinePush',
    ],
    'crypto': [
        r'TEA', r'XXTEA', r'encrypt', r'decrypt', r'Crypt',
        r'A512548E76954B6E92C21055517615B0',  # Crypto hash-like string
        r'0x9e3779b9',  # TEA delta constant
        r'CRC32', r'MD5', r'SHA',
    ],
    'registry': [
        r'RegCreate', r'RegOpen', r'RegQuery', r'RegSet', r'RegClose',
        r'RegDelete', r'HKEY_', r'SOFTWARE\\\\', r'CurrentVersion',
    ],
    'ui': [
        r'CreateWindow', r'ShowWindow', r'MessageBox', r'SetWindowText',
        r'GetWindowText', r'SendMessage', r'DefWindowProc',
        r'SkinH', r'EditBox', r'PicBox', r'GroupBox', r'Label', r'Button',
        r'CheckBox', r'RadioBox', r'ComboBox', r'Timer', r'ListView',
        r'StatusBar', r'HtmlViewer', r'TransLabel',
        r'WM_', r'WNDCLASS', r'DialogBox',
    ],
    'file_io': [
        r'CreateFile', r'ReadFile', r'WriteFile', r'DeleteFile',
        r'FindFirst', r'FindNext', r'GetFileSize', r'SetFilePointer',
        r'LoadLibrary', r'GetProcAddress', r'GetModuleHandle',
        r'VirtualAlloc', r'VirtualFree', r'VirtualProtect',
        r'\.txt', r'\.ini', r'\.dat', r'\.log', r'\.cfg',
    ],
    'system': [
        r'GetVersion', r'GetSystemInfo', r'GetTickCount',
        r'Sleep\(', r'CreateProcess', r'ShellExecute',
        r'CoInitialize', r'CoUninitialize', r'ExitProcess',
        r'MultiByteToWideChar', r'WideCharToMultiByte',
    ],
}

# QQ API URL patterns
qq_url_patterns = [
    r'GetTroopList', r'ModifyGroupInfo', r'ReqBatchProcess',
    r'RespBatchProcess', r'GetLastPic', r'GetSimpleInfo',
    r'GroupMng', r'AddFriend', r'ReqCreateDiscuss',
    r'QQService', r'ReqQuit', r'ReqGetDiscuss',
    r'VideoCall', r'SendVideo', r'ReqHeader',
    r'Encounter', r'ReqLastGame', r'MCardSvc',
    r'ReqHead', r'ReqSummaryCard', r'OnlinePush',
]

def classify_function(content, addr, func_data):
    """Classify a function based on its pseudocode content."""
    scores = defaultdict(int)

    # Check for category keywords in content
    for cat, patterns in category_keywords.items():
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            scores[cat] += len(matches) * 3  # Strong signal

    # Check for string references (hex addresses pointing to .rdata strings)
    # Look for push instructions with addresses in .rdata range
    rdata_refs = re.findall(r'0x5[0-9a-f]{5}', content, re.IGNORECASE)
    for ref in rdata_refs:
        # These could be string references - check against known patterns
        val = int(ref, 16)
        # 0x50CXXX-0x50DXXX range has DLL names and API names
        if 0x50C000 <= val <= 0x510000:
            scores['system'] += 1
        elif 0x510000 <= val <= 0x512000:
            scores['ui'] += 1  # UI-related strings in this range
        elif 0x5DB000 <= val <= 0x5E0000:
            scores['ui'] += 2  # MFC class names

    # Check for QQ API URL references
    for pattern in qq_url_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            scores['network'] += 5

    # Check for virtual method table calls
    vtable_calls = re.findall(r'CALL\(dword ptr \[eax \+ 0x([0-9a-f]+)\]\)', content, re.IGNORECASE)
    if vtable_calls:
        scores['ui'] += len(vtable_calls)

    # Check for arithmetic/crypto patterns
    if '0x9e3779b9' in content.lower() or '0x61c88647' in content.lower():
        scores['crypto'] += 10  # TEA delta constant

    # Check for specific known patterns
    # WinHTTP functions detected by offset
    if 'offset_in_rdata' in content:
        pass

    # Check function info from analysis
    info = func_info.get(addr, {})
    calls = info.get('calls_count', 0)
    conds = info.get('conditionals', 0)
    loops = info.get('loops', 0)
    size = info.get('size', 0)

    # Large functions with many calls are likely business logic
    if calls > 50:
        scores['business_logic'] += 5
    if loops > 0 and conds > 5:
        scores['business_logic'] += 2

    # Very small functions are likely utility/thunks
    if size < 20:
        scores['utility'] += 2

    # Check for IAT thunk calls (0x46eXXX)
    iat_thunk_calls = re.findall(r'CALL\(0x46e[0-9a-f]{3}\)', content, re.IGNORECASE)
    if iat_thunk_calls:
        scores['runtime_dispatch'] += len(iat_thunk_calls) * 2

    # Return the category with the highest score
    if not scores:
        return 'utility'

    max_score = max(scores.values())
    if max_score == 0:
        return 'utility'

    # Get all categories with the max score
    top_cats = [cat for cat, score in scores.items() if score == max_score]
    return top_cats[0]

# Classify all functions
classifications = defaultdict(list)
for addr, pcode in pseudocodes.items():
    category = classify_function(pcode['content'], addr, pcode)
    classifications[category].append(addr)
    pcode['category'] = category

print(f"  Classification results:")
for cat, addrs in sorted(classifications.items(), key=lambda x: -len(x[1])):
    print(f"    {cat:20s}: {len(addrs):3d} functions")

# === Replace CALL addresses with descriptive names ===
print("[5/7] Annotating pseudocode with descriptive names...")

# Build address -> function name map for internal calls
addr_to_funcname = {}
for addr, pcode in pseudocodes.items():
    info = func_info.get(addr, {})
    dname = "func_%08X" % pcode["addr_int"]
    name = info.get('name', dname)
    addr_to_funcname[addr] = name

# Also map by integer address for flexible matching
addr_int_to_name = {}
for addr, pcode in pseudocodes.items():
    addr_int_to_name[pcode['addr_int']] = addr_to_funcname[addr]

# Thunk address -> descriptive name
thunk_names = {
    '0x46e0dc': 'elang_dispatch_1',
    '0x46e0e2': 'elang_dispatch_2',
    '0x46e0e8': 'elang_dispatch_3',
    '0x46e0ee': 'elang_dispatch_4',
    '0x46e0f4': 'elang_dispatch_5',
    '0x46e0fa': 'elang_dispatch_6',
    '0x46e100': 'elang_dispatch_7',
    '0x46e106': 'elang_dispatch_8',
    '0x46e10c': 'elang_dispatch_9',
    '0x46e112': 'elang_dispatch_10',
    '0x46e118': 'elang_dispatch_11',
    '0x46e11e': 'elang_dispatch_12',
}

# Normalize thunk names
thunk_names_norm = {}
for k, v in thunk_names.items():
    thunk_names_norm[hex(int(k, 16))] = v

def annotate_pseudocode(content):
    """Replace CALL addresses with descriptive names."""
    # Replace thunk calls
    for thunk_addr, name in thunk_names_norm.items():
        # Match CALL(0x46e0dc) etc
        pattern = r'CALL\(' + re.escape(thunk_addr) + r'\)'
        content = re.sub(pattern, f'CALL({name})', content, flags=re.IGNORECASE)

    # Replace internal function calls
    def replace_internal_call(m):
        addr_str = m.group(1)
        try:
            addr_int = int(addr_str, 16)
            if addr_int in addr_int_to_name:
                fname = addr_int_to_name[addr_int]
                return f'CALL({fname})'
        except:
            pass
        return m.group(0)

    # Only replace if address is in the decompiled function range
    content = re.sub(r'CALL\(0x([0-9a-fA-F]+)\)', replace_internal_call, content)

    return content

# Annotate all pseudocode
for addr, pcode in pseudocodes.items():
    pcode['annotated'] = annotate_pseudocode(pcode['content'])

# === Generate output files ===
print("[6/7] Generating project structure...")

# Create output directories
src_dir = os.path.join(OUTPUT_DIR, "src")
include_dir = os.path.join(OUTPUT_DIR, "include")
pseudocode_dir = os.path.join(OUTPUT_DIR, "pseudocode")
docs_dir = os.path.join(OUTPUT_DIR, "docs")

for d in [src_dir, include_dir, pseudocode_dir, docs_dir]:
    os.makedirs(d, exist_ok=True)

# Category -> module name mapping
category_module = {
    'network': 'network',
    'crypto': 'crypto',
    'registry': 'registry',
    'ui': 'ui',
    'file_io': 'file_io',
    'system': 'system',
    'business_logic': 'business',
    'runtime_dispatch': 'runtime',
    'utility': 'utility',
}

category_description = {
    'network': 'Network communication (WinHTTP/WinInet, QQ API)',
    'crypto': 'Cryptographic operations (TEA/XXTEA, encryption)',
    'registry': 'Windows registry operations',
    'ui': 'User interface (E-language controls, MFC)',
    'file_io': 'File I/O and memory management',
    'system': 'System utilities (process, COM, time)',
    'business_logic': 'Core business logic (QQ group operations)',
    'runtime_dispatch': 'E-language runtime dispatch functions',
    'utility': 'Utility and helper functions',
}

# Generate module .c and .h files
generated_files = []

for category, addrs in classifications.items():
    module_name = category_module.get(category, category)
    desc = category_description.get(category, category)

    # Sort by address
    addrs_sorted = sorted(addrs, key=lambda a: pseudocodes[a]['addr_int'])

    # Generate .c file
    c_content = f"""/*
 * {module_name}.c - {desc}
 * Auto-generated from decompiled pseudocode
 * Original binary: 群排名优化软件.exe (CNM packed, E-language)
 *
 * Classification: {category} ({len(addrs)} functions)
 */

#include "{module_name}.h"
#include "common.h"

"""
    for addr in addrs_sorted:
        pcode = pseudocodes[addr]
        info = func_info.get(addr, {})
        default_name = "func_%08X" % pcode["addr_int"]
        name = info.get('name', default_name)
        default_sig = "int %s(void)" % name
        sig = info.get('signature', default_sig)

        c_content += f"/* Function at 0x{pcode['addr_int']:08X} */\n"
        c_content += f"/* Size: {info.get('size', '?')} bytes, Calls: {info.get('calls_count', '?')}, "
        c_content += f"Conds: {info.get('conditionals', '?')}, Loops: {info.get('loops', '?')} */\n\n"

        # Use annotated pseudocode
        c_content += pcode['annotated']
        c_content += "\n\n"

    c_path = os.path.join(src_dir, f"{module_name}.c")
    with open(c_path, 'w', encoding='utf-8') as f:
        f.write(c_content)
    generated_files.append(c_path)
    print(f"  Written: {module_name}.c ({len(addrs)} functions)")

    # Generate .h file
    h_content = f"""/*
 * {module_name}.h - {desc}
 * Auto-generated header
 */

#ifndef {module_name.upper()}_H
#define {module_name.upper()}_H

#include "common.h"

"""
    for addr in addrs_sorted:
        pcode = pseudocodes[addr]
        info = func_info.get(addr, {})
        dname2 = "func_%08X" % pcode["addr_int"]
        name = info.get('name', dname2)
        dsig2 = "int %s(void)" % name
        sig = info.get('signature', dsig2)

        h_content += ("/* 0x%08X */" + chr(10)) % pcode['addr_int']
        h_content += ("extern %s;" + chr(10) + chr(10)) % sig

    h_content += ("#endif /* %s_H */" + chr(10)) % module_name.upper()

    h_path = os.path.join(include_dir, f"{module_name}.h")
    with open(h_path, 'w', encoding='utf-8') as f:
        f.write(h_content)
    generated_files.append(h_path)

# === Generate common.h ===
common_h = """/*
 * common.h - Shared definitions for 群排名优化软件 decompiled project
 *
 * Original binary: E-language (易语言) application
 * Packer: CNM private packer (suspended-process dump)
 * Architecture: x86 (32-bit)
 *
 * Key findings:
 *   - 14 dynamically loaded DLLs (Winhttp.dll, zlib1.dll, SkinH_EL.dll, etc.)
 *   - 186 runtime API imports resolved via LoadLibraryA + GetProcAddress
 *   - TEA/XXTEA encryption detected
 *   - QQ Group API endpoints found
 *   - E-language runtime dispatch through 0x46E0DC-0x46E11E thunks
 */

#ifndef COMMON_H
#define COMMON_H

#include <windows.h>
#include <winhttp.h>
#include <wininet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Type definitions for decompiled code */
typedef unsigned char  uint8;
typedef unsigned short uint16;
typedef unsigned int   uint32;
typedef signed char    int8;
typedef signed short   int16;
typedef signed int     int32;

/* E-language runtime dispatch thunks
 * These 12 thunks at 0x46E0DC-0x46E11E are jmp [IAT] instructions
 * that dispatch through the E-language virtual machine.
 * Each thunk targets a different runtime IAT slot.
 */
#define ELANG_DISPATCH_1  0x46E0DC  /* -> IAT[0x5100EC] */
#define ELANG_DISPATCH_2  0x46E0E2  /* -> IAT[0x5100F0] */
#define ELANG_DISPATCH_3  0x46E0E8  /* -> IAT[0x5100F4] */
#define ELANG_DISPATCH_4  0x46E0EE  /* -> IAT[0x5100DC] */
#define ELANG_DISPATCH_5  0x46E0F4  /* -> IAT[0x5100E4] */
#define ELANG_DISPATCH_6  0x46E0FA  /* -> IAT[0x5100D0] */
#define ELANG_DISPATCH_7  0x46E100  /* -> IAT[0x5100E0] */
#define ELANG_DISPATCH_8  0x46E106  /* -> IAT[0x5100C4] */
#define ELANG_DISPATCH_9  0x46E10C  /* -> IAT[0x5100C8] */
#define ELANG_DISPATCH_10 0x46E112  /* -> IAT[0x5100CC] */
#define ELANG_DISPATCH_11 0x46E118  /* -> IAT[0x5100D4] */
#define ELANG_DISPATCH_12 0x46E11E  /* -> IAT[0x5100D8] */

/* PE Import Address Table (22 static imports)
 * These are the original PE imports, resolved at load time.
 */
#define IAT_GetVersion           0x859000  /* KERNEL32.dll */
#define IAT_GetVersionExA        0x859004  /* KERNEL32.dll */
#define IAT_GetSystemInfo        0x859008  /* KERNEL32.dll */
#define IAT_SystemParametersInfo 0x859010  /* USER32.dll */
#define IAT_GetWindowExtEx       0x859018  /* GDI32.dll */
#define IAT_waveOutPrepareHeader 0x859020  /* WINMM.dll */
#define IAT_ClosePrinter         0x859028  /* WINSPOOL.DRV */
#define IAT_RegCreateKeyExA      0x859030  /* ADVAPI32.dll */
#define IAT_ShellExecuteA        0x859038  /* SHELL32.dll */
#define IAT_CoFreeUnusedLibraries 0x859040 /* ole32.dll */
#define IAT_OLEAUT32_ordinal186  0x859048  /* OLEAUT32.dll */
#define IAT_COMCTL32_ordinal17   0x859050  /* COMCTL32.dll */
#define IAT_oledlg_ordinal8      0x859058  /* oledlg.dll */
#define IAT_WS2_32_ordinal52     0x859060  /* WS2_32.dll (gethostbyname) */
#define IAT_ChooseColorA         0x859068  /* comdlg32.dll */
#define IAT_GetModuleFileNameW    0x859070  /* KERNEL32.dll */
#define IAT_GetModuleHandleA     0x859078  /* KERNEL32.dll */
#define IAT_LoadLibraryA         0x85907C  /* KERNEL32.dll */
#define IAT_LocalAlloc           0x859080  /* KERNEL32.dll */
#define IAT_LocalFree            0x859084  /* KERNEL32.dll */
#define IAT_GetModuleFileNameA   0x859088  /* KERNEL32.dll */
#define IAT_ExitProcess          0x85908C  /* KERNEL32.dll */

/* Runtime dynamically loaded DLLs (14 total) */
#define DLL_KERNEL32    "kernel32.dll"
#define DLL_WINHTTP     "Winhttp.dll"
#define DLL_OLE32       "ole32.dll"
#define DLL_WININET     "wininet.dll"
#define DLL_SKINH       "SkinH_EL.dll"
#define DLL_ZLIB        "zlib1.dll"
#define DLL_USER32      "user32.dll"
#define DLL_WS2_32      "ws2_32.dll"
#define DLL_SHLWAPI     "shlwapi.dll"
#define DLL_COMCTL32    "COMCTL32.dll"
#define DLL_GDI32       "GDI32.dll"
#define DLL_MSIMG32     "MSIMG32.dll"
#define DLL_MSVCRT      "MSVCRT.dll"
#define DLL_MSVFW32     "MSVFW32.dll"

/* Pseudocode CALL macro */
#define CALL(addr) ((void(*)(void))(addr))()

/* Virtual method table call macro */
#define VCALL(obj, offset) ((void(*)(void*))(((void**)(obj))[(offset)/4]))(obj)

#endif /* COMMON_H */
"""

common_h_path = os.path.join(include_dir, "common.h")
with open(common_h_path, 'w', encoding='utf-8') as f:
    f.write(common_h)
generated_files.append(common_h_path)

# === Generate QQ API header ===
qq_api_h = """/*
 * qq_api.h - QQ Group API endpoint definitions
 * Extracted from string analysis of the decompiled binary
 */

#ifndef QQ_API_H
#define QQ_API_H

/* QQ Group Management API Endpoints */
"""

for url in urls:
    # Extract endpoint name from URL
    if '/' in url:
        endpoint = url.split('/')[-1].split('?')[0]
    else:
        endpoint = url
    safe_name = re.sub(r'[^a-zA-Z0-9_]', '_', endpoint).upper()
    if not safe_name:
        safe_name = f"QQ_API_{urls.index(url)}"
    qq_api_h += f'#define QQ_API_{safe_name} "{url}"\n'

qq_api_h += "\n#endif /* QQ_API_H */\n"

qq_api_h_path = os.path.join(include_dir, "qq_api.h")
with open(qq_api_h_path, 'w', encoding='utf-8') as f:
    f.write(qq_api_h)
generated_files.append(qq_api_h_path)

# === Generate strings header ===
strings_h = """/*
 * strings.h - String constants extracted from the binary
 * GBK strings indicate Chinese locale content
 */

#ifndef STRINGS_H
#define STRINGS_H

/* Key GBK strings (Chinese) */
"""

# Add GBK strings that look meaningful
meaningful_gbk = [s for s in gbk_strings if len(s) >= 2 and not s.startswith('\\x')]
for i, s in enumerate(meaningful_gbk[:50]):
    safe_id = f"STR_GBK_{i:03d}"
    strings_h += f'/* {safe_id} */ /* "{s}" */\n'

strings_h += "\n/* Key ASCII strings */\n"
meaningful_ascii = [s for s in ascii_strings if len(s) >= 6 and any(c.isalpha() for c in s)]
for i, s in enumerate(meaningful_ascii[:50]):
    safe_id = f"STR_ASCII_{i:03d}"
    # Escape special chars for C comment
    safe_s = s.replace('*/', '* /').replace('/*', '/ *')
    strings_h += f'/* {safe_id} */ /* "{safe_s}" */\n'

strings_h += "\n#endif /* STRINGS_H */\n"

strings_h_path = os.path.join(include_dir, "strings.h")
with open(strings_h_path, 'w', encoding='utf-8') as f:
    f.write(strings_h)
generated_files.append(strings_h_path)

# === Generate main.c (WinMain skeleton) ===
main_c = """/*
 * main.c - WinMain entry point
 * Reconstructed from decompiled E-language application
 *
 * Original: 群排名优化软件.exe
 * This is a reconstruction skeleton, not a functional replacement.
 */

#include "common.h"
#include "network.h"
#include "ui.h"
#include "registry.h"
#include "system.h"

/* Forward declarations */
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow);

/* E-language runtime object pointer at 0x61F6E8 */
void* g_elang_runtime = NULL;

/* E-language runtime data at 0x61FAF4 */
void* g_elang_data = NULL;

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow)
{
    /* The original program's OEP is at 0x004010A1
     * This is a very large function (21972 bytes, 484 calls)
     * that serves as the E-language program entry point.
     * It initializes the E-language runtime and dispatches
     * to the user-defined _启动子程序 (startup subroutine).
     *
     * Key operations:
     * 1. Initialize E-language runtime (COM, memory, strings)
     * 2. Load SkinH_EL.dll for UI theming
     * 3. Set up the main window and controls
     * 4. Enter message loop
     * 5. Handle QQ group operations via WinHTTP
     */

    /* E-language runtime initialization */
    CoInitialize(NULL);

    /* Load dynamic libraries */
    HMODULE hWinHttp = LoadLibraryA(DLL_WINHTTP);
    HMODULE hWinInet = LoadLibraryA(DLL_WININET);
    HMODULE hSkinH = LoadLibraryA(DLL_SKINH);
    HMODULE hZlib = LoadLibraryA(DLL_ZLIB);
    HMODULE hWs2 = LoadLibraryA(DLL_WS2_32);
    HMODULE hShlwapi = LoadLibraryA(DLL_SHLWAPI);

    /* The actual entry point logic is in func_004010A1
     * which was too large to reconstruct accurately here.
     * See: pseudocode/func_004010A1.c for the raw decompiled output.
     */

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    CoUninitialize();
    return (int)msg.wParam;
}
"""

main_c_path = os.path.join(src_dir, "main.c")
with open(main_c_path, 'w', encoding='utf-8') as f:
    f.write(main_c)
generated_files.append(main_c_path)

# === Generate CMakeLists.txt ===
module_sources = " ".join([f"src/{category_module.get(cat, cat)}.c" for cat in classifications.keys()])
cmake = f"""cmake_minimum_required(VERSION 3.10)
project(QQGroupRankOptimizer C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Source files
set(SOURCES
    src/main.c
    {chr(10).join(f'    src/{category_module.get(cat, cat)}.c' for cat in sorted(classifications.keys()))}
)

# Include directories
include_directories(include)

# Executable
add_executable(${{PROJECT_NAME}} ${{SOURCES}})

# Link libraries (Windows)
if(WIN32)
    target_link_libraries(${{PROJECT_NAME}}
        winhttp
        wininet
        ws2_32
        advapi32
        shell32
        ole32
        oleaut32
        comctl32
        comdlg32
        gdi32
        msimg32
        msvcrt
    )
endif()
"""

cmake_path = os.path.join(OUTPUT_DIR, "CMakeLists.txt")
with open(cmake_path, 'w', encoding='utf-8') as f:
    f.write(cmake)
generated_files.append(cmake_path)

# === Generate Makefile ===
makefile = f"""# Makefile for QQGroupRankOptimizer
# Reconstructed from decompiled binary

CC = gcc
CFLAGS = -m32 -Wall -O2 -DWIN32_LEAN_AND_MEAN
LDFLAGS = -m32
LIBS = -lwinhttp -lwininet -lws2_32 -ladvapi32 -lshell32 -lole32 -loleaut32 -lcomctl32 -lcomdlg32 -lgdi32

SRCS = src/main.c \\
{chr(10).join(f'       src/{category_module.get(cat, cat)}.c \\' for cat in sorted(classifications.keys())[:-1])}
{f'       src/{category_module.get(list(classifications.keys())[-1], list(classifications.keys())[-1])}.c' if classifications else ''}

OBJS = $(SRCS:.c=.o)
TARGET = QQGroupRankOptimizer.exe

all: $(TARGET)

$(TARGET): $(OBJS)
\t$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

%.o: %.c
\t$(CC) $(CFLAGS) -Iinclude -c -o $@ $<

clean:
\tdel /Q $(OBJS) $(TARGET) 2>nul

.PHONY: all clean
"""

makefile_path = os.path.join(OUTPUT_DIR, "Makefile")
with open(makefile_path, 'w', encoding='utf-8') as f:
    f.write(makefile)
generated_files.append(makefile_path)

# === Copy annotated pseudocode to output ===
print("[7/7] Copying annotated pseudocode...")
for addr, pcode in pseudocodes.items():
    src_fname = pcode['filename']
    dst_path = os.path.join(pseudocode_dir, src_fname)
    with open(dst_path, 'w', encoding='utf-8') as f:
        f.write(pcode['annotated'])

# === Generate overview document ===
overview = f"""# 群排名优化软件 - 逆向工程重构项目 (v2)

## 项目概述

本目录包含从 **群排名优化软件.exe** 逆向工程重构的源码项目。

### 原始程序信息
- **文件名**: 群排名优化软件.exe
- **类型**: 易语言 (E-language) 应用程序
- **壳**: CNM 私有壳（已使用挂起转储法脱壳）
- **架构**: x86 (32-bit)
- **原始入口点 (OEP)**: 0x004010A1

### 分析结果
- **总函数数**: {len(function_list)}
- **已反编译**: {len(pseudocodes)}
- **GBK 中文字符串**: {strings_data.get('gbk_quality', 0)}
- **ASCII 字符串**: {strings_data.get('ascii', 0)}
- **QQ API URL**: {len(urls)}
- **动态加载 DLL**: 14 个
- **运行时 API 导入**: 186 个
- **检测到的算法**: TEA/XXTEA 加密

### 项目结构

```
reconstructed_unpacked_v2/
├── src/
│   ├── main.c          # WinMain 入口点
"""

for cat in sorted(classifications.keys()):
    mod = category_module.get(cat, cat)
    count = len(classifications[cat])
    overview += f"│   ├── {mod}.c".ljust(28) + f"# {category_description.get(cat, cat)} ({count} 函数)\n"

overview += f"""├── include/
│   ├── common.h        # 共享定义和 IAT 映射
│   ├── qq_api.h        # QQ API 端点定义
│   ├── strings.h       # 提取的字符串常量
"""

for cat in sorted(classifications.keys()):
    mod = category_module.get(cat, cat)
    overview += f"│   ├── {mod}.h".ljust(28) + f"# {category_description.get(cat, cat)} 头文件\n"

overview += f"""├── pseudocode/         # 标注后的原始伪代码
├── CMakeLists.txt      # CMake 构建配置
├── Makefile            # GNU Make 构建配置
└── OVERVIEW.md         # 本文件
```

### 函数分类统计

| 类别 | 模块 | 函数数 | 描述 |
|---|---|---|---|
"""

for cat in sorted(classifications.keys(), key=lambda c: -len(classifications[c])):
    mod = category_module.get(cat, cat)
    count = len(classifications[cat])
    desc = category_description.get(cat, cat)
    overview += f"| {cat} | {mod} | {count} | {desc} |\n"

overview += f"""
### 运行时 IAT Thunks (0x46E0DC-0x46E11E)

程序使用 12 个易语言运行时分发 thunks，每个通过 `jmp [IAT_entry]` 指令
分发到易语言虚拟机的不同功能入口：

| Thunk 地址 | IAT 目标 | 分发名称 |
|---|---|---|
| 0x46E0DC | [0x5100EC] | elang_dispatch_1 |
| 0x46E0E2 | [0x5100F0] | elang_dispatch_2 |
| 0x46E0E8 | [0x5100F4] | elang_dispatch_3 |
| 0x46E0EE | [0x5100DC] | elang_dispatch_4 |
| 0x46E0F4 | [0x5100E4] | elang_dispatch_5 |
| 0x46E0FA | [0x5100D0] | elang_dispatch_6 |
| 0x46E100 | [0x5100E0] | elang_dispatch_7 |
| 0x46E106 | [0x5100C4] | elang_dispatch_8 |
| 0x46E10C | [0x5100C8] | elang_dispatch_9 |
| 0x46E112 | [0x5100CC] | elang_dispatch_10 |
| 0x46E118 | [0x5100D4] | elang_dispatch_11 |
| 0x46E11E | [0x5100D8] | elang_dispatch_12 |

### 静态 IAT 导入 (22 个)

| IAT 地址 | DLL | 函数 |
|---|---|---|
| 0x859000 | KERNEL32.dll | GetVersion |
| 0x859004 | KERNEL32.dll | GetVersionExA |
| 0x859008 | KERNEL32.dll | GetSystemInfo |
| 0x859010 | USER32.dll | SystemParametersInfoA |
| 0x859018 | GDI32.dll | GetWindowExtEx |
| 0x859020 | WINMM.dll | waveOutPrepareHeader |
| 0x859028 | WINSPOOL.DRV | ClosePrinter |
| 0x859030 | ADVAPI32.dll | RegCreateKeyExA |
| 0x859038 | SHELL32.dll | ShellExecuteA |
| 0x859040 | ole32.dll | CoFreeUnusedLibraries |
| 0x859048 | OLEAUT32.dll | ordinal#186 |
| 0x859050 | COMCTL32.dll | ordinal#17 |
| 0x859058 | oledlg.dll | ordinal#8 |
| 0x859060 | WS2_32.dll | ordinal#52 (gethostbyname) |
| 0x859068 | comdlg32.dll | ChooseColorA |
| 0x859070 | KERNEL32.dll | GetModuleFileNameW |
| 0x859078 | KERNEL32.dll | GetModuleHandleA |
| 0x85907C | KERNEL32.dll | LoadLibraryA |
| 0x859080 | KERNEL32.dll | LocalAlloc |
| 0x859084 | KERNEL32.dll | LocalFree |
| 0x859088 | KERNEL32.dll | GetModuleFileNameA |
| 0x85908C | KERNEL32.dll | ExitProcess |

### QQ API 端点

"""

for url in urls:
    overview += f"- `{url}`\n"

overview += """
### 关键发现

1. **易语言运行时**: 程序使用易语言编写，通过 `0x61F6E8` 处的运行时对象分发虚方法调用
2. **CNM 私有壳**: 原始 PE 使用 CNM 加壳，`.text/.rdata/.data` 段 RawSize=0（内存展开型）
3. **动态导入**: 186 个 API 通过 LoadLibraryA + GetProcAddress 动态加载
4. **TEA 加密**: 检测到 TEA/XXTEA 加密算法，用于 QQ 协议数据加密
5. **SkinH_EL.dll**: 易语言换肤库，用于界面美化
6. **WinHTTP**: 使用 WinHTTP 进行 QQ API 网络通信
7. **MFC 运行时**: 程序包含大量 MFC 类名引用（CDialog, CWnd, CString 等）

### 免责声明

本逆向工程产物仅用于 CTF 竞赛和学习目的。伪代码为自动生成，不保证完全正确。
"""

overview_path = os.path.join(OUTPUT_DIR, "OVERVIEW.md")
with open(overview_path, 'w', encoding='utf-8') as f:
    f.write(overview)
generated_files.append(overview_path)

# === Summary ===
print("\n" + "="*60)
print("INTEGRATION COMPLETE (v2)")
print("="*60)
print(f"\nOutput directory: {OUTPUT_DIR}")
print(f"Generated {len(generated_files)} files:")
for f in generated_files:
    rel = os.path.relpath(f, OUTPUT_DIR)
    size = os.path.getsize(f)
    print(f"  {rel} ({size:,} bytes)")

print(f"\nClassification summary:")
for cat, addrs in sorted(classifications.items(), key=lambda x: -len(x[1])):
    mod = category_module.get(cat, cat)
    print(f"  {mod:20s}: {len(addrs):3d} functions")

print(f"\nTotal annotated pseudocode: {len(pseudocodes)} files")
