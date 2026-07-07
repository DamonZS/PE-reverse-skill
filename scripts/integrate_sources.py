"""⚠️ DEPRECATED — v1 分类逻辑完全失败（200函数全归utility）。
原因是 CALL 地址指向运行时 IAT thunk，不在 PE 静态导入表中。
新项目请使用 integrate_v2.py（基于字符串+调用模式的分类策略）。

Integrate all source code into a unified project."""
import pefile
import json
import os
import re
import glob

BASE = "F:/baiduyun/QQ群排名技术/reconstructed_unpacked"
PE_PATH = "F:/baiduyun/QQ群排名技术/群排名优化软件_unpacked.exe"
PSEUDO_DIR = "F:/baiduyun/QQ群排名技术/deep_analysis/pseudocode"
DEEP_JSON = "F:/baiduyun/QQ群排名技术/deep_analysis/deep_analysis.json"

# 1. Parse PE IAT
pe = pefile.PE(PE_PATH)
iat_map = {}
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    dll_name = entry.dll.decode('utf-8', errors='ignore')
    for imp in entry.imports:
        if imp.address:
            api_name = imp.name.decode('utf-8', errors='ignore') if imp.name else f"ordinal_{imp.ordinal}"
            iat_map[hex(imp.address)] = f"{dll_name}!{api_name}"

print(f"PE IAT: {len(iat_map)} entries")
for addr, name in sorted(iat_map.items()):
    print(f"  {addr}: {name}")

# 2. Build function address map from deep_analysis.json
with open(DEEP_JSON, 'r', encoding='utf-8') as f:
    deep = json.load(f)

func_list = deep.get('function_list', [])
func_map = {f['addr']: f for f in func_list}

# 3. Read all pseudocode files and resolve CALL addresses
def resolve_call(addr_str):
    """Resolve a CALL address to a readable name."""
    addr = addr_str.lower()
    # Check IAT first
    if addr in iat_map:
        return iat_map[addr]
    # Check function map
    if addr in func_map:
        return f"sub_{addr}"
    return None

# 4. Read and annotate all pseudocode files
all_pseudocode = {}
for pc_file in sorted(glob.glob(os.path.join(PSEUDO_DIR, "*.c"))):
    fname = os.path.basename(pc_file)
    addr_match = re.search(r'func_([0-9A-Fa-f]+)', fname)
    if not addr_match:
        continue
    addr = "0x" + addr_match.group(1).lower()

    with open(pc_file, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    # Resolve CALL addresses in the content
    def replace_call(m):
        target = m.group(1).lower()
        resolved = resolve_call(target)
        if resolved:
            return f"CALL({target}/* {resolved} */)"
        return m.group(0)

    annotated = re.sub(r'CALL\((0x[0-9A-Fa-f]+)\)', replace_call, content)

    # Also resolve PUSH of known addresses
    all_pseudocode[addr] = {
        'file': fname,
        'content': annotated,
        'raw_content': content,
        'func_info': func_map.get(addr, {})
    }

# 5. Categorize functions by their CALL targets and content patterns
categories = {
    'entry_crt': [],       # Entry point / CRT startup
    'elang_runtime': [],   # E-language runtime dispatcher, memory, string
    'qq_api': [],          # QQ group API calls
    'network_http': [],    # WinHTTP/WinInet HTTP calls
    'ui_window': [],       # Window/dialog/GDI/SkinH
    'crypto': [],          # TEA/XXTEA encryption
    'registry_config': [],  # Registry/config operations
    'file_io': [],         # File I/O
    'compression': [],     # zlib
    'utility': [],         # Small utility functions
    'unknown': [],         # Unclassified
}

for addr, pc in all_pseudocode.items():
    content_lower = pc['content'].lower()
    func_info = pc.get('func_info', {})
    size = func_info.get('size', 0)
    calls = func_info.get('calls_count', 0)
    conds = func_info.get('conditionals', 0)

    cat = 'unknown'

    # Entry point
    if addr == '0x4010a1':
        cat = 'entry_crt'
    # Network / HTTP
    elif any(x in content_lower for x in ['winhttp', 'wininet', 'httpopen', 'httpsend', 'internetopen', 'internetread', 'httpread']):
        cat = 'network_http'
    # QQ API
    elif any(x in content_lower for x in ['qinfo.clt', 'ptlogin2', 'qun_info', 'qun.qzone', 'anonymoustalk', 'apis.map.qq']):
        cat = 'qq_api'
    # Crypto
    elif any(x in content_lower for x in ['0x9e3779b9', 'delta', 'tea']):
        cat = 'crypto'
    # Registry
    elif any(x in content_lower for x in ['regopenkey', 'regsetvalue', 'regcreatekey', 'regclosekey', 'regqueryvalue']):
        cat = 'registry_config'
    # UI
    elif any(x in content_lower for x in ['createwindow', 'dialogbox', 'messagebox', 'showwindow', 'skinh', 'setwindowtext', 'getdc', 'releasedc']):
        cat = 'ui_window'
    # File I/O
    elif any(x in content_lower for x in ['createfile', 'readfile', 'writefile', 'getfilesize']):
        cat = 'file_io'
    # Compression
    elif any(x in content_lower for x in ['zlib', 'compress', 'uncompress', 'deflate', 'inflate']):
        cat = 'compression'
    # E-language runtime (large functions with lots of CALL(0x46eXXX))
    elif calls > 50 or (size > 5000 and calls > 20):
        cat = 'elang_runtime'
    # Utility
    elif size < 200 and calls < 5:
        cat = 'utility'

    categories[cat].append(addr)

# 6. Print categorization
print("\n=== Function Categorization ===")
for cat, addrs in categories.items():
    if not addrs:
        continue
    print(f"\n--- {cat} ({len(addrs)}) ---")
    for addr in sorted(addrs):
        pc = all_pseudocode[addr]
        fi = pc.get('func_info', {})
        print(f"  {addr}  size={fi.get('size',0)}  calls={fi.get('calls_count',0)}  conds={fi.get('conditionals',0)}")

# 7. Write integrated source files
src_dir = os.path.join(BASE, "src")
os.makedirs(src_dir, exist_ok=True)

# Write each category as a separate .c file
cat_file_map = {
    'entry_crt': 'entry.c',
    'elang_runtime': 'elang_runtime.c',
    'qq_api': 'qq_api.c',
    'network_http': 'network_http.c',
    'ui_window': 'ui_window.c',
    'crypto': 'crypto.c',
    'registry_config': 'registry_config.c',
    'file_io': 'file_io.c',
    'compression': 'compression.c',
    'utility': 'utility.c',
    'unknown': 'unknown_funcs.c',
}

header_includes = {
    'entry_crt': ['#include <windows.h>', '#include "common.h"'],
    'elang_runtime': ['#include <windows.h>', '#include "common.h"'],
    'qq_api': ['#include <windows.h>', '#include <winhttp.h>', '#include "common.h"', '#include "qq_api.h"'],
    'network_http': ['#include <windows.h>', '#include <winhttp.h>', '#include <wininet.h>', '#include "common.h"', '#include "network.h"'],
    'ui_window': ['#include <windows.h>', '#include <commctrl.h>', '#include "common.h"', '#include "ui.h"'],
    'crypto': ['#include <windows.h>', '#include "common.h"', '#include "crypto.h"'],
    'registry_config': ['#include <windows.h>', '#include "common.h"', '#include "registry.h"'],
    'file_io': ['#include <windows.h>', '#include "common.h"', '#include "file_io.h"'],
    'compression': ['#include <windows.h>', '#include <zlib.h>', '#include "common.h"'],
    'utility': ['#include <windows.h>', '#include "common.h"'],
    'unknown': ['#include <windows.h>', '#include "common.h"'],
}

for cat, addrs in categories.items():
    if not addrs:
        continue

    fname = cat_file_map.get(cat, f'{cat}.c')
    fpath = os.path.join(src_dir, fname)

    lines = []
    lines.append(f"/*")
    lines.append(f" * {fname} - Auto-integrated from pseudocode")
    lines.append(f" * Category: {cat}")
    lines.append(f" * Functions: {len(addrs)}")
    lines.append(f" * Generated by deep_decompile.py + integrate_sources.py")
    lines.append(f" */")
    lines.append("")
    includes = header_includes.get(cat, ['#include <windows.h>', '#include "common.h"'])
    lines.extend(includes)
    lines.append("")
    lines.append(f"/* {cat}: {len(addrs)} functions */")
    lines.append("")

    for addr in sorted(addrs):
        pc = all_pseudocode[addr]
        content = pc['content']
        fi = pc.get('func_info', {})

        # Add separator
        lines.append(f"/* {'='*70} */")
        lines.append(f"/* {addr}  size={fi.get('size',0)}  calls={fi.get('calls_count',0)}  conds={fi.get('conditionals',0)}  */")
        lines.append(f"/* {'='*70} */")
        lines.append(content)
        lines.append("")

    with open(fpath, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))
    print(f"Wrote {fpath} ({len(addrs)} functions)")

# 8. Write common header
common_h = os.path.join(BASE, "include", "common.h")
with open(common_h, 'w', encoding='utf-8') as f:
    f.write("""/* common.h - Shared definitions for reconstructed project */
#ifndef COMMON_H
#define COMMON_H

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* E-language compatibility types */
typedef int ELANG_INT;
typedef const char* ELANG_STR;
typedef void* ELANG_PTR;

/* IAT thunk addresses (runtime-resolved imports) */
/* These addresses are in the CNM0/CNM1 sections and point to dynamically loaded APIs */
#define IAT_THUNK_BASE 0x46e000

/* Memory allocation helpers (E-language runtime) */
#define EL_ALLOC(sz)   LocalAlloc(LPTR, (sz))
#define EL_FREE(p)     LocalFree((HLOCAL)(p))

/* E-language string operations */
const char* el_str_new(int size);
void el_str_free(const char* s);
const char* el_str_cat(const char* a, const char* b);
int el_str_len(const char* s);
int el_str_cmp(const char* a, const char* b);

/* E-language array operations */
void* el_array_new(int count, int elem_size);
void el_array_free(void* arr);
int el_array_count(void* arr);

/* QQ API function declarations */
int qq_group_get_info(const char* group_id);
int qq_group_set_info(const char* group_id, const char* info);
int qq_group_set_more_cache(const char* group_id);
int qq_group_set_more_info(const char* group_id);
int qq_group_set_setting(const char* group_id);
int qq_anonymous_switch(const char* group_id, int enable);
int qq_group_list(const char* uin);
int qq_login(int appid, const char* redirect_url);

/* Network (WinHTTP) */
int http_get(const char* url, char** response);
int http_post(const char* url, const char* data, char** response);

/* Crypto */
void tea_encrypt(unsigned int* v, const unsigned int* k);
void tea_decrypt(unsigned int* v, const unsigned int* k);
void xxtea_encrypt(unsigned int* v, int n, const unsigned int* k);
void xxtea_decrypt(unsigned int* v, int n, const unsigned int* k);

/* Registry */
BOOL config_read(const char* key_name, char* buffer, int buf_size);
BOOL config_write(const char* key_name, const char* value, int value_len);

/* UI */
HWND create_main_window(HINSTANCE hInst);
int message_loop(void);

/* File I/O */
int file_read_all(const char* path, char** data, int* size);
int file_write_all(const char* path, const char* data, int size);

/* Function address → name mapping (from decompilation) */
/* 0x4010A1 = WinMain / entry point */
/* 0x406892 = main form initialization */
/* 0x40878F = event dispatcher (1082 conditionals - largest function) */
/* 0x414397 = HTTP request handler */
/* 0x416531 = string parser */
/* 0x416924 = URL builder */
/* 0x413A34 = data formatter */

#endif /* COMMON_H */
""")
print(f"Wrote {common_h}")

# 9. Write module headers
module_headers = {
    'qq_api.h': """/* qq_api.h - QQ Group API declarations */
#ifndef QQ_API_H
#define QQ_API_H
#include "common.h"

/* QQ API endpoints */
#define QQ_API_BASE "http://qinfo.clt.qq.com/cgi-bin/qun_info/"
#define QQ_LOGIN_URL_APP1 "http://ui.ptlogin2.qq.com/cgi-bin/login?appid=549000912"
#define QQ_LOGIN_URL_APP2 "http://ui.ptlogin2.qq.com/cgi-bin/login?appid=636014201"
#define QQ_ANONYMOUS_URL "http://qqweb.qq.com/c/anonymoustalk/set_anony_switch"
#define QQ_GROUP_LIST_URL "http://qun.qzone.qq.com/cgi-bin/get_group_list"
#define QQ_MAP_API_URL "http://apis.map.qq.com/jsapi?qt=poi&wd="

#endif /* QQ_API_H */
""",
    'network.h': """/* network.h - Network/HTTP declarations */
#ifndef NETWORK_H
#define NETWORK_H
#include "common.h"

typedef struct {
    HINTERNET hSession;
    HINTERNET hConnect;
    HINTERNET hRequest;
    BOOL connected;
} HttpSession;

int http_init(HttpSession* session, const char* agent);
int http_get_url(HttpSession* session, const char* url, char** response, int* resp_len);
int http_post_url(HttpSession* session, const char* url, const char* data, int data_len, char** response, int* resp_len);
void http_close(HttpSession* session);

#endif /* NETWORK_H */
""",
    'crypto.h': """/* crypto.h - Encryption declarations */
#ifndef CRYPTO_H
#define CRYPTO_H
#include "common.h"

/* TEA constants */
#define TEA_DELTA 0x9E3779B9

void tea_encrypt_block(unsigned int* v, const unsigned int* k);
void tea_decrypt_block(unsigned int* v, const unsigned int* k);
void xxtea_encrypt(unsigned int* v, int n, const unsigned int* k);
void xxtea_decrypt(unsigned int* v, int n, const unsigned int* k);

#endif /* CRYPTO_H */
""",
    'registry.h': """/* registry.h - Registry/config declarations */
#ifndef REGISTRY_H
#define REGISTRY_H
#include "common.h"

#define REG_BASE HKEY_CURRENT_USER
#define REG_PATH "SOFTWARE\\\\QQRankOptimize"

BOOL reg_read_string(const char* value_name, char* buffer, int buf_size);
BOOL reg_write_string(const char* value_name, const char* value);
BOOL reg_read_dword(const char* value_name, DWORD* value);
BOOL reg_write_dword(const char* value_name, DWORD value);

#endif /* REGISTRY_H */
""",
    'ui.h': """/* ui.h - UI declarations */
#ifndef UI_H
#define UI_H
#include "common.h"

/* SkinH_EL.dll - E-language skin library */
int SkinH_Attach();
int SkinH_Detach();

/* Window message handler */
LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

/* Control IDs */
#define IDC_BTN_LOGIN      1001
#define IDC_BTN_QUERY      1002
#define IDC_BTN_SETINFO    1003
#define IDC_EDIT_GROUPID   2001
#define IDC_EDIT_RESPONSE  2002

#endif /* UI_H */
""",
    'file_io.h': """/* file_io.h - File I/O declarations */
#ifndef FILE_IO_H
#define FILE_IO_H
#include "common.h"

int file_read_all(const char* path, char** data, int* size);
int file_write_all(const char* path, const char* data, int size);

#endif /* FILE_IO_H */
""",
}

for hname, content in module_headers.items():
    hpath = os.path.join(BASE, "include", hname)
    with open(hpath, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"Wrote {hpath}")

# 10. Update CMakeLists.txt
cmake = os.path.join(BASE, "CMakeLists.txt")
with open(cmake, 'w', encoding='utf-8') as f:
    f.write("""cmake_minimum_required(VERSION 3.15)
project(QQRankOptimize C)
set(CMAKE_C_STANDARD 11)

file(GLOB SOURCES "src/*.c")
add_executable(${PROJECT_NAME} WIN32 ${SOURCES})
target_include_directories(${PROJECT_NAME} PRIVATE include src)
target_link_libraries(${PROJECT_NAME} PRIVATE
    kernel32 user32 advapi32 ws2_32 shell32 winmm gdi32
    winhttp wininet shlwapi comctl32 msimg32 vfw32
)

if(MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE /W3 /utf-8)
elseif(MINGW)
    target_compile_options(${PROJECT_NAME} PRIVATE -Wall -m32)
    set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS "-m32 -mwindows")
endif()
""")
print(f"Wrote {cmake}")

# 11. Update Makefile
makefile = os.path.join(BASE, "Makefile")
with open(makefile, 'w', encoding='utf-8') as f:
    f.write("""CC = gcc
CFLAGS = -Wall -O2 -m32 -DUNICODE -D_UNICODE
LDFLAGS = -m32 -mwindows
LIBS = -lkernel32 -luser32 -ladvapi32 -lws2_32 -lshell32 -lwinmm -lgdi32 -lwinhttp -lwininet -lshlwapi -lcomctl32 -lmsimg32 -lvfw32

SRC_DIR = src
INC_DIR = include
BUILD_DIR = build

SOURCES = $(wildcard $(SRC_DIR)/*.c)
OBJECTS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SOURCES))
TARGET = QQRankOptimize.exe

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
""")
print(f"Wrote {makefile}")

# 12. Write integration summary
summary = {
    'total_functions': len(all_pseudocode),
    'categories': {cat: len(addrs) for cat, addrs in categories.items() if addrs},
    'iat_entries': len(iat_map),
    'iat_map': iat_map,
    'source_files': list(cat_file_map.values()),
    'header_files': ['common.h', 'qq_api.h', 'network.h', 'crypto.h', 'registry.h', 'ui.h', 'file_io.h', 'imports.h', 'protocol.h', 'strings.h', 'windows_compat.h']
}

with open(os.path.join(BASE, 'integration_summary.json'), 'w', encoding='utf-8') as f:
    json.dump(summary, f, indent=2, ensure_ascii=False)
print(f"\nWrote integration_summary.json")

print("\n=== Integration Complete ===")
print(f"Total pseudocode functions: {len(all_pseudocode)}")
print(f"Categories: {sum(len(v) for v in categories.values())} functions in {len([k for k,v in categories.items() if v])} categories")
print(f"IAT entries: {len(iat_map)}")
print(f"Source files: {len(cat_file_map)}")
print(f"Header files: {len(summary['header_files'])}")
