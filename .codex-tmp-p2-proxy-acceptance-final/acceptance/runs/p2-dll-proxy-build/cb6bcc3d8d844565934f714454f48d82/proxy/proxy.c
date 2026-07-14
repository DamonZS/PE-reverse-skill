#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#if defined(_M_IX86) || defined(__i386__)
#define DLL_PROXY_ARCH_X86 1
#elif defined(_M_X64) || defined(__x86_64__)
#define DLL_PROXY_ARCH_X64 1
#elif defined(_M_ARM64) || defined(__aarch64__)
#define DLL_PROXY_ARCH_ARM64 1
#elif defined(_M_ARM) || defined(__arm__)
#define DLL_PROXY_ARCH_ARM 1
#else
#error Unsupported compiler target architecture
#endif

#if !defined(DLL_PROXY_ARCH_X64)
#error Compiler target does not match the source DLL architecture
#endif

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)instance;
    (void)reason;
    (void)reserved;
    return TRUE;
}
