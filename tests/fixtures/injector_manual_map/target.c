#include <stdio.h>
#include <windows.h>

#define DLL_PREFERRED_IMAGE_BASE ((LPVOID)(ULONG_PTR)0x0000000180000000ULL)
#define RELOCATION_GUARD_SIZE 0x01000000U

int main(void) {
    LPVOID relocation_guard;

    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    relocation_guard = VirtualAlloc(
        DLL_PREFERRED_IMAGE_BASE,
        RELOCATION_GUARD_SIZE,
        MEM_RESERVE,
        PAGE_NOACCESS
    );
    if (relocation_guard != DLL_PREFERRED_IMAGE_BASE) {
        fprintf(stderr, "unable to reserve the DLL preferred image base: %lu\n", GetLastError());
        return 2;
    }

    printf(
        "{\"ready\":true,\"pid\":%lu,\"relocation_guard\":%llu}\n",
        (unsigned long)GetCurrentProcessId(),
        (unsigned long long)(ULONG_PTR)relocation_guard
    );
    fflush(stdout);

    (void)getchar();
    (void)VirtualFree(relocation_guard, 0, MEM_RELEASE);
    return 0;
}
