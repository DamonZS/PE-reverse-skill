#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#define TOKEN_ENVIRONMENT_VARIABLE L"RA_MANUAL_MAP_SMOKE_TOKEN"
#define EVENT_NAME_PREFIX L"Local\\ReverseAnalyzerManualMapSmoke-"

static BOOL signal_stage(LPCWSTR stage) {
    WCHAR token[65];
    WCHAR event_name[160];
    DWORD token_length = GetEnvironmentVariableW(
        TOKEN_ENVIRONMENT_VARIABLE,
        token,
        (DWORD)(sizeof(token) / sizeof(token[0]))
    );
    HANDLE event_handle;
    BOOL signaled;

    if (token_length == 0 || token_length >= (DWORD)(sizeof(token) / sizeof(token[0]))) {
        return FALSE;
    }

    lstrcpyW(event_name, EVENT_NAME_PREFIX);
    lstrcatW(event_name, token);
    lstrcatW(event_name, L"-");
    lstrcatW(event_name, stage);

    event_handle = OpenEventW(EVENT_MODIFY_STATE, FALSE, event_name);
    if (event_handle == NULL) {
        return FALSE;
    }
    signaled = SetEvent(event_handle);
    CloseHandle(event_handle);
    return signaled;
}

static BOOL (*volatile relocation_anchor)(LPCWSTR) = signal_stage;

__declspec(dllexport) DWORD WINAPI manual_map_smoke_probe(DWORD value) {
    return value ^ (relocation_anchor != NULL ? 0x5A17U : 0U);
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(instance);
        return signal_stage(L"attach");
    }
    if (reason == DLL_PROCESS_DETACH) {
        (void)signal_stage(L"detach");
    }
    return TRUE;
}
