rule SuspiciousWindowsApiCombo : suspicious api pe {
    meta:
        description = "Flags binaries carrying several high-risk Windows API names"
        severity = "medium"
        author = "Worker 2"
    strings:
        $a1 = "CreateRemoteThread" ascii wide nocase
        $a2 = "WriteProcessMemory" ascii wide nocase
        $a3 = "VirtualAlloc" ascii wide nocase
        $a4 = "LoadLibraryA" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and 2 of ($a*)
}