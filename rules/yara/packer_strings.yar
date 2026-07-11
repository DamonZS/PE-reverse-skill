rule CommonPackerArtifacts : packer strings pe {
    meta:
        description = "Detects common packer marker strings"
        severity = "medium"
        author = "Worker 2"
    strings:
        $u1 = "UPX!" ascii wide
        $u2 = "UPX0" ascii wide
        $u3 = "UPX1" ascii wide
        $p1 = "This file is packed" ascii wide nocase
        $p2 = "ASPack" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and any of them
}