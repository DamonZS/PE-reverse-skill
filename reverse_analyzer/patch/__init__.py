"""PE-aware patch planning and verification."""

from .android_elf import (
    AndroidElfImage,
    AndroidElfPatchError,
    parse_android_elf,
    plan_android_elf_patch,
    validate_android_elf_patch_plan,
    verify_android_elf_patch,
)
from .dll_proxy import (
    DllProxyGenerationError,
    DllProxyProject,
    PEExport,
    PEExportTable,
    generate_dll_proxy,
    generate_dll_proxy_project,
    parse_pe_exports,
)
from .planner import (
    PatchPlannerUnavailable,
    PatchPlanningError,
    plan_pe_patch,
    validate_pe_patch_plan,
    verify_pe_patch,
)

__all__ = [
    "AndroidElfImage",
    "AndroidElfPatchError",
    "DllProxyGenerationError",
    "DllProxyProject",
    "PEExport",
    "PEExportTable",
    "PatchPlannerUnavailable",
    "PatchPlanningError",
    "generate_dll_proxy",
    "generate_dll_proxy_project",
    "parse_android_elf",
    "parse_pe_exports",
    "plan_android_elf_patch",
    "plan_pe_patch",
    "validate_android_elf_patch_plan",
    "validate_pe_patch_plan",
    "verify_android_elf_patch",
    "verify_pe_patch",
]
