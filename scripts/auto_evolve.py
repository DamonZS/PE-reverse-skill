#!/usr/bin/env python3
"""
auto_evolve.py — PE Reverse Analyzer 自动进化升级脚本

每次逆向分析会话结束后自动运行，实现：
  1. 记录本次会话的所有操作、成功项、失败项
  2. 从多会话中提取模式、更新决策规则
  3. 自动扩充壳检测签名库
  4. 自动更新 SKILL.md 中的知识库章节
  5. 生成进化建议报告

用法:
  python auto_evolve.py --session <session_id> \
      --binary <target.exe> \
      --outcome <success|partial|failed> \
      --actions "pe_analyze,suspend_dump,deep_decompile,..." \
      --findings <findings.json> \
      --auto-apply

作者: pe-reverse-analyzer v2.5+
"""

import os
import sys
import json
import hashlib
import datetime
import argparse
import re
import shutil
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Optional, Tuple, Any


# ====== Configuration ======
SKILL_DIR = Path.home() / ".workbuddy" / "skills" / "pe-reverse-analyzer"
EVOLVE_DIR = SKILL_DIR / "evolution"
SESSIONS_FILE = EVOLVE_DIR / "sessions.json"
KNOWLEDGE_FILE = EVOLVE_DIR / "knowledge_base.json"
DETECTION_DB = EVOLVE_DIR / "detection_db.json"
SKILL_MD = SKILL_DIR / "SKILL.md"

# ====== Packer Signatures (auto-expandable) ======
DEFAULT_PACKER_SIGNATURES = {
    "section_names": {
        "VMProtect": [".vmp0", ".vmp1", ".vmp2", ".vmp3", ".vmp"],
        "UPX": ["UPX0", "UPX1", "UPX2"],
        "Themida": [".themida", ".themida2", ".tsuserex"],
        "ASPack": [".aspack", ".adata"],
        "CNM": ["CNM0", "CNM1", "CNM2"],
        "ASProtect": [".asprotect", ".act_v0", ".rdata0"],
        "Enigma": [".enigma1", ".enigma2"],
        "Obsidium": [".obsidium", ".obscode"],
        "PECompact": [".pec", ".pec2", "PEC2"],
        "Molebox": [".molebox", ".mole"],
        "Armadillo": [".arm", ".text1", ".data1"],
        "Safengine": [".safengine", ".se1", ".se2"],
        "Yoda": [".y0da", ".yP"],
        "NSIS": [".ndata", "nsis"],
        "TELock": [".tls", ".tevl", ".textz"],
    },
    "entry_patterns": {
        "UPX": [r"pusha", r"pushad"],
        "ASPack": [r"pusha\x68", r"call.{4}pusha"],
        "CNM": [r"pushfd", r"pushal", r"pushfd\x0cpushal"],
        "VMProtect": [r"push\s+(?:0x[0-9A-Fa-f]+|reg)", r"call\s+.*vmp"],
    },
    "high_entropy_threshold": 7.0,
    "section_existence_check": [".text", ".rdata", ".data"],
}

# ====== Decision Rules (self-evolving) ======
DEFAULT_DECISION_RULES = {
    "tool_selection": {
        "default": "capstone_first",
        "exceptions": {
            "packer==VMProtect": "capstone_only",
            "packer==CNM": "capstone_only",
            "packer==Themida": "capstone_only",
            "packer==None": "ghidra_then_capstone",
            "packer==UPX": "unpack_then_ghidra",
            "packer==ASPack": "unpack_then_ghidra",
        }
    },
    "unpack_attempt": {
        "VMProtect": "skip_unpack",
        "Themida": "skip_unpack",
        "CNM": "suspend_dump",
        "UPX": "upx_dash_d",
        "ASPack": "esp_law_or_x32dbg",
        "default": "suspend_dump_first",
    },
    "known_impossible": [
        "VMProtect full unpack",
        "Themida IAT reconstruction",
        "CNM Ghidra recursive descent",
        "VMP .text raw dump (memory only)",
    ],
    "strategy_by_goal": {
        "source_reconstruction": ["pe_analyze", "strings_extract", "imports_map", "side_channel_reconstruct"],
        "ctf_flag": ["strings_search", "memory_search", "api_breakpoints", "patch_verify"],
        "protocol_analysis": ["capture_traffic", "string_extraction", "crypto_detection", "packet_replay"],
        "malware_analysis": ["sandbox_run", "behavior_log", "registry_diff", "network_capture"],
    }
}

# ====== Shell Detection Logic (auto-expands) ======
def detect_packer_section_signatures(sections, detection_db):
    """Match section names against known packer signatures."""
    found = []
    section_names = [s.get("name", "") for s in sections]

    for packer, sigs in detection_db.get("section_names", {}).items():
        for sig in sigs:
            if any(sig.lower() in name.lower() for name in section_names):
                if packer not in found:
                    found.append(packer)
    return found


def detect_packer_high_entropy(sections, threshold=7.0):
    """Detect packer based on high entropy sections."""
    suspects = []
    for section in sections:
        entropy = section.get("entropy", 0)
        if entropy >= threshold:
            suspects.append({
                "name": section.get("name", "?"),
                "entropy": entropy,
                "virtual_addr": section.get("virtual_addr", 0),
            })
    return suspects


def detect_packer_empty_sections(sections):
    """Detect packer based on RawSize=0 sections (memory-expanded)."""
    empty = []
    for section in sections:
        raw_size = section.get("raw_size", 0)
        virtual_size = section.get("virtual_size", 0)
        if raw_size == 0 and virtual_size > 0:
            empty.append(section.get("name", "?"))
    return empty


# ====== Session Management ======
class EvolutionSession:
    """Tracks a single reverse engineering session."""

    def __init__(self, session_id: str = None):
        self.session_id = session_id or datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.data = {
            "session_id": self.session_id,
            "timestamp": datetime.datetime.now().isoformat(),
            "binary": {},
            "actions_executed": [],
            "actions_succeeded": [],
            "actions_failed": [],
            "packer_type": None,
            "packer_detection_method": None,
            "buildable_project": False,
            "project_line_count": 0,
            "errors_encountered": [],
            "workarounds_found": [],
            "new_patterns_discovered": [],
            "tool_decisions": {},
            "final_status": "unknown",
            "notes": "",
        }

    def record_binary(self, path: str, size: int, hash_md5: str = None):
        self.data["binary"] = {
            "path": str(path),
            "size": size,
            "md5": hash_md5 or "",
        }

    def record_action(self, name: str, success: bool, error: str = None):
        if success:
            self.data["actions_succeeded"].append(name)
        else:
            self.data["actions_failed"].append({"name": name, "error": error or ""})

    def record_tool_decision(self, tool: str, reason: str):
        self.data["tool_decisions"][tool] = reason

    def record_error(self, action: str, error: str, workaround: str = None):
        self.data["errors_encountered"].append({
            "action": action,
            "error": error,
            "workaround": workaround or "none",
        })
        if workaround:
            self.data["workarounds_found"].append({
                "problem": error[:100],
                "solution": workaround[:200],
            })

    def record_new_pattern(self, pattern_type: str, pattern_data: dict):
        self.data["new_patterns_discovered"].append({
            "type": pattern_type,
            "data": pattern_data,
        })

    def finalize(self, status: str, built_project: bool = False, line_count: int = 0):
        self.data["final_status"] = status
        self.data["buildable_project"] = built_project
        self.data["project_line_count"] = line_count

    def to_dict(self) -> dict:
        return dict(self.data)


# ====== Knowledge Base ======
class KnowledgeBase:
    """Self-evolving knowledge base."""

    def __init__(self):
        self.data = {
            "version": 1,
            "last_updated": None,
            "total_sessions": 0,
            "packer_detection_stats": defaultdict(int),
            "success_rate_by_packer": defaultdict(lambda: {"attempts": 0, "buildable": 0}),
            "action_success_rates": defaultdict(lambda: {"success": 0, "total": 0}),
            "error_patterns": defaultdict(list),
            "discovered_packers": [],  # new packer types discovered
            "new_section_names": [],   # new section names from unknown packers
            "tool_decisions": defaultdict(lambda: defaultdict(int)),  # tool → choice → count
            "impossible_confirmations": [],  # confirmed impossible patterns
            "evolution_log": [],
        }

    def load(self):
        if KNOWLEDGE_FILE.exists():
            try:
                with open(KNOWLEDGE_FILE, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                # Rebuild defaultdicts from loaded dicts
                if "packer_detection_stats" in loaded:
                    d = loaded.pop("packer_detection_stats")
                    self.data["packer_detection_stats"] = defaultdict(int, d)
                if "success_rate_by_packer" in loaded:
                    d = loaded.pop("success_rate_by_packer")
                    self.data["success_rate_by_packer"] = defaultdict(
                        lambda: {"attempts": 0, "buildable": 0}, d)
                if "action_success_rates" in loaded:
                    d = loaded.pop("action_success_rates")
                    self.data["action_success_rates"] = defaultdict(
                        lambda: {"success": 0, "total": 0}, d)
                if "error_patterns" in loaded:
                    d = loaded.pop("error_patterns")
                    self.data["error_patterns"] = defaultdict(list, d)
                if "tool_decisions" in loaded:
                    d = loaded.pop("tool_decisions")
                    self.data["tool_decisions"] = defaultdict(lambda: defaultdict(int),
                        {k: defaultdict(int, v) if isinstance(v, dict) else v
                         for k, v in d.items()})
                # Merge remaining
                self.data.update(loaded)
            except Exception as e:
                print(f"[evolve] Warning: Could not load knowledge base: {e}")
                import traceback
                traceback.print_exc()

    def save(self):
        EVOLVE_DIR.mkdir(parents=True, exist_ok=True)
        self.data["last_updated"] = datetime.datetime.now().isoformat()
        # Convert defaultdict to regular dict for JSON serialization
        data_copy = {}
        for k, v in self.data.items():
            if isinstance(v, defaultdict):
                if hasattr(v, 'default_factory'):
                    if v.default_factory == int:
                        data_copy[k] = dict(v)
                    elif isinstance(v.default_factory, type) and issubclass(v.default_factory, list):
                        data_copy[k] = dict(v)
                    else:
                        data_copy[k] = {kk: dict(vv) if isinstance(vv, defaultdict) else vv
                                        for kk, vv in v.items()}
                else:
                    data_copy[k] = dict(v)
            elif k in ("success_rate_by_packer",):
                data_copy[k] = {kk: dict(vv) for kk, vv in v.items()}
            elif k in ("tool_decisions",):
                data_copy[k] = {kk: dict(vv) for kk, vv in v.items()}
            else:
                data_copy[k] = v
        with open(KNOWLEDGE_FILE, "w", encoding="utf-8") as f:
            json.dump(data_copy, f, indent=2, ensure_ascii=False, default=str)

    def learn_from_session(self, session: EvolutionSession):
        """Update knowledge base with session findings."""
        s = session.data
        self.data["total_sessions"] += 1

        # Track packer
        packer = s.get("packer_type", "unknown")
        self.data["packer_detection_stats"][packer] += 1
        self.data["success_rate_by_packer"][packer]["attempts"] += 1
        if s.get("buildable_project"):
            self.data["success_rate_by_packer"][packer]["buildable"] += 1

        # Track actions
        for action in s.get("actions_succeeded", []):
            self.data["action_success_rates"][action]["success"] += 1
            self.data["action_success_rates"][action]["total"] += 1
        for failed in s.get("actions_failed", []):
            action_name = failed["name"] if isinstance(failed, dict) else failed
            self.data["action_success_rates"][action_name]["total"] += 1

        # Track errors
        for err in s.get("errors_encountered", []):
            self.data["error_patterns"][err["action"]].append({
                "error": err["error"],
                "workaround": err.get("workaround", "none"),
                "session": s["session_id"],
            })

        # Track new patterns
        for pattern in s.get("new_patterns_discovered", []):
            if pattern["type"] == "packer_section_name":
                self.data["new_section_names"].append(pattern["data"])
            if pattern["type"] == "packer":
                if pattern["data"] not in self.data["discovered_packers"]:
                    self.data["discovered_packers"].append(pattern["data"])

        # Track tool decisions
        for tool, reason in s.get("tool_decisions", {}).items():
            self.data["tool_decisions"][tool][reason] += 1

        # Evolution log
        self.data["evolution_log"].append({
            "session": s["session_id"],
            "packer": packer,
            "status": s["final_status"],
            "timestamp": s["timestamp"],
            "key_finding": s.get("notes", "")[:200],
        })


# ====== Evolution Actions ======
def generate_evolution_suggestions(kb: KnowledgeBase, session: EvolutionSession):
    """Analyze session + knowledge base to suggest improvements."""
    suggestions = []

    # Suggestion 1: If we keep failing on same packer, recommend skipping unpack
    packer = session.data.get("packer_type", "unknown")
    stats = kb.data["success_rate_by_packer"].get(packer, {})
    if stats.get("attempts", 0) >= 3 and stats.get("buildable", 0) == 0:
        suggestions.append({
            "priority": "HIGH",
            "type": "impossible_pattern",
            "message": f"Packer '{packer}' has {stats['attempts']} failed attempts for source reconstruction. "
                       f"Consider adding to 'known_impossible' list.",
            "action": "add_known_impossible",
            "value": f"{packer} source reconstruction via full unpack",
        })

    # Suggestion 2: New section names detected → add to detection DB
    for pattern in session.data.get("new_patterns_discovered", []):
        if pattern["type"] == "packer_section_name":
            suggestions.append({
                "priority": "MEDIUM",
                "type": "detection_expansion",
                "message": f"New section name pattern found: {pattern['data']}. Add to detection DB.",
                "action": "add_section_signature",
                "value": pattern["data"],
            })

    # Suggestion 3: Discovered new packer type
    packer_type = session.data.get("packer_type")
    if packer_type and packer_type not in DEFAULT_PACKER_SIGNATURES["section_names"]:
        suggestions.append({
            "priority": "HIGH",
            "type": "new_packer",
            "message": f"New packer type detected: '{packer_type}'. Add to packer database.",
            "action": "register_new_packer",
            "value": packer_type,
        })

    # Suggestion 4: Workaround frequency → promote to skill
    workarounds = defaultdict(int)
    for err_entry in kb.data["error_patterns"].values():
        for e in err_entry:
            if e.get("workaround") and e["workaround"] != "none":
                workarounds[e["workaround"]] += 1
    for workaround, count in workarounds.items():
        if count >= 3:
            suggestions.append({
                "priority": "MEDIUM",
                "type": "promote_workaround",
                "message": f"Workaround '{workaround[:80]}...' used {count} times. Consider adding to SKILL.md.",
                "action": "update_skill_doc",
                "value": workaround,
            })

    # Suggestion 5: if number of "impossible" patterns > 10, recommend major skill restructure
    if len(kb.data.get("known_impossible", [])) > 10:
        suggestions.append({
            "priority": "LOW",
            "type": "skill_restructure",
            "message": "Knowledge base has >10 impossible patterns. Consider restructuring SKILL.md sections.",
            "action": "recommend_restructure",
        })

    return suggestions


def apply_evolution_actions(suggestions: List[dict], kb: KnowledgeBase, auto: bool = False):
    """Apply approved evolution actions."""
    applied = []
    skipped = []

    for sug in suggestions:
        if sug["action"] == "add_known_impossible":
            if "known_impossible" not in kb.data:
                kb.data["known_impossible"] = []
            if sug["value"] not in kb.data["known_impossible"]:
                kb.data["known_impossible"].append(sug["value"])
                applied.append(sug)
            else:
                skipped.append(sug)

        elif sug["action"] == "add_section_signature":
            # Auto-apply section signatures (P2 - safe)
            if auto or sug["priority"] != "HIGH":
                section_data = sug["value"]
                packer_name = section_data.get("packer", "unknown")
                # Add to detection DB
                detection_db = load_detection_db()
                if "section_names" not in detection_db:
                    detection_db["section_names"] = {}
                if packer_name not in detection_db["section_names"]:
                    detection_db["section_names"][packer_name] = []
                section_name = section_data.get("section_name", "")
                if section_name not in detection_db["section_names"][packer_name]:
                    detection_db["section_names"][packer_name].append(section_name)
                save_detection_db(detection_db)
                applied.append(sug)
            else:
                print(f"[evolve] HIGH priority action needs review: {sug['message']}")
                skipped.append(sug)

        elif sug["action"] == "update_skill_doc":
            if auto:
                update_skill_markdown(sug["value"])
                applied.append(sug)
            else:
                skipped.append(sug)

        else:
            if auto:
                applied.append(sug)
            else:
                skipped.append(sug)

    return applied, skipped


# ====== SKILL.md 自动更新 ======
def update_skill_markdown(workaround_text: str = None, new_section: str = None):
    """Append new knowledge to SKILL.md automatically."""
    if not SKILL_MD.exists():
        print("[evolve] SKILL.md not found, skipping auto-update")
        return

    content = SKILL_MD.read_text(encoding="utf-8")

    # Check for auto-evolution section marker
    marker = "<!-- AUTO_EVOLVE_INSERT -->"
    if marker not in content:
        # Append marker at end of skill
        content += f"\n\n{marker}\n<!-- Auto-evolved knowledge will be inserted here -->\n"
        SKILL_MD.write_text(content, encoding="utf-8")

    if new_section:
        # Insert before marker
        content = SKILL_MD.read_text(encoding="utf-8")
        insert = f"\n### 自动进化知识 (v{kb_data.get('version', 1)})\n\n{new_section}\n"
        content = content.replace(marker, insert + marker)
        SKILL_MD.write_text(content, encoding="utf-8")
        print("[evolve] SKILL.md updated with new knowledge section")


# ====== Detection DB Management ======
def load_detection_db() -> dict:
    if DETECTION_DB.exists():
        with open(DETECTION_DB, "r", encoding="utf-8") as f:
            return json.load(f)
    return dict(DEFAULT_PACKER_SIGNATURES)


def save_detection_db(db: dict):
    EVOLVE_DIR.mkdir(parents=True, exist_ok=True)
    with open(DETECTION_DB, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2, ensure_ascii=False)


def init_evolution_system():
    """First-time initialization of evolution tracking."""
    EVOLVE_DIR.mkdir(parents=True, exist_ok=True)

    # Initialize detection DB
    if not DETECTION_DB.exists():
        save_detection_db(DEFAULT_PACKER_SIGNATURES)

    # Initialize knowledge base
    if not KNOWLEDGE_FILE.exists():
        kb = KnowledgeBase()
        kb.save()

    # Initialize sessions file
    if not SESSIONS_FILE.exists():
        with open(SESSIONS_FILE, "w", encoding="utf-8") as f:
            json.dump([], f)

    print(f"[evolve] Evolution system initialized at: {EVOLVE_DIR}")


# ====== Reports ======
def generate_evolution_report(kb: KnowledgeBase) -> str:
    """Generate a human-readable evolution report."""
    lines = []
    lines.append("=" * 60)
    lines.append("PE Reverse Analyzer - Evolution Report")
    lines.append(f"Generated: {datetime.datetime.now().isoformat()}")
    lines.append("=" * 60)
    lines.append(f"\nTotal sessions tracked: {kb.data['total_sessions']}")
    lines.append(f"Knowledge base version: {kb.data.get('version', 1)}")
    lines.append(f"Last updated: {kb.data.get('last_updated', 'never')}")

    lines.append("\n--- Packer Statistics ---")
    for packer, stats in sorted(kb.data["success_rate_by_packer"].items()):
        attempts = stats.get("attempts", 0)
        buildable = stats.get("buildable", 0)
        rate = (buildable / attempts * 100) if attempts > 0 else 0
        lines.append(f"  {packer}: {attempts} attempts, {buildable} buildable ({rate:.0f}%)")

    lines.append("\n--- Action Success Rates ---")
    for action, stats in sorted(kb.data["action_success_rates"].items(),
                                key=lambda x: x[1]["total"], reverse=True):
        s = stats["success"]
        t = stats["total"]
        rate = (s / t * 100) if t > 0 else 0
        lines.append(f"  {action}: {s}/{t} ({rate:.0f}%)")

    lines.append("\n--- Common Errors ---")
    for action, errors in sorted(kb.data["error_patterns"].items(),
                                  key=lambda x: len(x[1]), reverse=True):
        lines.append(f"  {action}: {len(errors)} occurrences")
        for e in errors[-3:]:  # last 3
            lines.append(f"    - {e['error'][:80]}")

    lines.append("\n--- Discovered Packers ---")
    for p in kb.data.get("discovered_packers", []):
        lines.append(f"  - {p}")

    lines.append("\n--- New Section Names ---")
    for s in kb.data.get("new_section_names", [])[-5:]:
        lines.append(f"  - {s}")

    lines.append("\n--- Impossible Confirmations ---")
    for c in kb.data.get("known_impossible", []):
        lines.append(f"  ✗ {c}")

    lines.append("\n" + "=" * 60)
    return "\n".join(lines)


# ====== Main ======
def main():
    parser = argparse.ArgumentParser(
        description="PE Reverse Analyzer 自动进化引擎",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 记录一次成功的逆向会话
  python auto_evolve.py --init
  python auto_evolve.py --record \\
      --binary target.exe --packer VMProtect \\
      --actions "pe_analyze,side_channel" \\
      --status partial --built-project --lines 1302 \\
      --notes "VMP无法脱壳，侧面信息重构成功"

  # 自动应用进化（在每次重构完成后运行）
  python auto_evolve.py --auto-apply

  # 生成进化报告
  python auto_evolve.py --report
        """
    )

    parser.add_argument("--init", action="store_true",
                        help="初始化进化系统（首次使用）")
    parser.add_argument("--record", action="store_true",
                        help="记录本次逆向会话")
    parser.add_argument("--binary", type=str,
                        help="目标二进制文件路径")
    parser.add_argument("--packer", type=str, default="unknown",
                        help="检测到的壳类型")
    parser.add_argument("--actions", type=str,
                        help="执行的操作列表（逗号分隔）")
    parser.add_argument("--failed", type=str,
                        help="失败的操作列表（逗号分隔）")
    parser.add_argument("--status", type=str, default="unknown",
                        choices=["success", "partial", "failed"],
                        help="最终状态")
    parser.add_argument("--built-project", action="store_true",
                        help="是否产出可编译项目")
    parser.add_argument("--lines", type=int, default=0,
                        help="重构项目代码行数")
    parser.add_argument("--notes", type=str, default="",
                        help="会话备注")
    parser.add_argument("--auto-apply", action="store_true",
                        help="自动应用进化建议")
    parser.add_argument("--report", action="store_true",
                        help="生成进化报告")
    parser.add_argument("--findings", type=str,
                        help="findings JSON 文件路径")

    args = parser.parse_args()

    # Init
    if args.init:
        init_evolution_system()
        return

    # Report
    if args.report:
        kb = KnowledgeBase()
        kb.load()
        report = generate_evolution_report(kb)
        print(report)
        report_file = EVOLVE_DIR / "evolution_report.txt"
        with open(report_file, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"\n[evolve] Report saved to: {report_file}")
        return

    # Record session
    if args.record:
        init_evolution_system()

        session = EvolutionSession()

        # Record binary info
        if args.binary:
            path = Path(args.binary)
            size = path.stat().st_size if path.exists() else 0
            session.record_binary(args.binary, size)

        # Record actions
        if args.actions:
            for action in args.actions.split(","):
                session.record_action(action.strip(), True)
        if args.failed:
            for action in args.failed.split(","):
                session.record_action(action.strip(), False,
                                      f"Failed: {action.strip()}")

        # Record packer + tool decision
        session.data["packer_type"] = args.packer
        if args.packer in ("VMProtect", "Themida", "CNM"):
            session.record_tool_decision("ghidra", "skip (packer incompatible)")
            session.record_tool_decision("capstone", "primary (linear scan)")
            session.record_action("ghidra_attempt", False,
                                  f"{args.packer} code not visible to recursive descent")

        # Load findings if provided
        if args.findings and Path(args.findings).exists():
            with open(args.findings, "r", encoding="utf-8") as f:
                findings = json.load(f)
            # Extract patterns from findings
            if "sections" in findings:
                sections = findings["sections"]
                for s in sections:
                    if "entropy" in s and s["entropy"] > 7.0:
                        session.record_new_pattern("high_entropy_section",
                                                    {"name": s["name"], "entropy": s["entropy"]})

        # Finalize
        session.finalize(args.status, args.built_project, args.lines)
        session.data["notes"] = args.notes

        # Save session
        sessions = []
        if SESSIONS_FILE.exists():
            with open(SESSIONS_FILE, "r", encoding="utf-8") as f:
                sessions = json.load(f)
        sessions.append(session.to_dict())
        with open(SESSIONS_FILE, "w", encoding="utf-8") as f:
            json.dump(sessions, f, indent=2, ensure_ascii=False)

        # Learn
        kb = KnowledgeBase()
        kb.load()
        kb.learn_from_session(session)
        kb.data["version"] += 1
        kb.save()

        # Generate suggestions
        suggestions = generate_evolution_suggestions(kb, session)

        print(f"\n[evolve] Session {session.session_id} recorded.")
        print(f"[evolve] Packer: {args.packer} | Status: {args.status} | "
              f"Buildable: {args.built_project} | Lines: {args.lines}")
        print(f"[evolve] Suggestions: {len(suggestions)} found")

        for sug in suggestions:
            print(f"  [{sug['priority']}] {sug['type']}: {sug['message'][:100]}")

        # Auto-apply if requested
        if args.auto_apply:
            applied, skipped = apply_evolution_actions(suggestions, kb, auto=True)
            print(f"\n[evolve] Auto-applied: {len(applied)} changes, "
                  f"Skipped: {len(skipped)}")
            kb.save()
            for a in applied:
                print(f"  ✓ {a['type']}: {a['message'][:80]}...")


if __name__ == "__main__":
    main()
