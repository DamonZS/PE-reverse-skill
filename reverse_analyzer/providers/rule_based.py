"""Deterministic provider used when no external model is enabled."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Dict, Iterable, Optional

from .base import ProviderMessage


class RuleBasedProvider:
    """A small, deterministic planning provider.

    The rule set intentionally favors broad, safe reverse-analysis coverage:
    identify the sample, inspect strings/imports/PE metadata/YARA hits, then
    summarize. Tool names are configurable because executors may expose
    different aliases.
    """

    name = "rule_based"

    def __init__(
        self,
        plan: Optional[Iterable[str]] = None,
        *,
        tool_args: Optional[Mapping[str, Mapping[str, Any]]] = None,
        finish_after_results: int = 2,
    ) -> None:
        self.plan = list(
            plan
            or [
                "file_info",
                "hash",
                "strings_extract",
                "pe_deep_scan",
                "packer_detect",
                "section_entropy_scan",
                "pe_header_scan",
                "yara_scan",
            ]
        )
        self.tool_args = {name: dict(args) for name, args in (tool_args or {}).items()}
        self.finish_after_results = finish_after_results

    def analyze(self, context: Mapping[str, Any]) -> ProviderMessage:
        results = _tool_results(context)
        failed_repeats = int(context.get("repeat_count") or 0)
        if failed_repeats:
            return ProviderMessage(
                content="Repeated tool request detected; stopping for caller review.",
                final_answer="Stopped because the same tool request was repeated.",
                barrier=True,
                confidence=0.8,
            )

        findings = _collect_findings(context, results)
        if _has_conclusive_result(results) or len(results) >= max(self.finish_after_results, len(self.plan)):
            return ProviderMessage(
                content="Enough observations have been collected to produce a reportable conclusion.",
                final_answer=_summarize(results, findings),
                findings=findings,
                confidence=0.75 if results else 0.45,
            )

        executed = {_result_tool_name(item) for item in results}
        for tool_name in self.plan:
            if tool_name not in executed:
                args = dict(self.tool_args.get(tool_name, {}))
                target = _target(context)
                if target is not None and "target" not in args and "path" not in args:
                    args[_path_arg_name(tool_name)] = target
                return ProviderMessage(
                    content=f"Run {tool_name} to gather the next reverse-analysis observation.",
                    tool_name=tool_name,
                    tool_args=args,
                    confidence=0.6,
                )

        return ProviderMessage(
            content="Plan exhausted; returning synthesized conclusion.",
            final_answer=_summarize(results, findings),
            findings=findings,
            confidence=0.7,
        )


def _target(context: Mapping[str, Any]) -> Any:
    if "target" in context:
        return context["target"]
    session = context.get("session")
    return getattr(session, "target", None) if session is not None else None


def _path_arg_name(tool_name: str) -> str:
    """Return the sample-path argument expected by known built-in tools."""

    if tool_name in {
        "file_info",
        "hash",
        "strings_extract",
        "pe_header_scan",
        "pe_deep_scan",
        "section_entropy_scan",
        "capstone_disassemble_stub",
        "packer_detect",
        "yara_scan",
        "yara_scan_stub",
        "reconstruct_project",
        "ghidra_decompile",
    }:
        return "path"
    return "target"


def _tool_results(context: Mapping[str, Any]) -> list[Any]:
    results = context.get("tool_results") or context.get("observations") or []
    return list(results) if isinstance(results, Sequence) and not isinstance(results, (str, bytes)) else []


def _result_tool_name(result: Any) -> Optional[str]:
    if isinstance(result, Mapping):
        return result.get("tool_name") or result.get("tool") or result.get("name")
    return getattr(result, "tool_name", None) or getattr(result, "tool", None) or getattr(result, "name", None)


def _result_payload(result: Any) -> Any:
    if isinstance(result, Mapping):
        payload = result.get("result", result.get("output", result.get("data", result)))
        if isinstance(payload, Mapping) and "data" in payload and ("status" in payload or "tool" in payload):
            return payload.get("data") or payload
        return payload
    return getattr(result, "result", getattr(result, "output", result))


def _has_conclusive_result(results: Sequence[Any]) -> bool:
    if not results:
        return False
    payload = _result_payload(results[-1])
    if isinstance(payload, Mapping):
        return bool(payload.get("final") or payload.get("conclusive") or payload.get("verdict"))
    return False


def _collect_findings(context: Mapping[str, Any], results: Sequence[Any]) -> list[Dict[str, Any]]:
    findings: list[Dict[str, Any]] = []
    for source in (context.get("knowledge"), context.get("findings")):
        if isinstance(source, Mapping):
            values = source.get("findings") or source.get("items") or []
        else:
            values = source or []
        if isinstance(values, Sequence) and not isinstance(values, (str, bytes)):
            findings.extend(dict(item) for item in values if isinstance(item, Mapping))
    for result in results:
        payload = _result_payload(result)
        if isinstance(payload, Mapping):
            values = payload.get("findings") or []
            if isinstance(values, Sequence) and not isinstance(values, (str, bytes)):
                findings.extend(dict(item) for item in values if isinstance(item, Mapping))
    return findings


def _summarize(results: Sequence[Any], findings: Sequence[Mapping[str, Any]]) -> str:
    if findings:
        titles = [str(item.get("title") or item.get("name") or item.get("summary") or "finding") for item in findings]
        return "Analysis complete. Findings: " + "; ".join(titles[:5])
    if results:
        tools = [name for name in (_result_tool_name(item) for item in results) if name]
        return "Analysis complete after running: " + ", ".join(tools)
    return "Analysis complete. No tool observations were available."
