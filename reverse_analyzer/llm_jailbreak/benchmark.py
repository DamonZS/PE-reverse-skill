"""Reproducible, same-budget benchmarks for campaign attack modes."""

from __future__ import annotations

import hashlib
import json
import statistics
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Mapping, Sequence, Tuple

from .artifacts import atomic_write_json
from .campaign import load_campaign, run_campaign, configure_campaign
from .instruction_assets import load_instruction_bundle
from .models import Campaign, CampaignResult, CampaignSource, SUPPORTED_ATTACK_MODES
from .transport import ChatTransport, OpenAICompatibleTransport


@dataclass(frozen=True)
class BenchmarkPricing:
    """Price per 1K input/output tokens used only for a transparent estimate."""

    prompt_per_1k: float = 0.0
    completion_per_1k: float = 0.0

    def __post_init__(self) -> None:
        if self.prompt_per_1k < 0 or self.completion_per_1k < 0:
            raise ValueError("benchmark token prices must not be negative")

    def to_dict(self) -> Dict[str, float]:
        return {"prompt_per_1k": self.prompt_per_1k, "completion_per_1k": self.completion_per_1k}


@dataclass(frozen=True)
class BenchmarkConfig:
    algorithms: Tuple[str, ...] = SUPPORTED_ATTACK_MODES
    repetitions: int = 1
    pricing: BenchmarkPricing = field(default_factory=BenchmarkPricing)
    models: Tuple[str, ...] = ()
    instruction_profiles: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        algorithms = tuple(str(item).strip().casefold() for item in self.algorithms)
        if not algorithms:
            raise ValueError("benchmark algorithms must not be empty")
        unknown = sorted(set(algorithms) - set(SUPPORTED_ATTACK_MODES))
        if unknown:
            raise ValueError("unsupported benchmark algorithms: " + ", ".join(unknown))
        if len(set(algorithms)) != len(algorithms):
            raise ValueError("benchmark algorithms must be unique")
        if self.repetitions <= 0:
            raise ValueError("benchmark repetitions must be positive")
        models = tuple(str(item).strip() for item in self.models if str(item).strip())
        profiles = tuple(str(item).strip() for item in self.instruction_profiles if str(item).strip())
        if len(set(models)) != len(models):
            raise ValueError("benchmark models must be unique")
        if len(set(profiles)) != len(profiles):
            raise ValueError("benchmark instruction profiles must be unique")
        object.__setattr__(self, "algorithms", algorithms)
        object.__setattr__(self, "models", models)
        object.__setattr__(self, "instruction_profiles", profiles)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "algorithms": list(self.algorithms),
            "repetitions": self.repetitions,
            "pricing": self.pricing.to_dict(),
            "models": list(self.models),
            "instruction_profiles": list(self.instruction_profiles),
        }


def _number(value: Any) -> float:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else 0.0


def _metrics(result: CampaignResult, pricing: BenchmarkPricing) -> Dict[str, Any]:
    prompt_tokens = completion_tokens = total_tokens = 0.0
    latency = 0.0
    agreements = verdicts = 0
    for attempt in result.attempts:
        response = attempt.response
        if response is not None:
            usage = response.usage
            attempt_prompt = _number(
                usage.get("prompt_tokens", usage.get("input_tokens", 0))
            )
            attempt_completion = _number(
                usage.get("completion_tokens", usage.get("output_tokens", 0))
            )
            prompt_tokens += attempt_prompt
            completion_tokens += attempt_completion
            total_tokens += _number(
                usage.get("total_tokens", attempt_prompt + attempt_completion)
            )
            latency += max(0.0, _number(response.latency_seconds))
        verdict = attempt.metadata.get("semantic_judge_verdict")
        if isinstance(verdict, Mapping) and isinstance(verdict.get("success"), bool):
            verdicts += 1
            agreements += int(verdict["success"] == bool(attempt.score and attempt.score.success))
    cost = prompt_tokens / 1000.0 * pricing.prompt_per_1k + completion_tokens / 1000.0 * pricing.completion_per_1k
    return {
        "breakthrough": bool(result.success),
        "attempts": len(result.attempts),
        "tokens": {"prompt": int(prompt_tokens), "completion": int(completion_tokens), "total": int(total_tokens)},
        "latency_seconds": round(latency, 6),
        "cost": round(cost, 8),
        "judge_agreement": (round(agreements / verdicts, 6) if verdicts else None),
        "judge_verdict_count": verdicts,
    }


def _portable_campaign(campaign: Campaign) -> tuple[Dict[str, Any], str]:
    bundle = load_instruction_bundle(
        campaign.instruction_profile,
        campaign.instruction_files,
    )
    payload = campaign.to_dict()
    source_refs = [
        asset.source
        for asset in bundle.assets
        if asset.provenance.get("kind") == "custom-markdown"
    ]
    if source_refs:
        payload["instruction_files"] = source_refs
    else:
        payload.pop("instruction_files", None)
    return payload, bundle.digest


def _fingerprint(
    campaign_payload: Mapping[str, Any],
    instruction_bundle_digest: str,
    config: BenchmarkConfig,
) -> str:
    payload = {
        "campaign": campaign_payload,
        "instruction_bundle_digest": instruction_bundle_digest,
        "config": config.to_dict(),
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


def _completed_checkpoint_matches(left: CampaignResult, right: CampaignResult) -> bool:
    left_payload = left.to_dict()
    right_payload = right.to_dict()
    left_payload.pop("artifacts", None)
    right_payload.pop("artifacts", None)
    for payload in (left_payload, right_payload):
        summary = dict(payload.get("summary", {}))
        summary.pop("resumed", None)
        payload["summary"] = summary
    return left_payload == right_payload


def run_benchmark(
    campaign: CampaignSource,
    *,
    out_dir: str | Path = "llm-jailbreak-benchmark",
    config: BenchmarkConfig | None = None,
    transport_factory: Callable[[Campaign, str, int], ChatTransport] | None = None,
    transport: ChatTransport | None = None,
) -> Dict[str, Any]:
    """Run each algorithm with identical budget and return a JSON-safe report.

    ``transport_factory`` receives the effective campaign, algorithm and repetition;
    this makes model/profile matrices deterministic and keeps tests network-free.
    """
    base = load_campaign(campaign)
    cfg = config or BenchmarkConfig()
    campaign_payload, instruction_bundle_digest = _portable_campaign(base)
    root = Path(out_dir)
    root.mkdir(parents=True, exist_ok=True)
    models = cfg.models or (base.target.model,)
    profiles = cfg.instruction_profiles or (base.instruction_profile or "",)
    rows = []
    for model in models:
        for profile in profiles:
            for algorithm in cfg.algorithms:
                for repetition in range(cfg.repetitions):
                    effective = configure_campaign(
                        base,
                        model=model or None,
                        instruction_profile=profile or None,
                        attack_modes=(algorithm,),
                    )
                    run_id = f"{algorithm}-{model or 'default'}-{profile or 'default'}-r{repetition + 1:03d}"
                    safe_id = "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in run_id)
                    path_digest = hashlib.sha256(run_id.encode("utf-8")).hexdigest()[:10]
                    run_path = root / f"{safe_id}-{path_digest}"
                    run_transport = transport_factory(effective, algorithm, repetition) if transport_factory else transport
                    if run_transport is None:
                        run_transport = OpenAICompatibleTransport.from_target(effective.target)
                    result = run_campaign(effective, transport=run_transport, out_dir=run_path)
                    recovery = False
                    recovery_scope = "completed-checkpoint/same-transport"
                    try:
                        if transport_factory is not None:
                            resume_transport = transport_factory(
                                effective, algorithm, repetition
                            )
                            recovery_scope = "completed-checkpoint/fresh-transport"
                        elif transport is None:
                            resume_transport = OpenAICompatibleTransport.from_target(
                                effective.target
                            )
                            recovery_scope = "completed-checkpoint/fresh-transport"
                        else:
                            resume_transport = run_transport
                        resumed = run_campaign(
                            effective,
                            transport=resume_transport,
                            out_dir=run_path,
                            resume=True,
                        )
                        recovery = _completed_checkpoint_matches(resumed, result)
                    except Exception:
                        recovery = False
                    metric = _metrics(result, cfg.pricing)
                    metric.update({
                        "algorithm": algorithm,
                        "model": model,
                        "instruction_profile": profile,
                        "repetition": repetition + 1,
                        "campaign_id": result.campaign_id,
                        "completed_checkpoint_recovery": recovery,
                        "completed_checkpoint_recovery_scope": recovery_scope,
                        "output": run_path.name,
                    })
                    rows.append(metric)
    by_algorithm: Dict[str, Dict[str, Any]] = {}
    for algorithm in cfg.algorithms:
        items = [item for item in rows if item["algorithm"] == algorithm]
        by_algorithm[algorithm] = {
            "runs": len(items),
            "breakthrough_rate": round(sum(item["breakthrough"] for item in items) / len(items), 6) if items else 0.0,
            "average_attempts": round(statistics.mean(item["attempts"] for item in items), 6) if items else 0.0,
            "average_tokens": round(statistics.mean(item["tokens"]["total"] for item in items), 6) if items else 0.0,
            "average_cost": round(statistics.mean(item["cost"] for item in items), 8) if items else 0.0,
            "average_latency_seconds": round(statistics.mean(item["latency_seconds"] for item in items), 6) if items else 0.0,
            "judge_agreement": (round(statistics.mean(item["judge_agreement"] for item in items if item["judge_agreement"] is not None), 6) if any(item["judge_agreement"] is not None for item in items) else None),
            "completed_checkpoint_recovery_rate": round(sum(item["completed_checkpoint_recovery"] for item in items) / len(items), 6) if items else 0.0,
        }
    report = {
        "schema_version": 1,
        "fingerprint": _fingerprint(campaign_payload, instruction_bundle_digest, cfg),
        "instruction_bundle_digest": instruction_bundle_digest,
        "campaign": campaign_payload,
        "config": cfg.to_dict(),
        "summary": by_algorithm,
        "runs": rows,
    }
    atomic_write_json(root / "benchmark.json", report)
    lines = ["# LLM Jailbreak Benchmark", "", f"Fingerprint: `{report['fingerprint']}`", "", "| Algorithm | Breakthrough | Attempts | Tokens | Cost | Latency (s) | Judge agreement | Completed checkpoint recovery |", "|---|---:|---:|---:|---:|---:|---:|---:|"]
    for algorithm, values in by_algorithm.items():
        lines.append(f"| {algorithm} | {values['breakthrough_rate']:.3f} | {values['average_attempts']:.2f} | {values['average_tokens']:.0f} | {values['average_cost']:.8f} | {values['average_latency_seconds']:.3f} | {values['judge_agreement'] if values['judge_agreement'] is not None else 'n/a'} | {values['completed_checkpoint_recovery_rate']:.3f} |")
    (root / "benchmark.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return report
