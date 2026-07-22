from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional, Sequence

from reverse_analyzer._version import __version__

from .campaign import configure_campaign, load_campaign, run_campaign
from .acceptance import promote_output
from .benchmark import BenchmarkConfig, BenchmarkPricing, run_benchmark
from .doctor import DoctorError, run_doctor
from .instruction_assets import list_instruction_profiles
from .models import (
    Campaign,
    CampaignValidationError,
    CheckpointError,
    SUPPORTED_ATTACK_MODES,
    SUPPORTED_SEMANTIC_JUDGES,
    SUPPORTED_STRATEGIES,
)
from .release import verify_release_manifest
from .templates import initialize_workspace
from .transport import OpenAICompatibleTransport, TransportError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m reverse_analyzer.llm_jailbreak",
        description="Run adaptive model-jailbreak campaigns against OpenAI-compatible chat endpoints.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    init = commands.add_parser(
        "init", help="write a starter campaign and JSON Schema from packaged assets"
    )
    init.add_argument("directory", type=Path, nargs="?", default=Path("."))
    init.add_argument("--force", action="store_true")
    init.add_argument("--json", action="store_true", dest="json_output")

    run = commands.add_parser("run", help="execute a jailbreak campaign")
    run.add_argument("campaign", type=Path, help="campaign JSON file")
    run.add_argument("--out", type=Path, default=Path("llm-jailbreak-out"))
    run.add_argument("--checkpoint", type=Path)
    run.add_argument("--resume", action="store_true")
    run.add_argument("--base-url")
    run.add_argument("--model")
    run.add_argument("--api-key-env")
    run.add_argument("--timeout", type=float)
    run.add_argument("--max-retries", type=int)
    run.add_argument("--requests-per-minute", type=float)
    run.add_argument(
        "--attack-mode",
        action="append",
        dest="attack_modes",
        metavar="MODE",
        help="attack mode; repeat the option or provide a comma-separated list",
    )
    run.add_argument("--semantic-judge", choices=SUPPORTED_SEMANTIC_JUDGES)
    run.add_argument("--judge-model")
    run.add_argument("--instruction-profile", metavar="PROFILE")
    run.add_argument(
        "--instruction-file",
        "--instruction-files",
        action="append",
        dest="instruction_files",
        metavar="PATH",
        help="instruction Markdown file; repeat the option to preserve file order",
    )
    run.add_argument("--require-success", action="store_true")
    run.add_argument("--json", action="store_true", dest="json_output")

    resume = commands.add_parser("resume", help="resume a campaign from its checkpoint")
    resume.add_argument("campaign", type=Path)
    resume.add_argument("--out", type=Path, default=Path("llm-jailbreak-out"))
    resume.add_argument("--checkpoint", type=Path)
    resume.add_argument("--json", action="store_true", dest="json_output")

    validate = commands.add_parser("validate", help="validate and normalize campaign JSON")
    validate.add_argument("campaign", type=Path)
    validate.add_argument("--json", action="store_true", dest="json_output")

    strategies = commands.add_parser("strategies", help="list built-in jailbreak strategies")
    strategies.add_argument("--json", action="store_true", dest="json_output")

    profiles = commands.add_parser(
        "profiles",
        help="list repository-backed instruction profiles",
    )
    profiles.add_argument("--json", action="store_true", dest="json_output")

    doctor = commands.add_parser("doctor", help="probe endpoint production readiness")
    doctor.add_argument("--base-url", required=True)
    doctor.add_argument("--model", required=True)
    doctor.add_argument("--api-key-env", default="OPENAI_API_KEY")
    doctor.add_argument("--timeout", type=float, default=30.0)
    doctor.add_argument("--json", action="store_true", dest="json_output")

    promote = commands.add_parser("promote", help="validate retained campaign evidence")
    promote.add_argument("path", type=Path)
    promote.add_argument("--secret-env", action="append", default=[])
    promote.add_argument("--json", action="store_true", dest="json_output")

    report = commands.add_parser("report", help="print a retained campaign report")
    report.add_argument("path", type=Path, help="report.json, result.json, or output directory")
    report.add_argument("--json", action="store_true", dest="json_output")

    release_verify = commands.add_parser(
        "release-verify", help="verify a portable release package manifest"
    )
    release_verify.add_argument("path", type=Path)
    release_verify.add_argument("--json", action="store_true", dest="json_output")

    benchmark = commands.add_parser(
        "benchmark", help="compare campaign algorithms with an identical attempt budget"
    )
    benchmark.add_argument("campaign", type=Path)
    benchmark.add_argument("--out", type=Path, default=Path("llm-jailbreak-benchmark"))
    benchmark.add_argument(
        "--algorithm", action="append", dest="algorithms", metavar="MODE"
    )
    benchmark.add_argument("--repetitions", type=int, default=1)
    benchmark.add_argument("--max-rounds", type=int)
    benchmark.add_argument("--model", action="append", dest="models")
    benchmark.add_argument(
        "--instruction-profile", action="append", dest="instruction_profiles"
    )
    benchmark.add_argument("--prompt-cost-per-1k", type=float, default=0.0)
    benchmark.add_argument("--completion-cost-per-1k", type=float, default=0.0)
    benchmark.add_argument("--json", action="store_true", dest="json_output")
    return parser


def _override_campaign(campaign: Campaign, args: argparse.Namespace) -> Campaign:
    override_names = (
        "base_url",
        "model",
        "api_key_env",
        "timeout",
        "max_retries",
        "requests_per_minute",
        "attack_modes",
        "semantic_judge",
        "judge_model",
        "instruction_profile",
        "instruction_files",
    )
    if all(getattr(args, name, None) is None for name in override_names):
        return campaign

    options = {
        name: getattr(args, name)
        for name in ("max_retries", "requests_per_minute")
        if getattr(args, name, None) is not None
    }
    effective_semantic_judge = (
        getattr(args, "semantic_judge", None) or campaign.semantic_judge
    )
    effective_judge_model = (
        campaign.judge_model
        if getattr(args, "judge_model", None) is None
        else str(args.judge_model).strip()
    )
    if effective_semantic_judge == "model" and not effective_judge_model:
        raise CampaignValidationError(
            ["--judge-model is required when --semantic-judge is model"]
        )
    return configure_campaign(
        campaign,
        base_url=getattr(args, "base_url", None),
        model=getattr(args, "model", None),
        api_key_env=getattr(args, "api_key_env", None),
        timeout=getattr(args, "timeout", None),
        attack_modes=getattr(args, "attack_modes", None),
        semantic_judge=getattr(args, "semantic_judge", None),
        judge_model=getattr(args, "judge_model", None),
        instruction_profile=getattr(args, "instruction_profile", None),
        instruction_files=getattr(args, "instruction_files", None),
        options=options or None,
    )


def _run_command(args: argparse.Namespace) -> int:
    campaign = _override_campaign(load_campaign(args.campaign), args)
    transport = OpenAICompatibleTransport.from_target(campaign.target)
    result = run_campaign(
        campaign,
        transport=transport,
        out_dir=args.out,
        resume=args.resume,
        checkpoint_path=args.checkpoint,
    )
    if args.json_output:
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True, ensure_ascii=False))
    else:
        print(
            f"campaign={result.campaign_id} status={result.status} "
            f"success={str(result.success).lower()} attempts={len(result.attempts)}"
        )
        print(f"result={args.out / 'result.json'}")
    return 3 if args.require_success and not result.success else 0


def _init_command(args: argparse.Namespace) -> int:
    payload = initialize_workspace(args.directory, force=args.force)
    if args.json_output:
        print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))
    else:
        print(
            f"initialized={payload['directory']} files={len(payload['files'])}"
        )
    return 0


def _resume_command(args: argparse.Namespace) -> int:
    args.resume = True
    args.require_success = False
    args.base_url = args.model = args.api_key_env = None
    args.timeout = args.max_retries = args.requests_per_minute = None
    args.attack_modes = args.semantic_judge = args.judge_model = None
    args.instruction_profile = args.instruction_files = None
    return _run_command(args)


def _report_command(args: argparse.Namespace) -> int:
    path = args.path
    if path.is_dir():
        path = path / "report.json"
        if not path.is_file():
            path = args.path / "result.json"
    if not path.is_file():
        raise OSError(f"report path does not exist: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if args.json_output:
        print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))
    else:
        section = payload.get("llm_jailbreak_analysis", payload)
        print(
            f"status={section.get('status', 'unknown')} "
            f"success={str(section.get('success', False)).lower()} "
            f"attempts={section.get('attempt_count', section.get('attempts', '?'))}"
        )
    return 0


def _release_verify_command(args: argparse.Namespace) -> int:
    payload = dict(verify_release_manifest(args.path))
    if args.json_output:
        print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))
    else:
        print(
            f"release={payload['status']} files={len(payload.get('files', []))} "
            f"errors={len(payload.get('errors', []))}"
        )
    return 0 if payload.get("ok") else 4


def _benchmark_command(args: argparse.Namespace) -> int:
    campaign = load_campaign(args.campaign)
    if args.max_rounds is not None:
        campaign = configure_campaign(campaign, max_rounds=args.max_rounds)
    raw_algorithms = args.algorithms or list(SUPPORTED_ATTACK_MODES)
    algorithms = tuple(
        value.strip().casefold()
        for group in raw_algorithms
        for value in str(group).split(",")
        if value.strip()
    )
    report = run_benchmark(
        campaign,
        out_dir=args.out,
        config=BenchmarkConfig(
            algorithms=algorithms,
            repetitions=args.repetitions,
            pricing=BenchmarkPricing(
                prompt_per_1k=args.prompt_cost_per_1k,
                completion_per_1k=args.completion_cost_per_1k,
            ),
            models=tuple(args.models or ()),
            instruction_profiles=tuple(args.instruction_profiles or ()),
        ),
    )
    if args.json_output:
        print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False))
    else:
        print(
            f"benchmark={report['fingerprint']} runs={len(report['runs'])} "
            f"result={args.out / 'benchmark.json'}"
        )
    return 0


def _validate_command(args: argparse.Namespace) -> int:
    campaign = load_campaign(args.campaign)
    if args.json_output:
        print(json.dumps(campaign.to_dict(), indent=2, sort_keys=True, ensure_ascii=False))
    else:
        print(
            f"valid campaign={campaign.id} model={campaign.target.model} "
            f"rounds={campaign.max_rounds}"
        )
    return 0


def _strategies_command(args: argparse.Namespace) -> int:
    if args.json_output:
        print(json.dumps({"strategies": list(SUPPORTED_STRATEGIES)}, indent=2))
    else:
        for name in SUPPORTED_STRATEGIES:
            print(name)
    return 0


def _profiles_command(args: argparse.Namespace) -> int:
    profiles = list_instruction_profiles()
    if args.json_output:
        print(json.dumps({"profiles": list(profiles)}, indent=2))
    else:
        for name in profiles:
            print(name)
    return 0


def _doctor_command(args: argparse.Namespace) -> int:
    result = run_doctor(
        base_url=args.base_url,
        model=args.model,
        api_key_env=args.api_key_env,
        timeout_seconds=args.timeout,
    )
    payload = result.to_dict()
    if args.json_output:
        print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))
    else:
        print(f"doctor={result.status} model={result.model} checks={len(result.checks)}")
    return 0


def _promote_command(args: argparse.Namespace) -> int:
    result = promote_output(args.path, secret_env_names=args.secret_env)
    payload = result.to_dict()
    if args.json_output:
        print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))
    else:
        print(
            f"promotion={result.status} checks={len(result.checks)} "
            f"record={result.promotion_path}"
        )
    return 0 if result.ok else 4


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            return _init_command(args)
        if args.command == "run":
            return _run_command(args)
        if args.command == "resume":
            return _resume_command(args)
        if args.command == "validate":
            return _validate_command(args)
        if args.command == "strategies":
            return _strategies_command(args)
        if args.command == "profiles":
            return _profiles_command(args)
        if args.command == "doctor":
            return _doctor_command(args)
        if args.command == "promote":
            return _promote_command(args)
        if args.command == "report":
            return _report_command(args)
        if args.command == "release-verify":
            return _release_verify_command(args)
        if args.command == "benchmark":
            return _benchmark_command(args)
    except (CampaignValidationError, CheckpointError, DoctorError, TransportError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
