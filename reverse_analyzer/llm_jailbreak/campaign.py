from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from .artifacts import ArtifactWriter, SCHEMA_VERSION, load_json, write_checkpoint
from .crescendo import CrescendoPlanner
from .evolution import EvolutionaryPromptOptimizer, PromptGenome
from .instruction_assets import InstructionBundle, load_instruction_bundle
from .judge import HeuristicSemanticJudge, JudgeVerdict, ModelSemanticJudge
from .models import (
    Attempt,
    Campaign,
    CampaignResult,
    CampaignSource,
    CampaignValidationError,
    ChatMessage,
    ChatResponse,
    CheckpointError,
    ScoreResult,
    SUPPORTED_STRATEGIES,
    TargetConfig,
    utc_now,
)
from .mutations import deterministic_mutation
from .optimizer import ATTACK_MODES, CheckpointOptimizer
from .pair import PAIRPlanner
from .scorer import ResponseScorer
from .strategies import StrategyContext, choose_adaptive_strategy, render_strategy
from .tap import TAPNode, TAPSearch
from .transport import (
    ChatTransport,
    OpenAICompatibleTransport,
    normalize_chat_response,
)


def load_campaign(source: CampaignSource) -> Campaign:
    if isinstance(source, Campaign):
        return source
    if isinstance(source, Mapping):
        return Campaign.from_dict(source)
    path = Path(source)
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except OSError as exc:
        raise CampaignValidationError([f"cannot read campaign file {path}: {exc}"]) from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CampaignValidationError([f"campaign file is not valid JSON: {exc}"]) from exc
    if not isinstance(value, Mapping):
        raise CampaignValidationError(["campaign JSON root must be an object"])
    return Campaign.from_dict(value)


@dataclass(frozen=True)
class _AttackCandidate:
    prompt: str
    identifier_key: str
    identifier: str
    metadata: Mapping[str, Any]


class CampaignRunner:
    def __init__(
        self,
        campaign: Campaign,
        transport: ChatTransport,
        out_dir: str | Path,
        checkpoint_path: str | Path | None = None,
        instruction_bundle: InstructionBundle | Mapping[str, Any] | None = None,
    ) -> None:
        self.campaign = campaign
        self.transport = transport
        self.out_dir = Path(out_dir)
        self.checkpoint_path = (
            Path(checkpoint_path) if checkpoint_path is not None else self.out_dir / "checkpoint.json"
        )
        self.writer = ArtifactWriter(self.out_dir)
        self.scorer = ResponseScorer(campaign.scoring)
        if instruction_bundle is None:
            self.instruction_bundle = load_instruction_bundle(
                campaign.instruction_profile,
                campaign.instruction_files,
            )
        elif isinstance(instruction_bundle, InstructionBundle):
            self.instruction_bundle = instruction_bundle
        elif isinstance(instruction_bundle, Mapping):
            self.instruction_bundle = InstructionBundle.from_dict(instruction_bundle)
        else:
            raise TypeError(
                "instruction_bundle must be an InstructionBundle, mapping, or None"
            )
        self.optimizer: CheckpointOptimizer
        self._pair: PAIRPlanner
        self._tap: TAPSearch
        self._crescendo: CrescendoPlanner
        self._evolution: EvolutionaryPromptOptimizer
        self.semantic_judge = self._build_semantic_judge()

    def run(self, *, resume: bool = False) -> CampaignResult:
        resumed = bool(resume and self.checkpoint_path.exists())
        state = self._load_state() if resumed else self._new_state()
        attempts = list(state["attempts"])
        messages = list(state["messages"])
        started_at = str(state["started_at"])
        next_round = int(state["next_round"])
        completed_at = str(state.get("completed_at", ""))
        self.optimizer = state["optimizer"]
        self._restore_algorithm_state()

        if not state.get("completed", False):
            for zero_based_round in range(next_round, self.campaign.max_rounds):
                round_index = zero_based_round + 1
                strategy = choose_adaptive_strategy(
                    self.campaign.strategies, tuple(attempts)
                )
                mutation_index = sum(1 for item in attempts if item.strategy == strategy)
                recommendation = self.optimizer.recommend(
                    self._allowed_attack_modes()
                )
                candidate = self._propose_candidate(
                    recommendation.mode,
                    round_index=round_index,
                    strategy=strategy,
                    mutation_index=mutation_index,
                    attempts=tuple(attempts),
                )
                request_messages = self._trim_messages(messages)
                request_messages.append(ChatMessage(role="user", content=candidate.prompt))
                attempt = self._execute_attempt(
                    round_index=round_index,
                    strategy=strategy,
                    mutation_index=mutation_index,
                    mutation_id=candidate.identifier,
                    prompt=candidate.prompt,
                    messages=tuple(request_messages),
                    attack_mode=recommendation.mode,
                    candidate=candidate,
                    optimizer_recommendation=recommendation.to_dict(),
                )
                attempts.append(attempt)
                self._observe_attempt(attempt, candidate)
                self.writer.write_attempt(attempt)
                if attempt.response is not None:
                    messages = request_messages + [
                        ChatMessage(role="assistant", content=attempt.response.content)
                    ]
                self._save_state(
                    attempts=attempts,
                    messages=messages,
                    started_at=started_at,
                    next_round=round_index,
                    completed=False,
                )
                if attempt.success and self.campaign.stop_on_success:
                    break
            completed_at = utc_now()

        result = self._build_result(
            attempts=tuple(attempts),
            started_at=started_at,
            completed_at=completed_at or utc_now(),
            resumed=resumed,
        )
        self._save_state(
            attempts=attempts,
            messages=messages,
            started_at=started_at,
            next_round=len(attempts),
            completed=True,
            completed_at=result.completed_at,
        )
        self.writer.finalize(
            self.campaign,
            result,
            checkpoint_path=self.checkpoint_path,
            instruction_bundle=self.instruction_bundle,
        )
        return result

    def _new_state(self) -> Dict[str, Any]:
        messages: List[ChatMessage] = []
        if self.campaign.system_prompt:
            messages.append(ChatMessage(role="system", content=self.campaign.system_prompt))
        if self.instruction_bundle.content:
            messages.append(
                ChatMessage(
                    role="developer",
                    name="instruction-assets",
                    content=self.instruction_bundle.content,
                )
            )
        messages.extend(self.campaign.messages)
        return {
            "attempts": [],
            "messages": messages,
            "started_at": utc_now(),
            "next_round": 0,
            "completed": False,
            "optimizer": self._new_optimizer(),
        }

    def _load_state(self) -> Dict[str, Any]:
        try:
            checkpoint = load_json(self.checkpoint_path)
        except ValueError as exc:
            raise CheckpointError(str(exc)) from exc
        if checkpoint.get("schema_version") != SCHEMA_VERSION:
            raise CheckpointError(
                f"unsupported checkpoint schema: {checkpoint.get('schema_version')!r}"
            )
        if checkpoint.get("campaign_id") != self.campaign.id:
            raise CheckpointError("checkpoint campaign id does not match the loaded campaign")
        if checkpoint.get("campaign_fingerprint") != self.campaign.fingerprint():
            raise CheckpointError("checkpoint campaign fingerprint does not match the loaded campaign")
        stored_bundle_digest = checkpoint.get("instruction_bundle_digest")
        if stored_bundle_digest is None:
            if self.instruction_bundle.assets:
                raise CheckpointError("checkpoint does not identify the configured instruction bundle")
        elif stored_bundle_digest != self.instruction_bundle.digest:
            raise CheckpointError("checkpoint instruction bundle digest does not match")
        raw_attempts = checkpoint.get("attempts", [])
        raw_messages = checkpoint.get("messages", [])
        if not isinstance(raw_attempts, list) or not isinstance(raw_messages, list):
            raise CheckpointError("checkpoint attempts and messages must be arrays")
        if not all(isinstance(item, Mapping) for item in raw_attempts):
            raise CheckpointError("checkpoint contains a non-object attempt")
        if not all(isinstance(item, Mapping) for item in raw_messages):
            raise CheckpointError("checkpoint contains a non-object message")
        try:
            attempts = [Attempt.from_dict(item) for item in raw_attempts]
            messages = [ChatMessage.from_dict(item) for item in raw_messages]
        except (CampaignValidationError, TypeError, ValueError) as exc:
            raise CheckpointError(f"checkpoint contains invalid campaign state: {exc}") from exc
        optimizer = self._load_optimizer(checkpoint, attempts)
        return {
            "attempts": attempts,
            "messages": messages,
            "started_at": str(checkpoint.get("started_at", utc_now())),
            "next_round": int(checkpoint.get("next_round", len(attempts))),
            "completed": bool(checkpoint.get("completed", False)),
            "completed_at": str(checkpoint.get("completed_at", "")),
            "optimizer": optimizer,
        }

    def _save_state(
        self,
        *,
        attempts: Sequence[Attempt],
        messages: Sequence[ChatMessage],
        started_at: str,
        next_round: int,
        completed: bool,
        completed_at: str = "",
    ) -> None:
        write_checkpoint(
            self.checkpoint_path,
            {
                "campaign_id": self.campaign.id,
                "campaign_fingerprint": self.campaign.fingerprint(),
                "started_at": started_at,
                "completed_at": completed_at,
                "next_round": next_round,
                "completed": completed,
                "attempts": [item.to_dict() for item in attempts],
                "messages": [item.to_dict() for item in messages],
                "optimizer": self.optimizer.to_dict(),
                "instruction_bundle_digest": self.instruction_bundle.digest,
            },
        )

    def _trim_messages(self, messages: Sequence[ChatMessage]) -> List[ChatMessage]:
        if self.campaign.max_context_turns == 0:
            return [item for item in messages if item.role in {"system", "developer"}]
        leading = [item for item in messages if item.role in {"system", "developer"}]
        conversational = [item for item in messages if item.role not in {"system", "developer"}]
        limit = self.campaign.max_context_turns * 2
        return leading + conversational[-limit:]

    def _execute_attempt(
        self,
        *,
        round_index: int,
        strategy: str,
        mutation_index: int,
        mutation_id: str,
        prompt: str,
        messages: Tuple[ChatMessage, ...],
        attack_mode: str,
        candidate: _AttackCandidate,
        optimizer_recommendation: Mapping[str, Any],
    ) -> Attempt:
        started_at = utc_now()
        attempt_id = (
            f"{self.campaign.id}-r{round_index:03d}-{strategy}-m{mutation_index:03d}"
        )
        response: Optional[ChatResponse] = None
        error = ""
        attempt_metadata = dict(candidate.metadata)
        attempt_metadata.update(
            {
                "attack_mode": attack_mode,
                candidate.identifier_key: candidate.identifier,
                "optimizer_recommendation": dict(optimizer_recommendation),
                "instruction_asset": self._instruction_metadata(),
            }
        )
        transport_metadata = {
            "campaign_id": self.campaign.id,
            "attempt_id": attempt_id,
            "round_index": round_index,
            "strategy": strategy,
            "mutation_id": mutation_id,
            **attempt_metadata,
        }
        try:
            response = self._complete(messages, metadata=transport_metadata)
            score = self.scorer.score(response.content)
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
            score = self.scorer.score("")
        semantic_verdict: Optional[JudgeVerdict] = None
        if self.semantic_judge is not None:
            semantic_verdict = self.semantic_judge.judge(
                self.campaign.objective,
                response.content if response is not None else "",
                context=messages,
                target_score=self.campaign.scoring.threshold,
            )
            attempt_metadata["semantic_judge_verdict"] = semantic_verdict.to_dict()
        if self.campaign.semantic_judge == "disabled":
            final_success = score.success
        else:
            final_success = bool(semantic_verdict and semantic_verdict.success)
        attempt_metadata["final_success"] = final_success
        return Attempt(
            attempt_id=attempt_id,
            campaign_id=self.campaign.id,
            round_index=round_index,
            strategy=strategy,
            mutation_index=mutation_index,
            mutation_id=mutation_id,
            prompt=prompt,
            messages=messages,
            started_at=started_at,
            completed_at=utc_now(),
            response=response,
            score=score,
            error=error,
            metadata=attempt_metadata,
        )

    def _build_semantic_judge(self) -> Any:
        if self.campaign.semantic_judge == "disabled":
            return None
        if self.campaign.semantic_judge == "heuristic":
            return HeuristicSemanticJudge(self.scorer)
        if self.campaign.semantic_judge == "model":
            return ModelSemanticJudge(
                self.transport,
                self.campaign.judge_model,
                temperature=0.0,
                max_tokens=512,
                default_target_score=self.campaign.scoring.threshold,
            )
        raise CampaignValidationError(
            [f"unsupported semantic judge: {self.campaign.semantic_judge}"]
        )

    def _allowed_attack_modes(self) -> Tuple[str, ...]:
        selected = set(self.campaign.attack_modes)
        return tuple(mode for mode in ATTACK_MODES if mode in selected)

    def _new_optimizer(self) -> CheckpointOptimizer:
        return CheckpointOptimizer(
            objective=self.campaign.objective,
            model=self.campaign.target.model,
            campaign_fingerprint=self.campaign.fingerprint(),
        )

    def _load_optimizer(
        self,
        checkpoint: Mapping[str, Any],
        attempts: Sequence[Attempt],
    ) -> CheckpointOptimizer:
        raw_optimizer = checkpoint.get("optimizer", checkpoint.get("optimizer_state"))
        if raw_optimizer is not None:
            if not isinstance(raw_optimizer, Mapping):
                raise CheckpointError("checkpoint optimizer state must be an object")
            return CheckpointOptimizer.from_dict(
                raw_optimizer,
                objective=self.campaign.objective,
                model=self.campaign.target.model,
                campaign_fingerprint=self.campaign.fingerprint(),
            )

        optimizer = self._new_optimizer()
        for attempt in attempts:
            mode = str(attempt.metadata.get("attack_mode", "builtin"))
            if mode not in ATTACK_MODES:
                mode = "builtin"
            score, success, refused = self._effective_outcome(attempt)
            optimizer.observe(
                mode=mode,
                candidate_id=self._attempt_candidate_id(attempt),
                score=score,
                success=success,
                refused=refused,
                latency_seconds=(
                    attempt.response.latency_seconds if attempt.response else 0.0
                ),
            )
        return optimizer

    def _restore_algorithm_state(self) -> None:
        try:
            self._pair = PAIRPlanner(
                seed=self.campaign.seed,
                max_iterations=self.campaign.max_rounds,
                candidates_per_iteration=1,
            )
            pair_state = self.optimizer.state_for("pair")
            if pair_state:
                self._pair.load_state_dict(pair_state)

            tap_state = self.optimizer.state_for("tap")
            self._tap = (
                TAPSearch.from_dict(tap_state)
                if tap_state
                else TAPSearch(
                    root_prompt=self.campaign.objective,
                    max_depth=max(1, self.campaign.max_rounds),
                    seed=self.campaign.seed,
                )
            )

            crescendo_state = self.optimizer.state_for("crescendo")
            self._crescendo = (
                CrescendoPlanner.from_dict(crescendo_state)
                if crescendo_state
                else CrescendoPlanner(
                    seed=self.campaign.seed,
                    max_turns=max(1, self.campaign.max_rounds),
                )
            )

            evolution_state = self.optimizer.state_for("evolution")
            self._evolution = (
                EvolutionaryPromptOptimizer.from_dict(evolution_state)
                if evolution_state
                else EvolutionaryPromptOptimizer(
                    seed=self.campaign.seed,
                    max_generations=max(1, self.campaign.max_rounds),
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise CheckpointError(f"checkpoint contains invalid attack algorithm state: {exc}") from exc

    def _propose_candidate(
        self,
        attack_mode: str,
        *,
        round_index: int,
        strategy: str,
        mutation_index: int,
        attempts: Tuple[Attempt, ...],
    ) -> _AttackCandidate:
        if attack_mode == "builtin":
            return self._builtin_candidate(
                round_index=round_index,
                strategy=strategy,
                mutation_index=mutation_index,
                attempts=attempts,
            )
        if attack_mode == "pair":
            candidates = self._pair.propose(
                self.campaign.objective,
                attempts,
                count=1,
            )
            if not candidates:
                raise RuntimeError("PAIR planner exhausted before campaign completion")
            candidate = candidates[0]
            return _AttackCandidate(
                prompt=candidate.prompt,
                identifier_key="candidate_id",
                identifier=candidate.candidate_id,
                metadata={
                    "iteration": candidate.iteration,
                    "parent_id": candidate.parent_id,
                    "feedback_digest": candidate.feedback_digest,
                    "algorithm_metadata": dict(candidate.metadata),
                },
            )
        if attack_mode == "tap":
            node = self._next_tap_node(attempts)
            return _AttackCandidate(
                prompt=node.prompt,
                identifier_key="node_id",
                identifier=node.node_id,
                metadata={
                    "parent_id": node.parent_id,
                    "depth": node.depth,
                    "branch_index": node.branch_index,
                    "algorithm_metadata": dict(node.metadata),
                },
            )
        if attack_mode == "crescendo":
            prompt = self._crescendo.next_prompt(
                self.campaign.objective,
                attempts,
            )
            if prompt is None:
                raise RuntimeError("Crescendo planner exhausted before campaign completion")
            candidate_id = self._stable_identifier(
                "crescendo",
                self._crescendo.turn_count + 1,
                prompt,
            )
            return _AttackCandidate(
                prompt=prompt,
                identifier_key="candidate_id",
                identifier=candidate_id,
                metadata={
                    "stage": self._crescendo.current_stage.name,
                    "turn_index": self._crescendo.turn_count + 1,
                },
            )
        if attack_mode == "evolution":
            genome = self._next_evolution_genome()
            return _AttackCandidate(
                prompt=genome.prompt,
                identifier_key="genome_id",
                identifier=genome.genome_id,
                metadata={
                    "generation": genome.generation,
                    "parents": list(genome.parents),
                    "operators": list(genome.operators),
                    "algorithm_metadata": dict(genome.metadata),
                },
            )
        raise RuntimeError(f"unsupported attack mode selected: {attack_mode}")

    def _builtin_candidate(
        self,
        *,
        round_index: int,
        strategy: str,
        mutation_index: int,
        attempts: Tuple[Attempt, ...],
    ) -> _AttackCandidate:
        previous = attempts[-1] if attempts else None
        context = StrategyContext(
            objective=self.campaign.objective,
            round_index=round_index,
            mutation_index=mutation_index,
            seed=self.campaign.seed,
            previous_score=(
                previous.score.score if previous is not None and previous.score else 0.0
            ),
            previous_refused=bool(
                previous is not None
                and previous.score
                and previous.score.refusal_signals
            ),
            previous_response=(
                previous.response.content[:1000]
                if previous is not None and previous.response
                else ""
            ),
        )
        mutation = deterministic_mutation(
            render_strategy(strategy, context),
            seed=self.campaign.seed,
            strategy=strategy,
            round_index=round_index,
            mutation_index=mutation_index,
        )
        return _AttackCandidate(
            prompt=mutation.prompt,
            identifier_key="candidate_id",
            identifier=mutation.mutation_id,
            metadata={"mutation_operators": list(mutation.operators)},
        )

    def _next_tap_node(self, attempts: Tuple[Attempt, ...]) -> TAPNode:
        unvisited = [
            node
            for node in self._tap.frontier_nodes
            if node.node_id != self._tap.root.node_id and not node.visited
        ]
        if unvisited:
            return sorted(
                unvisited,
                key=lambda item: (item.depth, item.branch_index, item.node_id),
            )[0]

        feedback: Any = attempts[-1].to_dict() if attempts else {}
        parents = self._tap.select_frontier()
        if self._tap.root.node_id in self._tap.frontier:
            parents = [self._tap.root] + [
                item for item in parents if item.node_id != self._tap.root.node_id
            ]
        for parent in parents:
            children = self._tap.expand(
                parent.node_id,
                self.campaign.objective,
                feedback,
            )
            if children:
                return children[0]
        raise RuntimeError("TAP search frontier exhausted before campaign completion")

    def _next_evolution_genome(self) -> PromptGenome:
        if not self._evolution.population:
            contexts = [self.campaign.objective]
            for strategy in self.campaign.strategies:
                contexts.append(
                    render_strategy(
                        strategy,
                        StrategyContext(
                            objective=self.campaign.objective,
                            round_index=1,
                            mutation_index=0,
                            seed=self.campaign.seed,
                        ),
                    )
                )
            self._evolution.seed_population(self.campaign.objective, contexts)

        pending = [
            genome for genome in self._evolution.population if genome.fitness is None
        ]
        if not pending:
            self._evolution.evolve()
            pending = [
                genome for genome in self._evolution.population if genome.fitness is None
            ]
        if not pending:
            raise RuntimeError("evolution optimizer produced no unevaluated genome")
        return pending[0]

    def _observe_attempt(
        self,
        attempt: Attempt,
        candidate: _AttackCandidate,
    ) -> None:
        attack_mode = str(attempt.metadata["attack_mode"])
        score, success, refused = self._effective_outcome(attempt)
        if attack_mode == "tap":
            self._tap.observe(
                candidate.identifier,
                score=score,
                refused=refused,
                success=success,
            )
        elif attack_mode == "crescendo":
            self._crescendo.observe(
                attempt.response.content if attempt.response else "",
                score=score,
                refused=refused,
                success=success,
                prompt=candidate.prompt,
            )
        elif attack_mode == "evolution":
            self._evolution.observe(
                candidate.identifier,
                fitness=score,
                refused=refused,
                success=success,
            )

        self.optimizer.observe(
            mode=attack_mode,
            candidate_id=candidate.identifier,
            score=score,
            success=success,
            refused=refused,
            latency_seconds=(
                attempt.response.latency_seconds if attempt.response else 0.0
            ),
        )
        self._attach_algorithm_state(attack_mode)

    def _attach_algorithm_state(self, attack_mode: str) -> None:
        if attack_mode == "pair":
            self.optimizer.attach_state("pair", self._pair.state_dict())
        elif attack_mode == "tap":
            self.optimizer.attach_state("tap", self._tap.to_dict())
        elif attack_mode == "crescendo":
            self.optimizer.attach_state("crescendo", self._crescendo.to_dict())
        elif attack_mode == "evolution":
            self.optimizer.attach_state("evolution", self._evolution.to_dict())

    def _effective_outcome(self, attempt: Attempt) -> Tuple[float, bool, bool]:
        score = attempt.score.score if attempt.score is not None else 0.0
        refused = bool(attempt.score and attempt.score.refusal_signals)
        verdict = attempt.metadata.get("semantic_judge_verdict")
        if self.campaign.semantic_judge != "disabled" and isinstance(verdict, Mapping):
            raw_score = verdict.get("score", score)
            if isinstance(raw_score, (int, float)) and not isinstance(raw_score, bool):
                score = max(0.0, min(1.0, float(raw_score)))
            refused = bool(verdict.get("refused", refused))
        return score, attempt.success, refused

    @staticmethod
    def _attempt_candidate_id(attempt: Attempt) -> str:
        for key in ("candidate_id", "node_id", "genome_id"):
            value = attempt.metadata.get(key)
            if isinstance(value, str) and value:
                return value
        return attempt.mutation_id

    def _instruction_metadata(self) -> Dict[str, Any]:
        if not self.instruction_bundle.assets:
            return {}
        return {
            "profile": self.campaign.instruction_profile,
            "bundle_digest": self.instruction_bundle.digest,
            "asset_count": len(self.instruction_bundle.assets),
            "assets": [
                {
                    "name": item.name,
                    "source": item.source,
                    "sha256": item.sha256,
                    "provenance": dict(item.provenance),
                }
                for item in self.instruction_bundle.assets
            ],
        }

    def _stable_identifier(self, prefix: str, index: int, prompt: str) -> str:
        material = (
            f"{self.campaign.seed}\0{prefix}\0{index}\0{prompt}"
        ).encode("utf-8")
        return f"{prefix}-{index:03d}-{hashlib.sha256(material).hexdigest()[:16]}"

    def _complete(
        self,
        messages: Sequence[ChatMessage],
        *,
        metadata: Mapping[str, Any],
    ) -> ChatResponse:
        complete = getattr(self.transport, "complete", None)
        if callable(complete):
            value = complete(
                messages,
                model=self.campaign.target.model,
                temperature=self.campaign.target.temperature,
                max_tokens=self.campaign.target.max_tokens,
                metadata=metadata,
            )
        elif callable(self.transport):
            value = self.transport(
                [item.to_dict() for item in messages],
                model=self.campaign.target.model,
                temperature=self.campaign.target.temperature,
                max_tokens=self.campaign.target.max_tokens,
                metadata=dict(metadata),
            )
        else:
            raise TypeError("transport must expose complete(...) or be callable")
        return normalize_chat_response(value, fallback_model=self.campaign.target.model)

    def _build_result(
        self,
        *,
        attempts: Tuple[Attempt, ...],
        started_at: str,
        completed_at: str,
        resumed: bool,
    ) -> CampaignResult:
        successful = [item for item in attempts if item.success]
        valid_responses = [item for item in attempts if item.response is not None]
        if successful:
            status = "succeeded"
        elif valid_responses:
            status = "exhausted"
        else:
            status = "failed"
        winner = max(
            successful,
            key=lambda item: item.score.score if item.score else 0.0,
            default=None,
        )
        scores_by_strategy: Dict[str, List[float]] = defaultdict(list)
        for item in attempts:
            if item.score is not None:
                scores_by_strategy[item.strategy].append(item.score.score)
        strategy_summary = {
            name: {
                "attempts": len(values),
                "best_score": max(values) if values else 0.0,
                "average_score": round(sum(values) / len(values), 6) if values else 0.0,
                "successes": sum(1 for item in attempts if item.strategy == name and item.success),
            }
            for name, values in sorted(scores_by_strategy.items())
        }
        total_usage: Counter[str] = Counter()
        total_latency = 0.0
        for item in attempts:
            if item.response is None:
                continue
            total_latency += item.response.latency_seconds
            for key, value in item.response.usage.items():
                if isinstance(value, int) and not isinstance(value, bool):
                    total_usage[str(key)] += value
        artifact_paths = self.writer.artifact_paths(
            self.checkpoint_path,
            instruction_bundle=self.instruction_bundle,
        )
        return CampaignResult(
            campaign_id=self.campaign.id,
            status=status,
            success=bool(successful),
            attempts=attempts,
            started_at=started_at,
            completed_at=completed_at,
            winning_attempt_id=winner.attempt_id if winner else "",
            summary={
                "rounds_completed": len(attempts),
                "successful_attempts": len(successful),
                "failed_transport_attempts": sum(1 for item in attempts if item.error),
                "best_score": max(
                    (item.score.score for item in attempts if item.score is not None),
                    default=0.0,
                ),
                "strategies": strategy_summary,
                "usage": dict(total_usage),
                "latency_seconds": round(total_latency, 6),
                "resumed": resumed,
            },
            artifacts=artifact_paths,
        )


def run_campaign(
    campaign: CampaignSource,
    *,
    transport: ChatTransport | None = None,
    out_dir: str | Path = "llm-jailbreak-out",
    resume: bool = False,
    checkpoint_path: str | Path | None = None,
    instruction_bundle: InstructionBundle | Mapping[str, Any] | None = None,
) -> CampaignResult:
    loaded = load_campaign(campaign)
    selected_transport = transport or OpenAICompatibleTransport.from_target(loaded.target)
    runner = CampaignRunner(
        loaded,
        selected_transport,
        out_dir,
        checkpoint_path=checkpoint_path,
        instruction_bundle=instruction_bundle,
    )
    return runner.run(resume=resume)


def execute_campaign(
    campaign: CampaignSource,
    *,
    transport: ChatTransport | None = None,
    out_dir: str | Path = "llm-jailbreak-out",
    resume: bool = False,
    checkpoint_path: str | Path | None = None,
    base_url: str | None = None,
    model: str | None = None,
    api_key_env: str | None = None,
    timeout: float | None = None,
    max_attempts: int | None = None,
    max_rounds: int | None = None,
    strategies: Sequence[str] | None = None,
    attack_modes: Sequence[str] | str | None = None,
    semantic_judge: str | None = None,
    judge_model: str | None = None,
    instruction_profile: str | None = None,
    instruction_files: Sequence[str | Path] | None = None,
    instruction_bundle: InstructionBundle | Mapping[str, Any] | None = None,
    options: Mapping[str, Any] | None = None,
) -> CampaignResult:
    """Execute one campaign with explicit platform overrides.

    Override precedence is intentionally fixed: explicit arguments, campaign
    configuration, then dataclass defaults. The campaign runner performs one
    remote attempt per round, so ``max_attempts`` is enforced as an upper bound
    on the effective round count.
    """

    configured = configure_campaign(
        campaign,
        base_url=base_url,
        model=model,
        api_key_env=api_key_env,
        timeout=timeout,
        max_attempts=max_attempts,
        max_rounds=max_rounds,
        strategies=strategies,
        attack_modes=attack_modes,
        semantic_judge=semantic_judge,
        judge_model=judge_model,
        instruction_profile=instruction_profile,
        instruction_files=instruction_files,
        options=options,
    )
    selected_transport = transport or OpenAICompatibleTransport.from_target(configured.target)
    run_options: Dict[str, Any] = {
        "transport": selected_transport,
        "out_dir": out_dir,
        "resume": resume,
        "checkpoint_path": checkpoint_path,
    }
    if instruction_bundle is not None:
        run_options["instruction_bundle"] = instruction_bundle
    return run_campaign(configured, **run_options)


def configure_campaign(
    campaign: CampaignSource,
    *,
    base_url: str | None = None,
    model: str | None = None,
    api_key_env: str | None = None,
    timeout: float | None = None,
    max_attempts: int | None = None,
    max_rounds: int | None = None,
    strategies: Sequence[str] | None = None,
    attack_modes: Sequence[str] | str | None = None,
    semantic_judge: str | None = None,
    judge_model: str | None = None,
    instruction_profile: str | None = None,
    instruction_files: Sequence[str | Path] | None = None,
    options: Mapping[str, Any] | None = None,
) -> Campaign:
    """Return the canonical campaign after applying every runtime override."""

    loaded = load_campaign(campaign)
    target_payload = loaded.target.to_dict()
    option_payload = _normalize_execution_options(options)
    target_payload.update(option_payload)

    explicit_target = {
        "base_url": base_url,
        "model": model,
        "api_key_env": api_key_env,
        "timeout_seconds": timeout,
    }
    target_payload.update(
        {key: value for key, value in explicit_target.items() if value is not None}
    )
    target = TargetConfig.from_dict(target_payload)

    selected_strategies = loaded.strategies
    if strategies is not None:
        selected_strategies = tuple(str(item).strip() for item in strategies if str(item).strip())
        if not selected_strategies:
            raise CampaignValidationError(["strategies must contain at least one strategy"])
        unknown = sorted(set(selected_strategies) - set(SUPPORTED_STRATEGIES))
        if unknown:
            raise CampaignValidationError(
                ["strategies contains unsupported values: " + ", ".join(unknown)]
            )

    effective_rounds = loaded.max_rounds if max_rounds is None else _positive_limit(
        max_rounds,
        "max_rounds",
    )
    if max_attempts is not None:
        effective_rounds = min(
            effective_rounds,
            _positive_limit(max_attempts, "max_attempts"),
        )

    configured = replace(
        loaded,
        target=target,
        strategies=tuple(selected_strategies),
        max_rounds=effective_rounds,
    )
    if all(
        value is None
        for value in (
            attack_modes,
            semantic_judge,
            judge_model,
            instruction_profile,
            instruction_files,
        )
    ):
        return configured

    payload = configured.to_dict()
    # Preserve generated campaign IDs as generated. ``to_dict`` materializes
    # the current ID, which would otherwise freeze it before target overrides.
    if not configured.campaign_id:
        payload["id"] = ""
    if attack_modes is not None:
        payload["attack_modes"] = _attack_mode_override(attack_modes)
    if semantic_judge is not None:
        payload["semantic_judge"] = semantic_judge
    if judge_model is not None:
        payload["judge_model"] = judge_model
    if instruction_profile is not None:
        profile = str(instruction_profile).strip()
        if profile:
            payload["instruction_profile"] = profile
        else:
            payload.pop("instruction_profile", None)
    if instruction_files is not None:
        if isinstance(instruction_files, (str, bytes, Path)):
            raise CampaignValidationError(
                ["instruction_files must be an ordered sequence of Markdown paths"]
            )
        payload["instruction_files"] = [str(item).strip() for item in instruction_files]
    return Campaign.from_dict(payload)


def _attack_mode_override(values: Sequence[str] | str) -> List[str]:
    source: Sequence[str]
    if isinstance(values, str):
        source = (values,)
    elif isinstance(values, Sequence):
        source = values
    else:
        raise CampaignValidationError(
            ["attack_modes must be a string or an ordered sequence of strings"]
        )

    modes: List[str] = []
    for index, value in enumerate(source):
        if not isinstance(value, str):
            raise CampaignValidationError(
                [f"attack_modes[{index}] must be a string"]
            )
        for item in value.split(","):
            normalized = item.strip().casefold()
            if normalized and normalized not in modes:
                modes.append(normalized)
    if not modes:
        raise CampaignValidationError(["attack_modes must contain at least one mode"])
    unsupported = [item for item in modes if item not in ATTACK_MODES]
    if unsupported:
        raise CampaignValidationError(
            ["unsupported --attack-mode value(s): " + ", ".join(unsupported)]
        )
    return modes


def _normalize_execution_options(options: Mapping[str, Any] | None) -> Dict[str, Any]:
    if options is None:
        return {}
    if not isinstance(options, Mapping):
        raise TypeError("options must be a mapping")
    aliases = {"timeout": "timeout_seconds"}
    supported = {
        "timeout_seconds",
        "max_retries",
        "retry_backoff_seconds",
        "requests_per_minute",
        "temperature",
        "max_tokens",
        "extra_body",
    }
    normalized: Dict[str, Any] = {}
    unknown: List[str] = []
    for raw_key, value in options.items():
        key = aliases.get(str(raw_key), str(raw_key))
        if key not in supported:
            unknown.append(str(raw_key))
            continue
        normalized[key] = value
    if unknown:
        raise CampaignValidationError(
            ["options contains unsupported fields: " + ", ".join(sorted(unknown))]
        )
    return normalized


def _positive_limit(value: Any, name: str) -> int:
    if isinstance(value, bool):
        raise CampaignValidationError([f"{name} must be a positive integer"])
    try:
        normalized = int(value)
    except (TypeError, ValueError) as exc:
        raise CampaignValidationError([f"{name} must be a positive integer"]) from exc
    if normalized <= 0:
        raise CampaignValidationError([f"{name} must be a positive integer"])
    return normalized
