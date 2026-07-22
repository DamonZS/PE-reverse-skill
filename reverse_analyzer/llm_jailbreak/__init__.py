"""Public API for the standalone adaptive model-jailbreak campaign engine."""

from .campaign import (
    CampaignRunner,
    configure_campaign,
    execute_campaign,
    load_campaign,
    run_campaign,
)
from .acceptance import PromotionResult, promote_output
from .benchmark import BenchmarkConfig, BenchmarkPricing, run_benchmark
from .crescendo import CrescendoPlanner, CrescendoStage, CrescendoTurn
from .evolution import EvolutionaryPromptOptimizer, PromptGenome
from .doctor import DoctorError, DoctorResult, run_doctor
from .instruction_assets import (
    InstructionAsset,
    InstructionBundle,
    list_instruction_profiles,
    load_instruction_bundle,
    resolve_instruction_profile,
)
from .judge import (
    CompositeSemanticJudge,
    HeuristicSemanticJudge,
    JudgeVerdict,
    ModelSemanticJudge,
    SemanticJudge,
)
from .models import (
    Attempt,
    Campaign,
    CampaignResult,
    CampaignValidationError,
    ChatMessage,
    ChatResponse,
    CheckpointError,
    ScoreResult,
    ScoringPolicy,
    SUPPORTED_ATTACK_MODES,
    SUPPORTED_SEMANTIC_JUDGES,
    SUPPORTED_STRATEGIES,
    TargetConfig,
)
from .mutations import Mutation, deterministic_mutation
from .optimizer import (
    ATTACK_MODES,
    CheckpointOptimizer,
    OptimizationObservation,
    OptimizationRecommendation,
)
from .pair import PAIRCandidate, PAIRPlanner
from .scorer import ResponseScorer
from .strategies import BUILTIN_STRATEGIES, StrategyContext, get_strategy, render_strategy
from .tap import TAPNode, TAPSearch
from .templates import TEMPLATE_FILES, initialize_workspace
from .transport import (
    ChatTransport,
    OpenAICompatibleTransport,
    TransportConfigurationError,
    TransportError,
    TransportResponseError,
)


__all__ = [
    "Attempt",
    "ATTACK_MODES",
    "BUILTIN_STRATEGIES",
    "BenchmarkConfig",
    "BenchmarkPricing",
    "Campaign",
    "CampaignResult",
    "CampaignRunner",
    "CampaignValidationError",
    "ChatMessage",
    "ChatResponse",
    "ChatTransport",
    "CheckpointError",
    "CheckpointOptimizer",
    "CompositeSemanticJudge",
    "CrescendoPlanner",
    "CrescendoStage",
    "CrescendoTurn",
    "EvolutionaryPromptOptimizer",
    "DoctorError",
    "DoctorResult",
    "HeuristicSemanticJudge",
    "InstructionAsset",
    "InstructionBundle",
    "JudgeVerdict",
    "ModelSemanticJudge",
    "Mutation",
    "OpenAICompatibleTransport",
    "OptimizationObservation",
    "OptimizationRecommendation",
    "PAIRCandidate",
    "PAIRPlanner",
    "PromptGenome",
    "PromotionResult",
    "ResponseScorer",
    "SUPPORTED_ATTACK_MODES",
    "SUPPORTED_SEMANTIC_JUDGES",
    "SUPPORTED_STRATEGIES",
    "ScoreResult",
    "ScoringPolicy",
    "StrategyContext",
    "SemanticJudge",
    "TAPNode",
    "TAPSearch",
    "TEMPLATE_FILES",
    "TargetConfig",
    "TransportConfigurationError",
    "TransportError",
    "TransportResponseError",
    "deterministic_mutation",
    "configure_campaign",
    "execute_campaign",
    "get_strategy",
    "initialize_workspace",
    "list_instruction_profiles",
    "load_campaign",
    "load_instruction_bundle",
    "render_strategy",
    "resolve_instruction_profile",
    "promote_output",
    "run_doctor",
    "run_campaign",
    "run_benchmark",
]
