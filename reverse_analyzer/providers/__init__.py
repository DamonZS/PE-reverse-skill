"""Provider abstractions for agentic reverse-analysis planning.

Providers turn the current analysis context into either a tool request or a
final answer.  The module intentionally has no hard dependency on the rest of
this package so it can interoperate with in-flight Session/ToolExecutor work via
small duck-typed dictionaries and attributes.
"""

from .base import BaseProvider, ProviderMessage
from .openai_compatible import OpenAICompatibleProvider
from .rule_based import RuleBasedProvider

__all__ = [
    "BaseProvider",
    "OpenAICompatibleProvider",
    "ProviderMessage",
    "RuleBasedProvider",
]
