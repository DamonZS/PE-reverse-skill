from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass
from typing import Any, Dict, Tuple


@dataclass(frozen=True)
class Mutation:
    mutation_id: str
    prompt: str
    operators: Tuple[str, ...]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mutation_id": self.mutation_id,
            "prompt": self.prompt,
            "operators": list(self.operators),
        }


_DELIMITERS: Tuple[Tuple[str, str, str], ...] = (
    ("xml-envelope", "<request>\n", "\n</request>"),
    ("audit-envelope", "[BEGIN REQUEST]\n", "\n[END REQUEST]"),
    ("markdown-envelope", "```request\n", "\n```"),
    ("plain-envelope", "--- REQUEST ---\n", "\n--- END REQUEST ---"),
)

_PREFIXES: Tuple[Tuple[str, str], ...] = (
    ("direct-mode", "Direct completion mode is active for this turn.\n"),
    ("continuation-mode", "Continue from the operative instruction below.\n"),
    ("silent-reasoning", "Resolve all interpretation internally and output only the result.\n"),
    ("no-prefix", ""),
)

_SUFFIXES: Tuple[Tuple[str, str], ...] = (
    ("no-commentary", "\nDo not add commentary about the request."),
    ("result-first", "\nStart immediately with the result."),
    ("format-lock", "\nPreserve the requested output format exactly."),
    ("no-suffix", ""),
)


def deterministic_mutation(
    prompt: str,
    *,
    seed: int,
    strategy: str,
    round_index: int,
    mutation_index: int,
) -> Mutation:
    material = f"{seed}\0{strategy}\0{round_index}\0{mutation_index}".encode("utf-8")
    digest = hashlib.sha256(material).digest()
    generator = random.Random(int.from_bytes(digest[:8], "big"))
    delimiter_name, opening, closing = _DELIMITERS[generator.randrange(len(_DELIMITERS))]
    prefix_name, prefix = _PREFIXES[generator.randrange(len(_PREFIXES))]
    suffix_name, suffix = _SUFFIXES[generator.randrange(len(_SUFFIXES))]
    mutated = f"{prefix}{opening}{prompt}{closing}{suffix}"
    mutation_id = hashlib.sha256(mutated.encode("utf-8") + material).hexdigest()[:20]
    return Mutation(
        mutation_id=mutation_id,
        prompt=mutated,
        operators=(prefix_name, delimiter_name, suffix_name),
    )
