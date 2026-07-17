"""Transport-independent Tree of Attacks with Pruning search primitives."""

from __future__ import annotations

import hashlib
import inspect
import json
import math
from dataclasses import dataclass, field, replace
from numbers import Real
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple, Union


MutationOutput = Union[str, Mapping[str, Any]]
Mutator = Callable[..., MutationOutput]


def _json_mapping(value: Any, field_name: str) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{field_name} must be a mapping")
    try:
        encoded = json.dumps(
            dict(value),
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
        )
        normalized = json.loads(encoded)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be JSON serializable: {exc}") from exc
    if not isinstance(normalized, dict):
        raise ValueError(f"{field_name} must serialize to an object")
    return normalized


def _integer(value: Any, field_name: str, *, minimum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        qualifier = "positive" if minimum == 1 else "non-negative"
        raise ValueError(f"{field_name} must be a {qualifier} integer")
    return value


def _score(value: Any, field_name: str = "score") -> float:
    if isinstance(value, bool) or not isinstance(value, Real):
        raise ValueError(f"{field_name} must be a finite number")
    normalized = float(value)
    if not math.isfinite(normalized):
        raise ValueError(f"{field_name} must be a finite number")
    return normalized


@dataclass(frozen=True)
class TAPNode:
    """One immutable prompt candidate and its local search observations."""

    node_id: str
    prompt: str
    parent_id: Optional[str] = None
    depth: int = 0
    branch_index: int = 0
    score: float = 0.0
    refused: bool = False
    visited: bool = False
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.node_id, str) or not self.node_id:
            raise ValueError("node_id must be a non-empty string")
        if not isinstance(self.prompt, str) or not self.prompt.strip():
            raise ValueError("prompt must be a non-empty string")
        if self.parent_id is not None and (
            not isinstance(self.parent_id, str) or not self.parent_id
        ):
            raise ValueError("parent_id must be null or a non-empty string")
        _integer(self.depth, "depth", minimum=0)
        _integer(self.branch_index, "branch_index", minimum=0)
        normalized_score = _score(self.score)
        if not isinstance(self.refused, bool):
            raise ValueError("refused must be a boolean")
        if not isinstance(self.visited, bool):
            raise ValueError("visited must be a boolean")
        normalized_metadata = _json_mapping(self.metadata, "metadata")
        if "success" in normalized_metadata and not isinstance(
            normalized_metadata["success"], bool
        ):
            raise ValueError("metadata.success must be a boolean")
        object.__setattr__(self, "score", normalized_score)
        object.__setattr__(self, "metadata", normalized_metadata)

    @property
    def success(self) -> bool:
        return self.metadata.get("success") is True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "prompt": self.prompt,
            "parent_id": self.parent_id,
            "depth": self.depth,
            "branch_index": self.branch_index,
            "score": self.score,
            "refused": self.refused,
            "visited": self.visited,
            "metadata": _json_mapping(self.metadata, "metadata"),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "TAPNode":
        if not isinstance(value, Mapping):
            raise ValueError("TAP node must be a mapping")
        fields = {
            "node_id",
            "prompt",
            "parent_id",
            "depth",
            "branch_index",
            "score",
            "refused",
            "visited",
            "metadata",
        }
        unknown = sorted(str(key) for key in set(value) - fields)
        missing = sorted(str(key) for key in fields - set(value))
        if unknown:
            raise ValueError("TAP node contains unknown fields: " + ", ".join(unknown))
        if missing:
            raise ValueError("TAP node is missing fields: " + ", ".join(missing))
        try:
            return cls(
                node_id=value["node_id"],
                prompt=value["prompt"],
                parent_id=value["parent_id"],
                depth=value["depth"],
                branch_index=value["branch_index"],
                score=value["score"],
                refused=value["refused"],
                visited=value["visited"],
                metadata=value["metadata"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"invalid TAP node: {exc}") from exc


class TAPSearch:
    """Maintain a deterministic, serializable TAP candidate frontier."""

    STATE_VERSION = 1
    DEFAULT_BRANCH_FACTOR = 3
    DEFAULT_BEAM_WIDTH = 3
    DEFAULT_MAX_DEPTH = 3

    _DIRECTIVES: Tuple[Tuple[str, str], ...] = (
        (
            "direct",
            "Make the request more direct and require only the requested result.",
        ),
        (
            "context",
            "Restate the active context, then make the objective the final instruction.",
        ),
        (
            "format",
            "Preserve the objective while changing its framing and output constraints.",
        ),
        (
            "feedback",
            "Address the feedback explicitly without repeating the previous wording.",
        ),
        (
            "minimal",
            "Remove commentary and reduce the candidate to an imperative request.",
        ),
    )

    def __init__(
        self,
        root_prompt: str,
        *,
        branch_factor: int = DEFAULT_BRANCH_FACTOR,
        beam_width: int = DEFAULT_BEAM_WIDTH,
        max_depth: int = DEFAULT_MAX_DEPTH,
        seed: int = 0,
    ) -> None:
        if not isinstance(root_prompt, str) or not root_prompt.strip():
            raise ValueError("root_prompt must be a non-empty string")
        self.branch_factor = _integer(branch_factor, "branch_factor", minimum=1)
        self.beam_width = _integer(beam_width, "beam_width", minimum=1)
        self.max_depth = _integer(max_depth, "max_depth", minimum=0)
        if isinstance(seed, bool) or not isinstance(seed, int):
            raise ValueError("seed must be an integer")
        self.seed = seed
        self.root_id = "root"
        root = TAPNode(node_id=self.root_id, prompt=root_prompt)
        self.nodes: Dict[str, TAPNode] = {root.node_id: root}
        self.frontier: List[str] = [root.node_id]
        self.best_id: Optional[str] = None
        self._prompt_ids: Dict[str, str] = {root.prompt: root.node_id}

    @property
    def root(self) -> TAPNode:
        return self.nodes[self.root_id]

    @property
    def best(self) -> Optional[TAPNode]:
        return self.nodes[self.best_id] if self.best_id is not None else None

    @property
    def frontier_nodes(self) -> Tuple[TAPNode, ...]:
        return tuple(self._frontier_nodes())

    def expand(
        self,
        node_id: str,
        objective: str,
        feedback: Any,
        mutator: Optional[Mutator] = None,
    ) -> List[TAPNode]:
        """Expand one node once and append unique children to the frontier.

        Mutators may consume named candidate context or the positional sequence
        prompt, objective, feedback, branch_index, seed. Each call must return
        a prompt string or a mapping containing prompt and optional metadata.
        """

        parent = self._get_node(node_id)
        if not isinstance(objective, str):
            raise ValueError("objective must be a string")
        if mutator is not None and not callable(mutator):
            raise ValueError("mutator must be callable")

        if parent.depth >= self.max_depth or self._children_of(parent.node_id):
            self._remove_from_frontier(parent.node_id)
            return []

        candidates: List[TAPNode] = []
        known_prompts = set(self._prompt_ids)
        known_ids = set(self.nodes)
        for branch_index in range(self.branch_factor):
            if mutator is None:
                output = self._default_mutation(
                    parent,
                    objective=objective,
                    feedback=feedback,
                    branch_index=branch_index,
                )
            else:
                output = self._invoke_mutator(
                    mutator,
                    parent=parent,
                    objective=objective,
                    feedback=feedback,
                    branch_index=branch_index,
                )
            prompt, metadata = self._candidate_output(output, branch_index)
            if prompt in known_prompts:
                continue
            child_id = self._child_id(parent, branch_index, prompt)
            if child_id in known_ids:
                raise ValueError(f"generated duplicate TAP node id: {child_id}")
            child = TAPNode(
                node_id=child_id,
                prompt=prompt,
                parent_id=parent.node_id,
                depth=parent.depth + 1,
                branch_index=branch_index,
                metadata=metadata,
            )
            candidates.append(child)
            known_prompts.add(prompt)
            known_ids.add(child_id)

        self._remove_from_frontier(parent.node_id)
        for child in candidates:
            self.nodes[child.node_id] = child
            self.frontier.append(child.node_id)
            self._prompt_ids[child.prompt] = child.node_id
        return candidates

    def observe(
        self,
        node_id: str,
        score: Real,
        refused: bool,
        success: bool = False,
    ) -> TAPNode:
        node = self._get_node(node_id)
        normalized_score = _score(score)
        if not isinstance(refused, bool):
            raise ValueError("refused must be a boolean")
        if not isinstance(success, bool):
            raise ValueError("success must be a boolean")
        metadata = dict(node.metadata)
        metadata["success"] = success
        updated = replace(
            node,
            score=normalized_score,
            refused=refused,
            visited=True,
            metadata=metadata,
        )
        self.nodes[node_id] = updated
        self._recompute_best()
        return updated

    def select_frontier(self) -> List[TAPNode]:
        return sorted(self._frontier_nodes(), key=self._priority)[: self.beam_width]

    def prune(self) -> List[TAPNode]:
        selected = self.select_frontier()
        self.frontier = [node.node_id for node in selected]
        return selected

    def to_dict(self) -> Dict[str, Any]:
        self._validate_state()
        return {
            "version": self.STATE_VERSION,
            "branch_factor": self.branch_factor,
            "beam_width": self.beam_width,
            "max_depth": self.max_depth,
            "seed": self.seed,
            "root_id": self.root_id,
            "frontier": list(self.frontier),
            "best_id": self.best_id,
            "nodes": [node.to_dict() for node in self.nodes.values()],
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "TAPSearch":
        if not isinstance(value, Mapping):
            raise ValueError("TAP search state must be a mapping")
        fields = {
            "version",
            "branch_factor",
            "beam_width",
            "max_depth",
            "seed",
            "root_id",
            "frontier",
            "best_id",
            "nodes",
        }
        unknown = sorted(str(key) for key in set(value) - fields)
        missing = sorted(str(key) for key in fields - set(value))
        if unknown:
            raise ValueError("TAP search state contains unknown fields: " + ", ".join(unknown))
        if missing:
            raise ValueError("TAP search state is missing fields: " + ", ".join(missing))
        version = value.get("version")
        if isinstance(version, bool) or version != cls.STATE_VERSION:
            raise ValueError(f"unsupported TAP state version: {value.get('version')!r}")

        branch_factor = _integer(value["branch_factor"], "branch_factor", minimum=1)
        beam_width = _integer(value["beam_width"], "beam_width", minimum=1)
        max_depth = _integer(value["max_depth"], "max_depth", minimum=0)
        seed = value["seed"]
        if isinstance(seed, bool) or not isinstance(seed, int):
            raise ValueError("seed must be an integer")
        root_id = value["root_id"]
        if not isinstance(root_id, str) or not root_id:
            raise ValueError("root_id must be a non-empty string")
        raw_frontier = value["frontier"]
        if not isinstance(raw_frontier, list) or not all(
            isinstance(node_id, str) and node_id for node_id in raw_frontier
        ):
            raise ValueError("frontier must be an array of non-empty node ids")
        if len(raw_frontier) != len(set(raw_frontier)):
            raise ValueError("frontier contains duplicate node ids")
        best_id = value["best_id"]
        if best_id is not None and (not isinstance(best_id, str) or not best_id):
            raise ValueError("best_id must be null or a non-empty string")
        raw_nodes = value["nodes"]
        if not isinstance(raw_nodes, list) or not raw_nodes:
            raise ValueError("nodes must be a non-empty array")

        nodes: Dict[str, TAPNode] = {}
        for index, raw_node in enumerate(raw_nodes):
            try:
                node = TAPNode.from_dict(raw_node)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"invalid TAP node at index {index}: {exc}") from exc
            if node.node_id in nodes:
                raise ValueError(f"nodes contains duplicate node id: {node.node_id}")
            nodes[node.node_id] = node

        search = cls.__new__(cls)
        search.branch_factor = branch_factor
        search.beam_width = beam_width
        search.max_depth = max_depth
        search.seed = seed
        search.root_id = root_id
        search.nodes = nodes
        search.frontier = list(raw_frontier)
        search.best_id = best_id
        search._prompt_ids = {}
        search._validate_state()
        search._prompt_ids = {node.prompt: node.node_id for node in nodes.values()}
        return search

    def _default_mutation(
        self,
        parent: TAPNode,
        *,
        objective: str,
        feedback: Any,
        branch_index: int,
    ) -> Mapping[str, Any]:
        feedback_text = self._feedback_text(feedback)
        material = "\0".join(
            (
                str(self.seed),
                parent.node_id,
                parent.prompt,
                objective,
                feedback_text,
                str(branch_index),
            )
        ).encode("utf-8")
        digest = hashlib.sha256(material).hexdigest()
        directive_name, directive = self._DIRECTIVES[
            int(digest[:16], 16) % len(self._DIRECTIVES)
        ]
        feedback_block = feedback_text if feedback_text else "No feedback was provided."
        prompt = (
            f"{parent.prompt}\n\n"
            f"Objective:\n{objective}\n\n"
            f"Feedback:\n{feedback_block}\n\n"
            f"Candidate branch {branch_index + 1} [{digest[:8]}]:\n{directive}"
        )
        return {
            "prompt": prompt,
            "metadata": {
                "mutation": "deterministic",
                "directive": directive_name,
                "seed": self.seed,
            },
        }

    @staticmethod
    def _feedback_text(feedback: Any) -> str:
        if feedback is None:
            return ""
        if isinstance(feedback, str):
            return feedback
        try:
            return json.dumps(
                feedback,
                sort_keys=True,
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
            )
        except (TypeError, ValueError) as exc:
            raise ValueError(f"feedback must be JSON serializable: {exc}") from exc

    def _invoke_mutator(
        self,
        mutator: Mutator,
        *,
        parent: TAPNode,
        objective: str,
        feedback: Any,
        branch_index: int,
    ) -> MutationOutput:
        context = {
            "node_id": parent.node_id,
            "parent": parent,
            "node": parent,
            "prompt": parent.prompt,
            "objective": objective,
            "feedback": feedback,
            "branch_index": branch_index,
            "depth": parent.depth + 1,
            "seed": self.seed,
        }
        context["context"] = {
            key: value for key, value in context.items() if key not in {"parent", "node"}
        }
        try:
            signature = inspect.signature(mutator)
        except (TypeError, ValueError):
            return mutator(
                parent.prompt,
                objective,
                feedback,
                branch_index,
                self.seed,
            )

        parameters = signature.parameters.values()
        has_var_keyword = any(
            parameter.kind is inspect.Parameter.VAR_KEYWORD
            for parameter in parameters
        )
        has_var_positional = any(
            parameter.kind is inspect.Parameter.VAR_POSITIONAL
            for parameter in parameters
        )
        has_positional_only = any(
            parameter.kind is inspect.Parameter.POSITIONAL_ONLY
            for parameter in parameters
        )
        keyword_arguments: Dict[str, Any] = {}
        if has_var_keyword:
            keyword_arguments = {
                key: context[key]
                for key in ("prompt", "objective", "feedback", "branch_index", "seed")
            }
            keyword_arguments.update(
                {
                    parameter.name: context[parameter.name]
                    for parameter in parameters
                    if parameter.kind
                    in {
                        inspect.Parameter.POSITIONAL_OR_KEYWORD,
                        inspect.Parameter.KEYWORD_ONLY,
                    }
                    and parameter.name in context
                }
            )
        else:
            keyword_arguments = {
                parameter.name: context[parameter.name]
                for parameter in parameters
                if parameter.kind
                in {
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    inspect.Parameter.KEYWORD_ONLY,
                }
                and parameter.name in context
            }
        if not has_positional_only and (keyword_arguments or has_var_keyword):
            try:
                signature.bind(**keyword_arguments)
            except TypeError:
                pass
            else:
                return mutator(**keyword_arguments)

        positional = (
            parent.prompt,
            objective,
            feedback,
            branch_index,
            self.seed,
        )
        candidates = [positional[:length] for length in range(len(positional), -1, -1)]
        if has_var_positional:
            candidates = [positional]
        for arguments in candidates:
            try:
                signature.bind(*arguments)
            except TypeError:
                continue
            return mutator(*arguments)
        raise TypeError(
            "mutator must accept candidate context or prompt/objective/feedback/branch_index/seed"
        )

    @staticmethod
    def _candidate_output(
        output: MutationOutput,
        branch_index: int,
    ) -> Tuple[str, Dict[str, Any]]:
        if isinstance(output, str):
            prompt = output
            metadata: Dict[str, Any] = {}
        elif isinstance(output, Mapping):
            candidate = dict(output)
            prompt_key = next(
                (key for key in ("prompt", "text", "content") if key in candidate),
                None,
            )
            if prompt_key is None:
                raise ValueError(
                    f"mutator output for branch {branch_index} must contain prompt"
                )
            prompt = candidate[prompt_key]
            raw_metadata = candidate.get("metadata", {})
            metadata = _json_mapping(raw_metadata, "mutator metadata")
            for key, value in candidate.items():
                if key not in {"prompt", "text", "content", "metadata"}:
                    metadata[str(key)] = value
            metadata = _json_mapping(metadata, "mutator metadata")
        else:
            raise ValueError(
                f"mutator output for branch {branch_index} must be a string or mapping"
            )
        if not isinstance(prompt, str) or not prompt.strip():
            raise ValueError(
                f"mutator output for branch {branch_index} has an invalid prompt"
            )
        if "success" in metadata:
            raise ValueError("mutator metadata cannot set reserved field success")
        return prompt, metadata

    def _child_id(self, parent: TAPNode, branch_index: int, prompt: str) -> str:
        material = "\0".join(
            (
                str(self.seed),
                parent.node_id,
                str(parent.depth + 1),
                str(branch_index),
                prompt,
            )
        ).encode("utf-8")
        digest = hashlib.sha256(material).hexdigest()[:20]
        return f"tap-d{parent.depth + 1:03d}-b{branch_index:03d}-{digest}"

    @staticmethod
    def _priority(node: TAPNode) -> Tuple[int, float, int, int, str]:
        return (
            0 if node.success else 1,
            -node.score,
            0 if not node.visited else 1,
            node.depth,
            node.node_id,
        )

    def _recompute_best(self) -> None:
        observed = [node for node in self.nodes.values() if node.visited]
        self.best_id = (
            min(observed, key=self._priority).node_id if observed else None
        )

    def _get_node(self, node_id: str) -> TAPNode:
        if not isinstance(node_id, str) or not node_id:
            raise ValueError("node_id must be a non-empty string")
        try:
            return self.nodes[node_id]
        except KeyError as exc:
            raise KeyError(f"unknown TAP node: {node_id}") from exc

    def _children_of(self, node_id: str) -> List[TAPNode]:
        return [node for node in self.nodes.values() if node.parent_id == node_id]

    def _remove_from_frontier(self, node_id: str) -> None:
        self.frontier = [candidate for candidate in self.frontier if candidate != node_id]

    def _frontier_nodes(self) -> List[TAPNode]:
        result: List[TAPNode] = []
        for node_id in self.frontier:
            if node_id not in self.nodes:
                raise ValueError(f"frontier references unknown node: {node_id}")
            result.append(self.nodes[node_id])
        return result

    def _validate_state(self) -> None:
        _integer(self.branch_factor, "branch_factor", minimum=1)
        _integer(self.beam_width, "beam_width", minimum=1)
        _integer(self.max_depth, "max_depth", minimum=0)
        if isinstance(self.seed, bool) or not isinstance(self.seed, int):
            raise ValueError("seed must be an integer")
        if not isinstance(self.root_id, str) or not self.root_id:
            raise ValueError("root_id must be a non-empty string")
        if not isinstance(self.nodes, dict) or not self.nodes:
            raise ValueError("nodes must be a non-empty mapping")
        if self.root_id not in self.nodes:
            raise ValueError("root_id does not reference a node")

        root = self.nodes[self.root_id]
        if not isinstance(root, TAPNode):
            raise ValueError("root must be a TAPNode")
        if root.parent_id is not None or root.depth != 0 or root.branch_index != 0:
            raise ValueError("root node must have null parent, depth zero, and branch index zero")

        roots = [node for node in self.nodes.values() if node.parent_id is None]
        if len(roots) != 1 or roots[0].node_id != self.root_id:
            raise ValueError("TAP state must contain exactly one root node")

        prompts: Dict[str, str] = {}
        sibling_indexes = set()
        for node_id, node in self.nodes.items():
            if not isinstance(node, TAPNode):
                raise ValueError(f"nodes[{node_id!r}] must be a TAPNode")
            if node_id != node.node_id:
                raise ValueError(f"node mapping key does not match node id: {node_id}")
            if node.prompt in prompts:
                raise ValueError(
                    f"nodes contain duplicate prompt: {node.node_id} and {prompts[node.prompt]}"
                )
            prompts[node.prompt] = node.node_id
            if node.depth > self.max_depth:
                raise ValueError(f"node exceeds max_depth: {node.node_id}")
            if not node.visited and (
                node.score != 0.0 or node.refused or node.success
            ):
                raise ValueError(f"unvisited node has observation data: {node.node_id}")
            if node.node_id == self.root_id:
                continue
            if node.parent_id not in self.nodes:
                raise ValueError(f"node references unknown parent: {node.node_id}")
            parent = self.nodes[node.parent_id]
            if node.depth != parent.depth + 1:
                raise ValueError(f"node depth does not follow parent: {node.node_id}")
            if node.branch_index >= self.branch_factor:
                raise ValueError(f"node branch index exceeds branch_factor: {node.node_id}")
            sibling_key = (node.parent_id, node.branch_index)
            if sibling_key in sibling_indexes:
                raise ValueError(
                    f"siblings contain duplicate branch index under {node.parent_id}"
                )
            sibling_indexes.add(sibling_key)

        if not isinstance(self.frontier, list) or not all(
            isinstance(node_id, str) and node_id for node_id in self.frontier
        ):
            raise ValueError("frontier must be an array of non-empty node ids")
        if len(self.frontier) != len(set(self.frontier)):
            raise ValueError("frontier contains duplicate node ids")
        missing_frontier = [node_id for node_id in self.frontier if node_id not in self.nodes]
        if missing_frontier:
            raise ValueError(
                "frontier references unknown nodes: " + ", ".join(missing_frontier)
            )

        observed = [node for node in self.nodes.values() if node.visited]
        expected_best = min(observed, key=self._priority).node_id if observed else None
        if self.best_id != expected_best:
            raise ValueError(
                f"best_id is inconsistent: expected {expected_best!r}, got {self.best_id!r}"
            )
        self._prompt_ids = prompts


__all__ = ["Mutator", "MutationOutput", "TAPNode", "TAPSearch"]
