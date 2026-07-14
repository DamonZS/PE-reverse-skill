"""Evidence-oriented world-to-viewport projection for GUI diagnostics.

The engine consumes an already-composed 4x4 view-projection matrix.  Matrix
storage, clip-space convention, handedness, viewport orientation, and matrix
source are explicit inputs and are retained in every top-level result.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
import copy
from dataclasses import dataclass
import hashlib
import json
import math
from numbers import Real
import os
from pathlib import Path
import tempfile
from typing import Any


SCHEMA_VERSION = 1
ARTIFACT_TYPE = "world_projection_evidence"

ROW_MAJOR = "row-major"
COLUMN_MAJOR = "column-major"
OPENGL = "opengl"
D3D = "d3d"
RIGHT_HANDED = "right-handed"
LEFT_HANDED = "left-handed"
TOP_LEFT = "top-left"
BOTTOM_LEFT = "bottom-left"

DEFAULT_W_EPSILON = 1.0e-8

_MATRIX_LAYOUTS = {
    "row": ROW_MAJOR,
    "row-major": ROW_MAJOR,
    "row_major": ROW_MAJOR,
    "column": COLUMN_MAJOR,
    "column-major": COLUMN_MAJOR,
    "column_major": COLUMN_MAJOR,
}
_CLIP_CONVENTIONS = {
    "d3d": D3D,
    "direct3d": D3D,
    "direct-3d": D3D,
    "gl": OPENGL,
    "open-gl": OPENGL,
    "opengl": OPENGL,
}
_HANDEDNESS = {
    "left": LEFT_HANDED,
    "left-handed": LEFT_HANDED,
    "left_handed": LEFT_HANDED,
    "lh": LEFT_HANDED,
    "right": RIGHT_HANDED,
    "right-handed": RIGHT_HANDED,
    "right_handed": RIGHT_HANDED,
    "rh": RIGHT_HANDED,
}
_VIEWPORT_ORIGINS = {
    "bottom-left": BOTTOM_LEFT,
    "bottom_left": BOTTOM_LEFT,
    "top-left": TOP_LEFT,
    "top_left": TOP_LEFT,
}
_CLIP_REASON_ORDER = (
    "w_too_small",
    "behind_camera",
    "near_plane",
    "far_plane",
    "left",
    "right",
    "bottom",
    "top",
)

ClipPoint = tuple[float, float, float, float]


@dataclass(frozen=True, slots=True)
class Viewport:
    """Logical viewport rectangle and logical-to-physical DPI transform."""

    width: float
    height: float
    x: float = 0.0
    y: float = 0.0
    origin: str = TOP_LEFT
    dpi_scale: float | Sequence[float] = 1.0

    def __post_init__(self) -> None:
        width = _finite_number(self.width, "viewport.width")
        height = _finite_number(self.height, "viewport.height")
        x = _finite_number(self.x, "viewport.x")
        y = _finite_number(self.y, "viewport.y")
        if width <= 0.0:
            raise ValueError("viewport.width must be greater than zero")
        if height <= 0.0:
            raise ValueError("viewport.height must be greater than zero")
        origin = _normalize_token(self.origin, "viewport.origin", _VIEWPORT_ORIGINS)
        dpi_x, dpi_y = _dpi_pair(self.dpi_scale)
        object.__setattr__(self, "width", width)
        object.__setattr__(self, "height", height)
        object.__setattr__(self, "x", x)
        object.__setattr__(self, "y", y)
        object.__setattr__(self, "origin", origin)
        object.__setattr__(self, "dpi_scale", (dpi_x, dpi_y))

    @property
    def dpi_x(self) -> float:
        return self.dpi_scale[0]  # type: ignore[index]

    @property
    def dpi_y(self) -> float:
        return self.dpi_scale[1]  # type: ignore[index]

    def to_dict(self) -> dict[str, Any]:
        return {
            "x": self.x,
            "y": self.y,
            "width": self.width,
            "height": self.height,
            "origin": self.origin,
            "dpi_scale": [self.dpi_x, self.dpi_y],
            "logical_units": "logical-pixels",
            "physical_units": "physical-pixels",
            "physical_rect": {
                "x": self.x * self.dpi_x,
                "y": self.y * self.dpi_y,
                "width": self.width * self.dpi_x,
                "height": self.height * self.dpi_y,
            },
        }


class WorldProjectionEngine:
    """Project world points with one explicit, immutable projection contract."""

    def __init__(
        self,
        matrix: Iterable[Real],
        *,
        matrix_layout: str,
        clip_convention: str,
        handedness: str,
        viewport: Viewport | Mapping[str, Any],
        matrix_source: str | Mapping[str, Any],
        coordinate_system: str | Mapping[str, Any],
        reversed_z: bool = False,
        w_epsilon: float = DEFAULT_W_EPSILON,
    ) -> None:
        self.matrix_layout = _normalize_token(
            matrix_layout, "matrix_layout", _MATRIX_LAYOUTS
        )
        self.clip_convention = _normalize_token(
            clip_convention, "clip_convention", _CLIP_CONVENTIONS
        )
        self.handedness = _normalize_token(handedness, "handedness", _HANDEDNESS)
        if not isinstance(reversed_z, bool):
            raise TypeError("reversed_z must be a bool")
        self.reversed_z = reversed_z
        self.w_epsilon = _finite_number(w_epsilon, "w_epsilon")
        if self.w_epsilon <= 0.0:
            raise ValueError("w_epsilon must be greater than zero")
        self.viewport = _coerce_viewport(viewport)
        self._matrix_values = _matrix_values(matrix)
        self._matrix_rows = _matrix_rows(self._matrix_values, self.matrix_layout)
        self._matrix_source = _provenance_value(matrix_source, "matrix_source")
        self._coordinate_system = _provenance_value(
            coordinate_system, "coordinate_system"
        )
        self._validate_coordinate_provenance()
        matrix_identity = {
            "layout": self.matrix_layout,
            "values": list(self._matrix_values),
        }
        self._matrix_sha256 = hashlib.sha256(
            _compact_json(matrix_identity).encode("utf-8")
        ).hexdigest()

    @property
    def matrix(self) -> tuple[float, ...]:
        return self._matrix_values

    @property
    def provenance(self) -> dict[str, Any]:
        coordinate_system: dict[str, Any]
        if isinstance(self._coordinate_system, str):
            coordinate_system = {"name": self._coordinate_system}
        else:
            coordinate_system = copy.deepcopy(self._coordinate_system)
        coordinate_system.update(
            {
                "handedness": self.handedness,
                "clip_convention": self.clip_convention,
                "ndc_depth_range": (
                    [-1.0, 1.0] if self.clip_convention == OPENGL else [0.0, 1.0]
                ),
                "reversed_z": self.reversed_z,
                "front_facing_clip_w": "positive",
            }
        )
        return {
            "matrix": {
                "source": copy.deepcopy(self._matrix_source),
                "layout": self.matrix_layout,
                "element_count": 16,
                "values": list(self._matrix_values),
                "canonical_rows": [list(row) for row in self._matrix_rows],
                "sha256": self._matrix_sha256,
            },
            "coordinate_system": coordinate_system,
            "viewport": self.viewport.to_dict(),
            "projection_policy": {
                "w_epsilon": self.w_epsilon,
                "clip_boundaries_inclusive": True,
                "screen_coordinates_for_nonpositive_w": False,
            },
        }

    def project_point(
        self,
        point: Iterable[Real],
        *,
        point_id: Any | None = None,
    ) -> dict[str, Any]:
        """Project one world point and retain every transformation stage."""

        result = self._project_point(point)
        result.update(
            {
                "schema_version": SCHEMA_VERSION,
                "kind": "world_point_projection",
                "provenance": self.provenance,
            }
        )
        if point_id is not None:
            result["point_id"] = _json_value(point_id, "point_id")
        return result

    def project_points(self, points: Iterable[Iterable[Real]]) -> dict[str, Any]:
        """Project an ordered batch of points with a deterministic summary."""

        observations = self._project_point_batch(points)
        summary = _point_summary(observations)
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": "world_point_projection_batch",
            "provenance": self.provenance,
            "points": observations,
            "summary": summary,
        }

    def project_aabb(
        self,
        minimum: Iterable[Real],
        maximum: Iterable[Real],
        *,
        aabb_id: Any | None = None,
    ) -> dict[str, Any]:
        """Project and frustum-clip one axis-aligned world-space box."""

        result = self._project_aabb(minimum, maximum)
        result.update(
            {
                "schema_version": SCHEMA_VERSION,
                "kind": "world_aabb_projection",
                "provenance": self.provenance,
            }
        )
        if aabb_id is not None:
            result["aabb_id"] = _json_value(aabb_id, "aabb_id")
        return result

    def project_aabbs(self, aabbs: Iterable[Any]) -> dict[str, Any]:
        """Project an ordered batch of ``(minimum, maximum)`` AABB pairs."""

        observations = self._project_aabb_batch(aabbs)
        visible = sum(1 for item in observations if item["visible"])
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": "world_aabb_projection_batch",
            "provenance": self.provenance,
            "aabbs": observations,
            "summary": {
                "aabb_count": len(observations),
                "visible_count": visible,
                "clipped_count": len(observations) - visible,
            },
        }

    def build_artifact(
        self,
        *,
        points: Iterable[Iterable[Real]] | None = None,
        aabbs: Iterable[Any] | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Build one JSON-safe evidence artifact without time-dependent fields."""

        point_observations = self._project_point_batch(points or ())
        aabb_observations = self._project_aabb_batch(aabbs or ())
        visible_points = sum(1 for item in point_observations if item["visible"])
        visible_aabbs = sum(1 for item in aabb_observations if item["visible"])
        artifact: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "artifact_type": ARTIFACT_TYPE,
            "provenance": self.provenance,
            "points": point_observations,
            "aabbs": aabb_observations,
            "summary": {
                "point_count": len(point_observations),
                "visible_point_count": visible_points,
                "clipped_point_count": len(point_observations) - visible_points,
                "aabb_count": len(aabb_observations),
                "visible_aabb_count": visible_aabbs,
                "clipped_aabb_count": len(aabb_observations) - visible_aabbs,
            },
        }
        if metadata is not None:
            normalized = _json_value(metadata, "metadata")
            if not isinstance(normalized, dict):  # pragma: no cover - Mapping contract
                raise TypeError("metadata must be a mapping")
            artifact["metadata"] = normalized
        return artifact

    def write_artifact(
        self,
        destination: str | os.PathLike[str],
        *,
        points: Iterable[Iterable[Real]] | None = None,
        aabbs: Iterable[Any] | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        artifact = self.build_artifact(
            points=points,
            aabbs=aabbs,
            metadata=metadata,
        )
        return write_projection_artifact(destination, artifact)

    def _project_point(self, point: Iterable[Real]) -> dict[str, Any]:
        world = _point3(point, "point")
        clip = self._transform(world)
        classification = self._classify_clip(clip)
        screen: dict[str, list[float]] | None = None
        ndc: list[float] | None = None
        viewport_depth: float | None = None
        if classification["w_status"] == "positive":
            ndc_tuple = _clip_to_ndc(clip)
            logical, physical = self._ndc_to_viewport(ndc_tuple)
            ndc = list(ndc_tuple)
            screen = {"logical": list(logical), "physical": list(physical)}
            viewport_depth = (
                (ndc_tuple[2] + 1.0) * 0.5
                if self.clip_convention == OPENGL
                else ndc_tuple[2]
            )
        reasons = classification["reasons"]
        visible = not reasons
        return {
            "world": list(world),
            "clip": list(clip),
            "clip_w": clip[3],
            "ndc": ndc,
            "viewport_depth": viewport_depth,
            "screen": screen,
            "screen_2d": None if screen is None else list(screen["physical"]),
            "visible": visible,
            "visibility": "visible" if visible else "clipped",
            "clipped": not visible,
            "clipped_reason": None if visible else reasons[0],
            "clipped_reasons": list(reasons),
            "w_status": classification["w_status"],
            "camera_status": classification["camera_status"],
            "depth_status": classification["depth_status"],
            "axis_status": classification["axis_status"],
        }

    def _project_point_batch(
        self, points: Iterable[Iterable[Real]]
    ) -> list[dict[str, Any]]:
        _reject_text_or_mapping(points, "points")
        observations: list[dict[str, Any]] = []
        try:
            iterator = iter(points)
        except TypeError as exc:
            raise TypeError("points must be an iterable of 3D points") from exc
        for index, point in enumerate(iterator):
            observation = self._project_point(point)
            observation["index"] = index
            observations.append(observation)
        return observations

    def _project_aabb(
        self, minimum: Iterable[Real], maximum: Iterable[Real]
    ) -> dict[str, Any]:
        minimum_point = _point3(minimum, "minimum")
        maximum_point = _point3(maximum, "maximum")
        for axis, (lower, upper) in enumerate(zip(minimum_point, maximum_point)):
            if lower > upper:
                raise ValueError(
                    f"minimum[{axis}] must be less than or equal to maximum[{axis}]"
                )

        corners = _aabb_corners(minimum_point, maximum_point)
        clip_corners = [self._transform(corner) for corner in corners]
        projected_corners: list[dict[str, Any]] = []
        for index, corner in enumerate(corners):
            observation = self._project_point_from_values(corner, clip_corners[index])
            observation["index"] = index
            projected_corners.append(observation)

        logical_candidates: list[tuple[float, float]] = []
        physical_candidates: list[tuple[float, float]] = []
        clipped_polygon_count = 0
        for face in _AABB_FACES:
            polygon = [clip_corners[index] for index in face]
            clipped = self._clip_polygon_to_frustum(polygon)
            if not clipped:
                continue
            clipped_polygon_count += 1
            for clip_point in clipped:
                if clip_point[3] <= self.w_epsilon:
                    continue
                ndc = _clip_to_ndc(clip_point)
                logical, physical = self._ndc_to_viewport(ndc)
                logical_candidates.append(logical)
                physical_candidates.append(physical)

        all_visible = all(item["visible"] for item in projected_corners)
        if all_visible:
            visibility = "fully_visible"
        elif physical_candidates:
            visibility = "partially_visible"
        else:
            visibility = "not_visible"
        visible = visibility != "not_visible"

        corner_reasons = {
            reason
            for item in projected_corners
            for reason in item["clipped_reasons"]
        }
        clipped_reasons = [
            reason for reason in _CLIP_REASON_ORDER if reason in corner_reasons
        ]
        if visibility == "fully_visible":
            clipped_reason = None
            clipped_reasons = []
        elif visibility == "partially_visible":
            clipped_reason = "partially_clipped"
        else:
            clipped_reason = _aabb_rejection_reason(projected_corners)

        bbox_logical = _bbox(logical_candidates) if visible else None
        bbox_physical = _bbox(physical_candidates) if visible else None
        result: dict[str, Any] = {
            "minimum": list(minimum_point),
            "maximum": list(maximum_point),
            "corners": projected_corners,
            "visible": visible,
            "visibility": visibility,
            "clipped": visibility != "fully_visible",
            "clipped_reason": clipped_reason,
            "clipped_reasons": clipped_reasons,
            "bbox_2d": bbox_physical,
            "bbox_2d_logical": bbox_logical,
            "bbox": _bbox_details(bbox_logical, bbox_physical),
            "clip_geometry": {
                "source_face_count": len(_AABB_FACES),
                "intersecting_face_count": clipped_polygon_count,
                "projected_vertex_count": len(physical_candidates),
            },
        }
        return result

    def _project_point_from_values(
        self, world: tuple[float, float, float], clip: ClipPoint
    ) -> dict[str, Any]:
        classification = self._classify_clip(clip)
        reasons = classification["reasons"]
        visible = not reasons
        ndc: list[float] | None = None
        screen: dict[str, list[float]] | None = None
        viewport_depth: float | None = None
        if classification["w_status"] == "positive":
            ndc_tuple = _clip_to_ndc(clip)
            logical, physical = self._ndc_to_viewport(ndc_tuple)
            ndc = list(ndc_tuple)
            screen = {"logical": list(logical), "physical": list(physical)}
            viewport_depth = (
                (ndc_tuple[2] + 1.0) * 0.5
                if self.clip_convention == OPENGL
                else ndc_tuple[2]
            )
        return {
            "world": list(world),
            "clip": list(clip),
            "clip_w": clip[3],
            "ndc": ndc,
            "viewport_depth": viewport_depth,
            "screen": screen,
            "screen_2d": None if screen is None else list(screen["physical"]),
            "visible": visible,
            "visibility": "visible" if visible else "clipped",
            "clipped": not visible,
            "clipped_reason": None if visible else reasons[0],
            "clipped_reasons": list(reasons),
            "w_status": classification["w_status"],
            "camera_status": classification["camera_status"],
            "depth_status": classification["depth_status"],
            "axis_status": classification["axis_status"],
        }

    def _project_aabb_batch(self, aabbs: Iterable[Any]) -> list[dict[str, Any]]:
        _reject_text_or_mapping(aabbs, "aabbs")
        try:
            iterator = iter(aabbs)
        except TypeError as exc:
            raise TypeError("aabbs must be an iterable of AABB pairs") from exc
        observations: list[dict[str, Any]] = []
        for index, item in enumerate(iterator):
            minimum, maximum, aabb_id = _aabb_entry(item, index)
            observation = self._project_aabb(minimum, maximum)
            observation["index"] = index
            if aabb_id is not None:
                observation["aabb_id"] = aabb_id
            observations.append(observation)
        return observations

    def _transform(self, point: tuple[float, float, float]) -> ClipPoint:
        vector = (point[0], point[1], point[2], 1.0)
        transformed = tuple(
            sum(row[column] * vector[column] for column in range(4))
            for row in self._matrix_rows
        )
        if not all(math.isfinite(value) for value in transformed):
            raise ValueError("matrix multiplication produced non-finite clip coordinates")
        return transformed  # type: ignore[return-value]

    def _classify_clip(self, clip: ClipPoint) -> dict[str, Any]:
        x, y, z, w = clip
        if abs(w) <= self.w_epsilon:
            return {
                "reasons": ["w_too_small"],
                "w_status": "too_small",
                "camera_status": "on_camera_plane",
                "depth_status": "indeterminate",
                "axis_status": {
                    "horizontal": "indeterminate",
                    "vertical": "indeterminate",
                },
            }
        if w < 0.0:
            return {
                "reasons": ["behind_camera"],
                "w_status": "negative",
                "camera_status": "behind_camera",
                "depth_status": "indeterminate",
                "axis_status": {
                    "horizontal": "indeterminate",
                    "vertical": "indeterminate",
                },
            }

        tolerance = self.w_epsilon * max(1.0, abs(w))
        horizontal = "inside"
        vertical = "inside"
        if x < -w - tolerance:
            horizontal = "left"
        elif x > w + tolerance:
            horizontal = "right"
        if y < -w - tolerance:
            vertical = "bottom"
        elif y > w + tolerance:
            vertical = "top"

        lower = -w if self.clip_convention == OPENGL else 0.0
        upper = w
        if z < lower - tolerance:
            depth_status = "far_plane" if self.reversed_z else "near_plane"
        elif z > upper + tolerance:
            depth_status = "near_plane" if self.reversed_z else "far_plane"
        else:
            depth_status = "inside"

        reasons: list[str] = []
        if depth_status != "inside":
            reasons.append(depth_status)
        if horizontal != "inside":
            reasons.append(horizontal)
        if vertical != "inside":
            reasons.append(vertical)
        return {
            "reasons": reasons,
            "w_status": "positive",
            "camera_status": "in_front",
            "depth_status": depth_status,
            "axis_status": {
                "horizontal": horizontal,
                "vertical": vertical,
            },
        }

    def _ndc_to_viewport(
        self, ndc: tuple[float, float, float]
    ) -> tuple[tuple[float, float], tuple[float, float]]:
        logical_x = self.viewport.x + (ndc[0] + 1.0) * 0.5 * self.viewport.width
        normalized_y = (ndc[1] + 1.0) * 0.5
        if self.viewport.origin == TOP_LEFT:
            normalized_y = 1.0 - normalized_y
        logical_y = self.viewport.y + normalized_y * self.viewport.height
        physical_x = logical_x * self.viewport.dpi_x
        physical_y = logical_y * self.viewport.dpi_y
        coordinates = (logical_x, logical_y, physical_x, physical_y)
        if not all(math.isfinite(value) for value in coordinates):
            raise ValueError("viewport transform produced non-finite coordinates")
        return (logical_x, logical_y), (physical_x, physical_y)

    def _clip_polygon_to_frustum(
        self, polygon: list[ClipPoint]
    ) -> list[ClipPoint]:
        output = polygon
        for coefficients in self._clip_plane_coefficients():
            output = _clip_polygon(output, coefficients, self.w_epsilon)
            if not output:
                break
        return output

    def _clip_plane_coefficients(self) -> tuple[ClipPoint, ...]:
        depth_lower = (
            (0.0, 0.0, 1.0, 1.0)
            if self.clip_convention == OPENGL
            else (0.0, 0.0, 1.0, 0.0)
        )
        return (
            (1.0, 0.0, 0.0, 1.0),
            (-1.0, 0.0, 0.0, 1.0),
            (0.0, 1.0, 0.0, 1.0),
            (0.0, -1.0, 0.0, 1.0),
            depth_lower,
            (0.0, 0.0, -1.0, 1.0),
        )

    def _validate_coordinate_provenance(self) -> None:
        if not isinstance(self._coordinate_system, dict):
            return
        checks = (
            ("handedness", self.handedness, _HANDEDNESS),
            ("clip_convention", self.clip_convention, _CLIP_CONVENTIONS),
        )
        for key, expected, aliases in checks:
            if key not in self._coordinate_system:
                continue
            actual = _normalize_token(
                self._coordinate_system[key], f"coordinate_system.{key}", aliases
            )
            if actual != expected:
                raise ValueError(
                    f"coordinate_system.{key} conflicts with explicit {key}"
                )
        if "reversed_z" in self._coordinate_system:
            value = self._coordinate_system["reversed_z"]
            if not isinstance(value, bool):
                raise TypeError("coordinate_system.reversed_z must be a bool")
            if value != self.reversed_z:
                raise ValueError(
                    "coordinate_system.reversed_z conflicts with explicit reversed_z"
                )


ProjectionEngine = WorldProjectionEngine
ProjectionEvidenceEngine = WorldProjectionEngine


def project_world_point(
    point: Iterable[Real],
    matrix: Iterable[Real],
    *,
    matrix_layout: str,
    clip_convention: str,
    handedness: str,
    viewport: Viewport | Mapping[str, Any],
    matrix_source: str | Mapping[str, Any],
    coordinate_system: str | Mapping[str, Any],
    reversed_z: bool = False,
    w_epsilon: float = DEFAULT_W_EPSILON,
    point_id: Any | None = None,
) -> dict[str, Any]:
    """Convenience wrapper for a single explicit projection contract."""

    engine = WorldProjectionEngine(
        matrix,
        matrix_layout=matrix_layout,
        clip_convention=clip_convention,
        handedness=handedness,
        viewport=viewport,
        matrix_source=matrix_source,
        coordinate_system=coordinate_system,
        reversed_z=reversed_z,
        w_epsilon=w_epsilon,
    )
    return engine.project_point(point, point_id=point_id)


def project_world_points(
    points: Iterable[Iterable[Real]],
    matrix: Iterable[Real],
    *,
    matrix_layout: str,
    clip_convention: str,
    handedness: str,
    viewport: Viewport | Mapping[str, Any],
    matrix_source: str | Mapping[str, Any],
    coordinate_system: str | Mapping[str, Any],
    reversed_z: bool = False,
    w_epsilon: float = DEFAULT_W_EPSILON,
) -> dict[str, Any]:
    engine = WorldProjectionEngine(
        matrix,
        matrix_layout=matrix_layout,
        clip_convention=clip_convention,
        handedness=handedness,
        viewport=viewport,
        matrix_source=matrix_source,
        coordinate_system=coordinate_system,
        reversed_z=reversed_z,
        w_epsilon=w_epsilon,
    )
    return engine.project_points(points)


def project_world_aabb(
    minimum: Iterable[Real],
    maximum: Iterable[Real],
    matrix: Iterable[Real],
    *,
    matrix_layout: str,
    clip_convention: str,
    handedness: str,
    viewport: Viewport | Mapping[str, Any],
    matrix_source: str | Mapping[str, Any],
    coordinate_system: str | Mapping[str, Any],
    reversed_z: bool = False,
    w_epsilon: float = DEFAULT_W_EPSILON,
    aabb_id: Any | None = None,
) -> dict[str, Any]:
    engine = WorldProjectionEngine(
        matrix,
        matrix_layout=matrix_layout,
        clip_convention=clip_convention,
        handedness=handedness,
        viewport=viewport,
        matrix_source=matrix_source,
        coordinate_system=coordinate_system,
        reversed_z=reversed_z,
        w_epsilon=w_epsilon,
    )
    return engine.project_aabb(minimum, maximum, aabb_id=aabb_id)


project_point = project_world_point
project_points = project_world_points
project_aabb = project_world_aabb
world_to_screen = project_world_point


def projection_artifact_bytes(payload: Mapping[str, Any]) -> bytes:
    """Serialize JSON deterministically and reject non-JSON/non-finite values."""

    if not isinstance(payload, Mapping):
        raise TypeError("projection artifact payload must be a mapping")
    normalized = _json_value(payload, "payload")
    encoded = json.dumps(
        normalized,
        ensure_ascii=True,
        allow_nan=False,
        indent=2,
        sort_keys=True,
    )
    return (encoded + "\n").encode("utf-8")


def projection_artifact_sha256(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(projection_artifact_bytes(payload)).hexdigest()


def write_projection_artifact(
    destination: str | os.PathLike[str], payload: Mapping[str, Any]
) -> dict[str, Any]:
    """Atomically write deterministic JSON and a ``.sha256`` sidecar."""

    path = Path(destination)
    if not path.name:
        raise ValueError("artifact destination must name a file")
    if path.exists() and path.is_dir():
        raise IsADirectoryError(f"artifact destination is a directory: {path}")
    encoded = projection_artifact_bytes(payload)
    digest = hashlib.sha256(encoded).hexdigest()
    hash_path = Path(f"{path}.sha256")
    path.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write(path, encoded)
    _atomic_write(hash_path, (digest + "\n").encode("ascii"))
    return {
        "path": str(path),
        "hash_path": str(hash_path),
        "sha256": digest,
        "size": len(encoded),
    }


def _finite_number(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, Real):
        raise TypeError(f"{name} must be a real number")
    result = float(value)
    if not math.isfinite(result):
        raise ValueError(f"{name} must be finite")
    return result


def _normalize_token(value: Any, name: str, aliases: Mapping[str, str]) -> str:
    if not isinstance(value, str) or not value.strip():
        raise TypeError(f"{name} must be a non-empty string")
    normalized = value.strip().lower()
    if normalized not in aliases:
        supported = ", ".join(sorted(set(aliases.values())))
        raise ValueError(f"{name} must be one of: {supported}")
    return aliases[normalized]


def _dpi_pair(value: float | Sequence[float]) -> tuple[float, float]:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        if len(value) != 2:
            raise ValueError("viewport.dpi_scale sequence must contain exactly 2 values")
        dpi_x = _finite_number(value[0], "viewport.dpi_scale[0]")
        dpi_y = _finite_number(value[1], "viewport.dpi_scale[1]")
    else:
        dpi_x = dpi_y = _finite_number(value, "viewport.dpi_scale")
    if dpi_x <= 0.0 or dpi_y <= 0.0:
        raise ValueError("viewport.dpi_scale values must be greater than zero")
    return dpi_x, dpi_y


def _coerce_viewport(value: Viewport | Mapping[str, Any]) -> Viewport:
    if isinstance(value, Viewport):
        return value
    if not isinstance(value, Mapping):
        raise TypeError("viewport must be a Viewport or mapping")
    allowed = {"width", "height", "x", "y", "origin", "dpi_scale"}
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ValueError(f"viewport contains unsupported fields: {', '.join(unknown)}")
    missing = sorted({"width", "height"} - set(value))
    if missing:
        raise ValueError(f"viewport is missing required fields: {', '.join(missing)}")
    return Viewport(**dict(value))


def _matrix_values(matrix: Iterable[Real]) -> tuple[float, ...]:
    if isinstance(matrix, (str, bytes, bytearray, Mapping)):
        raise TypeError("matrix must be a flat iterable of exactly 16 real numbers")
    try:
        raw = tuple(matrix)
    except TypeError as exc:
        raise TypeError("matrix must be a flat iterable of exactly 16 real numbers") from exc
    if len(raw) != 16:
        raise ValueError(f"matrix must contain exactly 16 values; received {len(raw)}")
    return tuple(_finite_number(value, f"matrix[{index}]") for index, value in enumerate(raw))


def _matrix_rows(
    values: tuple[float, ...], layout: str
) -> tuple[ClipPoint, ClipPoint, ClipPoint, ClipPoint]:
    if layout == ROW_MAJOR:
        rows = tuple(
            tuple(values[row * 4 + column] for column in range(4))
            for row in range(4)
        )
    else:
        rows = tuple(
            tuple(values[column * 4 + row] for column in range(4))
            for row in range(4)
        )
    return rows  # type: ignore[return-value]


def _point3(point: Iterable[Real], name: str) -> tuple[float, float, float]:
    if isinstance(point, (str, bytes, bytearray, Mapping)):
        raise TypeError(f"{name} must be a flat iterable of exactly 3 real numbers")
    try:
        values = tuple(point)
    except TypeError as exc:
        raise TypeError(f"{name} must be a flat iterable of exactly 3 real numbers") from exc
    if len(values) != 3:
        raise ValueError(f"{name} must contain exactly 3 values; received {len(values)}")
    return tuple(
        _finite_number(value, f"{name}[{index}]")
        for index, value in enumerate(values)
    )  # type: ignore[return-value]


def _clip_to_ndc(clip: ClipPoint) -> tuple[float, float, float]:
    x, y, z, w = clip
    ndc = (x / w, y / w, z / w)
    if not all(math.isfinite(value) for value in ndc):
        raise ValueError("perspective divide produced non-finite NDC coordinates")
    return ndc


def _point_summary(observations: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    visible = sum(1 for item in observations if item["visible"])
    reasons = Counter(
        str(item["clipped_reason"])
        for item in observations
        if item["clipped_reason"] is not None
    )
    return {
        "point_count": len(observations),
        "visible_count": visible,
        "clipped_count": len(observations) - visible,
        "clipped_reasons": {key: reasons[key] for key in sorted(reasons)},
    }


def _aabb_corners(
    minimum: tuple[float, float, float], maximum: tuple[float, float, float]
) -> tuple[tuple[float, float, float], ...]:
    return tuple(
        (
            maximum[0] if index & 1 else minimum[0],
            maximum[1] if index & 2 else minimum[1],
            maximum[2] if index & 4 else minimum[2],
        )
        for index in range(8)
    )


_AABB_FACES = (
    (0, 1, 3, 2),
    (4, 6, 7, 5),
    (0, 4, 5, 1),
    (2, 3, 7, 6),
    (0, 2, 6, 4),
    (1, 5, 7, 3),
)


def _plane_distance(point: ClipPoint, coefficients: ClipPoint) -> float:
    return sum(point[index] * coefficients[index] for index in range(4))


def _clip_polygon(
    polygon: Sequence[ClipPoint],
    coefficients: ClipPoint,
    epsilon: float,
) -> list[ClipPoint]:
    if not polygon:
        return []
    output: list[ClipPoint] = []
    previous = polygon[-1]
    previous_distance = _plane_distance(previous, coefficients)
    previous_inside = previous_distance >= -epsilon
    for current in polygon:
        current_distance = _plane_distance(current, coefficients)
        current_inside = current_distance >= -epsilon
        if current_inside != previous_inside:
            denominator = previous_distance - current_distance
            if denominator != 0.0:
                amount = previous_distance / denominator
                amount = min(1.0, max(0.0, amount))
                intersection = tuple(
                    previous[index] + amount * (current[index] - previous[index])
                    for index in range(4)
                )
                if not all(math.isfinite(value) for value in intersection):
                    raise ValueError("frustum clipping produced non-finite coordinates")
                output.append(intersection)  # type: ignore[arg-type]
        if current_inside:
            output.append(current)
        previous = current
        previous_distance = current_distance
        previous_inside = current_inside
    return output


def _bbox(points: Sequence[tuple[float, float]]) -> list[float] | None:
    if not points:
        return None
    xs = [point[0] for point in points]
    ys = [point[1] for point in points]
    return [min(xs), min(ys), max(xs), max(ys)]


def _bbox_details(
    logical: list[float] | None, physical: list[float] | None
) -> dict[str, Any] | None:
    if logical is None or physical is None:
        return None
    return {
        "logical": {
            "min": logical[:2],
            "max": logical[2:],
            "x": logical[0],
            "y": logical[1],
            "width": logical[2] - logical[0],
            "height": logical[3] - logical[1],
        },
        "physical": {
            "min": physical[:2],
            "max": physical[2:],
            "x": physical[0],
            "y": physical[1],
            "width": physical[2] - physical[0],
            "height": physical[3] - physical[1],
        },
    }


def _aabb_rejection_reason(corners: Sequence[Mapping[str, Any]]) -> str:
    reason_sets = [set(item["clipped_reasons"]) for item in corners]
    if not reason_sets:
        return "outside_frustum"
    common = set.intersection(*reason_sets)
    for reason in _CLIP_REASON_ORDER:
        if reason in common:
            return reason
    return "outside_frustum"


def _aabb_entry(item: Any, index: int) -> tuple[Any, Any, Any | None]:
    if isinstance(item, Mapping):
        allowed = {"minimum", "maximum", "min", "max", "id", "aabb_id"}
        unknown = sorted(set(item) - allowed)
        if unknown:
            raise ValueError(
                f"aabbs[{index}] contains unsupported fields: {', '.join(unknown)}"
            )
        minimum_key = "minimum" if "minimum" in item else "min"
        maximum_key = "maximum" if "maximum" in item else "max"
        if minimum_key not in item or maximum_key not in item:
            raise ValueError(f"aabbs[{index}] must define minimum and maximum")
        identifier = item.get("aabb_id", item.get("id"))
        normalized_id = (
            None if identifier is None else _json_value(identifier, f"aabbs[{index}].id")
        )
        return item[minimum_key], item[maximum_key], normalized_id
    if isinstance(item, (str, bytes, bytearray)):
        raise TypeError(f"aabbs[{index}] must be an AABB pair or mapping")
    try:
        pair = tuple(item)
    except TypeError as exc:
        raise TypeError(f"aabbs[{index}] must be an AABB pair or mapping") from exc
    if len(pair) != 2:
        raise ValueError(f"aabbs[{index}] must contain exactly minimum and maximum")
    return pair[0], pair[1], None


def _provenance_value(value: Any, name: str) -> str | dict[str, Any]:
    if isinstance(value, str):
        if not value.strip():
            raise ValueError(f"{name} must not be empty")
        return value.strip()
    if not isinstance(value, Mapping):
        raise TypeError(f"{name} must be a non-empty string or mapping")
    if not value:
        raise ValueError(f"{name} mapping must not be empty")
    normalized = _json_value(value, name)
    if not isinstance(normalized, dict):  # pragma: no cover - Mapping contract
        raise TypeError(f"{name} must be a mapping")
    return normalized


def _json_value(value: Any, name: str) -> Any:
    if value is None or isinstance(value, (str, bool)):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, Real):
        return _finite_number(value, name)
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key in sorted(value):
            if not isinstance(key, str):
                raise TypeError(f"{name} mapping keys must be strings")
            result[key] = _json_value(value[key], f"{name}.{key}")
        return result
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [
            _json_value(item, f"{name}[{index}]")
            for index, item in enumerate(value)
        ]
    raise TypeError(f"{name} contains a non-JSON value of type {type(value).__name__}")


def _compact_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _reject_text_or_mapping(value: Any, name: str) -> None:
    if isinstance(value, (str, bytes, bytearray, Mapping)):
        raise TypeError(f"{name} must be an iterable, not {type(value).__name__}")


def _atomic_write(path: Path, data: bytes) -> None:
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary.write(data)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_name = temporary.name
        os.replace(temporary_name, path)
        temporary_name = None
    finally:
        if temporary_name is not None:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass


__all__ = [
    "ARTIFACT_TYPE",
    "BOTTOM_LEFT",
    "COLUMN_MAJOR",
    "D3D",
    "LEFT_HANDED",
    "OPENGL",
    "ProjectionEngine",
    "ProjectionEvidenceEngine",
    "RIGHT_HANDED",
    "ROW_MAJOR",
    "SCHEMA_VERSION",
    "TOP_LEFT",
    "Viewport",
    "WorldProjectionEngine",
    "project_aabb",
    "project_point",
    "project_points",
    "project_world_aabb",
    "project_world_point",
    "project_world_points",
    "projection_artifact_bytes",
    "projection_artifact_sha256",
    "world_to_screen",
    "write_projection_artifact",
]
