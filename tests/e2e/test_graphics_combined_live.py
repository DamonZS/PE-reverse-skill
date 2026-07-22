"""Opt-in retained acceptance for the bounded P7 graphics composition path."""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import unittest
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from reverse_analyzer.core.capabilities.models import CapabilityRequest, TargetIdentity
from reverse_analyzer.gui.world_projection import Viewport, WorldProjectionEngine
from reverse_analyzer.providers.graphics_runtime import GraphicsRuntimeProvider
from reverse_analyzer.providers.render_overlay import RenderOverlayProvider
from tests._graphics_acceptance import (
    acceptance_context,
    assert_non_synthetic,
    required_pid,
    write_bundle,
)


def _required_handle() -> int:
    raw = str(os.environ.get("REVERSE_ANALYZER_GRAPHICS_FIXTURE_HWND") or "").strip()
    try:
        value = int(raw, 16 if raw.casefold().startswith("0x") else 10)
    except ValueError as exc:
        raise AssertionError(
            "REVERSE_ANALYZER_GRAPHICS_FIXTURE_HWND must contain a positive handle"
        ) from exc
    if value <= 0:
        raise AssertionError(
            "REVERSE_ANALYZER_GRAPHICS_FIXTURE_HWND must contain a positive handle"
        )
    return value


def _mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise AssertionError(f"native bridge {name} must be an object")
    result = dict(value)
    assert_non_synthetic(result, location=name)
    return result


def _world_points(value: Any) -> list[tuple[str, tuple[float, float, float]]]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise AssertionError("matrix capture world_points must be an array")
    if not 1 <= len(value) <= 256:
        raise AssertionError("matrix capture must contain 1-256 world points")
    points: list[tuple[str, tuple[float, float, float]]] = []
    for index, item in enumerate(value):
        entry = _mapping(item, f"world_points[{index}]")
        position = entry.get("position")
        if (
            not isinstance(position, Sequence)
            or isinstance(position, (str, bytes, bytearray))
            or len(position) != 3
        ):
            raise AssertionError(f"world_points[{index}].position must contain three numbers")
        try:
            coordinates = tuple(float(component) for component in position)
        except (TypeError, ValueError) as exc:
            raise AssertionError(
                f"world_points[{index}].position must contain three numbers"
            ) from exc
        points.append((str(entry.get("id") or f"point-{index}"), coordinates))
    return points


def _bridge_sha256(description: Mapping[str, Any]) -> str | None:
    identity = description.get("executable_identity")
    return str(identity.get("sha256")) if isinstance(identity, Mapping) else None


@unittest.skipUnless(
    sys.platform == "win32" and os.environ.get("RUN_GRAPHICS_COMBINED_LIVE") == "1",
    "set RUN_GRAPHICS_COMBINED_LIVE=1 on an interactive Windows graphics fixture",
)
class GraphicsCombinedLiveTests(unittest.TestCase):
    def test_present_matrix_projection_overlay_retains_artifacts(self) -> None:
        acceptance = acceptance_context("p7-graphics-combined-live")
        if acceptance is None:
            self.skipTest("p7-graphics-combined-live acceptance context is not active")
        pid = required_pid()
        hwnd = _required_handle()
        bridge_path = str(os.environ.get("REVERSE_ANALYZER_GRAPHICS_BRIDGE") or "").strip()
        self.assertTrue(bridge_path)
        target = TargetIdentity(
            kind="process",
            pid=pid,
            display_name=f"controlled-graphics-host-{pid}",
            metadata={"hwnd": hwnd},
        )

        graphics = GraphicsRuntimeProvider(
            bridge_executable=bridge_path,
            platform_name="win32",
        )
        request = CapabilityRequest(
            capability="graphics_present_runtime",
            action="capture",
            target=target,
            params={
                "duration_ms": 2_000,
                "timeout_ms": 15_000,
                "max_events": 20_000,
                "capture_format": "json",
                "api_filter": ["D3D11"],
            },
            session_id=acceptance.session_id,
            provenance={"source": "p7-graphics-combined-acceptance"},
        )
        plan = graphics.plan(request)
        self.assertEqual(plan.parameters["execution_adapter"], "native_bridge")
        validation = graphics.validate(plan)
        self.assertTrue(validation.ok, validation.to_dict())
        graphics_result = graphics.execute(plan)
        self.assertIn(graphics_result.status, {"ok", "partial"})
        events = list(graphics_result.report_section.get("events") or [])
        self.assertGreater(len(events), 0)
        self.assertTrue(all(int(item.get("pid") or 0) == pid for item in events))

        matrix_probe = graphics.bridge.probe(
            required_operations=("acquire_matrix",),
            required_backends=("d3d11",),
        )
        self.assertTrue(matrix_probe.ok, matrix_probe.error)
        matrix_call = graphics.bridge.invoke(
            "acquire_matrix",
            {
                "pid": pid,
                "hwnd": hwnd,
                "backend": "d3d11",
                "present_event": events[-1],
            },
            session_id=acceptance.session_id,
            timeout_ms=15_000,
        )
        self.assertTrue(matrix_call.ok, matrix_call.error)
        response = _mapping(matrix_call.response, "matrix_response")
        capture = _mapping(response.get("result"), "matrix_capture")
        self.assertEqual(int(capture.get("pid") or 0), pid)
        self.assertEqual(int(capture.get("hwnd") or 0), hwnd)
        self.assertTrue(capture.get("frame_id"))
        self.assertEqual(capture.get("source"), "native_host_bridge")
        matrix = capture.get("matrix")
        if not isinstance(matrix, Sequence) or isinstance(matrix, (str, bytes, bytearray)):
            self.fail("matrix capture matrix must be an array")
        viewport_payload = _mapping(capture.get("viewport"), "matrix_capture.viewport")
        points = _world_points(capture.get("world_points"))
        engine = WorldProjectionEngine(
            matrix,
            matrix_layout=str(capture.get("matrix_layout") or "row-major"),
            clip_convention=str(capture.get("clip_convention") or "d3d"),
            handedness=str(capture.get("handedness") or "left-handed"),
            reversed_z=capture.get("reversed_z") is True,
            viewport=Viewport(
                **{
                    key: viewport_payload[key]
                    for key in ("width", "height", "x", "y", "origin", "dpi_scale")
                    if key in viewport_payload
                }
            ),
            matrix_source={
                "kind": "live-native-bridge-capture",
                "frame_id": capture["frame_id"],
                "bridge_sha256": _bridge_sha256(graphics.bridge.describe()),
            },
            coordinate_system=_mapping(
                capture.get("coordinate_system"), "matrix_capture.coordinate_system"
            ),
        )
        projection = engine.project_points(position for _, position in points)
        for identity, observation in zip(points, projection["points"], strict=True):
            observation["point_id"] = identity[0]
        visible = [item for item in projection["points"] if item.get("visible")]
        self.assertGreater(len(visible), 0, projection)

        width = int(float(viewport_payload["width"]))
        height = int(float(viewport_payload["height"]))
        primitives: list[dict[str, Any]] = []
        for item in visible[:64]:
            logical = list(_mapping(item.get("screen"), "projection.screen")["logical"])
            x = min(max(int(round(float(logical[0]))), 0), width - 1)
            y = min(max(int(round(float(logical[1]))), 0), height - 1)
            primitives.append(
                {
                    "type": "text",
                    "x": x,
                    "y": y,
                    "text": str(item.get("point_id") or "point")[:64],
                    "color": "#00FF66",
                    "font_size": 14,
                }
            )

        overlay = RenderOverlayProvider()
        overlay_request = CapabilityRequest(
            capability="render_overlay_runtime",
            action="render",
            target=target,
            params={
                "pid": pid,
                "hwnd": hwnd,
                "duration_ms": 100,
                "frame_interval_ms": 16,
                "primitives": primitives,
            },
            session_id=acceptance.session_id,
            provenance={
                "source": "p7-graphics-combined-acceptance",
                "matrix_frame_id": capture["frame_id"],
            },
        )
        overlay_plan = overlay.plan(overlay_request)
        overlay_validation = overlay.validate(overlay_plan)
        self.assertTrue(overlay_validation.ok, overlay_validation.to_dict())
        overlay_result = overlay.execute(overlay_plan)
        self.assertEqual(overlay_result.status, "ok", overlay_result.report_section)
        cleanup = dict(overlay_result.after_snapshot.get("resource_cleanup") or {})
        self.assertTrue(cleanup.get("resources_released"), cleanup)
        overlay_rollback = overlay.rollback(overlay_result)
        self.assertTrue(overlay_rollback.ok, overlay_rollback.details)
        graphics_rollback = graphics.rollback(graphics_result)
        self.assertTrue(graphics_rollback.ok, graphics_rollback.details)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            bundle = overlay.collect_artifacts(overlay_result, root)
            audit_artifact = next(
                item for item in bundle.artifacts if item.kind == "render-overlay-audit"
            )
            overlay_audit = json.loads((root / audit_artifact.path).read_text("utf-8"))

        matrix_audit = {
            **capture,
            "bridge_executable_sha256": _bridge_sha256(graphics.bridge.describe()),
            "bridge_request_sha256": hashlib.sha256(
                json.dumps(matrix_call.request, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
            "bridge_response_sha256": hashlib.sha256(
                json.dumps(response, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
        }
        present_observation = {
            "status": "ok",
            "provider": graphics_result.provider,
            "target_pid": pid,
            "event_count": len(events),
            "apis": graphics_result.report_section.get("apis"),
            "last_event": events[-1],
            "matrix_frame_id": capture["frame_id"],
        }
        cleanup_proof = {
            "status": "completed",
            "verified": True,
            "rollback_verified": True,
            "cleanup_verified": True,
            "overlay": cleanup,
            "overlay_rollback": overlay_rollback.details,
            "graphics_rollback": graphics_rollback.details,
        }
        execution_proof = {
            "status": "ok",
            "provider": "native-graphics-bridge-plus-windows-gdi",
            "evidence_class": "live_host_proof",
            "executed_tests": 1,
            "skipped_tests": 0,
            "live_operations": 4,
            "actions": [
                "observe_present",
                "acquire_matrix",
                "project_world_points",
                "render_external_overlay",
            ],
            "present_event_count": len(events),
            "projected_point_count": len(projection["points"]),
            "visible_point_count": len(visible),
            "overlay_frame_count": overlay_audit.get("frame_count"),
            "target_pid": pid,
            "target_hwnd": hwnd,
            "matrix_frame_id": capture["frame_id"],
            "cleanup_verified": True,
        }
        artifacts = {
            "graphics-combined/target-identity.json": target.to_dict(),
            "graphics-combined/present-observation.json": present_observation,
            "graphics-combined/matrix-capture.json": matrix_audit,
            "graphics-combined/projection.json": projection,
            "graphics-combined/overlay-audit.json": overlay_audit,
            "graphics-combined/cleanup.json": cleanup_proof,
            "graphics-combined/execution-proof.json": execution_proof,
        }
        for payload in artifacts.values():
            assert_non_synthetic(payload)
        write_bundle(acceptance, artifacts)


if __name__ == "__main__":
    unittest.main()
