from __future__ import annotations

import copy
import hashlib
import json
import math
import tempfile
import unittest
from pathlib import Path

from reverse_analyzer.core.capabilities.audit_contract import validate_capability_audit_record
from reverse_analyzer.core.capabilities.models import CapabilityRequest, TargetIdentity
from reverse_analyzer.providers.target_control import (
    MAX_CANDIDATES_PER_FRAME,
    MAX_FRAMES,
    MAX_TRAJECTORY_STEPS,
    SimulationConfig,
    TargetControlProvider,
    score_candidate,
    select_target,
    simulate_target_control,
)


def _target() -> TargetIdentity:
    return TargetIdentity(
        kind="offline_observation_set",
        display_name="deterministic-fixture",
        sha256="a" * 64,
        metadata={"source": "unit-test", "offline": True},
    )


def _candidate(
    target_id: str,
    *,
    x: float = 1.0,
    y: float = 0.0,
    distance: float = 100.0,
    confidence: float = 0.9,
    **extra: object,
) -> dict[str, object]:
    return {
        "target_id": target_id,
        "offset_x": x,
        "offset_y": y,
        "distance": distance,
        "confidence": confidence,
        **extra,
    }


def _frames(*, reverse_candidates: bool = False) -> list[dict[str, object]]:
    candidates = [
        _candidate("beta", x=2.0, y=1.0, distance=50.0, confidence=0.95),
        _candidate("alpha", x=2.0, y=1.0, distance=50.0, confidence=0.95),
        _candidate("friendly", x=0.0, y=0.0, distance=1.0, confidence=1.0, hostile=False),
    ]
    if reverse_candidates:
        candidates.reverse()
    return [
        {
            "frame_id": "frame-0",
            "timestamp_ms": 0,
            "recoil": {"x": 0.5, "y": 0.25},
            "candidates": candidates,
        },
        {
            "frame_id": "frame-1",
            "timestamp_ms": 16,
            "recoil": {"x": 0.25, "y": 0.5},
            "candidates": [
                _candidate("alpha", x=0.5, y=0.25, distance=45.0, confidence=0.97),
                _candidate("hidden", x=0.0, y=0.0, distance=1.0, confidence=1.0, visible=False),
            ],
        },
    ]


def _request(
    *,
    params: dict[str, object] | None = None,
    action: str = "simulate",
    capability: str = "target_control_simulation",
    session_id: str = "target-control-fixture",
) -> CapabilityRequest:
    return CapabilityRequest(
        capability=capability,
        action=action,
        target=_target(),
        params=params
        or {
            "frames": _frames(),
            "config": {
                "max_fov": 20.0,
                "max_distance": 500.0,
                "min_confidence": 0.5,
                "smoothing_factor": 0.5,
                "trajectory_steps": 3,
                "max_step": 10.0,
                "trigger_radius": 0.25,
                "trigger_min_confidence": 0.8,
                "recoil_scale_x": 1.0,
                "recoil_scale_y": 2.0,
            },
        },
        session_id=session_id,
        provenance={"fixture": "explicit-offline-observations"},
    )


class TargetControlPureAlgorithmTests(unittest.TestCase):
    def test_direct_config_instances_are_revalidated(self) -> None:
        candidate = _candidate("finite-config")
        with self.assertRaises(ValueError):
            score_candidate(candidate, SimulationConfig(max_fov=float("nan")))
        with self.assertRaises(ValueError):
            select_target(
                [candidate],
                SimulationConfig(trajectory_steps=MAX_TRAJECTORY_STEPS + 1),
            )

    def test_scoring_filters_and_identity_tie_break_are_deterministic(self) -> None:
        config = SimulationConfig.from_mapping(
            {
                "max_fov": 10.0,
                "max_distance": 100.0,
                "min_confidence": 0.5,
                "weights": {"fov": 0.5, "distance": 0.25, "confidence": 0.25},
            }
        )
        alpha = _candidate("alpha", x=1.0, distance=25.0, confidence=0.8)
        beta = _candidate("beta", x=1.0, distance=25.0, confidence=0.8)
        friendly = _candidate("friendly", x=0.0, distance=1.0, confidence=1.0, hostile=False)

        scored = score_candidate(alpha, config)
        self.assertTrue(scored["eligible"])
        self.assertAlmostEqual(scored["score_components"]["fov"], 0.9)
        self.assertEqual(select_target([beta, friendly, alpha], config)["target_id"], "alpha")
        self.assertEqual(select_target([alpha, friendly, beta], config)["target_id"], "alpha")

        rejected = score_candidate({**alpha, "confidence": 0.1, "visible": False}, config)
        self.assertFalse(rejected["eligible"])
        self.assertEqual(rejected["rejection_reasons"], ["not_visible", "confidence_below_minimum"])

    def test_full_simulation_is_order_independent_and_finite(self) -> None:
        config = {
            "max_fov": 20.0,
            "max_distance": 500.0,
            "smoothing_factor": 0.5,
            "trajectory_steps": 3,
            "max_step": 10.0,
            "trigger_radius": 0.25,
            "recoil_compensation": {"enabled": True, "scale_x": 1.0, "scale_y": 2.0},
        }
        first = simulate_target_control(_frames(), config)
        second = simulate_target_control(_frames(reverse_candidates=True), config)

        self.assertEqual(first, second)
        self.assertEqual(first["frames"][0]["selected_target"]["target_id"], "alpha")
        self.assertEqual(first["frames"][0]["recoil"]["compensation"], {"x": -0.5, "y": -0.5})
        self.assertEqual(len(first["control_trajectory"]), 6)
        self.assertFalse(first["boundary"]["input_emission"])
        for point in first["control_trajectory"]:
            self.assertTrue(math.isfinite(point["command"]["x"]))
            self.assertTrue(math.isfinite(point["command"]["y"]))

    def test_no_eligible_candidate_holds_control_and_never_triggers(self) -> None:
        output = simulate_target_control(
            [
                {
                    "frame_id": "empty",
                    "candidates": [
                        _candidate("hidden", visible=False),
                        _candidate("far", distance=2000.0),
                    ],
                }
            ],
            {"max_distance": 1000.0, "initial_control": {"x": 2.0, "y": -3.0}},
        )
        frame = output["frames"][0]
        self.assertIsNone(frame["selected_target"])
        self.assertEqual(frame["control"]["end"], {"x": 2.0, "y": -3.0})
        self.assertFalse(frame["trigger"]["would_trigger"])
        self.assertEqual(output["trigger_events"], [])

    def test_absolute_screen_positions_are_reduced_to_bounded_offsets(self) -> None:
        output = simulate_target_control(
            [
                {
                    "frame_id": "pixels",
                    "crosshair": {"x": 960, "y": 540},
                    "candidates": [
                        {
                            "id": "centered",
                            "screen_position": {"x": 962, "y": 539},
                            "distance": 10,
                            "confidence": 1.0,
                        }
                    ],
                }
            ],
            {"max_fov": 10.0},
        )
        selected = output["frames"][0]["selected_target"]
        self.assertEqual(selected["offset"], {"x": 2.0, "y": -1.0})
        self.assertAlmostEqual(selected["fov"], math.sqrt(5.0))


class TargetControlProviderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.provider = TargetControlProvider()

    def test_plan_validate_execute_exposes_complete_truthful_offline_audit(self) -> None:
        request = _request()
        self.assertTrue(self.provider.supports(request))

        plan = self.provider.plan(request)
        self.assertEqual(plan.capability, "target_control_simulation")
        self.assertEqual(plan.provider, "offline_target_control_simulator")
        self.assertEqual(len(plan.precondition_hash), 64)
        self.assertEqual(plan.before_snapshot["frame_count"], 2)
        self.assertEqual(plan.before_snapshot["candidate_count"], 5)
        self.assertFalse(plan.provenance["mocked"])
        self.assertEqual(plan.provenance["dependency"]["status"], "not_required")
        self.assertFalse(plan.provenance["boundary"]["process_access"])

        validation = self.provider.validate(plan)
        self.assertTrue(validation.ok, validation.errors)
        self.assertTrue(all(check["status"] == "ok" for check in validation.checks))

        result = self.provider.execute(plan)
        self.assertEqual(result.status, "ok")
        self.assertEqual(result.session_id, request.session_id)
        self.assertEqual(result.after_snapshot["selected_target_identity"]["id"], "alpha")
        self.assertTrue(result.after_snapshot["simulation_completed"])
        self.assertFalse(result.after_snapshot["external_state_changed"])
        self.assertFalse(result.provenance["mocked"])
        self.assertEqual(result.provenance["dependency"], {"required": False, "status": "not_required"})
        self.assertFalse(result.provenance["live_automated_target_control_completed"])
        self.assertFalse(result.report_section["live_automated_target_control_completed"])
        self.assertFalse(hasattr(self.provider, "backend"))

    def test_precondition_hash_is_reproducible_order_independent_and_tamper_evident(self) -> None:
        first_plan = self.provider.plan(_request())
        second_plan = self.provider.plan(
            _request(params={"frames": _frames(reverse_candidates=True), "config": copy.deepcopy(_request().params["config"])})
        )
        canonical = json.dumps(
            first_plan.before_snapshot["precondition_payload"],
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
        self.assertEqual(first_plan.precondition_hash, hashlib.sha256(canonical).hexdigest())
        self.assertEqual(first_plan.precondition_hash, second_plan.precondition_hash)

        changed = _frames()
        changed[0]["candidates"][0]["confidence"] = 0.94
        changed_plan = self.provider.plan(
            _request(params={"frames": changed, "config": copy.deepcopy(_request().params["config"])})
        )
        self.assertNotEqual(first_plan.precondition_hash, changed_plan.precondition_hash)

        first_plan.parameters["frames"][0]["candidates"][0]["confidence"] = 0.1
        validation = self.provider.validate(first_plan)
        self.assertFalse(validation.ok)
        self.assertTrue(any("precondition hash" in error for error in validation.errors))
        rejected = self.provider.execute(first_plan)
        self.assertEqual(rejected.status, "failed")
        self.assertFalse(rejected.after_snapshot["simulation_completed"])

    def test_flat_observations_are_grouped_into_bounded_frames(self) -> None:
        observations = [
            {**_candidate("b", x=2.0), "frame_id": "f0", "timestamp_ms": 0},
            {**_candidate("a", x=1.0), "frame_id": "f0", "timestamp_ms": 0},
            {**_candidate("a", x=0.5), "frame_id": "f1", "timestamp_ms": 5},
        ]
        plan = self.provider.plan(_request(params={"observations": observations}))
        self.assertEqual(plan.parameters["source_kind"], "observations")
        self.assertEqual([frame["frame_id"] for frame in plan.parameters["frames"]], ["f0", "f1"])
        self.assertEqual(
            [item["target_id"] for item in plan.parameters["frames"][0]["candidates"]],
            ["a", "b"],
        )
        self.assertTrue(self.provider.validate(plan).ok)

    def test_rollback_restores_only_simulated_state_and_is_idempotent(self) -> None:
        result = self.provider.execute(self.provider.plan(_request()))
        first = self.provider.rollback(result)
        self.assertTrue(first.ok)
        self.assertTrue(first.restored)
        self.assertEqual(first.details["control"], {"x": 0.0, "y": 0.0})
        self.assertTrue(first.details["simulation_state_restored"])
        self.assertFalse(first.details["external_state_changed"])
        self.assertFalse(first.details["external_state_restored"])
        self.assertEqual(result.rollback_plan["status"], "completed")

        second = self.provider.rollback(result)
        self.assertTrue(second.ok)
        self.assertTrue(second.restored)
        self.assertEqual(second.details["status"], "already_completed")

    def test_artifacts_persist_deterministically_with_hashes_and_valid_audit(self) -> None:
        result = self.provider.execute(self.provider.plan(_request()))
        self.provider.rollback(result)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first_bundle = self.provider.collect_artifacts(result, str(root))
            first_bytes = {item.path: (root / item.path).read_bytes() for item in first_bundle.artifacts}
            second_bundle = self.provider.collect_artifacts(result, str(root))
            second_bytes = {item.path: (root / item.path).read_bytes() for item in second_bundle.artifacts}

            self.assertEqual(first_bytes, second_bytes)
            self.assertEqual(len(first_bundle.artifacts), 3)
            self.assertEqual(len(first_bundle.manifest_entries), 3)
            for artifact in first_bundle.artifacts:
                payload = first_bytes[artifact.path]
                self.assertEqual(artifact.metadata["sha256"], hashlib.sha256(payload).hexdigest())
                self.assertEqual(artifact.metadata["size"], len(payload))
                self.assertTrue((root / artifact.path).resolve().is_relative_to(root.resolve()))

            audit_artifact = next(item for item in first_bundle.artifacts if item.kind == "target-control-audit")
            manifest_artifact = next(item for item in first_bundle.artifacts if item.kind == "evidence-manifest")
            audit = json.loads(first_bytes[audit_artifact.path])
            manifest = json.loads(first_bytes[manifest_artifact.path])
            contract = validate_capability_audit_record(audit)
            self.assertTrue(contract.ok, contract.errors)
            self.assertEqual(audit["session_id"], result.session_id)
            self.assertEqual(audit["precondition_hash"], result.provenance["precondition_hash"])
            self.assertFalse(audit["boundary"]["input_device_access"])
            self.assertFalse(audit["live_automated_target_control_completed"])
            self.assertEqual(manifest["entry_count"], 2)
            self.assertEqual(manifest["manifest_artifact"]["path"], manifest_artifact.path)
            self.assertTrue(all(entry["sha256"] for entry in manifest["entries"]))
            self.assertTrue(all(entry["sha256"] for entry in second_bundle.manifest_entries))

    def test_rejects_unknown_actions_nonfinite_values_bounds_and_count_overflow(self) -> None:
        unknown = _request(action="live_control")
        self.assertFalse(self.provider.supports(unknown))
        with self.assertRaises(ValueError):
            self.provider.plan(unknown)
        with self.assertRaises(ValueError):
            self.provider.plan(_request(capability="automated_target_control"))

        invalid_params: list[dict[str, object]] = [
            {"frames": [{"candidates": [_candidate("nan", x=float("nan"))]}]},
            {"frames": [{"candidates": [_candidate("inf", distance=float("inf"))]}]},
            {"frames": [{"candidates": [_candidate("confidence", confidence=1.01)]}]},
            {"frames": [{"candidates": [_candidate("distance", distance=-1.0)]}]},
            {"frames": [{"candidates": [_candidate("boolean", x=True)]}]},
            {"frames": [{"candidates": [_candidate("huge", x=10**4000)]}]},
            {"frames": [{"timestamp_ms": 2, "candidates": []}, {"timestamp_ms": 1, "candidates": []}]},
            {"frames": [{"candidates": [_candidate("duplicate"), _candidate("duplicate")]}]},
            {"frames": [{"candidates": []}], "config": {"max_fov": 0.0}},
            {
                "frames": [{"candidates": []}],
                "config": {"trajectory_steps": MAX_TRAJECTORY_STEPS + 1},
            },
            {"frames": [{"candidates": []}], "observations": []},
            {"frames": [{"candidates": []}], "unknown_parameter": 1},
            {
                "frames": [
                    {"frame_id": index, "timestamp_ms": index, "candidates": []}
                    for index in range(MAX_FRAMES + 1)
                ]
            },
            {
                "frames": [
                    {
                        "candidates": [
                            _candidate(f"target-{index}")
                            for index in range(MAX_CANDIDATES_PER_FRAME + 1)
                        ]
                    }
                ]
            },
        ]
        for params in invalid_params:
            with self.subTest(params=list(params)):
                with self.assertRaises((TypeError, ValueError)):
                    self.provider.plan(_request(params=params))


if __name__ == "__main__":
    unittest.main()
