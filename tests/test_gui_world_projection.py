"""Deterministic contracts for GUI world-to-viewport projection evidence."""

from __future__ import annotations

import json
import math
import tempfile
import unittest
from pathlib import Path

from reverse_analyzer.gui.world_projection import (
    Viewport,
    WorldProjectionEngine,
    write_projection_artifact,
)


IDENTITY = (
    1.0,
    0.0,
    0.0,
    0.0,
    0.0,
    1.0,
    0.0,
    0.0,
    0.0,
    0.0,
    1.0,
    0.0,
    0.0,
    0.0,
    0.0,
    1.0,
)


class WorldProjectionTests(unittest.TestCase):
    def _engine(
        self,
        matrix=IDENTITY,
        *,
        matrix_layout: str = "row-major",
        clip_convention: str = "opengl",
        handedness: str = "right-handed",
        reversed_z: bool = False,
        viewport: Viewport | None = None,
    ) -> WorldProjectionEngine:
        return WorldProjectionEngine(
            matrix,
            matrix_layout=matrix_layout,
            clip_convention=clip_convention,
            handedness=handedness,
            reversed_z=reversed_z,
            viewport=viewport or Viewport(width=200.0, height=100.0),
            matrix_source={"kind": "unit-test", "name": "analytic-fixture"},
            coordinate_system={"name": "fixture-world", "units": "meters"},
        )

    def test_known_identity_matrix_maps_ndc_to_offset_top_left_viewport(self) -> None:
        engine = self._engine(
            viewport=Viewport(
                width=200.0,
                height=100.0,
                x=10.0,
                y=20.0,
                origin="top-left",
            )
        )

        center = engine.project_point((0.0, 0.0, 0.0), point_id="origin")
        upper_right = engine.project_point((1.0, 1.0, 0.0))

        self.assertTrue(center["visible"])
        self.assertEqual(center["visibility"], "visible")
        self.assertEqual(center["clip"], [0.0, 0.0, 0.0, 1.0])
        self.assertEqual(center["ndc"], [0.0, 0.0, 0.0])
        self.assertEqual(center["screen"]["logical"], [110.0, 70.0])
        self.assertEqual(center["screen"]["physical"], [110.0, 70.0])
        self.assertEqual(center["point_id"], "origin")
        self.assertEqual(upper_right["screen"]["logical"], [210.0, 20.0])
        self.assertEqual(
            center["provenance"]["matrix"]["source"]["kind"], "unit-test"
        )
        self.assertEqual(
            center["provenance"]["coordinate_system"]["handedness"],
            "right-handed",
        )

    def test_row_major_and_column_major_storage_produce_same_projection(self) -> None:
        rows = (
            (2.0, 0.0, 0.0, 0.5),
            (0.0, 1.0, 0.0, -0.25),
            (0.0, 0.0, 1.0, 0.0),
            (0.0, 0.0, 0.0, 1.0),
        )
        row_major = tuple(value for row in rows for value in row)
        column_major = tuple(rows[row][column] for column in range(4) for row in range(4))

        row_result = self._engine(row_major).project_point((0.0, 0.0, 0.0))
        column_result = self._engine(
            column_major,
            matrix_layout="column-major",
        ).project_point((0.0, 0.0, 0.0))

        self.assertEqual(row_result["clip"], [0.5, -0.25, 0.0, 1.0])
        self.assertEqual(row_result["ndc"], column_result["ndc"])
        self.assertEqual(row_result["screen"], column_result["screen"])

    def test_right_handed_opengl_perspective_and_camera_rejection(self) -> None:
        # fov=90, aspect=1, near=1, far=10. Front-facing view-space Z is negative.
        matrix = (
            1.0,
            0.0,
            0.0,
            0.0,
            0.0,
            1.0,
            0.0,
            0.0,
            0.0,
            0.0,
            -11.0 / 9.0,
            -20.0 / 9.0,
            0.0,
            0.0,
            -1.0,
            0.0,
        )
        engine = self._engine(matrix)

        front = engine.project_point((0.0, 0.0, -2.0))
        behind = engine.project_point((0.0, 0.0, 1.0))
        on_camera_plane = engine.project_point((0.0, 0.0, 0.0))

        self.assertTrue(front["visible"])
        self.assertAlmostEqual(front["ndc"][2], 1.0 / 9.0)
        self.assertEqual(front["w_status"], "positive")
        self.assertFalse(behind["visible"])
        self.assertEqual(behind["clipped_reason"], "behind_camera")
        self.assertIsNone(behind["screen"])
        self.assertEqual(on_camera_plane["clipped_reason"], "w_too_small")

    def test_left_handed_d3d_perspective_uses_zero_to_one_depth(self) -> None:
        # fov=90, aspect=1, near=1, far=10. Front-facing view-space Z is positive.
        matrix = (
            1.0,
            0.0,
            0.0,
            0.0,
            0.0,
            1.0,
            0.0,
            0.0,
            0.0,
            0.0,
            10.0 / 9.0,
            -10.0 / 9.0,
            0.0,
            0.0,
            1.0,
            0.0,
        )
        engine = self._engine(
            matrix,
            clip_convention="d3d",
            handedness="left-handed",
        )

        front = engine.project_point((0.0, 0.0, 2.0))
        behind = engine.project_point((0.0, 0.0, -2.0))

        self.assertTrue(front["visible"])
        self.assertAlmostEqual(front["ndc"][2], 5.0 / 9.0)
        self.assertEqual(
            front["provenance"]["coordinate_system"]["ndc_depth_range"],
            [0.0, 1.0],
        )
        self.assertEqual(behind["clipped_reason"], "behind_camera")

    def test_offscreen_point_retains_projected_coordinates_and_clip_reason(self) -> None:
        result = self._engine(
            viewport=Viewport(width=100.0, height=100.0)
        ).project_point((2.0, 0.0, 0.0))

        self.assertFalse(result["visible"])
        self.assertEqual(result["visibility"], "clipped")
        self.assertEqual(result["clipped_reason"], "right")
        self.assertEqual(result["screen"]["physical"], [150.0, 50.0])
        self.assertEqual(result["axis_status"]["horizontal"], "right")

    def test_opengl_d3d_and_reversed_z_classify_near_and_far_planes(self) -> None:
        gl = self._engine()
        d3d = self._engine(clip_convention="d3d", handedness="left-handed")
        gl_reversed = self._engine(reversed_z=True)
        d3d_reversed = self._engine(
            clip_convention="d3d",
            handedness="left-handed",
            reversed_z=True,
        )

        self.assertEqual(gl.project_point((0.0, 0.0, -1.25))["clipped_reason"], "near_plane")
        self.assertEqual(gl.project_point((0.0, 0.0, 1.25))["clipped_reason"], "far_plane")
        self.assertEqual(d3d.project_point((0.0, 0.0, -0.1))["clipped_reason"], "near_plane")
        self.assertEqual(d3d.project_point((0.0, 0.0, 1.1))["clipped_reason"], "far_plane")
        self.assertEqual(
            gl_reversed.project_point((0.0, 0.0, 1.25))["clipped_reason"],
            "near_plane",
        )
        self.assertEqual(
            gl_reversed.project_point((0.0, 0.0, -1.25))["clipped_reason"],
            "far_plane",
        )
        self.assertEqual(
            d3d_reversed.project_point((0.0, 0.0, 1.1))["clipped_reason"],
            "near_plane",
        )
        self.assertEqual(
            d3d_reversed.project_point((0.0, 0.0, -0.1))["clipped_reason"],
            "far_plane",
        )

    def test_top_left_viewport_origin_and_dpi_scaling_are_explicit(self) -> None:
        viewport = Viewport(
            width=200.0,
            height=100.0,
            x=10.0,
            y=20.0,
            origin="top-left",
            dpi_scale=2.0,
        )
        result = self._engine(viewport=viewport).project_point((0.0, 1.0, 0.0))

        self.assertEqual(result["screen"]["logical"], [110.0, 20.0])
        self.assertEqual(result["screen"]["physical"], [220.0, 40.0])
        self.assertEqual(result["screen_2d"], [220.0, 40.0])
        self.assertEqual(result["provenance"]["viewport"]["origin"], "top-left")
        self.assertEqual(result["provenance"]["viewport"]["dpi_scale"], [2.0, 2.0])

    def test_batch_points_report_visibility_summary(self) -> None:
        result = self._engine().project_points(
            [(0.0, 0.0, 0.0), (2.0, 0.0, 0.0), (0.0, 0.0, -2.0)]
        )

        self.assertEqual(len(result["points"]), 3)
        self.assertEqual(result["summary"]["point_count"], 3)
        self.assertEqual(result["summary"]["visible_count"], 1)
        self.assertEqual(result["summary"]["clipped_count"], 2)
        self.assertEqual(result["summary"]["clipped_reasons"], {"near_plane": 1, "right": 1})

    def test_partially_visible_aabb_clips_faces_and_emits_eight_corners_and_bbox(self) -> None:
        engine = self._engine(viewport=Viewport(width=100.0, height=100.0))

        result = engine.project_aabb((0.5, -0.5, 0.0), (1.5, 0.5, 0.0), aabb_id="actor")

        self.assertTrue(result["visible"])
        self.assertEqual(result["visibility"], "partially_visible")
        self.assertEqual(result["clipped_reason"], "partially_clipped")
        self.assertEqual(result["clipped_reasons"], ["right"])
        self.assertEqual(len(result["corners"]), 8)
        self.assertEqual(result["bbox_2d"], [75.0, 25.0, 100.0, 75.0])
        self.assertEqual(result["aabb_id"], "actor")

    def test_invalid_numeric_and_ambiguous_inputs_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "exactly 16"):
            self._engine(IDENTITY[:-1])
        with self.assertRaisesRegex(ValueError, "finite"):
            self._engine((*IDENTITY[:-1], math.nan))
        with self.assertRaisesRegex(ValueError, "width"):
            Viewport(width=0.0, height=100.0)
        with self.assertRaisesRegex(ValueError, "dpi_scale"):
            Viewport(width=100.0, height=100.0, dpi_scale=math.inf)
        with self.assertRaisesRegex(ValueError, "finite"):
            self._engine().project_point((0.0, math.inf, 0.0))
        with self.assertRaisesRegex(ValueError, "minimum"):
            self._engine().project_aabb((1.0, 0.0, 0.0), (0.0, 1.0, 1.0))
        with self.assertRaisesRegex(ValueError, "matrix_layout"):
            self._engine(matrix_layout="automatic")
        with self.assertRaisesRegex(ValueError, "clip_convention"):
            self._engine(clip_convention="automatic")

    def test_artifact_json_and_hash_are_deterministic(self) -> None:
        engine = self._engine(viewport=Viewport(width=100.0, height=100.0, dpi_scale=1.5))
        artifact = engine.build_artifact(
            points=[(0.0, 0.0, 0.0), (2.0, 0.0, 0.0)],
            aabbs=[((0.5, -0.5, 0.0), (1.5, 0.5, 0.0))],
            metadata={"session_id": "fixture-session", "frame": 7},
        )

        with tempfile.TemporaryDirectory() as first_tmp, tempfile.TemporaryDirectory() as second_tmp:
            first_path = Path(first_tmp) / "projection.json"
            second_path = Path(second_tmp) / "projection.json"
            first = write_projection_artifact(first_path, artifact)
            second = write_projection_artifact(second_path, artifact)

            self.assertEqual(first_path.read_bytes(), second_path.read_bytes())
            self.assertEqual(first["sha256"], second["sha256"])
            self.assertEqual(first["size"], len(first_path.read_bytes()))
            self.assertEqual(
                first_path.with_suffix(".json.sha256").read_text(encoding="ascii"),
                first["sha256"] + "\n",
            )
            self.assertEqual(json.loads(first_path.read_text(encoding="utf-8")), artifact)
            self.assertEqual(artifact["summary"]["point_count"], 2)
            self.assertEqual(artifact["summary"]["aabb_count"], 1)


if __name__ == "__main__":
    unittest.main()
