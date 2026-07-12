# Skill Parity Matrix

| capability | current_status | current_modules | target_modules | required_report_fields | required_artifacts | required_tests | phase | acceptance_command |
|---|---|---|---|---|---|---|---|---|
| semantic_ir | partial | report/evidence | reverse_analyzer/core/ir/semantic_ir.py | semantic_ir | semantic_ir.json | tests/test_capability_core.py | 1 | python -m reverse_analyzer analyze sample.exe --out out |
| evidence_graph | partial | evidence manifest | reverse_analyzer/core/ir/evidence_graph.py | evidence_graph | evidence_graph.json | tests/test_capability_core.py | 1 | python -m reverse_analyzer analyze sample.exe --out out |
| memory_runtime | partial | reverse_analyzer/tools/memory.py | reverse_analyzer/providers/memory_runtime/* | memory_analysis | memory/* | tests/test_memory_runtime.py | 2 | python -m reverse_analyzer memory scan ... |
| injector | missing | - | reverse_analyzer/providers/injector/* | memory_analysis | memory/injection.json | tests/test_memory_runtime.py | 2 | python -m reverse_analyzer memory inject ... |
| hook_runtime | missing | - | reverse_analyzer/providers/hook_runtime/* | memory_analysis | memory/hooks.json | tests/test_memory_runtime.py | 2 | python -m reverse_analyzer memory hook-trace ... |
| patch_executor | partial | reverse_analyzer/tools/patch.py | reverse_analyzer/providers/patch_executor/* | patch_analysis | patch/* | tests/test_patch_planner.py | 3 | python -m reverse_analyzer patch plan sample.exe |
| engine_analysis | partial | gui/static analysis | reverse_analyzer/engine/* | engine_analysis | engine/* | tests/test_engine_unity.py,tests/test_engine_unreal.py | 4 | python -m reverse_analyzer analyze sample.exe --out out |
| android_analysis | partial | gui/apk fingerprint | reverse_analyzer/android/* | android_analysis | android/* | tests/test_android_pipeline.py | 5 | python -m reverse_analyzer android analyze sample.apk |
| android_rebuild | missing | - | reverse_analyzer/providers/android_rebuild/* | android_analysis | android/rebuild_verify.json | tests/test_android_pipeline.py | 5 | python -m reverse_analyzer android rebuild ... |
| protocol_analysis | missing | - | reverse_analyzer/protocol/* | protocol_analysis | protocol/* | tests/test_protocol_analysis.py | 6 | python -m reverse_analyzer protocol summarize ... |
| gui_analysis | partial | gui_* modules | reverse_analyzer/gui/* | gui_analysis | gui/* | tests/test_gui_pipeline.py | 7 | python -m reverse_analyzer analyze sample.exe --gui |
| source_reconstruction | partial | reconstruct_project | reverse_analyzer/source/* | source_reconstruction | source/* | tests/test_source_reconstruction.py | 7 | python -m reverse_analyzer source reconstruct sample.exe |
| dashboard | partial | reverse_analyzer/dashboard.py | reverse_analyzer/dashboard/* | all sections | dashboard trace | tests/test_dashboard_views.py | 8 | python -m reverse_analyzer dashboard out |
