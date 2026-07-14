"""Bounded native Windows UI Automation inspection through ``comtypes``.

The adapter attaches to an existing process or window.  It does not launch,
focus, click, or otherwise interact with the target.  ``comtypes`` is loaded
lazily so importing :mod:`reverse_analyzer.gui` remains portable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import importlib
from importlib import metadata
import math
from queue import Empty, Queue
import sys
import threading
import time
from typing import Any, Callable, Dict, Mapping


WINDOWS_UIA_BACKEND = "windows-uia-comtypes"
WINDOWS_UIA_PROVIDER = "Microsoft UI Automation"
WINDOWS_UIA_DEPENDENCY = "comtypes"

DEFAULT_MAX_DEPTH = 12
DEFAULT_MAX_NODES = 2_000
DEFAULT_TIMEOUT_SECONDS = 5.0
MAX_DEPTH = 64
MAX_NODES = 10_000
MAX_TIMEOUT_SECONDS = 60.0
MAX_RECORDED_ERRORS = 100
MAX_TEXT_CHARS = 4_096

_TREE_SCOPE_CHILDREN = 0x2
_PROCESS_ID_PROPERTY_ID = 30_002
_CLASS_NOT_REGISTERED = {-2_147_221_164, 0x80040154}

_CONTROL_TYPE_NAMES = {
    50_000: "Button",
    50_001: "Calendar",
    50_002: "CheckBox",
    50_003: "ComboBox",
    50_004: "Edit",
    50_005: "Hyperlink",
    50_006: "Image",
    50_007: "ListItem",
    50_008: "List",
    50_009: "Menu",
    50_010: "MenuBar",
    50_011: "MenuItem",
    50_012: "ProgressBar",
    50_013: "RadioButton",
    50_014: "ScrollBar",
    50_015: "Slider",
    50_016: "Spinner",
    50_017: "StatusBar",
    50_018: "Tab",
    50_019: "TabItem",
    50_020: "Text",
    50_021: "ToolBar",
    50_022: "ToolTip",
    50_023: "Tree",
    50_024: "TreeItem",
    50_025: "Custom",
    50_026: "Group",
    50_027: "Thumb",
    50_028: "DataGrid",
    50_029: "DataItem",
    50_030: "Document",
    50_031: "SplitButton",
    50_032: "Window",
    50_033: "Pane",
    50_034: "Header",
    50_035: "HeaderItem",
    50_036: "Table",
    50_037: "TitleBar",
    50_038: "Separator",
    50_039: "SemanticZoom",
    50_040: "AppBar",
}


class _BackendUnavailable(RuntimeError):
    def __init__(
        self,
        reason: str,
        *,
        code: str,
        dependency: Mapping[str, Any],
        cause: BaseException | None = None,
    ) -> None:
        self.reason = _limit_text(reason)
        self.code = code
        self.dependency = dict(dependency)
        self.cause = cause
        super().__init__(self.reason)


class _TraversalDeadlineExceeded(TimeoutError):
    pass


class _TargetError(RuntimeError):
    def __init__(self, code: str, reason: str) -> None:
        self.code = code
        self.reason = _limit_text(reason)
        super().__init__(self.reason)


@dataclass(slots=True)
class _ComtypesBackend:
    automation: Any
    uia: Any
    dependency: Dict[str, Any]
    _comtypes: Any = field(repr=False)
    _initialized: bool = field(default=True, repr=False)

    def close(self) -> None:
        if self._initialized:
            self._initialized = False
            self._comtypes.CoUninitialize()


@dataclass(slots=True)
class _ErrorCollector:
    items: list[Dict[str, Any]] = field(default_factory=list)
    truncated: bool = False

    def add(
        self,
        code: str,
        message: str,
        *,
        scope: str,
        exc: BaseException | None = None,
        property_name: str | None = None,
    ) -> None:
        if len(self.items) >= MAX_RECORDED_ERRORS:
            self.truncated = True
            return
        record: Dict[str, Any] = {
            "code": code,
            "message": _limit_text(message),
            "scope": _limit_text(scope, 256),
        }
        if exc is not None:
            record["type"] = type(exc).__name__
            hresult = getattr(exc, "hresult", None)
            if isinstance(hresult, int):
                record["hresult"] = hresult
        if property_name:
            record["property"] = property_name
        self.items.append(record)


BackendLoader = Callable[[], Any]
Clock = Callable[[], float]


@dataclass(frozen=True, slots=True)
class WindowsUIAAdapter:
    """Inspect one live Windows UIA tree with hard output and wait limits.

    ``timeout_seconds`` bounds how long the caller waits.  Windows does not
    expose a safe way to terminate an in-flight provider COM call, so a timed
    out worker is left as a daemon and its result is discarded.
    """

    max_depth: int = DEFAULT_MAX_DEPTH
    max_nodes: int = DEFAULT_MAX_NODES
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    backend_loader: BackendLoader | None = field(default=None, repr=False, compare=False)
    clock: Clock = field(default=time.monotonic, repr=False, compare=False)

    def __post_init__(self) -> None:
        _bounded_integer(self.max_depth, "max_depth", minimum=0, maximum=MAX_DEPTH)
        _bounded_integer(self.max_nodes, "max_nodes", minimum=1, maximum=MAX_NODES)
        _bounded_timeout(self.timeout_seconds)
        if not callable(self.backend_loader or _load_comtypes_backend):
            raise TypeError("backend_loader must be callable")
        if not callable(self.clock):
            raise TypeError("clock must be callable")

    def probe(
        self,
        process_id: int | None = None,
        *,
        window_handle: int | None = None,
        platform_name: str | None = None,
    ) -> Dict[str, Any]:
        """Return a normalized UIA tree rooted by PID or native HWND."""

        target, target_error = _normalize_target(process_id, window_handle)
        result = _base_result(target, self)
        if target_error is not None:
            return _finish_failure(result, target_error.code, target_error.reason, scope="target")

        host_platform = platform_name or sys.platform
        result["provenance"]["host_platform"] = host_platform
        if not _is_windows(host_platform):
            result["status"] = "unavailable"
            result["reason"] = "Windows UI Automation is only available on Windows"
            result["provider"]["status"] = "unavailable"
            result["dependency"]["status"] = "not_checked"
            error = {
                "code": "platform_unavailable",
                "message": result["reason"],
                "scope": "platform",
            }
            result["errors"] = [error]
            result["error"] = error
            return result

        outcome_queue: Queue[Dict[str, Any]] = Queue(maxsize=1)
        loader = self.backend_loader or _load_comtypes_backend

        def run() -> None:
            outcome = self._probe_in_worker(target, loader)
            try:
                outcome_queue.put_nowait(outcome)
            except Exception:
                return

        started = time.monotonic()
        worker = threading.Thread(
            target=run,
            name="reverse-analyzer-windows-uia",
            daemon=True,
        )
        worker.start()
        try:
            outcome = outcome_queue.get(timeout=float(self.timeout_seconds))
        except Empty:
            elapsed = time.monotonic() - started
            result["status"] = "failed"
            result["reason"] = (
                f"Windows UI Automation exceeded the {self.timeout_seconds:g}-second caller timeout"
            )
            result["provider"]["status"] = "timeout"
            result["truncated"] = True
            result["truncation_reasons"] = ["timeout"]
            error = {
                "code": "timeout",
                "message": result["reason"],
                "scope": "provider",
                "type": "TimeoutError",
            }
            result["errors"] = [error]
            result["error"] = error
            result["elapsed_seconds"] = round(elapsed, 6)
            result["coverage"]["truncated"] = True
            return result

        result.update(outcome)
        result["elapsed_seconds"] = round(time.monotonic() - started, 6)
        result["coverage"]["truncated"] = bool(result["truncated"])
        result["coverage"]["errors_truncated"] = bool(result["errors_truncated"])
        return result

    def _probe_in_worker(
        self,
        target: Mapping[str, int | None],
        loader: BackendLoader,
    ) -> Dict[str, Any]:
        started = self.clock()
        deadline = started + float(self.timeout_seconds)
        backend: Any = None
        errors = _ErrorCollector()
        try:
            _check_deadline(self.clock, deadline)
            backend = loader()
            _check_deadline(self.clock, deadline)
        except _BackendUnavailable as exc:
            cause = exc.cause or exc
            error = _exception_record(exc.code, exc.reason, "dependency", cause)
            return {
                "status": "unavailable",
                "reason": exc.reason,
                "provider": _provider_record("unavailable"),
                "dependency": dict(exc.dependency),
                "errors": [error],
                "error": error,
            }
        except ModuleNotFoundError as exc:
            dependency = _dependency_record("missing")
            dependency["missing_module"] = _limit_text(exc.name or WINDOWS_UIA_DEPENDENCY, 256)
            reason = f"required dependency is unavailable: {dependency['missing_module']}"
            error = _exception_record("dependency_missing", reason, "dependency", exc)
            return {
                "status": "unavailable",
                "reason": reason,
                "provider": _provider_record("unavailable"),
                "dependency": dependency,
                "errors": [error],
                "error": error,
            }
        except _TraversalDeadlineExceeded as exc:
            if backend is not None:
                _close_backend_quietly(backend)
            reason = str(exc)
            error = _exception_record("timeout", reason, "provider", exc)
            return {
                "status": "failed",
                "reason": reason,
                "provider": _provider_record("timeout"),
                "dependency": _dependency_record("unknown"),
                "truncated": True,
                "truncation_reasons": ["timeout"],
                "errors": [error],
                "error": error,
            }
        except Exception as exc:  # noqa: BLE001 - COM initialization errors are evidence.
            reason = f"Windows UI Automation backend initialization failed: {_exception_message(exc)}"
            error = _exception_record("backend_initialization_failed", reason, "provider", exc)
            return {
                "status": "failed",
                "reason": reason,
                "provider": _provider_record("failed"),
                "dependency": _dependency_record("unknown"),
                "errors": [error],
                "error": error,
            }

        dependency = _backend_dependency(backend)
        try:
            collected = _collect_tree(
                backend.automation,
                backend.uia,
                target,
                max_depth=self.max_depth,
                max_nodes=self.max_nodes,
                clock=self.clock,
                deadline=deadline,
                errors=errors,
            )
        except _TargetError as exc:
            errors.add(exc.code, exc.reason, scope="target", exc=exc)
            collected = _empty_collection()
            status = "failed"
            reason = exc.reason
        except _TraversalDeadlineExceeded as exc:
            errors.add("timeout", str(exc), scope="provider", exc=exc)
            collected = _empty_collection(truncated=True, truncation_reasons=["timeout"])
            status = "failed"
            reason = str(exc)
        except Exception as exc:  # noqa: BLE001 - provider exceptions must be reported.
            reason = f"Windows UI Automation traversal failed: {_exception_message(exc)}"
            errors.add("traversal_failed", reason, scope="provider", exc=exc)
            collected = _empty_collection()
            status = "failed"
        else:
            if collected["node_count"] == 0:
                reason = "Windows UI Automation returned no readable target windows or controls"
                errors.add("empty_tree", reason, scope="target")
                status = "failed"
            elif errors.items:
                reason = "Windows UI Automation returned a partial tree with provider errors"
                status = "partial"
            else:
                reason = "Windows UI Automation returned a live target control tree"
                status = "ok"

        try:
            close = getattr(backend, "close", None)
            if callable(close):
                close()
        except Exception as exc:  # noqa: BLE001 - teardown failure is retained in provenance.
            errors.add(
                "provider_teardown_failed",
                f"Windows UI Automation teardown failed: {_exception_message(exc)}",
                scope="provider",
                exc=exc,
            )
            if status == "ok":
                status = "partial"
                reason = "Windows UI Automation returned a tree but provider teardown failed"

        error = errors.items[0] if errors.items else None
        return {
            "status": status,
            "reason": reason,
            "provider": _provider_record("available" if status == "ok" else status),
            "dependency": dependency,
            "errors": errors.items,
            "error": error,
            "errors_truncated": errors.truncated,
            **collected,
        }


def probe_windows_uia(
    process_id: int | None = None,
    *,
    window_handle: int | None = None,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_nodes: int = DEFAULT_MAX_NODES,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    platform_name: str | None = None,
    backend_loader: BackendLoader | None = None,
) -> Dict[str, Any]:
    """Convenience wrapper around :class:`WindowsUIAAdapter`."""

    return WindowsUIAAdapter(
        max_depth=max_depth,
        max_nodes=max_nodes,
        timeout_seconds=timeout_seconds,
        backend_loader=backend_loader,
    ).probe(
        process_id,
        window_handle=window_handle,
        platform_name=platform_name,
    )


def _load_comtypes_backend() -> _ComtypesBackend:
    dependency = _dependency_record("loading")
    try:
        comtypes = importlib.import_module("comtypes")
    except ModuleNotFoundError as exc:
        missing = exc.name or WINDOWS_UIA_DEPENDENCY
        dependency.update({"status": "missing", "missing_module": _limit_text(missing, 256)})
        raise _BackendUnavailable(
            f"required dependency is unavailable: {missing}",
            code="dependency_missing",
            dependency=dependency,
            cause=exc,
        ) from exc

    dependency.update({"status": "available", "version": _dependency_version(comtypes)})
    initialized = False
    try:
        comtypes.CoInitialize()
        initialized = True
        client = importlib.import_module("comtypes.client")
        try:
            uia = importlib.import_module("comtypes.gen.UIAutomationClient")
        except ImportError:
            generated = client.GetModule("UIAutomationCore.dll")
            try:
                uia = importlib.import_module("comtypes.gen.UIAutomationClient")
            except ImportError:
                uia = generated
        automation = _create_automation(client, uia)
        return _ComtypesBackend(automation, uia, dependency, comtypes)
    except Exception as exc:
        if initialized:
            try:
                comtypes.CoUninitialize()
            except Exception:
                pass
        if _provider_is_unavailable(exc):
            raise _BackendUnavailable(
                f"UIAutomationClient provider is unavailable: {_exception_message(exc)}",
                code="provider_unavailable",
                dependency=dependency,
                cause=exc,
            ) from exc
        raise


def _create_automation(client: Any, uia: Any) -> Any:
    failures: list[BaseException] = []
    for class_name in ("CUIAutomation8", "CUIAutomation"):
        automation_class = getattr(uia, class_name, None)
        if automation_class is None:
            continue
        interfaces = [
            interface
            for interface in (
                getattr(uia, "IUIAutomation6", None),
                getattr(uia, "IUIAutomation", None),
            )
            if interface is not None
        ]
        for interface in [*interfaces, None]:
            try:
                if interface is None:
                    return client.CreateObject(automation_class)
                return client.CreateObject(automation_class, interface=interface)
            except Exception as exc:  # noqa: BLE001 - try older UIA interfaces.
                failures.append(exc)
    try:
        return client.CreateObject("UIAutomationClient.CUIAutomation")
    except Exception as exc:  # noqa: BLE001 - report the last provider error.
        failures.append(exc)
    raise failures[-1] if failures else RuntimeError("UIAutomationClient exposes no CUIAutomation class")


def _collect_tree(
    automation: Any,
    uia: Any,
    target: Mapping[str, int | None],
    *,
    max_depth: int,
    max_nodes: int,
    clock: Clock,
    deadline: float,
    errors: _ErrorCollector,
) -> Dict[str, Any]:
    truncation_reasons: set[str] = set()
    process_id = target.get("process_id")
    window_handle = target.get("window_handle")
    roots, resolved_process_id = _target_roots(
        automation,
        uia,
        process_id=process_id,
        window_handle=window_handle,
        max_roots=max_nodes,
        clock=clock,
        deadline=deadline,
        truncation_reasons=truncation_reasons,
        errors=errors,
    )
    windows: list[Dict[str, Any]] = []
    if not roots:
        return {
            "target": {
                "process_id": resolved_process_id,
                "window_handle": window_handle,
            },
            "window_count": 0,
            "node_count": 0,
            "control_count": 0,
            "filtered_node_count": 0,
            "windows": windows,
            "truncated": bool(truncation_reasons),
            "truncation_reasons": sorted(truncation_reasons),
        }

    walker = _control_view_walker(automation)
    control_type_names = _control_type_map(uia)
    stack: list[tuple[Any, int, list[Dict[str, Any]], bool, bool]] = []
    for root in reversed(roots):
        stack.append((root, 0, windows, False, True))

    node_count = 0
    filtered_node_count = 0
    while stack:
        _check_deadline(clock, deadline)
        if node_count >= max_nodes:
            truncation_reasons.add("max_nodes")
            break

        element, depth, sink, follow_sibling, is_window = stack.pop()
        scope = f"node:{node_count}"
        if follow_sibling:
            sibling = _walker_call(
                walker,
                "GetNextSiblingElement",
                element,
                errors=errors,
                scope=scope,
            )
            if sibling is not None:
                stack.append((sibling, depth, sink, True, False))

        node, element_process_id = _serialize_element(
            element,
            depth=depth,
            control_type_names=control_type_names,
            errors=errors,
            scope=scope,
        )
        if (
            resolved_process_id is not None
            and element_process_id is not None
            and element_process_id != resolved_process_id
        ):
            filtered_node_count += 1
            continue

        if is_window:
            node["title"] = node["name"]
        sink.append(node)
        node_count += 1

        if depth >= max_depth:
            child = _walker_call(
                walker,
                "GetFirstChildElement",
                element,
                errors=errors,
                scope=scope,
            )
            if child is not None:
                truncation_reasons.add("max_depth")
            continue

        child = _walker_call(
            walker,
            "GetFirstChildElement",
            element,
            errors=errors,
            scope=scope,
        )
        if child is not None:
            stack.append((child, depth + 1, node["children"], True, False))

    for window in windows:
        window["control_count"] = _descendant_count(window)

    return {
        "target": {
            "process_id": resolved_process_id,
            "window_handle": window_handle,
        },
        "window_count": len(windows),
        "node_count": node_count,
        "control_count": max(0, node_count - len(windows)),
        "filtered_node_count": filtered_node_count,
        "windows": windows,
        "truncated": bool(truncation_reasons),
        "truncation_reasons": sorted(truncation_reasons),
    }


def _target_roots(
    automation: Any,
    uia: Any,
    *,
    process_id: int | None,
    window_handle: int | None,
    max_roots: int,
    clock: Clock,
    deadline: float,
    truncation_reasons: set[str],
    errors: _ErrorCollector,
) -> tuple[list[Any], int | None]:
    _check_deadline(clock, deadline)
    if window_handle is not None:
        try:
            element = automation.ElementFromHandle(window_handle)
        except Exception as exc:
            raise _TargetError(
                "window_lookup_failed",
                f"UI Automation could not resolve window handle {window_handle}: {_exception_message(exc)}",
            ) from exc
        if element is None:
            raise _TargetError(
                "window_not_found",
                f"UI Automation returned no element for window handle {window_handle}",
            )
        actual_process_id = _optional_int(
            _read_current(
                element,
                "ProcessId",
                errors=errors,
                scope="window-root",
                required=False,
            )
        )
        if process_id is not None and actual_process_id not in {None, process_id}:
            raise _TargetError(
                "target_mismatch",
                f"window handle {window_handle} belongs to PID {actual_process_id}, not PID {process_id}",
            )
        return [element], process_id or actual_process_id

    assert process_id is not None
    try:
        root = automation.GetRootElement()
        property_id = int(getattr(uia, "UIA_ProcessIdPropertyId", _PROCESS_ID_PROPERTY_ID))
        tree_scope = int(getattr(uia, "TreeScope_Children", _TREE_SCOPE_CHILDREN))
        condition = automation.CreatePropertyCondition(property_id, process_id)
        collection = root.FindAll(tree_scope, condition)
        length = _collection_length(collection)
    except Exception as exc:
        raise _TargetError(
            "process_lookup_failed",
            f"UI Automation could not enumerate PID {process_id}: {_exception_message(exc)}",
        ) from exc

    roots: list[Any] = []
    for index in range(min(length, max_roots)):
        _check_deadline(clock, deadline)
        try:
            roots.append(collection.GetElement(index))
        except Exception as exc:
            errors.add(
                "root_read_failed",
                f"UI Automation could not read top-level element {index}: {_exception_message(exc)}",
                scope=f"root:{index}",
                exc=exc,
            )
    if length > max_roots:
        truncation_reasons.add("max_nodes")
    return roots, process_id


def _serialize_element(
    element: Any,
    *,
    depth: int,
    control_type_names: Mapping[int, str],
    errors: _ErrorCollector,
    scope: str,
) -> tuple[Dict[str, Any], int | None]:
    automation_id = _clean_text(
        _read_current(element, "AutomationId", errors=errors, scope=scope)
    )
    name = _clean_text(_read_current(element, "Name", errors=errors, scope=scope))
    raw_control_type = _read_current(element, "ControlType", errors=errors, scope=scope)
    raw_bounds = _read_current(element, "BoundingRectangle", errors=errors, scope=scope)
    enabled = _optional_bool(_read_current(element, "IsEnabled", errors=errors, scope=scope))
    offscreen = _optional_bool(_read_current(element, "IsOffscreen", errors=errors, scope=scope))
    process_id = _optional_int(
        _read_current(element, "ProcessId", errors=errors, scope=scope, required=False)
    )
    native_window_handle = _optional_int(
        _read_current(element, "NativeWindowHandle", errors=errors, scope=scope, required=False)
    )
    bounds = _normalize_bounds(raw_bounds)
    if raw_bounds is not None and bounds is None:
        errors.add(
            "property_invalid",
            "UI Automation returned an invalid bounding rectangle",
            scope=scope,
            property_name="BoundingRectangle",
        )
    node = {
        "automation_id": automation_id,
        "name": name,
        "control_type": _control_type_name(raw_control_type, control_type_names),
        "bounds": bounds,
        "enabled": enabled,
        "offscreen": offscreen,
        "process_id": process_id,
        "native_window_handle": native_window_handle,
        "depth": depth,
        "children": [],
    }
    return node, process_id


def _read_current(
    element: Any,
    property_name: str,
    *,
    errors: _ErrorCollector,
    scope: str,
    required: bool = True,
) -> Any:
    direct_names = (f"Current{property_name}", f"get_Current{property_name}")
    for name in direct_names:
        try:
            value = getattr(element, name)
        except AttributeError:
            continue
        except Exception as exc:
            errors.add(
                "property_read_failed",
                f"UI Automation property {property_name} failed: {_exception_message(exc)}",
                scope=scope,
                exc=exc,
                property_name=property_name,
            )
            return None
        try:
            return value() if callable(value) else value
        except Exception as exc:
            errors.add(
                "property_read_failed",
                f"UI Automation property {property_name} failed: {_exception_message(exc)}",
                scope=scope,
                exc=exc,
                property_name=property_name,
            )
            return None

    try:
        current = getattr(element, "Current")
        return getattr(current, property_name)
    except AttributeError:
        if required:
            errors.add(
                "property_unavailable",
                f"UI Automation property {property_name} is unavailable",
                scope=scope,
                property_name=property_name,
            )
    except Exception as exc:
        errors.add(
            "property_read_failed",
            f"UI Automation property {property_name} failed: {_exception_message(exc)}",
            scope=scope,
            exc=exc,
            property_name=property_name,
        )
    return None


def _walker_call(
    walker: Any,
    method_name: str,
    element: Any,
    *,
    errors: _ErrorCollector,
    scope: str,
) -> Any:
    try:
        return getattr(walker, method_name)(element)
    except Exception as exc:
        errors.add(
            "tree_navigation_failed",
            f"UI Automation {method_name} failed: {_exception_message(exc)}",
            scope=scope,
            exc=exc,
        )
        return None


def _control_view_walker(automation: Any) -> Any:
    for name in ("ControlViewWalker", "get_ControlViewWalker", "GetControlViewWalker"):
        try:
            value = getattr(automation, name)
        except AttributeError:
            continue
        return value() if callable(value) else value
    raise RuntimeError("UIAutomationClient does not expose ControlViewWalker")


def _collection_length(collection: Any) -> int:
    value = getattr(collection, "Length")
    length = value() if callable(value) else value
    if isinstance(length, bool) or not isinstance(length, int) or length < 0:
        raise ValueError("UI Automation collection returned an invalid Length")
    return length


def _control_type_map(uia: Any) -> Dict[int, str]:
    names = dict(_CONTROL_TYPE_NAMES)
    for attribute in dir(uia):
        if not attribute.startswith("UIA_") or not attribute.endswith("ControlTypeId"):
            continue
        try:
            value = int(getattr(uia, attribute))
        except (TypeError, ValueError):
            continue
        names[value] = attribute[len("UIA_") : -len("ControlTypeId")]
    return names


def _control_type_name(value: Any, names: Mapping[int, str]) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        text = _clean_text(value)
        if text and text.startswith("ControlType."):
            return text.split(".", 1)[1]
        return text
    try:
        numeric = int(value)
    except (TypeError, ValueError):
        return _clean_text(value)
    return names.get(numeric, f"Unknown({numeric})")


def _normalize_bounds(value: Any) -> Dict[str, int | float] | None:
    if value is None:
        return None
    left = _number(_value_member(value, "left", "Left", "x", "X"))
    top = _number(_value_member(value, "top", "Top", "y", "Y"))
    width = _number(_value_member(value, "width", "Width"))
    height = _number(_value_member(value, "height", "Height"))
    right = _number(_value_member(value, "right", "Right"))
    bottom = _number(_value_member(value, "bottom", "Bottom"))
    if None in {left, top} and isinstance(value, (list, tuple)) and len(value) == 4:
        left, top, right, bottom = (_number(item) for item in value)
    if width is None and left is not None and right is not None:
        width = max(0, right - left)
    if height is None and top is not None and bottom is not None:
        height = max(0, bottom - top)
    if None in {left, top, width, height}:
        return None
    assert left is not None and top is not None and width is not None and height is not None
    return {
        "left": left,
        "top": top,
        "width": max(0, width),
        "height": max(0, height),
    }


def _value_member(value: Any, *names: str) -> Any:
    if isinstance(value, Mapping):
        for name in names:
            if name in value:
                return value[name]
        return None
    for name in names:
        try:
            return getattr(value, name)
        except AttributeError:
            continue
    return None


def _number(value: Any) -> int | float | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if not math.isfinite(number):
        return None
    if number.is_integer():
        return int(number)
    return number


def _optional_int(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return None


def _optional_bool(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1"}:
            return True
        if normalized in {"false", "0"}:
            return False
        return None
    return bool(value)


def _clean_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).replace("\x00", "").strip()
    return _limit_text(text) if text else None


def _limit_text(value: Any, limit: int = MAX_TEXT_CHARS) -> str:
    text = str(value)
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)] + "..."


def _normalize_target(
    process_id: Any,
    window_handle: Any,
) -> tuple[Dict[str, int | None], _TargetError | None]:
    target = {"process_id": None, "window_handle": None}
    if process_id is None and window_handle is None:
        return target, _TargetError(
            "target_required",
            "Windows UI Automation requires a process_id or window_handle",
        )
    for name, value, maximum in (
        ("process_id", process_id, 0xFFFFFFFF),
        ("window_handle", window_handle, 0xFFFFFFFFFFFFFFFF),
    ):
        if value is None:
            continue
        if isinstance(value, bool):
            return target, _TargetError("target_invalid", f"{name} must be a positive integer")
        try:
            normalized = int(value)
        except (TypeError, ValueError, OverflowError):
            return target, _TargetError("target_invalid", f"{name} must be a positive integer")
        if normalized <= 0 or normalized > maximum:
            return target, _TargetError("target_invalid", f"{name} must be a positive integer")
        target[name] = normalized
    return target, None


def _base_result(target: Mapping[str, int | None], adapter: WindowsUIAAdapter) -> Dict[str, Any]:
    limits = {
        "max_depth": adapter.max_depth,
        "max_nodes": adapter.max_nodes,
        "timeout_seconds": float(adapter.timeout_seconds),
        "max_recorded_errors": MAX_RECORDED_ERRORS,
    }
    return {
        "status": "failed",
        "backend": WINDOWS_UIA_BACKEND,
        "reason": "Windows UI Automation did not run",
        "provider": _provider_record("not_started"),
        "dependency": _dependency_record("not_checked"),
        "target": dict(target),
        "limits": limits,
        "coverage": {
            "scope": "window-handle" if target.get("window_handle") else "attached-process",
            "hierarchy": "UI Automation Control View",
            "properties": [
                "automation_id",
                "name",
                "control_type",
                "bounds",
                "enabled",
                "offscreen",
            ],
            "limits": dict(limits),
            "truncated": False,
            "errors_truncated": False,
            "limitations": [
                "The adapter observes an already-running target and performs no UI interaction.",
                "Traversal is limited to the UI Automation Control View and the selected PID or HWND.",
                "The timeout bounds caller wait; an in-flight provider COM call cannot be forcibly cancelled.",
                "Provider visibility depends on desktop session, process integrity level, and provider support.",
            ],
        },
        "provenance": {
            "provider": WINDOWS_UIA_PROVIDER,
            "adapter": WINDOWS_UIA_BACKEND,
            "dependency": WINDOWS_UIA_DEPENDENCY,
            "transport": "in-process COM via UIAutomationClient",
            "source": "live attached target",
            "target_executed": False,
        },
        "window_count": 0,
        "node_count": 0,
        "control_count": 0,
        "filtered_node_count": 0,
        "windows": [],
        "truncated": False,
        "truncation_reasons": [],
        "errors": [],
        "error": None,
        "errors_truncated": False,
        "elapsed_seconds": 0.0,
    }


def _finish_failure(
    result: Dict[str, Any],
    code: str,
    reason: str,
    *,
    scope: str,
) -> Dict[str, Any]:
    error = {"code": code, "message": _limit_text(reason), "scope": scope}
    result["status"] = "failed"
    result["reason"] = error["message"]
    result["provider"]["status"] = "not_started"
    result["errors"] = [error]
    result["error"] = error
    return result


def _empty_collection(
    *,
    truncated: bool = False,
    truncation_reasons: list[str] | None = None,
) -> Dict[str, Any]:
    return {
        "window_count": 0,
        "node_count": 0,
        "control_count": 0,
        "filtered_node_count": 0,
        "windows": [],
        "truncated": truncated,
        "truncation_reasons": list(truncation_reasons or []),
    }


def _provider_record(status: str) -> Dict[str, Any]:
    return {
        "name": WINDOWS_UIA_PROVIDER,
        "api": "UIAutomationClient",
        "transport": "COM",
        "implementation": WINDOWS_UIA_DEPENDENCY,
        "status": status,
    }


def _dependency_record(status: str) -> Dict[str, Any]:
    return {
        "name": WINDOWS_UIA_DEPENDENCY,
        "required": True,
        "status": status,
        "install_command": "python -m pip install comtypes",
    }


def _backend_dependency(backend: Any) -> Dict[str, Any]:
    raw = getattr(backend, "dependency", None)
    if isinstance(raw, Mapping):
        dependency = dict(raw)
        dependency.setdefault("name", WINDOWS_UIA_DEPENDENCY)
        dependency.setdefault("required", True)
        dependency.setdefault("status", "available")
        return dependency
    return _dependency_record("available")


def _close_backend_quietly(backend: Any) -> None:
    try:
        close = getattr(backend, "close", None)
        if callable(close):
            close()
    except Exception:
        pass


def _dependency_version(module: Any) -> str | None:
    version = getattr(module, "__version__", None)
    if version:
        return _limit_text(version, 128)
    try:
        return _limit_text(metadata.version(WINDOWS_UIA_DEPENDENCY), 128)
    except metadata.PackageNotFoundError:
        return None


def _exception_record(
    code: str,
    message: str,
    scope: str,
    exc: BaseException,
) -> Dict[str, Any]:
    record: Dict[str, Any] = {
        "code": code,
        "message": _limit_text(message),
        "scope": scope,
        "type": type(exc).__name__,
    }
    hresult = getattr(exc, "hresult", None)
    if isinstance(hresult, int):
        record["hresult"] = hresult
    return record


def _exception_message(exc: BaseException) -> str:
    return _limit_text(str(exc).strip() or type(exc).__name__, 1_000)


def _provider_is_unavailable(exc: BaseException) -> bool:
    if isinstance(exc, (ImportError, OSError)):
        return True
    hresult = getattr(exc, "hresult", None)
    return isinstance(hresult, int) and hresult in _CLASS_NOT_REGISTERED


def _descendant_count(node: Mapping[str, Any]) -> int:
    count = 0
    stack = list(node.get("children") or [])
    while stack:
        child = stack.pop()
        count += 1
        if isinstance(child, Mapping):
            stack.extend(child.get("children") or [])
    return count


def _check_deadline(clock: Clock, deadline: float) -> None:
    if clock() >= deadline:
        raise _TraversalDeadlineExceeded("Windows UI Automation traversal reached its time limit")


def _bounded_integer(value: Any, name: str, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer between {minimum} and {maximum}")
    return value


def _bounded_timeout(value: Any) -> float:
    try:
        timeout = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("timeout_seconds must be a positive finite number") from exc
    if not math.isfinite(timeout) or not 0 < timeout <= MAX_TIMEOUT_SECONDS:
        raise ValueError(
            f"timeout_seconds must be greater than 0 and no more than {MAX_TIMEOUT_SECONDS:g}"
        )
    return timeout


def _is_windows(platform_name: str) -> bool:
    normalized = str(platform_name).strip().lower()
    return normalized == "nt" or normalized.startswith("win")


__all__ = [
    "DEFAULT_MAX_DEPTH",
    "DEFAULT_MAX_NODES",
    "DEFAULT_TIMEOUT_SECONDS",
    "MAX_DEPTH",
    "MAX_NODES",
    "MAX_TIMEOUT_SECONDS",
    "WINDOWS_UIA_BACKEND",
    "WINDOWS_UIA_DEPENDENCY",
    "WINDOWS_UIA_PROVIDER",
    "WindowsUIAAdapter",
    "probe_windows_uia",
]
