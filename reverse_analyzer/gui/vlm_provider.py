"""Dependency-free production loader for GUI vision-language providers.

Provider configuration is intentionally JSON-compatible so callers can pass it
through a CLI or config file without importing application code. A production
provider is referenced as ``module:attribute``. Functions receive a validated
request mapping; classes are instantiated and must expose ``analyze(request)``
or ``__call__(request)``.

Example configuration::

    {
        "provider": "my_vlm_plugin:Provider",
        "timeout_seconds": 20,
        "options": {"model": "vision-model"},
        "secret_env": {"api_key": "MY_VLM_API_KEY"}
    }

Runtime secrets are never included in load or invocation provenance.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import importlib
import inspect
import json
import math
import os
from pathlib import Path
import queue
import re
import threading
import time
from typing import Any, Callable, Dict, Mapping, Protocol, runtime_checkable


VLM_SCHEMA_VERSION = 1
DEFAULT_VLM_TIMEOUT_SECONDS = 30.0
MAX_VLM_TIMEOUT_SECONDS = 600.0
MAX_VLM_CONFIG_BYTES = 64 * 1024
MAX_VLM_IMAGE_BYTES = 256 * 1024 * 1024
MAX_VLM_ITEMS = 500
MAX_VLM_TEXT_CHARS = 16_384

GUI_VLM_PROVIDER_ENV = "REVERSE_ANALYZER_GUI_VLM_PROVIDER"
GUI_VLM_CONFIG_ENV = "REVERSE_ANALYZER_GUI_VLM_CONFIG"
GUI_VLM_TIMEOUT_ENV = "REVERSE_ANALYZER_GUI_VLM_TIMEOUT"

_IMPORT_PATH_RE = re.compile(
    r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)*:"
    r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)*$"
)
_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_SENSITIVE_KEY_RE = re.compile(
    r"(?:api[_-]?key|access[_-]?key|authorization|bearer|cookie|credential|"
    r"password|private[_-]?key|refresh[_-]?token|secret|session|token)",
    re.IGNORECASE,
)
_INLINE_SECRET_RE = re.compile(
    r"(?i)\b(api[_-]?key|authorization|credential|password|secret|token)"
    r"\s*([:=])\s*([^\s,;]+)"
)
_OUTPUT_STATUSES = {"ok", "partial", "failed", "unavailable"}
_MEDIA_TYPES = {
    ".bmp": "image/bmp",
    ".jpeg": "image/jpeg",
    ".jpg": "image/jpeg",
    ".png": "image/png",
    ".webp": "image/webp",
}
_ALLOWED_CONFIG_KEYS = {
    "config",
    "constructor",
    "enabled",
    "import_path",
    "name",
    "options",
    "provider",
    "secret_env",
    "secrets",
    "timeout",
    "timeout_seconds",
}


@runtime_checkable
class VLMProvider(Protocol):
    """Structural interface implemented by class-based VLM plugins."""

    def analyze(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        """Return a versioned VLM response for one validated image request."""


@dataclass(frozen=True, slots=True)
class VLMProviderErrorInfo:
    """Serializable provider error with an explicit stage status."""

    code: str
    status: str
    message: str

    def to_dict(self) -> Dict[str, str]:
        return {"code": self.code, "status": self.status, "message": self.message}


@dataclass(slots=True)
class VLMInvocationResult:
    """Result of one bounded provider invocation."""

    status: str
    output: Dict[str, Any] | None
    provenance: Dict[str, Any]
    duration_ms: int
    error: VLMProviderErrorInfo | None = None

    @property
    def succeeded(self) -> bool:
        return self.status in {"ok", "partial"} and self.output is not None

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "status": self.status,
            "duration_ms": self.duration_ms,
            "provenance": dict(self.provenance),
        }
        if self.output is not None:
            data["output"] = dict(self.output)
        if self.error is not None:
            data["error"] = self.error.to_dict()
        return data


@dataclass(slots=True)
class LoadedVLMProvider:
    """Loaded plugin handle that owns private runtime configuration."""

    name: str
    import_path: str | None
    implementation: str
    timeout_seconds: float
    source: str
    _invoke: Callable[..., Any] = field(repr=False)
    _runtime_config: Dict[str, Any] = field(default_factory=dict, repr=False)
    _redactor: "_SecretRedactor" = field(default_factory=lambda: _SecretRedactor(()), repr=False)
    _strict_schema: bool = field(default=True, repr=False)
    _legacy_path_request: bool = field(default=False, repr=False)
    _configuration_provenance: Dict[str, Any] = field(default_factory=dict, repr=False)

    @property
    def provenance(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "schema_version": VLM_SCHEMA_VERSION,
            "configured": True,
            "status": "ok",
            "source": self.source,
            "provider": self.name,
            "implementation": self.implementation,
            "timeout_seconds": self.timeout_seconds,
            "configuration": dict(self._configuration_provenance),
        }
        if self.import_path:
            data["import_path"] = self.import_path
        return data

    def invoke(self, image_path: str | os.PathLike[str]) -> VLMInvocationResult:
        """Validate and analyze one image without allowing provider exceptions out."""

        started = time.monotonic()
        try:
            path = Path(image_path)
            request = _build_request(path, self.timeout_seconds)
        except _ProviderFailure as exc:
            return self._failure_result(exc, started)
        except (OSError, TypeError, ValueError) as exc:
            return self._failure_result(
                _ProviderFailure(
                    "provider_input_schema_invalid",
                    "failed",
                    f"VLM input image path is invalid: {type(exc).__name__}",
                ),
                started,
            )

        def operation() -> Any:
            if self._legacy_path_request:
                return self._invoke(str(path))
            return _call_provider(self._invoke, request, self._runtime_config)

        try:
            raw, _ = _run_with_timeout(operation, self.timeout_seconds)
            output = _normalize_response(
                raw,
                strict_schema=self._strict_schema,
                redactor=self._redactor,
            )
        except _OperationTimeout:
            return self._failure_result(
                _ProviderFailure(
                    "provider_timeout",
                    "failed",
                    f"VLM provider exceeded the {self.timeout_seconds:g}-second timeout",
                ),
                started,
            )
        except ModuleNotFoundError as exc:
            dependency = str(getattr(exc, "name", None) or "provider dependency")
            return self._failure_result(
                _ProviderFailure(
                    "provider_dependency_missing",
                    "unavailable",
                    f"VLM provider dependency is unavailable: {dependency}",
                ),
                started,
            )
        except ImportError as exc:
            return self._failure_result(
                _ProviderFailure(
                    "provider_dependency_unavailable",
                    "unavailable",
                    f"VLM provider dependency import failed: {self._redactor.redact(exc)}",
                ),
                started,
            )
        except _ProviderFailure as exc:
            return self._failure_result(exc, started)
        except BaseException as exc:  # noqa: BLE001 - plugin boundary includes SystemExit.
            return self._failure_result(
                _ProviderFailure(
                    "provider_execution_failed",
                    "failed",
                    f"VLM provider execution failed: {type(exc).__name__}: {self._redactor.redact(exc)}",
                ),
                started,
            )

        status = str(output["status"])
        provenance = self._invocation_provenance(output.get("provenance"))
        duration_ms = _duration_ms(started)
        if status in {"failed", "unavailable"}:
            reason = self._redactor.redact(output.get("reason") or f"provider reported {status}")
            error = VLMProviderErrorInfo(
                code=f"provider_reported_{status}",
                status=status,
                message=reason,
            )
            return VLMInvocationResult(
                status=status,
                output=output,
                provenance=provenance,
                duration_ms=duration_ms,
                error=error,
            )
        return VLMInvocationResult(
            status=status,
            output=output,
            provenance=provenance,
            duration_ms=duration_ms,
        )

    def _failure_result(self, failure: "_ProviderFailure", started: float) -> VLMInvocationResult:
        message = self._redactor.redact(failure.message)
        return VLMInvocationResult(
            status=failure.status,
            output=None,
            provenance=self._invocation_provenance(None),
            duration_ms=_duration_ms(started),
            error=VLMProviderErrorInfo(failure.code, failure.status, message),
        )

    def _invocation_provenance(self, response: Any) -> Dict[str, Any]:
        data = {
            "schema_version": VLM_SCHEMA_VERSION,
            "provider": self.name,
            "implementation": self.implementation,
        }
        if self.import_path:
            data["import_path"] = self.import_path
        if isinstance(response, Mapping) and response:
            data["response"] = dict(response)
        return data


@dataclass(slots=True)
class VLMProviderLoadResult:
    """Non-throwing provider load result used at CLI/tool boundaries."""

    status: str
    provider: LoadedVLMProvider | None
    provenance: Dict[str, Any]
    error: VLMProviderErrorInfo | None = None

    @property
    def available(self) -> bool:
        return self.status == "ok" and self.provider is not None

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "status": self.status,
            "available": self.available,
            "provenance": dict(self.provenance),
        }
        if self.error is not None:
            data["error"] = self.error.to_dict()
        return data


@dataclass(frozen=True, slots=True)
class _ProviderSettings:
    import_path: str
    name: str
    timeout_seconds: float
    constructor: str
    runtime_config: Dict[str, Any]
    source: str
    configuration_provenance: Dict[str, Any]
    redactor: "_SecretRedactor"


@dataclass(frozen=True, slots=True)
class _SecretRedactor:
    values: tuple[str, ...]

    def redact(self, value: Any) -> str:
        text = str(value or "")
        for secret in sorted(self.values, key=len, reverse=True):
            if secret:
                text = text.replace(secret, "<redacted>")
        return _INLINE_SECRET_RE.sub(r"\1\2<redacted>", text)


class _ProviderFailure(RuntimeError):
    def __init__(self, code: str, status: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.status = status
        self.message = message


class _OperationTimeout(TimeoutError):
    pass


def load_vlm_provider(
    spec: Any = None,
    *,
    timeout_seconds: float | None = None,
    environ: Mapping[str, str] | None = None,
) -> VLMProviderLoadResult:
    """Load an import-path, class, instance, or legacy injected callable.

    ``None`` consults ``REVERSE_ANALYZER_GUI_VLM_CONFIG`` first, then
    ``REVERSE_ANALYZER_GUI_VLM_PROVIDER``. Config can be inline JSON or a JSON
    file path. Missing modules/dependencies are ``unavailable``; malformed
    config, invalid targets, constructor errors, and load timeouts are
    ``failed``. No branch substitutes a synthetic provider.
    """

    environment = os.environ if environ is None else environ
    if isinstance(spec, LoadedVLMProvider):
        return VLMProviderLoadResult("ok", spec, spec.provenance)

    if spec is not None and not isinstance(spec, (str, os.PathLike, Mapping)):
        return _load_injected_provider(spec, timeout_seconds=timeout_seconds)

    try:
        settings = _parse_settings(spec, timeout_seconds=timeout_seconds, environ=environment)
    except _ProviderFailure as exc:
        return _load_failure(exc, configured=spec is not None or _environment_configured(environment))
    except BaseException as exc:  # noqa: BLE001 - configuration boundary stays non-throwing.
        failure = _ProviderFailure(
            "provider_config_invalid",
            "failed",
            f"VLM provider configuration failed: {type(exc).__name__}: {exc}",
        )
        return _load_failure(failure, configured=True)

    try:
        resolved, _ = _run_with_timeout(
            lambda: _resolve_imported_provider(settings),
            settings.timeout_seconds,
        )
    except _OperationTimeout:
        return _load_failure(
            _ProviderFailure(
                "provider_load_timeout",
                "failed",
                f"VLM provider load exceeded the {settings.timeout_seconds:g}-second timeout",
            ),
            configured=True,
            settings=settings,
        )
    except ModuleNotFoundError as exc:
        missing = str(getattr(exc, "name", None) or settings.import_path.split(":", 1)[0])
        code = (
            "provider_module_missing"
            if settings.import_path.split(":", 1)[0].startswith(missing)
            else "provider_dependency_missing"
        )
        return _load_failure(
            _ProviderFailure(code, "unavailable", f"VLM provider module or dependency is unavailable: {missing}"),
            configured=True,
            settings=settings,
        )
    except ImportError as exc:
        return _load_failure(
            _ProviderFailure(
                "provider_import_unavailable",
                "unavailable",
                f"VLM provider import failed: {settings.redactor.redact(exc)}",
            ),
            configured=True,
            settings=settings,
        )
    except _ProviderFailure as exc:
        return _load_failure(exc, configured=True, settings=settings)
    except BaseException as exc:  # noqa: BLE001 - plugin import/constructor boundary.
        return _load_failure(
            _ProviderFailure(
                "provider_load_failed",
                "failed",
                f"VLM provider load failed: {type(exc).__name__}: {settings.redactor.redact(exc)}",
            ),
            configured=True,
            settings=settings,
        )

    handle = LoadedVLMProvider(
        name=settings.name,
        import_path=settings.import_path,
        implementation=resolved[1],
        timeout_seconds=settings.timeout_seconds,
        source=settings.source,
        _invoke=resolved[0],
        _runtime_config=dict(settings.runtime_config),
        _redactor=settings.redactor,
        _strict_schema=True,
        _legacy_path_request=False,
        _configuration_provenance=dict(settings.configuration_provenance),
    )
    return VLMProviderLoadResult("ok", handle, handle.provenance)


def _load_injected_provider(spec: Any, *, timeout_seconds: float | None) -> VLMProviderLoadResult:
    try:
        timeout = _timeout_value(timeout_seconds, default=DEFAULT_VLM_TIMEOUT_SECONDS)
        if inspect.isclass(spec):
            instance, _ = _run_with_timeout(spec, timeout)
            invoke = _provider_invoker(instance)
            strict_schema = True
            legacy = False
            source = "injected_class"
            implementation = _implementation_name(instance)
            name = _provider_name(instance, fallback=spec.__name__)
        elif callable(getattr(spec, "analyze", None)):
            invoke = spec.analyze
            strict_schema = True
            legacy = False
            source = "injected_instance"
            implementation = _implementation_name(spec)
            name = _provider_name(spec, fallback=type(spec).__name__)
        elif callable(spec):
            invoke = spec
            strict_schema = False
            legacy = True
            source = "injected_callable"
            implementation = _implementation_name(spec)
            name = _provider_name(spec, fallback=getattr(spec, "__name__", "injected_callable"))
        else:
            raise _ProviderFailure(
                "provider_target_invalid",
                "failed",
                "injected VLM provider must be callable or expose analyze(request)",
            )
    except _OperationTimeout:
        return _load_failure(
            _ProviderFailure(
                "provider_load_timeout",
                "failed",
                f"VLM provider load exceeded the {timeout:g}-second timeout",
            ),
            configured=True,
        )
    except ModuleNotFoundError as exc:
        dependency = str(getattr(exc, "name", None) or "provider dependency")
        return _load_failure(
            _ProviderFailure(
                "provider_dependency_missing",
                "unavailable",
                f"VLM provider dependency is unavailable: {dependency}",
            ),
            configured=True,
        )
    except ImportError as exc:
        return _load_failure(
            _ProviderFailure(
                "provider_dependency_unavailable",
                "unavailable",
                f"VLM provider dependency import failed: {exc}",
            ),
            configured=True,
        )
    except _ProviderFailure as exc:
        return _load_failure(exc, configured=True)
    except BaseException as exc:  # noqa: BLE001 - injected constructor boundary.
        return _load_failure(
            _ProviderFailure(
                "provider_load_failed",
                "failed",
                f"injected VLM provider load failed: {type(exc).__name__}: {exc}",
            ),
            configured=True,
        )

    handle = LoadedVLMProvider(
        name=_safe_name(name),
        import_path=None,
        implementation=implementation,
        timeout_seconds=timeout,
        source=source,
        _invoke=invoke,
        _strict_schema=strict_schema,
        _legacy_path_request=legacy,
        _configuration_provenance={"public_option_keys": [], "secret_count": 0},
    )
    return VLMProviderLoadResult("ok", handle, handle.provenance)


def _parse_settings(
    spec: Any,
    *,
    timeout_seconds: float | None,
    environ: Mapping[str, str],
) -> _ProviderSettings:
    raw, source = _load_raw_spec(spec, environ=environ)
    unknown = sorted(str(key) for key in raw if key not in _ALLOWED_CONFIG_KEYS)
    if unknown:
        raise _ProviderFailure(
            "provider_config_schema_invalid",
            "failed",
            f"unsupported VLM provider configuration key(s): {', '.join(unknown)}",
        )
    if raw.get("enabled") is False:
        raise _ProviderFailure("provider_disabled", "unavailable", "VLM provider is disabled by configuration")
    if "enabled" in raw and not isinstance(raw.get("enabled"), bool):
        raise _ProviderFailure(
            "provider_config_schema_invalid",
            "failed",
            "enabled must be a boolean",
        )

    provider_value = raw.get("provider")
    import_value = raw.get("import_path")
    if provider_value and import_value and provider_value != import_value:
        raise _ProviderFailure(
            "provider_config_schema_invalid",
            "failed",
            "provider and import_path cannot specify different values",
        )
    import_path = str(provider_value or import_value or "").strip()
    _validate_import_path(import_path)

    options_value = raw.get("options")
    config_value = raw.get("config")
    if options_value is not None and config_value is not None:
        raise _ProviderFailure(
            "provider_config_schema_invalid",
            "failed",
            "use either options or config, not both",
        )
    options = _config_mapping(options_value if options_value is not None else config_value, "options")
    secrets = _config_mapping(raw.get("secrets"), "secrets")
    secret_env = _string_mapping(raw.get("secret_env"), "secret_env")
    overlap = sorted(set(options) & (set(secrets) | set(secret_env)))
    if overlap:
        raise _ProviderFailure(
            "provider_config_schema_invalid",
            "failed",
            f"provider config keys cannot be both public and secret: {', '.join(overlap)}",
        )
    for key, env_name in secret_env.items():
        if not _ENV_NAME_RE.fullmatch(env_name):
            raise _ProviderFailure(
                "provider_config_schema_invalid",
                "failed",
                f"invalid environment variable name for secret key {key}",
            )
        value = environ.get(env_name)
        if value is None or value == "":
            raise _ProviderFailure(
                "provider_secret_unavailable",
                "unavailable",
                f"required VLM provider secret environment variable is unavailable: {env_name}",
            )
        secrets[key] = value

    runtime_config = {**options, **secrets}
    sensitive_option_keys = {key for key in options if _SENSITIVE_KEY_RE.search(key)}
    secret_values = _collect_secret_values(secrets)
    for key in sensitive_option_keys:
        secret_values.extend(_collect_secret_values(options[key]))
    redactor = _SecretRedactor(tuple(dict.fromkeys(value for value in secret_values if value)))

    if "timeout_seconds" in raw and "timeout" in raw and raw.get("timeout_seconds") != raw.get("timeout"):
        raise _ProviderFailure(
            "provider_config_schema_invalid",
            "failed",
            "timeout and timeout_seconds cannot specify different values",
        )
    configured_timeout = raw.get("timeout_seconds", raw.get("timeout"))
    selected_timeout = timeout_seconds if timeout_seconds is not None else configured_timeout
    if selected_timeout is None:
        selected_timeout = environ.get(GUI_VLM_TIMEOUT_ENV)
    timeout = _timeout_value(selected_timeout, default=DEFAULT_VLM_TIMEOUT_SECONDS)
    constructor = str(raw.get("constructor") or "auto").strip().lower()
    if constructor not in {"auto", "config", "kwargs", "none"}:
        raise _ProviderFailure(
            "provider_config_schema_invalid",
            "failed",
            "constructor must be one of: auto, config, kwargs, none",
        )
    if constructor == "none" and runtime_config:
        raise _ProviderFailure(
            "provider_config_schema_invalid",
            "failed",
            "constructor=none cannot be combined with provider options or secrets",
        )

    fallback_name = import_path.split(":", 1)[1].rsplit(".", 1)[-1]
    name = _safe_name(raw.get("name") or fallback_name)
    public_keys = sorted(key for key in options if key not in sensitive_option_keys)
    configuration_provenance = {
        "public_option_keys": public_keys,
        "secret_count": len(set(secrets) | sensitive_option_keys),
        "secret_env_count": len(secret_env),
        "constructor": constructor,
    }
    return _ProviderSettings(
        import_path=import_path,
        name=name,
        timeout_seconds=timeout,
        constructor=constructor,
        runtime_config=runtime_config,
        source=source,
        configuration_provenance=configuration_provenance,
        redactor=redactor,
    )


def _load_raw_spec(spec: Any, *, environ: Mapping[str, str]) -> tuple[Dict[str, Any], str]:
    if spec is None:
        config_value = str(environ.get(GUI_VLM_CONFIG_ENV) or "").strip()
        provider_value = str(environ.get(GUI_VLM_PROVIDER_ENV) or "").strip()
        if config_value:
            raw = _raw_config_value(config_value, allow_plain_path=True)
            if provider_value and not raw.get("provider") and not raw.get("import_path"):
                raw["provider"] = provider_value
            return raw, "environment_config"
        if provider_value:
            return {"provider": provider_value}, "environment"
        raise _ProviderFailure("provider_not_configured", "unavailable", "VLM provider is not configured")
    if isinstance(spec, Mapping):
        return {str(key): value for key, value in spec.items()}, "mapping"
    if isinstance(spec, os.PathLike):
        return _read_config_file(Path(spec)), "config_file"
    text = str(spec).strip()
    if _IMPORT_PATH_RE.fullmatch(text):
        return {"provider": text}, "import_path"
    if text.startswith("{"):
        return _decode_config_json(text), "inline_json"
    if text.startswith("@"):
        return _read_config_file(Path(text[1:])), "config_file"
    raise _ProviderFailure(
        "provider_import_path_invalid",
        "failed",
        "VLM provider must use a module:attribute import path or a JSON configuration",
    )


def _raw_config_value(value: str, *, allow_plain_path: bool) -> Dict[str, Any]:
    if value.startswith("{"):
        return _decode_config_json(value)
    path_text = value[1:] if value.startswith("@") else value
    if allow_plain_path or value.startswith("@"):
        return _read_config_file(Path(path_text))
    raise _ProviderFailure("provider_config_invalid", "failed", "invalid VLM provider configuration")


def _read_config_file(path: Path) -> Dict[str, Any]:
    try:
        stat = path.stat()
    except FileNotFoundError as exc:
        raise _ProviderFailure(
            "provider_config_unavailable",
            "unavailable",
            "VLM provider configuration file is unavailable",
        ) from exc
    except OSError as exc:
        raise _ProviderFailure(
            "provider_config_unavailable",
            "unavailable",
            f"VLM provider configuration file cannot be read: {type(exc).__name__}",
        ) from exc
    if not path.is_file():
        raise _ProviderFailure(
            "provider_config_invalid",
            "failed",
            "VLM provider configuration path must be a file",
        )
    if stat.st_size > MAX_VLM_CONFIG_BYTES:
        raise _ProviderFailure(
            "provider_config_invalid",
            "failed",
            f"VLM provider configuration exceeds {MAX_VLM_CONFIG_BYTES} bytes",
        )
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise _ProviderFailure(
            "provider_config_invalid",
            "failed",
            f"VLM provider configuration is not readable UTF-8 JSON: {type(exc).__name__}",
        ) from exc
    return _decode_config_json(text)


def _decode_config_json(text: str) -> Dict[str, Any]:
    if len(text.encode("utf-8", errors="replace")) > MAX_VLM_CONFIG_BYTES:
        raise _ProviderFailure(
            "provider_config_invalid",
            "failed",
            f"VLM provider configuration exceeds {MAX_VLM_CONFIG_BYTES} bytes",
        )

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON number: {value}")

    try:
        decoded = json.loads(text, parse_constant=reject_constant)
    except (json.JSONDecodeError, ValueError) as exc:
        raise _ProviderFailure(
            "provider_config_invalid",
            "failed",
            f"VLM provider configuration is invalid JSON: {exc}",
        ) from exc
    if not isinstance(decoded, Mapping):
        raise _ProviderFailure(
            "provider_config_schema_invalid",
            "failed",
            "VLM provider configuration root must be an object",
        )
    return {str(key): value for key, value in decoded.items()}


def _resolve_imported_provider(settings: _ProviderSettings) -> tuple[Callable[..., Any], str]:
    module_name, attribute_path = settings.import_path.split(":", 1)
    module = importlib.import_module(module_name)
    target: Any = module
    for component in attribute_path.split("."):
        try:
            target = getattr(target, component)
        except AttributeError as exc:
            raise _ProviderFailure(
                "provider_attribute_missing",
                "failed",
                f"VLM provider attribute is unavailable: {settings.import_path}",
            ) from exc

    if inspect.isclass(target):
        try:
            if settings.constructor == "config" or (
                settings.constructor == "auto" and settings.runtime_config
            ):
                instance = target(config=dict(settings.runtime_config))
            elif settings.constructor == "kwargs":
                instance = target(**dict(settings.runtime_config))
            elif settings.constructor == "auto" and _accepts_constructor_config(target):
                instance = target(config={})
            else:
                instance = target()
        except ImportError:
            raise
        except BaseException as exc:  # noqa: BLE001 - normalized by the loader boundary.
            raise _ProviderFailure(
                "provider_constructor_failed",
                "failed",
                f"VLM provider constructor failed: {type(exc).__name__}: {settings.redactor.redact(exc)}",
            ) from exc
        return _provider_invoker(instance), _implementation_name(instance)
    if not callable(target):
        raise _ProviderFailure(
            "provider_target_invalid",
            "failed",
            f"VLM provider target is not callable: {settings.import_path}",
        )
    if settings.runtime_config and not _accepts_config_keyword(target):
        raise _ProviderFailure(
            "provider_target_invalid",
            "failed",
            "configured VLM provider function must accept a config keyword argument",
        )
    return target, _implementation_name(target)


def _provider_invoker(instance: Any) -> Callable[..., Any]:
    analyze = getattr(instance, "analyze", None)
    if callable(analyze):
        return analyze
    if callable(instance):
        return instance
    raise _ProviderFailure(
        "provider_target_invalid",
        "failed",
        "VLM provider class must expose analyze(request) or __call__(request)",
    )


def _call_provider(
    invoke: Callable[..., Any],
    request: Mapping[str, Any],
    runtime_config: Mapping[str, Any],
) -> Any:
    if _accepts_config_keyword(invoke):
        return invoke(dict(request), config=dict(runtime_config))
    return invoke(dict(request))


def _accepts_config_keyword(invoke: Callable[..., Any]) -> bool:
    try:
        signature = inspect.signature(invoke)
    except (TypeError, ValueError):
        return False
    parameter = signature.parameters.get("config")
    if parameter is not None and parameter.kind in {
        inspect.Parameter.POSITIONAL_OR_KEYWORD,
        inspect.Parameter.KEYWORD_ONLY,
    }:
        return True
    return any(item.kind == inspect.Parameter.VAR_KEYWORD for item in signature.parameters.values())


def _accepts_constructor_config(provider_class: type[Any]) -> bool:
    try:
        signature = inspect.signature(provider_class)
    except (TypeError, ValueError):
        return False
    parameter = signature.parameters.get("config")
    return parameter is not None and parameter.kind in {
        inspect.Parameter.POSITIONAL_OR_KEYWORD,
        inspect.Parameter.KEYWORD_ONLY,
    }


def _build_request(path: Path, timeout_seconds: float) -> Dict[str, Any]:
    try:
        stat = path.stat()
    except OSError as exc:
        raise _ProviderFailure(
            "provider_input_unavailable",
            "unavailable",
            f"VLM input image is unavailable: {type(exc).__name__}",
        ) from exc
    if not path.is_file():
        raise _ProviderFailure("provider_input_schema_invalid", "failed", "VLM input image must be a file")
    if stat.st_size <= 0:
        raise _ProviderFailure("provider_input_schema_invalid", "failed", "VLM input image is empty")
    if stat.st_size > MAX_VLM_IMAGE_BYTES:
        raise _ProviderFailure(
            "provider_input_schema_invalid",
            "failed",
            f"VLM input image exceeds {MAX_VLM_IMAGE_BYTES} bytes",
        )
    media_type = _MEDIA_TYPES.get(path.suffix.lower())
    if media_type is None:
        raise _ProviderFailure(
            "provider_input_schema_invalid",
            "failed",
            f"unsupported VLM input image suffix: {path.suffix or '<none>'}",
        )
    try:
        digest = _sha256_file(path)
    except OSError as exc:
        raise _ProviderFailure(
            "provider_input_unavailable",
            "unavailable",
            f"VLM input image cannot be read: {type(exc).__name__}",
        ) from exc
    return {
        "schema_version": VLM_SCHEMA_VERSION,
        "task": "gui_visual_parse",
        "image_path": str(path.resolve()),
        "filename": path.name,
        "media_type": media_type,
        "size_bytes": int(stat.st_size),
        "sha256": digest,
        "timeout_seconds": timeout_seconds,
    }


def _normalize_response(
    value: Any,
    *,
    strict_schema: bool,
    redactor: _SecretRedactor,
) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise _ProviderFailure(
            "provider_output_schema_invalid",
            "failed",
            "VLM provider response must be an object",
        )
    schema_version = value.get("schema_version")
    if strict_schema and (type(schema_version) is not int or schema_version != VLM_SCHEMA_VERSION):
        raise _ProviderFailure(
            "provider_output_schema_invalid",
            "failed",
            f"VLM provider response schema_version must be {VLM_SCHEMA_VERSION}",
        )
    status_value = value.get("status")
    if strict_schema and (not isinstance(status_value, str) or not status_value.strip()):
        raise _ProviderFailure(
            "provider_output_schema_invalid",
            "failed",
            "VLM provider response status must be a non-empty string",
        )
    raw_status = str(status_value or "ok").strip().lower()
    status = "failed" if raw_status == "error" else raw_status
    if status not in _OUTPUT_STATUSES:
        raise _ProviderFailure(
            "provider_output_schema_invalid",
            "failed",
            f"unsupported VLM provider response status: {raw_status or '<empty>'}",
        )
    if strict_schema and status in {"ok", "partial"} and (
        "text_regions" not in value or "widgets" not in value
    ):
        raise _ProviderFailure(
            "provider_output_schema_invalid",
            "failed",
            "VLM provider response must include text_regions and widgets lists",
        )
    text_regions = _normalize_items(
        value.get("text_regions", []),
        item_kind="text_region",
        strict_schema=strict_schema,
        redactor=redactor,
    )
    widgets = _normalize_items(
        value.get("widgets", []),
        item_kind="widget",
        strict_schema=strict_schema,
        redactor=redactor,
    )
    output: Dict[str, Any] = {
        "schema_version": VLM_SCHEMA_VERSION,
        "status": status,
        "text_regions": text_regions,
        "widgets": widgets,
    }
    reason = value.get("reason") if value.get("reason") is not None else value.get("error")
    if reason is not None:
        output["reason"] = _limit_text(redactor.redact(reason), 2_000)
    provenance = _normalize_response_provenance(
        value.get("provenance"),
        strict_schema=strict_schema,
        redactor=redactor,
    )
    if provenance:
        output["provenance"] = provenance
    return output


def _normalize_items(
    value: Any,
    *,
    item_kind: str,
    strict_schema: bool,
    redactor: _SecretRedactor,
) -> list[Dict[str, Any]]:
    if not isinstance(value, list):
        raise _ProviderFailure(
            "provider_output_schema_invalid",
            "failed",
            f"VLM provider {item_kind} collection must be a list",
        )
    if len(value) > MAX_VLM_ITEMS:
        raise _ProviderFailure(
            "provider_output_schema_invalid",
            "failed",
            f"VLM provider {item_kind} collection exceeds {MAX_VLM_ITEMS} items",
        )
    normalized: list[Dict[str, Any]] = []
    for index, raw in enumerate(value):
        try:
            item = (
                _normalize_text_region(raw, redactor=redactor)
                if item_kind == "text_region"
                else _normalize_widget(raw, redactor=redactor)
            )
        except _ProviderFailure:
            if strict_schema:
                raise
            continue
        if item:
            normalized.append(item)
        elif strict_schema:
            raise _ProviderFailure(
                "provider_output_schema_invalid",
                "failed",
                f"VLM provider {item_kind} item {index} has no usable evidence",
            )
    return normalized


def _normalize_text_region(value: Any, *, redactor: _SecretRedactor) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise _ProviderFailure(
            "provider_output_schema_invalid",
            "failed",
            "VLM provider text region items must be objects",
        )
    text = value.get("text")
    if not isinstance(text, str) or not text.strip():
        return {}
    item: Dict[str, Any] = {"text": _limit_text(redactor.redact(text), MAX_VLM_TEXT_CHARS)}
    _copy_optional_confidence(value, item)
    _copy_optional_bbox(value, item)
    language = value.get("language")
    if isinstance(language, str) and language.strip():
        item["language"] = _limit_text(redactor.redact(language.strip()), 64)
    return item


def _normalize_widget(value: Any, *, redactor: _SecretRedactor) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise _ProviderFailure(
            "provider_output_schema_invalid",
            "failed",
            "VLM provider widget items must be objects",
        )
    widget_type = value.get("type") if value.get("type") is not None else value.get("control_type")
    text = value.get("text") if value.get("text") is not None else value.get("label")
    if not isinstance(widget_type, str) or not widget_type.strip():
        if not isinstance(text, str) or not text.strip():
            return {}
        widget_type = "unknown"
    item: Dict[str, Any] = {"type": _limit_text(redactor.redact(widget_type.strip()), 128)}
    if isinstance(text, str) and text.strip():
        item["text"] = _limit_text(redactor.redact(text), MAX_VLM_TEXT_CHARS)
    _copy_optional_confidence(value, item)
    _copy_optional_bbox(value, item)
    return item


def _copy_optional_confidence(source: Mapping[str, Any], target: Dict[str, Any]) -> None:
    if "confidence" not in source:
        return
    confidence = source.get("confidence")
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        raise _ProviderFailure(
            "provider_output_schema_invalid",
            "failed",
            "VLM provider confidence must be a finite number",
        )
    number = float(confidence)
    if not math.isfinite(number) or number < 0.0 or number > 1.0:
        raise _ProviderFailure(
            "provider_output_schema_invalid",
            "failed",
            "VLM provider confidence must be between 0 and 1",
        )
    target["confidence"] = round(number, 4)


def _copy_optional_bbox(source: Mapping[str, Any], target: Dict[str, Any]) -> None:
    if "bbox" not in source or source.get("bbox") is None:
        return
    bbox = source.get("bbox")
    if not isinstance(bbox, Mapping):
        raise _ProviderFailure(
            "provider_output_schema_invalid",
            "failed",
            "VLM provider bbox must be an object",
        )
    normalized: Dict[str, int | float] = {}
    for key in ("x", "y", "width", "height"):
        value = bbox.get(key)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise _ProviderFailure(
                "provider_output_schema_invalid",
                "failed",
                f"VLM provider bbox.{key} must be a finite number",
            )
        number = float(value)
        if not math.isfinite(number) or (key in {"width", "height"} and number < 0):
            raise _ProviderFailure(
                "provider_output_schema_invalid",
                "failed",
                f"VLM provider bbox.{key} is outside the accepted range",
            )
        normalized[key] = int(number) if number.is_integer() else round(number, 3)
    target["bbox"] = normalized


def _normalize_response_provenance(
    value: Any,
    *,
    strict_schema: bool,
    redactor: _SecretRedactor,
) -> Dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        if strict_schema:
            raise _ProviderFailure(
                "provider_output_schema_invalid",
                "failed",
                "VLM provider response provenance must be an object",
            )
        return {}
    normalized: Dict[str, Any] = {}
    for key in ("model", "model_version", "provider", "region", "request_id", "version"):
        item = value.get(key)
        if item is None:
            continue
        if isinstance(item, (str, int)) and not isinstance(item, bool):
            normalized[key] = _limit_text(redactor.redact(item), 256)
        elif strict_schema:
            raise _ProviderFailure(
                "provider_output_schema_invalid",
                "failed",
                f"VLM provider response provenance.{key} must be a string or integer",
            )
    return normalized


def _config_mapping(value: Any, label: str) -> Dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise _ProviderFailure(
            "provider_config_schema_invalid",
            "failed",
            f"VLM provider {label} must be an object",
        )
    normalized: Dict[str, Any] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not key or len(key) > 128:
            raise _ProviderFailure(
                "provider_config_schema_invalid",
                "failed",
                f"VLM provider {label} keys must be non-empty strings",
            )
        normalized[key] = _config_value(item, depth=0)
    return normalized


def _string_mapping(value: Any, label: str) -> Dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise _ProviderFailure(
            "provider_config_schema_invalid",
            "failed",
            f"VLM provider {label} must be an object",
        )
    normalized: Dict[str, str] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not key or not isinstance(item, str) or not item:
            raise _ProviderFailure(
                "provider_config_schema_invalid",
                "failed",
                f"VLM provider {label} entries must map non-empty strings to strings",
            )
        normalized[key] = item
    return normalized


def _config_value(value: Any, *, depth: int) -> Any:
    if depth > 8:
        raise _ProviderFailure(
            "provider_config_schema_invalid",
            "failed",
            "VLM provider configuration nesting exceeds 8 levels",
        )
    if value is None or isinstance(value, (str, int, bool)):
        if isinstance(value, str) and len(value) > MAX_VLM_CONFIG_BYTES:
            raise _ProviderFailure(
                "provider_config_schema_invalid",
                "failed",
                "VLM provider configuration string is too large",
            )
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise _ProviderFailure(
                "provider_config_schema_invalid",
                "failed",
                "VLM provider configuration numbers must be finite",
            )
        return value
    if isinstance(value, list):
        if len(value) > 1_000:
            raise _ProviderFailure(
                "provider_config_schema_invalid",
                "failed",
                "VLM provider configuration list is too large",
            )
        return [_config_value(item, depth=depth + 1) for item in value]
    if isinstance(value, Mapping):
        if len(value) > 1_000:
            raise _ProviderFailure(
                "provider_config_schema_invalid",
                "failed",
                "VLM provider configuration object is too large",
            )
        if any(not isinstance(key, str) for key in value):
            raise _ProviderFailure(
                "provider_config_schema_invalid",
                "failed",
                "VLM provider nested configuration keys must be strings",
            )
        return {key: _config_value(item, depth=depth + 1) for key, item in value.items()}
    raise _ProviderFailure(
        "provider_config_schema_invalid",
        "failed",
        f"unsupported VLM provider configuration value: {type(value).__name__}",
    )


def _timeout_value(value: Any, *, default: float) -> float:
    if value is None or value == "":
        return float(default)
    if isinstance(value, bool):
        raise _ProviderFailure(
            "provider_config_schema_invalid",
            "failed",
            "VLM provider timeout must be a finite positive number",
        )
    try:
        timeout = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise _ProviderFailure(
            "provider_config_schema_invalid",
            "failed",
            "VLM provider timeout must be a finite positive number",
        ) from exc
    if not math.isfinite(timeout) or timeout <= 0 or timeout > MAX_VLM_TIMEOUT_SECONDS:
        raise _ProviderFailure(
            "provider_config_schema_invalid",
            "failed",
            f"VLM provider timeout must be greater than 0 and at most {MAX_VLM_TIMEOUT_SECONDS:g} seconds",
        )
    return timeout


def _validate_import_path(value: str) -> None:
    if not value or not _IMPORT_PATH_RE.fullmatch(value):
        raise _ProviderFailure(
            "provider_import_path_invalid",
            "failed",
            "VLM provider import path must use the form module:callable with public identifiers",
        )


def _load_failure(
    failure: _ProviderFailure,
    *,
    configured: bool,
    settings: _ProviderSettings | None = None,
) -> VLMProviderLoadResult:
    message = settings.redactor.redact(failure.message) if settings else _SecretRedactor(()).redact(failure.message)
    provenance: Dict[str, Any] = {
        "schema_version": VLM_SCHEMA_VERSION,
        "configured": configured,
        "status": failure.status,
    }
    if settings is not None:
        provenance.update(
            {
                "source": settings.source,
                "provider": settings.name,
                "import_path": settings.import_path,
                "timeout_seconds": settings.timeout_seconds,
                "configuration": dict(settings.configuration_provenance),
            }
        )
    error = VLMProviderErrorInfo(failure.code, failure.status, message)
    return VLMProviderLoadResult(failure.status, None, provenance, error)


def _environment_configured(environ: Mapping[str, str]) -> bool:
    return bool(environ.get(GUI_VLM_CONFIG_ENV) or environ.get(GUI_VLM_PROVIDER_ENV))


def _run_with_timeout(operation: Callable[[], Any], timeout_seconds: float) -> tuple[Any, int]:
    result_queue: queue.Queue[tuple[bool, Any]] = queue.Queue(maxsize=1)
    started = time.monotonic()

    def runner() -> None:
        try:
            result_queue.put((True, operation()))
        except BaseException as exc:  # noqa: BLE001 - transported to the caller thread.
            result_queue.put((False, exc))

    thread = threading.Thread(target=runner, name="reverse-analyzer-vlm-provider", daemon=True)
    thread.start()
    try:
        succeeded, value = result_queue.get(timeout=timeout_seconds)
    except queue.Empty as exc:
        raise _OperationTimeout from exc
    if not succeeded:
        raise value
    return value, _duration_ms(started)


def _collect_secret_values(value: Any) -> list[str]:
    if isinstance(value, Mapping):
        values: list[str] = []
        for item in value.values():
            values.extend(_collect_secret_values(item))
        return values
    if isinstance(value, list):
        values = []
        for item in value:
            values.extend(_collect_secret_values(item))
        return values
    if value is None:
        return []
    return [str(value)]


def _provider_name(value: Any, *, fallback: Any) -> str:
    try:
        name = getattr(value, "name", None)
    except BaseException:  # noqa: BLE001 - plugin properties are untrusted.
        name = None
    return _safe_name(name or fallback)


def _safe_name(value: Any) -> str:
    text = str(value or "vlm_provider").strip()
    return _limit_text(text, 256) or "vlm_provider"


def _implementation_name(value: Any) -> str:
    if inspect.ismethod(value) or inspect.isfunction(value) or inspect.isclass(value):
        module = getattr(value, "__module__", "")
        qualname = getattr(value, "__qualname__", getattr(value, "__name__", type(value).__name__))
    else:
        implementation = type(value)
        module = getattr(implementation, "__module__", "")
        qualname = getattr(implementation, "__qualname__", implementation.__name__)
    return f"{module}.{qualname}".strip(".")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _duration_ms(started: float) -> int:
    return max(0, int(round((time.monotonic() - started) * 1_000)))


def _limit_text(value: Any, limit: int) -> str:
    text = str(value or "")
    if len(text) <= limit:
        return text
    return f"{text[: max(0, limit - 3)]}..."
