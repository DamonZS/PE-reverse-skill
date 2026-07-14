"""Bounded C-like memory layouts for audited process-memory operations.

The schema is intentionally explicit: callers provide byte offsets, byte order,
array lengths, and bit ranges.  No host ABI packing assumptions are made.
"""

from __future__ import annotations

import math
import re
import struct
from dataclasses import dataclass
from typing import Any, Mapping, Sequence


DEFAULT_MAX_SCHEMA_SIZE = 16 * 1024 * 1024
DEFAULT_MAX_DEPTH = 16
DEFAULT_MAX_FIELDS = 4096
DEFAULT_MAX_ARRAY_LENGTH = 65536

_SCALARS: dict[str, tuple[str, int, bool]] = {
    "int8": ("b", 1, False),
    "uint8": ("B", 1, False),
    "int16": ("h", 2, False),
    "uint16": ("H", 2, False),
    "int32": ("i", 4, False),
    "uint32": ("I", 4, False),
    "int64": ("q", 8, False),
    "uint64": ("Q", 8, False),
    "float32": ("f", 4, False),
    "float64": ("d", 8, False),
    "bool": ("B", 1, True),
}
_ALIASES = {
    "i8": "int8",
    "u8": "uint8",
    "i16": "int16",
    "u16": "uint16",
    "i32": "int32",
    "u32": "uint32",
    "i64": "int64",
    "u64": "uint64",
    "float": "float32",
    "double": "float64",
    "boolean": "bool",
}
_PATH_TOKEN = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)|\[([0-9]+)\]")


@dataclass(frozen=True)
class BitMember:
    name: str
    bit_offset: int
    width: int
    signed: bool = False


@dataclass(frozen=True)
class LayoutNode:
    kind: str
    size: int
    endian: str
    scalar_type: str | None = None
    fields: tuple["StructField", ...] = ()
    element: "LayoutNode | None" = None
    count: int = 0
    storage_type: str | None = None
    bits: tuple[BitMember, ...] = ()


@dataclass(frozen=True)
class StructField:
    name: str
    offset: int
    node: LayoutNode


@dataclass(frozen=True)
class MemoryLayout:
    root: LayoutNode

    @property
    def size(self) -> int:
        return self.root.size

    @property
    def endian(self) -> str:
        return self.root.endian


@dataclass(frozen=True)
class FieldReference:
    path: str
    offset: int
    node: LayoutNode
    bit: BitMember | None = None


@dataclass
class _Budget:
    fields: int = 0


def compile_memory_schema(
    schema: Mapping[str, Any],
    *,
    max_size: int = DEFAULT_MAX_SCHEMA_SIZE,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_fields: int = DEFAULT_MAX_FIELDS,
    max_array_length: int = DEFAULT_MAX_ARRAY_LENGTH,
) -> MemoryLayout:
    """Validate and compile an explicit, JSON-compatible memory schema."""

    if not isinstance(schema, Mapping):
        raise ValueError("memory schema must be an object")
    limits = {
        "max_size": _positive_limit(max_size, "max_size"),
        "max_depth": _positive_limit(max_depth, "max_depth"),
        "max_fields": _positive_limit(max_fields, "max_fields"),
        "max_array_length": _positive_limit(max_array_length, "max_array_length"),
    }
    root_endian = _endian(schema.get("endian", "little"))
    root = _compile_node(schema, root_endian, 0, _Budget(), limits)
    if root.kind != "struct":
        raise ValueError("top-level memory schema must have type 'struct'")
    return MemoryLayout(root=root)


def decode_structure(data: bytes, schema: MemoryLayout | Mapping[str, Any]) -> dict[str, Any]:
    layout = _layout(schema)
    raw = bytes(data)
    if len(raw) != layout.size:
        raise ValueError(
            f"schema requires {layout.size} bytes, received {len(raw)}"
        )
    value = _decode_node(raw, 0, layout.root)
    return {
        "size": layout.size,
        "endian": layout.endian,
        "value": value,
    }


def read_structure_field(
    data: bytes,
    schema: MemoryLayout | Mapping[str, Any],
    path: str,
) -> Any:
    layout = _layout(schema)
    raw = bytes(data)
    if len(raw) != layout.size:
        raise ValueError(
            f"schema requires {layout.size} bytes, received {len(raw)}"
        )
    reference = resolve_structure_field(layout, path)
    return _decode_reference(raw, reference)


def write_structure_field(
    data: bytes,
    schema: MemoryLayout | Mapping[str, Any],
    path: str,
    value: Any,
    *,
    expected: Any,
) -> dict[str, Any]:
    """Patch one schema field while preserving all unrelated bytes and bits."""

    layout = _layout(schema)
    original = bytes(data)
    if len(original) != layout.size:
        raise ValueError(
            f"schema requires {layout.size} bytes, received {len(original)}"
        )
    reference = resolve_structure_field(layout, path)
    before = _decode_reference(original, reference)
    if not _values_equal(before, expected):
        raise ValueError(
            f"field precondition mismatch for {path}: expected {expected!r}, actual {before!r}"
        )

    patched = bytearray(original)
    if reference.bit is not None:
        storage = reference.node
        storage_bytes = original[reference.offset : reference.offset + storage.size]
        current = int.from_bytes(storage_bytes, storage.endian, signed=False)
        member = reference.bit
        encoded = _encode_bit_value(value, member)
        mask = ((1 << member.width) - 1) << member.bit_offset
        updated = (current & ~mask) | ((encoded << member.bit_offset) & mask)
        patched[reference.offset : reference.offset + storage.size] = updated.to_bytes(
            storage.size, storage.endian, signed=False
        )
    else:
        encoded = _encode_node(value, reference.node)
        patched[reference.offset : reference.offset + reference.node.size] = encoded

    after_bytes = bytes(patched)
    after = _decode_reference(after_bytes, reference)
    return {
        "path": reference.path,
        "offset": reference.offset,
        "size": reference.node.size,
        "bit_offset": reference.bit.bit_offset if reference.bit else None,
        "bit_width": reference.bit.width if reference.bit else None,
        "before": before,
        "after": after,
        "before_hex": original.hex(),
        "after_hex": after_bytes.hex(),
        "data": after_bytes,
    }


def resolve_structure_field(
    schema: MemoryLayout | Mapping[str, Any], path: str
) -> FieldReference:
    layout = _layout(schema)
    tokens = _parse_path(path)
    node = layout.root
    offset = 0
    canonical: list[str] = []
    index = 0
    while index < len(tokens):
        token_kind, token_value = tokens[index]
        if node.kind == "struct":
            if token_kind != "name":
                raise ValueError("struct field path requires a field name")
            field = next((item for item in node.fields if item.name == token_value), None)
            if field is None:
                raise ValueError(f"unknown struct field: {token_value}")
            offset += field.offset
            node = field.node
            canonical.append(str(token_value))
        elif node.kind == "array":
            if token_kind != "index":
                raise ValueError("array field path requires an index")
            element_index = int(token_value)
            if element_index >= node.count:
                raise ValueError(
                    f"array index {element_index} is outside length {node.count}"
                )
            if node.element is None:
                raise ValueError("array schema has no element layout")
            offset += element_index * node.element.size
            node = node.element
            if not canonical:
                raise ValueError("field path cannot start with an array index")
            canonical[-1] += f"[{element_index}]"
        elif node.kind == "bitfield":
            if token_kind != "name" or index != len(tokens) - 1:
                raise ValueError("bitfield path must end with a named bit member")
            member = next((item for item in node.bits if item.name == token_value), None)
            if member is None:
                raise ValueError(f"unknown bitfield member: {token_value}")
            canonical.append(str(token_value))
            return FieldReference(".".join(canonical), offset, node, member)
        else:
            raise ValueError("field path continues beyond a scalar value")
        index += 1
    if node.kind in {"struct", "array", "bitfield"}:
        raise ValueError("field path must resolve to a scalar, bytes, or bit member")
    return FieldReference(".".join(canonical), offset, node)


def describe_memory_layout(schema: MemoryLayout | Mapping[str, Any]) -> dict[str, Any]:
    layout = _layout(schema)
    return _describe_node(layout.root)


def _compile_node(
    spec: Any,
    inherited_endian: str,
    depth: int,
    budget: _Budget,
    limits: Mapping[str, int],
) -> LayoutNode:
    if depth > limits["max_depth"]:
        raise ValueError(f"memory schema exceeds maximum depth ({limits['max_depth']})")
    if isinstance(spec, str):
        scalar = _scalar_name(spec)
        if scalar is None:
            raise ValueError(f"unsupported memory field type: {spec}")
        return LayoutNode("scalar", _SCALARS[scalar][1], inherited_endian, scalar_type=scalar)
    if not isinstance(spec, Mapping):
        raise ValueError("memory field schema must be a type name or object")

    endian = _endian(spec.get("endian", inherited_endian))
    raw_type = spec.get("type", spec.get("kind", "struct" if "fields" in spec else None))
    if isinstance(raw_type, Mapping):
        return _compile_node(raw_type, endian, depth + 1, budget, limits)
    kind = str(raw_type or "").strip().lower().replace("-", "_")
    scalar = _scalar_name(kind)
    if scalar is not None:
        return LayoutNode("scalar", _SCALARS[scalar][1], endian, scalar_type=scalar)

    if kind in {"bytes", "blob", "padding"}:
        size = _bounded_int(spec.get("size", spec.get("length")), "bytes size", 1, limits["max_size"])
        return LayoutNode("bytes", size, endian)

    if kind in {"array", "fixed_array"}:
        count = _bounded_int(spec.get("count", spec.get("length")), "array count", 1, limits["max_array_length"])
        element_spec = spec.get("element", spec.get("items", spec.get("item")))
        if element_spec is None:
            raise ValueError("array schema requires an element type")
        element = _compile_node(element_spec, endian, depth + 1, budget, limits)
        size = count * element.size
        if size > limits["max_size"]:
            raise ValueError(f"array byte size exceeds maximum ({limits['max_size']})")
        return LayoutNode("array", size, endian, element=element, count=count)

    if kind in {"bitfield", "bits"}:
        storage_type = _scalar_name(spec.get("storage", spec.get("storage_type", "uint32")))
        if storage_type is None or storage_type.startswith("float") or storage_type == "bool":
            raise ValueError("bitfield storage must be an integer scalar type")
        storage_size = _SCALARS[storage_type][1]
        width_limit = storage_size * 8
        raw_bits = spec.get("bits", spec.get("fields"))
        if not isinstance(raw_bits, Sequence) or isinstance(raw_bits, (str, bytes, bytearray)) or not raw_bits:
            raise ValueError("bitfield schema requires a non-empty bits array")
        members: list[BitMember] = []
        used = 0
        for raw_member in raw_bits:
            if not isinstance(raw_member, Mapping):
                raise ValueError("bitfield members must be objects")
            name = _field_name(raw_member.get("name"))
            bit_offset = _bounded_int(raw_member.get("offset", raw_member.get("bit_offset")), f"bit offset for {name}", 0, width_limit - 1)
            width = _bounded_int(raw_member.get("width", raw_member.get("bit_width", 1)), f"bit width for {name}", 1, width_limit)
            if bit_offset + width > width_limit:
                raise ValueError(f"bitfield member {name} exceeds {width_limit}-bit storage")
            mask = ((1 << width) - 1) << bit_offset
            if used & mask:
                raise ValueError(f"bitfield member {name} overlaps another member")
            used |= mask
            members.append(BitMember(name, bit_offset, width, bool(raw_member.get("signed", False))))
            budget.fields += 1
            if budget.fields > limits["max_fields"]:
                raise ValueError(f"memory schema exceeds maximum fields ({limits['max_fields']})")
        return LayoutNode(
            "bitfield",
            storage_size,
            endian,
            storage_type=storage_type,
            bits=tuple(members),
        )

    if kind != "struct":
        raise ValueError(f"unsupported memory field type: {raw_type}")
    raw_fields = spec.get("fields")
    if not isinstance(raw_fields, Sequence) or isinstance(raw_fields, (str, bytes, bytearray)) or not raw_fields:
        raise ValueError("struct schema requires a non-empty fields array")
    fields: list[StructField] = []
    names: set[str] = set()
    occupied: list[tuple[int, int, str]] = []
    cursor = 0
    for raw_field in raw_fields:
        if not isinstance(raw_field, Mapping):
            raise ValueError("struct fields must be objects")
        name = _field_name(raw_field.get("name"))
        if name in names:
            raise ValueError(f"duplicate struct field: {name}")
        names.add(name)
        offset_value = raw_field.get("offset")
        offset = cursor if offset_value is None else _bounded_int(offset_value, f"offset for {name}", 0, limits["max_size"] - 1)
        field_spec = _field_type_spec(raw_field)
        child = _compile_node(field_spec, endian, depth + 1, budget, limits)
        end = offset + child.size
        if end > limits["max_size"]:
            raise ValueError(f"field {name} exceeds maximum schema size ({limits['max_size']})")
        for prior_start, prior_end, prior_name in occupied:
            if offset < prior_end and prior_start < end:
                raise ValueError(f"struct field {name} overlaps field {prior_name}")
        occupied.append((offset, end, name))
        fields.append(StructField(name, offset, child))
        cursor = max(cursor, end)
        budget.fields += 1
        if budget.fields > limits["max_fields"]:
            raise ValueError(f"memory schema exceeds maximum fields ({limits['max_fields']})")
    explicit_size = spec.get("size")
    size = cursor if explicit_size is None else _bounded_int(explicit_size, "struct size", cursor, limits["max_size"])
    if size <= 0:
        raise ValueError("struct size must be positive")
    return LayoutNode("struct", size, endian, fields=tuple(fields))


def _field_type_spec(field: Mapping[str, Any]) -> Any:
    raw_type = field.get("type", field.get("schema"))
    if isinstance(raw_type, Mapping):
        return raw_type
    normalized = str(raw_type or "").strip().lower().replace("-", "_")
    if normalized in {"struct", "array", "fixed_array", "bitfield", "bits", "bytes", "blob", "padding"}:
        return {key: value for key, value in field.items() if key not in {"name", "offset"}}
    if raw_type is None:
        raise ValueError(f"struct field {field.get('name')!r} requires a type")
    return raw_type


def _decode_node(data: bytes, offset: int, node: LayoutNode) -> Any:
    raw = data[offset : offset + node.size]
    if len(raw) != node.size:
        raise ValueError("memory bytes do not cover the compiled schema")
    if node.kind == "scalar":
        return _decode_scalar(raw, node)
    if node.kind == "bytes":
        return raw.hex()
    if node.kind == "array":
        if node.element is None:
            raise ValueError("array schema has no element layout")
        return [
            _decode_node(data, offset + index * node.element.size, node.element)
            for index in range(node.count)
        ]
    if node.kind == "struct":
        return {
            field.name: _decode_node(data, offset + field.offset, field.node)
            for field in node.fields
        }
    if node.kind == "bitfield":
        storage = int.from_bytes(raw, node.endian, signed=False)
        return {
            member.name: _decode_bit_value(storage, member)
            for member in node.bits
        }
    raise ValueError(f"unsupported compiled node kind: {node.kind}")


def _encode_node(value: Any, node: LayoutNode) -> bytes:
    if node.kind == "scalar":
        return _encode_scalar(value, node)
    if node.kind == "bytes":
        raw = _bytes_value(value)
        if len(raw) != node.size:
            raise ValueError(f"bytes field requires exactly {node.size} bytes")
        return raw
    if node.kind == "array":
        if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
            raise ValueError("array field value must be a sequence")
        if len(value) != node.count or node.element is None:
            raise ValueError(f"array field requires exactly {node.count} values")
        return b"".join(_encode_node(item, node.element) for item in value)
    if node.kind == "struct":
        if not isinstance(value, Mapping):
            raise ValueError("struct field value must be an object")
        output = bytearray(node.size)
        for field in node.fields:
            if field.name not in value:
                raise ValueError(f"struct field value is missing {field.name}")
            encoded = _encode_node(value[field.name], field.node)
            output[field.offset : field.offset + field.node.size] = encoded
        return bytes(output)
    if node.kind == "bitfield":
        if not isinstance(value, Mapping):
            raise ValueError("bitfield value must be an object")
        storage = 0
        for member in node.bits:
            if member.name not in value:
                raise ValueError(f"bitfield value is missing {member.name}")
            encoded = _encode_bit_value(value[member.name], member)
            storage |= encoded << member.bit_offset
        return storage.to_bytes(node.size, node.endian, signed=False)
    raise ValueError(f"unsupported compiled node kind: {node.kind}")


def _decode_reference(data: bytes, reference: FieldReference) -> Any:
    if reference.bit is None:
        return _decode_node(data, reference.offset, reference.node)
    raw = data[reference.offset : reference.offset + reference.node.size]
    storage = int.from_bytes(raw, reference.node.endian, signed=False)
    return _decode_bit_value(storage, reference.bit)


def _decode_scalar(raw: bytes, node: LayoutNode) -> Any:
    scalar = str(node.scalar_type)
    code, size, boolean = _SCALARS[scalar]
    if len(raw) != size:
        raise ValueError(f"{scalar} requires {size} bytes")
    value = struct.unpack(("<" if node.endian == "little" else ">") + code, raw)[0]
    return bool(value) if boolean else value


def _encode_scalar(value: Any, node: LayoutNode) -> bytes:
    scalar = str(node.scalar_type)
    code, size, boolean = _SCALARS[scalar]
    if boolean:
        if not isinstance(value, bool):
            raise ValueError("bool field value must be true or false")
        normalized: Any = int(value)
    elif code in {"f", "d"}:
        if isinstance(value, bool):
            raise ValueError(f"{scalar} field value must be numeric")
        try:
            normalized = float(value)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError(f"{scalar} field value must be numeric") from exc
        if not math.isfinite(normalized):
            raise ValueError(f"{scalar} field value must be finite")
    else:
        if isinstance(value, bool):
            raise ValueError(f"{scalar} field value must be an integer")
        try:
            normalized = int(value, 0) if isinstance(value, str) else int(value)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError(f"{scalar} field value must be an integer") from exc
        signed = code.islower()
        bits = size * 8
        minimum = -(1 << (bits - 1)) if signed else 0
        maximum = (1 << (bits - 1)) - 1 if signed else (1 << bits) - 1
        if not minimum <= normalized <= maximum:
            raise ValueError(f"{scalar} field value is outside [{minimum}, {maximum}]")
    try:
        return struct.pack(("<" if node.endian == "little" else ">") + code, normalized)
    except struct.error as exc:
        raise ValueError(f"{scalar} field value cannot be encoded") from exc


def _decode_bit_value(storage: int, member: BitMember) -> int:
    raw = (storage >> member.bit_offset) & ((1 << member.width) - 1)
    if member.signed and raw & (1 << (member.width - 1)):
        raw -= 1 << member.width
    return raw


def _encode_bit_value(value: Any, member: BitMember) -> int:
    if isinstance(value, bool):
        normalized = int(value)
    else:
        try:
            normalized = int(value, 0) if isinstance(value, str) else int(value)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError(f"bitfield member {member.name} must be an integer") from exc
    if member.signed:
        minimum = -(1 << (member.width - 1))
        maximum = (1 << (member.width - 1)) - 1
        if not minimum <= normalized <= maximum:
            raise ValueError(f"signed bitfield member {member.name} is outside [{minimum}, {maximum}]")
        return normalized & ((1 << member.width) - 1)
    maximum = (1 << member.width) - 1
    if not 0 <= normalized <= maximum:
        raise ValueError(f"bitfield member {member.name} is outside [0, {maximum}]")
    return normalized


def _parse_path(path: str) -> list[tuple[str, str | int]]:
    raw = str(path or "").strip()
    if not raw:
        raise ValueError("field_path must be non-empty")
    tokens: list[tuple[str, str | int]] = []
    position = 0
    expect_component = True
    while position < len(raw):
        if raw[position] == ".":
            if expect_component:
                raise ValueError(f"invalid field path: {raw}")
            expect_component = True
            position += 1
            continue
        match = _PATH_TOKEN.match(raw, position)
        if not match:
            raise ValueError(f"invalid field path: {raw}")
        if match.group(1) is not None:
            if not expect_component:
                raise ValueError(f"field names must be separated by '.': {raw}")
            tokens.append(("name", match.group(1)))
        else:
            if expect_component:
                raise ValueError(f"array index has no parent field: {raw}")
            tokens.append(("index", int(match.group(2))))
        expect_component = False
        position = match.end()
    if expect_component or not tokens:
        raise ValueError(f"invalid field path: {raw}")
    return tokens


def _describe_node(node: LayoutNode) -> dict[str, Any]:
    result: dict[str, Any] = {"type": node.kind, "size": node.size, "endian": node.endian}
    if node.scalar_type:
        result["scalar_type"] = node.scalar_type
    if node.kind == "struct":
        result["fields"] = [
            {"name": field.name, "offset": field.offset, "layout": _describe_node(field.node)}
            for field in node.fields
        ]
    elif node.kind == "array" and node.element is not None:
        result.update({"count": node.count, "element": _describe_node(node.element)})
    elif node.kind == "bitfield":
        result.update(
            {
                "storage_type": node.storage_type,
                "bits": [
                    {
                        "name": member.name,
                        "bit_offset": member.bit_offset,
                        "width": member.width,
                        "signed": member.signed,
                    }
                    for member in node.bits
                ],
            }
        )
    return result


def _layout(schema: MemoryLayout | Mapping[str, Any]) -> MemoryLayout:
    return schema if isinstance(schema, MemoryLayout) else compile_memory_schema(schema)


def _scalar_name(value: Any) -> str | None:
    normalized = str(value or "").strip().lower().replace("_t", "")
    normalized = _ALIASES.get(normalized, normalized)
    return normalized if normalized in _SCALARS else None


def _endian(value: Any) -> str:
    normalized = str(value or "").strip().lower().replace("_", "-")
    if normalized in {"little", "little-endian", "le", "<"}:
        return "little"
    if normalized in {"big", "big-endian", "be", ">"}:
        return "big"
    raise ValueError("memory schema endian must be little or big")


def _field_name(value: Any) -> str:
    name = str(value or "").strip()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
        raise ValueError(f"invalid memory schema field name: {value!r}")
    return name


def _bounded_int(value: Any, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be an integer")
    try:
        normalized = int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if not minimum <= normalized <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return normalized


def _positive_limit(value: Any, name: str) -> int:
    return _bounded_int(value, name, 1, 1 << 31)


def _bytes_value(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str):
        cleaned = value.strip().replace("0x", "").replace(" ", "").replace("_", "")
        try:
            return bytes.fromhex(cleaned)
        except ValueError as exc:
            raise ValueError("bytes field value must be hexadecimal") from exc
    if isinstance(value, Sequence):
        try:
            return bytes(value)
        except (TypeError, ValueError) as exc:
            raise ValueError("bytes field value must contain octets") from exc
    raise ValueError("bytes field value must be bytes or hexadecimal")


def _values_equal(actual: Any, expected: Any) -> bool:
    if isinstance(actual, float) or isinstance(expected, float):
        try:
            return math.isclose(float(actual), float(expected), rel_tol=0.0, abs_tol=0.0)
        except (TypeError, ValueError, OverflowError):
            return False
    return actual == expected


__all__ = [
    "MemoryLayout",
    "compile_memory_schema",
    "decode_structure",
    "describe_memory_layout",
    "read_structure_field",
    "resolve_structure_field",
    "write_structure_field",
]
