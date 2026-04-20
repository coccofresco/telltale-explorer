"""
Math-type MetaClass registration for Telltale.

Registers Vector2/3/4, Quaternion, Color, and Transform as
@meta_class dataclasses, with fixed-byte decoders inserted into
the shared dispatch table from telltale.meta_intrinsics.

Byte layouts are empirically derived from Tales of Monkey Island's
iOS binary (Transform::SerializeIn reversed in v1.1).  The
canonical reference implementation is parse_anm_values._read_sv
for SingleValue<T> variants — meta_math MUST produce byte-for-byte
equivalent decodes.

Transform layout (LOAD-BEARING — differs from some TelltaleToolLib
platform defaults):
    0..15 : Quaternion (f32 x, y, z, w)
    16..27: Vector3    (f32 x, y, z)
    total : 28 bytes — NO padAlign, NO trailing pad.

Quaternion component order is x, y, z, w (NOT w, x, y, z).  Confirmed
against parse_anm_values._read_sv line 192-193 and parse_ctk decoder.

Color serialized order: r, g, b, a (forward member order on disk).
TelltaleToolLib/ToolLibrary/MetaInitialize.h declares members in reverse
(alpha, b, g, r via mpNextMember linked list) but the on-disk serialization
order is r, g, b, a.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

from telltale.metaclass import meta_class, meta_member
from telltale.meta_intrinsics import register
from telltale.metastream import MetaStreamReader

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Dataclasses registered with @meta_class
# ---------------------------------------------------------------------------

@meta_class("Vector2")
@dataclass
class Vector2:
    """2D vector: 8 bytes (f32 x, f32 y)."""
    x: float = meta_member("x", float)
    y: float = meta_member("y", float)


@meta_class("Vector3")
@dataclass
class Vector3:
    """3D vector: 12 bytes (f32 x, f32 y, f32 z).

    Byte layout confirmed against parse_anm_values._read_sv("SingleValue<Vector3>"):
        x, y, z = struct.unpack_from("<fff", data, p)
    """
    x: float = meta_member("x", float)
    y: float = meta_member("y", float)
    z: float = meta_member("z", float)


@meta_class("Vector4")
@dataclass
class Vector4:
    """4D vector: 16 bytes (f32 x, f32 y, f32 z, f32 w)."""
    x: float = meta_member("x", float)
    y: float = meta_member("y", float)
    z: float = meta_member("z", float)
    w: float = meta_member("w", float)


@meta_class("Quaternion")
@dataclass
class Quaternion:
    """Quaternion: 16 bytes (f32 x, f32 y, f32 z, f32 w).

    Component order on disk: x, y, z, w — NOT w, x, y, z.
    Confirmed against parse_anm_values._read_sv("SingleValue<Quaternion>"):
        x, y, z, w = struct.unpack_from("<ffff", data, p)
    Also matches parse_ctk.py output format {x, y, z, w}.
    """
    # Component order: x, y, z, w (empirical — do not reorder).
    x: float = meta_member("x", float)
    y: float = meta_member("y", float)
    z: float = meta_member("z", float)
    w: float = meta_member("w", float)


@meta_class("Color")
@dataclass
class Color:
    """RGBA color: 16 bytes (f32 r, f32 g, f32 b, f32 a).

    Serialized order: r, g, b, a (forward member order on disk).
    TelltaleToolLib MetaInitialize.h declares them in reverse insertion
    order (alpha, b, g, r) due to mpNextMember linked-list construction,
    but the on-disk byte sequence is r, g, b, a.
    """
    r: float = meta_member("r", float)
    g: float = meta_member("g", float)
    b: float = meta_member("b", float)
    a: float = meta_member("a", float)


@meta_class("Transform")
@dataclass
class Transform:
    """Transform: 28 bytes = Quaternion (16 B) + Vector3 (12 B), NO padAlign.

    Layout (LOAD-BEARING — matches iOS Transform::SerializeIn reversed in v1.1):
        Offset 0..15 : Quaternion — f32 x, y, z, w (order x,y,z,w confirmed)
        Offset 16..27: Vector3    — f32 x, y, z
        Total: 28 bytes.  NO padAlign between Quaternion and Vector3.
        NO trailing pad.

    Reference: parse_anm_values._read_sv("SingleValue<Transform>") line 194-197:
        qx, qy, qz, qw, tx, ty, tz = struct.unpack_from("<fffffff", data, p)

    Member declaration uses the two sub-types so Phase 4+ container walkers
    can dispatch via get_by_name("Quaternion") / get_by_name("Vector3").
    """
    quat: "Quaternion" = meta_member("mRot", Quaternion)
    pos: "Vector3" = meta_member("mTrans", Vector3)


# ---------------------------------------------------------------------------
# Decoders
# ---------------------------------------------------------------------------

def decode_vector2(reader: MetaStreamReader, stream_version: int) -> Vector2:
    """Decode Vector2: 8 bytes (f32 x, f32 y)."""
    x = reader.read_float32()
    y = reader.read_float32()
    return Vector2(x=x, y=y)


def decode_vector3(reader: MetaStreamReader, stream_version: int) -> Vector3:
    """Decode Vector3: 12 bytes (f32 x, f32 y, f32 z).

    Byte-for-byte equivalent to parse_anm_values._read_sv("SingleValue<Vector3>").
    """
    x = reader.read_float32()
    y = reader.read_float32()
    z = reader.read_float32()
    return Vector3(x=x, y=y, z=z)


def decode_vector4(reader: MetaStreamReader, stream_version: int) -> Vector4:
    """Decode Vector4: 16 bytes (f32 x, f32 y, f32 z, f32 w)."""
    x = reader.read_float32()
    y = reader.read_float32()
    z = reader.read_float32()
    w = reader.read_float32()
    return Vector4(x=x, y=y, z=z, w=w)


def decode_quaternion(reader: MetaStreamReader, stream_version: int) -> Quaternion:
    """Decode Quaternion: 16 bytes (f32 x, f32 y, f32 z, f32 w).

    Order: x, y, z, w — confirmed empirical layout.
    Byte-for-byte equivalent to parse_anm_values._read_sv("SingleValue<Quaternion>").
    """
    # Component order x, y, z, w — do NOT change this order.
    x = reader.read_float32()
    y = reader.read_float32()
    z = reader.read_float32()
    w = reader.read_float32()
    return Quaternion(x=x, y=y, z=z, w=w)


def decode_color(reader: MetaStreamReader, stream_version: int) -> Color:
    """Decode Color: 16 bytes (f32 r, f32 g, f32 b, f32 a)."""
    r = reader.read_float32()
    g = reader.read_float32()
    b = reader.read_float32()
    a = reader.read_float32()
    return Color(r=r, g=g, b=b, a=a)


def decode_transform(reader: MetaStreamReader, stream_version: int) -> Transform:
    """Decode Transform: 28 bytes = Quaternion (16 B) + Vector3 (12 B), NO padAlign.

    Layout (LOAD-BEARING):
        Offset 0..15 : decode_quaternion -> f32 x, y, z, w
        Offset 16..27: decode_vector3    -> f32 x, y, z

    Nested calls — do NOT inline the 7 f32 reads.  Keeping the composition
    explicit documents the layout derivation and ensures the decoder stays
    consistent with decode_quaternion and decode_vector3 if either is updated.

    Byte-for-byte equivalent to parse_anm_values._read_sv("SingleValue<Transform>"):
        qx, qy, qz, qw, tx, ty, tz = struct.unpack_from("<fffffff", data, p)
    """
    quat = decode_quaternion(reader, stream_version)
    pos = decode_vector3(reader, stream_version)
    return Transform(quat=quat, pos=pos)


# ---------------------------------------------------------------------------
# Registration into shared _DECODERS table
# ---------------------------------------------------------------------------

def register_math_types() -> None:
    """Idempotent registration of math decoders into
    telltale.meta_intrinsics._DECODERS (which also mirrors into
    telltale.metaclass._REGISTRY).

    Note: the @meta_class decorators above ALREADY inserted each
    dataclass into _REGISTRY under the right hash (with dataclass_cls
    set and members populated).  This function adds the DECODER side
    of the pair — both are needed for full Phase 4+ dispatch.

    decoder_only=True preserves the MetaClassDescription that
    @meta_class("Vector3") etc. already inserted (with dataclass_cls
    set and members populated).  Without decoder_only=True, register()
    would overwrite that entry with a bare MetaClassDescription
    (dataclass_cls=None, members=[]), losing the dataclass binding
    that Phase 4+ container walkers need.

    See telltale.meta_intrinsics.register for the full contract.
    """
    register("Vector2",    decode_vector2,    decoder_only=True)
    register("Vector3",    decode_vector3,    decoder_only=True)
    register("Vector4",    decode_vector4,    decoder_only=True)
    register("Quaternion", decode_quaternion, decoder_only=True)
    register("Color",      decode_color,      decoder_only=True)
    register("Transform",  decode_transform,  decoder_only=True)
    log.debug("registered 6 math type decoders")


register_math_types()
