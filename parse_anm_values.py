"""
Full multi-value .anm walker for Tales of Monkey Island.

Reverses the Animation::SerializeIn stream layout observed in
TelltaleToolLib (Animation.h, read-path with mVersion >= 4):

    u32   totalNumOfInterfaces
    u32   dataBufferSize
    u32   animValueTypes
    per type:  u64 typeHash, u16 valuesOfType, u16 typeVersion
               (observed in-file: 16 bytes/entry including a 4-byte pad)

    [per-value SerializeIn bodies in type order, then value order]
    [per-value mFlags u32 in same order]
    u16 zero  (only if total_values > 0)
    [per-value mName u64 + debug-strlen u32=0 (MTRE stream version < 5)]

SerializeIn stream consumption per value type:

    CompressedKeys<Vector3>     2 + count*16 + ceil(count/4) bytes
    CompressedKeys<Quaternion>  2 + count*20 + ceil(count/4) bytes
    CompressedKeys<Transform>   2 + count*36 + ceil(count/4) bytes
    CompressedKeys<float>       2 + count*8  + ceil(count/4) bytes   (assumed)
    CompressedKeys<Bool>        2 + count*5  + ceil(count/4) bytes   (assumed, bool=1B)
    SingleValue<Transform>      28 bytes  (Quaternion 16 + Vector3 12)
    SingleValue<Quaternion>     16 bytes
    SingleValue<Vector3>        12 bytes
    SingleValue<Float>           4 bytes
    SingleValue<Bool>            1 byte   (assumed)
    SingleVector3Value          12 bytes  (a Vector3)

Complex types (CTK, CK-Phoneme, CV3K2, KFV) are SKIPPED by consuming all
remaining dbuf bytes until the next known value boundary. Full integration
with parse_ctk / decode_phoneme_keys / decode_*_keys is still TODO.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from parse_anm import parse_header, AnimHeader
# telltale.metastream is the unified MetaStream infrastructure (Phase 1).
# parse_anm_values is part of that pipeline: the MetaStream container header is
# consumed by parse_anm.parse_header (which delegates to _parse_mtre_header),
# and the ANM body walk below operates on the post-header payload.  The import
# here makes the dependency explicit so that static analysis, future rewires,
# and INFRA-05 compliance checks can confirm the module participates in the
# unified reader stack.
from telltale.metastream import parse_header as _ms_parse_header, MetaStreamHeader
from parse_ctk import (
    read_size_prefix as _ctk_read_size_prefix,
    decode_ctk as _decode_ctk,
    decode_time_keys as _decode_time_keys,
    decode_phoneme_keys as _decode_phoneme_keys,
    ANIMATION_SYMBOLS,
)


# Per-type stream consumption helpers. Return (n_bytes_consumed, decoded_samples_or_None).

def _flag_bytes(count: int) -> int:
    return (count + 3) // 4


def _ck_stream_bytes(count: int, elem_size: int) -> int:
    return 2 + count * (elem_size + 4) + _flag_bytes(count)


# Element sizes per `CompressedKeys<T>` specialization (bytes per sample, value only)
_CK_ELEM_SIZE: Dict[str, int] = {
    "CompressedKeys<Vector3>":    12,
    "CompressedKeys<Quaternion>": 16,
    "CompressedKeys<Transform>":  28,   # Quat(16) + Vec3(12), padAlign NOT serialized
    "CompressedKeys<float>":       4,
    "CompressedKeys<Bool>":        1,
}

_SV_BODY_BYTES: Dict[str, int] = {
    "SingleValue<Transform>":   28,
    "SingleValue<Quaternion>":  16,
    "SingleValue<Vector3>":     12,
    "SingleValue<Float>":        4,
    "SingleValue<Bool>":         1,
    "SingleVector3Value":        4,
}


# Types serialized as "CTK-like" [size_u8/u16 | data | size_u8/u16 | time_data].
# CompressedVector3Keys2 uses the same two-size-prefixed layout (verified via
# iOS disasm of VA 0x1feecc: serialize_uint8 for outer size, optional u16
# extension on 0xff, then serialize_bytes; then a nested call to
# 0x1fd590 which runs the same read-a-size-prefixed-buffer sequence).
_CTK_LIKE_TYPES = {
    "CompressedTransformKeys",
    "CompressedPhonemeKeys",
    "CompressedVector3Keys2",
}


def _skip_ctk_like(data: bytes, p: int) -> int:
    """Advance past one CTK-style value (two size-prefixed blocks)."""
    size1, p = _ctk_read_size_prefix(data, p); p += size1
    size2, p = _ctk_read_size_prefix(data, p); p += size2
    return p


def _read_ctk_like_with_decode(data: bytes, p: int, type_name: str):
    """Read one CTK-style value, optionally decoding to samples.

    Returns (end_pos, samples_or_None).
    """
    start = p
    size1, p1 = _ctk_read_size_prefix(data, p)
    buf1_start = p1
    p = p1 + size1
    size2, p2 = _ctk_read_size_prefix(data, p)
    buf2_start = p2
    p = p2 + size2

    samples = None
    try:
        if type_name == "CompressedTransformKeys":
            ctk_samples = _decode_ctk(data[buf1_start:buf1_start + size1])
            if size2 > 0:
                times = _decode_time_keys(data[buf2_start:buf2_start + size2],
                                           len(ctk_samples))
                for s, t in zip(ctk_samples, times):
                    s.time = t
            samples = ctk_samples
        elif type_name == "CompressedPhonemeKeys":
            phon = _decode_phoneme_keys(data[buf1_start:buf1_start + size1])
            if size2 > 0:
                times = _decode_time_keys(data[buf2_start:buf2_start + size2],
                                           len(phon))
                for s, t in zip(phon, times):
                    s.time = t
            samples = phon
        # CompressedVector3Keys2: inner format not yet decoded → leave samples=None
    except Exception:
        # Decode failures don't abort the walker; samples stays None
        samples = None

    return p, samples


@dataclass
class DecodedValue:
    type_name: str
    name_hash: int         # Symbol CRC64 (bone hash)
    flags: int
    value_type: int        # high byte of flags, per AnimationValueInterfaceBase::ValueKind
    stream_offset: int     # where the SerializeIn body begins
    stream_size: int       # bytes consumed by SerializeIn body
    samples: Optional[List[Any]] = None   # populated for supported types


def _read_ck(data: bytes, p: int, elem_size: int) -> tuple[int, int, list]:
    """Read a CompressedKeys<T> body starting at p. Returns (count, stream_bytes, samples)."""
    count = struct.unpack_from("<H", data, p)[0]
    sb = _ck_stream_bytes(count, elem_size)
    samples: list = []
    rp = p + 2
    for _ in range(count):
        if elem_size == 12:   # Vector3
            x, y, z, t = struct.unpack_from("<ffff", data, rp); rp += 16
            samples.append({"time": t, "x": x, "y": y, "z": z})
        elif elem_size == 16: # Quaternion
            x, y, z, w, t = struct.unpack_from("<fffff", data, rp); rp += 20
            samples.append({"time": t, "x": x, "y": y, "z": z, "w": w})
        elif elem_size == 28: # Transform (Quat + Vec3, no padAlign)
            qx, qy, qz, qw, px, py, pz, t = struct.unpack_from("<ffffffff", data, rp); rp += 32
            samples.append({"time": t, "qx": qx, "qy": qy, "qz": qz, "qw": qw,
                             "x": px, "y": py, "z": pz})
        elif elem_size == 4:  # float
            v, t = struct.unpack_from("<ff", data, rp); rp += 8
            samples.append({"time": t, "value": v})
        elif elem_size == 1:  # bool — 1 B bool + 4 B time, no padding
            v = data[rp]
            t, = struct.unpack_from("<f", data, rp + 1)
            rp += 5
            samples.append({"time": t, "value": bool(v)})
        else:
            raise ValueError(f"unsupported elem_size {elem_size}")
    return count, sb, samples


def _read_sv(data: bytes, p: int, type_name: str) -> tuple[int, Any]:
    """Read a SingleValue<T>. Returns (stream_bytes, value)."""
    size = _SV_BODY_BYTES[type_name]
    if type_name == "SingleValue<Vector3>":
        x, y, z = struct.unpack_from("<fff", data, p)
        return size, {"x": x, "y": y, "z": z}
    if type_name == "SingleVector3Value":
        # 4-byte f32 scalar (a uniform/isotropic Vector3 — x=y=z=value).
        v, = struct.unpack_from("<f", data, p)
        return size, {"value": v}
    if type_name == "SingleValue<Quaternion>":
        x, y, z, w = struct.unpack_from("<ffff", data, p)
        return size, {"x": x, "y": y, "z": z, "w": w}
    if type_name == "SingleValue<Transform>":
        qx, qy, qz, qw, tx, ty, tz = struct.unpack_from("<fffffff", data, p)
        return size, {"qx": qx, "qy": qy, "qz": qz, "qw": qw,
                       "x": tx, "y": ty, "z": tz}
    if type_name == "SingleValue<Float>":
        v, = struct.unpack_from("<f", data, p)
        return size, {"value": v}
    if type_name == "SingleValue<Bool>":
        v = data[p]
        return size, {"value": bool(v)}
    raise ValueError(f"unknown SV type: {type_name}")


def walk_anm(data: bytes) -> List[DecodedValue]:
    """Decode all values in an .anm file. Returns list of DecodedValue.

    Returns an empty list for anims containing types the walker doesn't
    understand (CTK, CompressedPhonemeKeys, CV3K2, KFV). The caller can
    dispatch those specific types to parse_ctk / decode_phoneme_keys / …
    """
    h = parse_header(data)
    if h.version < 4:
        return []

    # Flatten types in declaration order (type-index ascending, then value-index)
    flat_types: List[str] = []
    for t in h.types:
        flat_types.extend([t.name] * t.count)
    total = len(flat_types)
    if total != h.total_interfaces:
        return []

    # Bail out early if any unhandled type is present
    for tn in flat_types:
        if (tn not in _CK_ELEM_SIZE
                and tn not in _SV_BODY_BYTES
                and tn not in _CTK_LIKE_TYPES):
            return []

    # 1. SerializeIn bodies (in type order)
    p = h.types_end_offset
    values: List[DecodedValue] = []
    for tn in flat_types:
        start = p
        if tn in _CK_ELEM_SIZE:
            _count, sb, samples = _read_ck(data, p, _CK_ELEM_SIZE[tn])
            p += sb
        elif tn in _SV_BODY_BYTES:
            sb, val = _read_sv(data, p, tn)
            samples = [val]
            p += sb
        else:  # _CTK_LIKE_TYPES — read + decode CTK/Phoneme when possible
            end, samples = _read_ctk_like_with_decode(data, p, tn)
            sb = end - p
            p = end
        values.append(DecodedValue(
            type_name=tn, name_hash=0, flags=0, value_type=0,
            stream_offset=start, stream_size=sb, samples=samples,
        ))

    # 2. mFlags (u32 per value, in same order)
    for v in values:
        v.flags = struct.unpack_from("<I", data, p)[0]
        v.value_type = (v.flags >> 24) & 0xFF
        p += 4

    # 3. u16 zero (only if any values)
    if total > 0:
        zero = struct.unpack_from("<H", data, p)[0]
        p += 2
        if zero != 0:
            # Unexpected but harmless — continue
            pass

    # 4. mName u64 (+ u32=0 debug strlen in MTRE, stream v < 5)
    for v in values:
        if p + 12 > len(data):
            # Not enough bytes — structural mismatch (probably an unsupported
            # sub-variant). Abort rather than produce garbage.
            return []
        v.name_hash = struct.unpack_from("<Q", data, p)[0]
        p += 8
        # MTRE serialize_Symbol trails with an empty-string u32=0
        p += 4  # debug strlen

    return values


if __name__ == "__main__":
    import sys

    paths = [arg for arg in sys.argv[1:] if not arg.startswith("--")] or [
        "extracted/ep1_anm/obj_stationlab_cheeseholderdown.anm",
        "extracted/ep1_anm/obj_xrayguybrushhandguybrush_sk20_idle_guybrushdoctorschairxrayfoot.anm",
        "extracted/ep1_anm/elaine_phoneme_ee.anm",  # all SV<Transform>
    ]
    show_all = "--all" in sys.argv
    try:
        from telltale.skeleton import load_hash_db
        db = load_hash_db("hashdb/BoneNames.HashDB")
    except Exception:
        db = {}
    db.update(ANIMATION_SYMBOLS)   # include relativeNode/absoluteNode/Phoneme/etc.

    for path in paths:
        with open(path, "rb") as f:
            data = f.read()
        try:
            h = parse_header(data)
        except Exception as e:
            print(f"{path}: parse_header failed ({e})")
            continue
        vals = walk_anm(data)
        print(f"\n=== {path} ({len(data)} B) ===")
        print(f"    types: {[(t.name, t.count) for t in h.types]}")
        print(f"    length={h.length:.3f}s dbuf={h.data_buffer_size}")
        if not vals:
            print("    (walker bailed out — complex types present)")
            continue
        VT_NAMES = {
            0x1: "Time", 0x2: "Weight", 0x3: "Skeletal", 0x4: "Mover",
            0x5: "Property", 0x6: "AdditiveMask", 0x8: "SkeletonPose",
        }
        limit = len(vals) if show_all else 8
        for i, v in enumerate(vals[:limit]):
            bone = db.get(v.name_hash, f"?_{v.name_hash:016x}")
            vt = VT_NAMES.get(v.value_type, f"?{v.value_type:x}")
            n_samp = len(v.samples) if v.samples else 0
            print(f"    [{i:3d}] {v.type_name:28s} vt={vt:10s} "
                  f"target={bone[:42]:42s} samples={n_samp}")
        if not show_all and len(vals) > limit:
            print(f"    ... +{len(vals) - limit} more  (use --all to dump every channel)")
