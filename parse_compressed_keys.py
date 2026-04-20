"""
Decoder for CompressedKeys<T> template specializations in Tales of Monkey Island.

Despite the name, these formats store keyframes UNCOMPRESSED — raw (value, time)
pairs with a small trailing bitmask. Format reversed from iOS binary SerializeIn
VAs (CompressedKeys<Vector3>::SerializeIn @ 0x432870,
CompressedKeys<Quaternion>::SerializeIn @ 0x4427c8).

Wire format (per value):
    u16 count
    per sample: <T>          value (12 B Vector3, 16 B Quaternion, 32 B Transform)
                f32          time
    u8[ceil(count/4)] flags  2-bit-per-sample packed bitfield (role unclear,
                              possibly "interpolation kind" or skip markers)

Total buffer size = 2 + count * (sizeof(T) + 4) + ceil(count/4)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import List


# ---------------------------------------------------------------------------
# Sample types
# ---------------------------------------------------------------------------

@dataclass
class Vector3Sample:
    time: float
    x: float
    y: float
    z: float


@dataclass
class QuaternionSample:
    time: float
    x: float
    y: float
    z: float
    w: float


@dataclass
class TransformSample:
    time: float
    # Transform layout in the engine: Quaternion(16B) + Vector3(12B) + f32 scale(4B) = 32 B
    qx: float
    qy: float
    qz: float
    qw: float
    x: float
    y: float
    z: float
    scale: float


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _u16(buf: bytes, p: int) -> int:
    return struct.unpack_from("<H", buf, p)[0]


def _expected_size(count: int, elem_bytes: int) -> int:
    flag_bytes = (count + 3) // 4
    return 2 + count * (elem_bytes + 4) + flag_bytes


# ---------------------------------------------------------------------------
# Decoders
# ---------------------------------------------------------------------------

def decode_vector3_keys(buf: bytes) -> List[Vector3Sample]:
    """Decode a CompressedKeys<Vector3> buffer into [Vector3Sample]."""
    count = _u16(buf, 0)
    expected = _expected_size(count, 12)
    if len(buf) < expected:
        raise ValueError(f"buffer too short: have {len(buf)} need {expected} for count={count}")
    out: List[Vector3Sample] = []
    p = 2
    for _ in range(count):
        x, y, z, t = struct.unpack_from("<ffff", buf, p); p += 16
        out.append(Vector3Sample(time=t, x=x, y=y, z=z))
    # trailing (count+3)/4 flag bytes are not currently decoded
    return out


def decode_quaternion_keys(buf: bytes) -> List[QuaternionSample]:
    """Decode a CompressedKeys<Quaternion> buffer into [QuaternionSample]."""
    count = _u16(buf, 0)
    expected = _expected_size(count, 16)
    if len(buf) < expected:
        raise ValueError(f"buffer too short: have {len(buf)} need {expected} for count={count}")
    out: List[QuaternionSample] = []
    p = 2
    for _ in range(count):
        x, y, z, w, t = struct.unpack_from("<fffff", buf, p); p += 20
        out.append(QuaternionSample(time=t, x=x, y=y, z=z, w=w))
    return out


def decode_transform_keys(buf: bytes) -> List[TransformSample]:
    """Decode a CompressedKeys<Transform> buffer into [TransformSample].

    Transform layout per the engine: Quaternion (16 B) + Vector3 (12 B) +
    f32 scale (4 B) = 32 bytes per value.
    """
    count = _u16(buf, 0)
    expected = _expected_size(count, 32)
    if len(buf) < expected:
        raise ValueError(f"buffer too short: have {len(buf)} need {expected} for count={count}")
    out: List[TransformSample] = []
    p = 2
    for _ in range(count):
        qx, qy, qz, qw, x, y, z, scale, t = struct.unpack_from("<fffffffff", buf, p); p += 36
        out.append(TransformSample(time=t, qx=qx, qy=qy, qz=qz, qw=qw, x=x, y=y, z=z, scale=scale))
    return out


if __name__ == "__main__":
    import sys
    from parse_anm import parse_header

    paths = sys.argv[1:] or [
        "extracted/ep1_anm/obj_xrayguybrushhandguybrush_sk20_idle_guybrushdoctorschairxrayfoot.anm",
    ]
    for path in paths:
        with open(path, "rb") as f:
            data = f.read()
        h = parse_header(data)
        # assumption: first value in types order occupies the data_buffer directly
        buf = data[h.types_end_offset:h.types_end_offset + h.data_buffer_size]
        first = h.types[0]
        print(f"=== {path} ===")
        print(f"    first type = {first.name} x{first.count}")
        print(f"    data_buffer = {h.data_buffer_size} B")
        try:
            if first.name == "CompressedKeys<Vector3>":
                samples = decode_vector3_keys(buf)
                print(f"    {len(samples)} Vector3 samples:")
                for s in samples:
                    print(f"      t={s.time:7.3f}s  ({s.x:+9.4f}, {s.y:+9.4f}, {s.z:+9.4f})")
            elif first.name == "CompressedKeys<Quaternion>":
                samples = decode_quaternion_keys(buf)
                print(f"    {len(samples)} Quaternion samples:")
                for s in samples:
                    print(f"      t={s.time:7.3f}s  ({s.x:+7.4f}, {s.y:+7.4f}, {s.z:+7.4f}, {s.w:+7.4f})")
            elif first.name == "CompressedKeys<Transform>":
                samples = decode_transform_keys(buf)
                print(f"    {len(samples)} Transform samples (showing first 3):")
                for s in samples[:3]:
                    print(f"      t={s.time:.3f}s pos=({s.x:.3f},{s.y:.3f},{s.z:.3f}) "
                          f"quat=({s.qx:.3f},{s.qy:.3f},{s.qz:.3f},{s.qw:.3f}) s={s.scale}")
        except Exception as e:
            print(f"    decode failed: {e}")
