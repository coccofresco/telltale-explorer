"""Telltale ANM (animation) file parser.

Parses the container: MetaStream header, Animation base fields
(version/flags/name/length), and the type-table inside the outer block.

Output: AnimHeader(types=[AnimType(hash, name, count, version)], ...).
See docs/FORMAT_ANIMATION.md for the on-disk layout and the per-value
decoders (parse_anm_values.py, parse_compressed_keys.py, parse_ctk.py).
"""
from __future__ import annotations
import struct
from dataclasses import dataclass, field
from telltale.crc64 import crc64_str


# Type CRC64s for all AnimationValueInterface subclasses seen in the wild
_TYPE_NAMES = [
    'CompressedSkeletonPoseKeys', 'CompressedSkeletonPoseKeys2',
    'CompressedQuaternionKeys', 'CompressedQuaternionKeys2',
    'CompressedVector3Keys', 'CompressedVector3Keys2',
    'CompressedTransformKeys', 'CompressedTransformKeys2',
    'CompressedPhonemeKeys', 'CompressedVertexNormalKeys',
    'CompressedVertexPositionKeys',
    'CompressedKeys<Vector3>', 'CompressedKeys<Quaternion>',
    'CompressedKeys<Bool>', 'CompressedKeys<float>',
    'CompressedKeys<Transform>', 'CompressedKeys<PhonemeKey>',
    'KeyframedValue<String>', 'KeyframedValue<PhonemeKey>',
    'KeyframedValue<Transform>', 'KeyframedValue<Bool>',
    'KeyframedValue<Vector3>', 'KeyframedValue<Float>',
    'KeyframedValue<Quaternion>', 'KeyframedValue<Vector2>',
    'SingleValue<Transform>', 'SingleValue<Quaternion>',
    'SingleValue<Vector3>', 'SingleValue<Float>',
    'SingleValue<Bool>', 'SingleValue<Symbol>', 'SingleValue<String>',
    'SingleVector3Value',
]
TYPE_HASH_TO_NAME = {crc64_str(n): n for n in _TYPE_NAMES}


@dataclass
class AnimType:
    hash: int
    name: str
    count: int
    version: int


@dataclass
class AnimValue:
    """One value interface (= one animation channel in the ANM)."""
    type_name: str              # e.g. 'KeyframedValue<Transform>'
    type_hash: int
    type_version: int
    name_hash: int              # Symbol mName (from base class serialization)
    flags: int                  # u32 mFlags (contains ValueType in high byte)
    value_type: int             # mFlags >> 24
    start_offset: int           # file offset where this value's SerializeIn starts
    end_offset: int             # exclusive
    body_size: int              # bytes used by this value (including 24B header)


@dataclass
class AnimHeader:
    version: int
    flags: int
    name_hash: int
    additive_mask: float
    length: float
    total_interfaces: int
    data_buffer_size: int
    types: list[AnimType] = field(default_factory=list)
    types_end_offset: int = 0
    block_size: int = 0
    block_end: int = 0
    values: list[AnimValue] = field(default_factory=list)


def _parse_mtre_header(data: bytes) -> int:
    """Return the offset of the Animation base fields (post MTRE+params)."""
    magic = struct.unpack_from('<I', data, 0)[0]
    if magic != 0x4D545245:  # "ERTM"
        raise ValueError(f"not a MTRE file (magic=0x{magic:08x})")
    param_count = struct.unpack_from('<I', data, 4)[0]
    # For ANM files observed in MI, params are the 12-byte (hash+size) style.
    # A more robust detector would peek at the next u32 and pick name-prefix
    # style if small; adapt if we hit unknown headers.
    return 8 + param_count * 12


def parse_header(data: bytes) -> AnimHeader:
    hdr_end = _parse_mtre_header(data)
    base = hdr_end
    version = struct.unpack_from('<I', data, base + 0)[0]
    flags = struct.unpack_from('<I', data, base + 4)[0]
    name_hash = struct.unpack_from('<Q', data, base + 8)[0]
    additive = struct.unpack_from('<f', data, base + 16)[0]
    length = struct.unpack_from('<f', data, base + 20)[0]
    block_size = struct.unpack_from('<I', data, base + 24)[0]
    block_start = base + 24
    block_end = block_start + block_size

    if version not in (4, 5):
        raise ValueError(f"unsupported animation version {version}")

    p = base + 28
    totalN = struct.unpack_from('<I', data, p)[0]; p += 4
    dbuf = struct.unpack_from('<I', data, p)[0]; p += 4
    n_types = struct.unpack_from('<I', data, p)[0]; p += 4

    types: list[AnimType] = []
    for _ in range(n_types):
        lo, hi = struct.unpack_from('<II', data, p); p += 8
        _pad = struct.unpack_from('<I', data, p)[0]; p += 4
        num = struct.unpack_from('<H', data, p)[0]; p += 2
        ver = struct.unpack_from('<H', data, p)[0]; p += 2
        h = (hi << 32) | lo
        types.append(AnimType(hash=h, name=TYPE_HASH_TO_NAME.get(h, '?'),
                              count=num, version=ver))

    # ----------------------------------------------------------------------
    # Locate each value interface. Every instance begins with a fixed
    # 8-byte prefix: outer_size=24, inner_size=20, followed by:
    #   u64  mName (Symbol CRC64)
    #   u32  padding
    #   u32  mFlags (high byte = ValueType enum per AnimationValueInterfaceBase)
    # The body (mMinVal/mMaxVal/mSamples for KeyframedValue<T>, or a raw
    # compressed blob for Compressed*Keys) follows immediately after.
    # ----------------------------------------------------------------------
    HEADER_PATTERN = b"\x18\x00\x00\x00\x14\x00\x00\x00"
    value_offsets: list[int] = []
    search_pos = p  # after the types table
    while True:
        idx = data.find(HEADER_PATTERN, search_pos)
        if idx < 0 or idx >= block_end:
            break
        value_offsets.append(idx)
        search_pos = idx + 1
    # Use the number of offsets we found to bound the value list.
    if len(value_offsets) >= totalN:
        value_offsets = value_offsets[:totalN]

    # Type of each value (order: all of type 0, then type 1, ...)
    flat_types: list[AnimType] = []
    for t in types:
        flat_types.extend([t] * t.count)

    values: list[AnimValue] = []
    for i, off in enumerate(value_offsets):
        name_lo = struct.unpack_from('<I', data, off + 8)[0]
        name_hi = struct.unpack_from('<I', data, off + 12)[0]
        name = (name_hi << 32) | name_lo
        flg = struct.unpack_from('<I', data, off + 20)[0]
        end = value_offsets[i + 1] if i + 1 < len(value_offsets) else block_end
        t = flat_types[i] if i < len(flat_types) else AnimType(0, '?', 0, 0)
        values.append(AnimValue(
            type_name=t.name, type_hash=t.hash, type_version=t.version,
            name_hash=name, flags=flg, value_type=flg >> 24,
            start_offset=off, end_offset=end, body_size=end - off,
        ))

    return AnimHeader(
        version=version, flags=flags, name_hash=name_hash,
        additive_mask=additive, length=length,
        total_interfaces=totalN, data_buffer_size=dbuf,
        types=types, types_end_offset=p,
        block_size=block_size, block_end=block_end,
        values=values,
    )


if __name__ == '__main__':
    import sys, os
    try:
        from telltale.skeleton import load_hash_db
        db = load_hash_db('hashdb/BoneNames.HashDB')
    except Exception:
        db = {}

    VALUE_TYPE_NAMES = {
        0x1: 'Time', 0x2: 'Weight', 0x3: 'Skeletal', 0x4: 'Mover',
        0x5: 'Property', 0x6: 'AdditiveMask', 0x7: 'TargetedMover',
        0x8: 'SkeletonPose', 0x9: 'SkeletonRootAnim',
        0x41: 'VertexPosition', 0x42: 'VertexNormal',
        0x61: 'AutoAct', 0x62: 'ExplicitCompute',
    }

    for path in sys.argv[1:] or [
        'extracted/ep1_anm/obj_idolsmerfolk_wheelaspin.anm',
        'extracted/ep1_anm/sk20_move_guybrushwalk.anm',
        'extracted/ep1_anm/sk20_move_guybrushrun.anm',
    ]:
        if not os.path.exists(path):
            continue
        with open(path, 'rb') as f:
            data = f.read()
        h = parse_header(data)
        print(f'=== {os.path.basename(path)} ({len(data)} B) ===')
        print(f'  ver={h.version} name=0x{h.name_hash:016X}  length={h.length:.3f}s')
        print(f'  interfaces={h.total_interfaces}  data_buffer={h.data_buffer_size}')
        for t in h.types:
            print(f'    {t.name:35s} × {t.count}  (ver={t.version})')
        # Show first 8 and last 3 values
        print(f'  values: {len(h.values)} found')
        for i, v in enumerate(h.values[:8]):
            bone = db.get(v.name_hash, f'?_{v.name_hash:016X}')
            vt = VALUE_TYPE_NAMES.get(v.value_type, f'?{v.value_type:x}')
            print(f'    [{i:3d}] off=0x{v.start_offset:05x} size={v.body_size:6d} '
                  f'type={vt:10s} target={bone[:40]} [{v.type_name}]')
        if len(h.values) > 8:
            print(f'    ...')
            for i in range(len(h.values) - 3, len(h.values)):
                v = h.values[i]
                bone = db.get(v.name_hash, f'?_{v.name_hash:016X}')
                vt = VALUE_TYPE_NAMES.get(v.value_type, f'?{v.value_type:x}')
                print(f'    [{i:3d}] off=0x{v.start_offset:05x} size={v.body_size:6d} '
                      f'type={vt:10s} target={bone[:40]} [{v.type_name}]')
        print()
