"""
Parse Telltale .skl skeleton files.

Supports all known SKL versions from the earliest string-name games (Texas
Hold'em, Bone, Sam & Max) through CRC64-hashed names (Monkey Island era and
later) up to the latest MSV6-era titles.

Format reference:
  - MetaStream header detection (MBIN / MTRE / MSV5 / MSV6)
  - Per-bone layout varies by version and EarlyGameFix setting
  - Bone hierarchy assembled via parent_index chain
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from telltale.crc64 import crc64

# ---------------------------------------------------------------------------
# MetaStream header magic values (little-endian uint32)
# ---------------------------------------------------------------------------
_MAGIC_MBIN = 0x4D42494E  # "MBIN"
_MAGIC_MTRE = 0x4D545245  # "MTRE"
_MAGIC_MSV5 = 0x4D535635  # "MSV5"
_MAGIC_MSV6 = 0x4D535636  # "MSV6"

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class IKConstraint:
    """A single IK constraint attached to a bone."""
    name: str
    hash_value: int  # non-zero when IK name is stored as hash (v55)
    influence: float


@dataclass
class Bone:
    """A single bone in a Telltale skeleton."""
    name: str               # resolved from hash database or direct string
    hash_value: int          # CRC64 hash (0 if name was a raw string)
    parent_index: int        # -1 for root bones
    local_position: Tuple[float, float, float]
    local_rotation: Tuple[float, float, float, float]  # quaternion (x, y, z, w)
    rest_matrix: Tuple[float, ...]  # 3x3 row-major as 9 floats
    ik_constraints: List[IKConstraint] = field(default_factory=list)


@dataclass
class Skeleton:
    """A complete parsed skeleton."""
    bones: List[Bone] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Hash database loader
# ---------------------------------------------------------------------------

def load_hash_db(filepath: str) -> Dict[int, str]:
    """Load a BoneNames.HashDB binary file.

    Format::

        uint32  pair_count
        For each pair:
            uint32  hash_low   (CRC64 low 32 bits)
            uint32  hash_high  (CRC64 high 32 bits)
            null-terminated string

    Returns a dict mapping ``(hash_high << 32) | hash_low`` to name string.
    """
    db: Dict[int, str] = {}
    with open(filepath, "rb") as fh:
        raw = fh.read()

    if len(raw) < 4:
        return db

    pair_count = struct.unpack_from("<I", raw, 0)[0]
    offset = 4

    for _ in range(pair_count):
        if offset + 8 > len(raw):
            break
        hash_low, hash_high = struct.unpack_from("<II", raw, offset)
        offset += 8

        # Read null-terminated string
        end = raw.index(b"\x00", offset)
        name = raw[offset:end].decode("ascii", errors="replace")
        offset = end + 1

        key = (hash_high << 32) | hash_low
        db[key] = name

    return db


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

class _Reader:
    """Minimal sequential binary reader over a bytes buffer."""

    __slots__ = ("_data", "_pos")

    def __init__(self, data: bytes, pos: int = 0) -> None:
        self._data = data
        self._pos = pos

    @property
    def pos(self) -> int:
        return self._pos

    @pos.setter
    def pos(self, value: int) -> None:
        self._pos = value

    def remaining(self) -> int:
        return len(self._data) - self._pos

    def skip(self, n: int) -> None:
        self._pos += n

    def read_bytes(self, n: int) -> bytes:
        end = self._pos + n
        chunk = self._data[self._pos:end]
        self._pos = end
        return chunk

    def u8(self) -> int:
        val = self._data[self._pos]
        self._pos += 1
        return val

    def u16(self) -> int:
        val = struct.unpack_from("<H", self._data, self._pos)[0]
        self._pos += 2
        return val

    def u32(self) -> int:
        val = struct.unpack_from("<I", self._data, self._pos)[0]
        self._pos += 4
        return val

    def i32(self) -> int:
        val = struct.unpack_from("<i", self._data, self._pos)[0]
        self._pos += 4
        return val

    def f32(self) -> float:
        val = struct.unpack_from("<f", self._data, self._pos)[0]
        self._pos += 4
        return val

    def f32x(self, count: int) -> Tuple[float, ...]:
        fmt = f"<{count}f"
        size = struct.calcsize(fmt)
        vals = struct.unpack_from(fmt, self._data, self._pos)
        self._pos += size
        return vals

    def string(self, length: int) -> str:
        raw = self._data[self._pos:self._pos + length]
        self._pos += length
        return raw.decode("ascii", errors="replace").rstrip("\x00")


def _parse_metastream_header(r: _Reader) -> int:
    """Parse MetaStream header and return the stream version.

    Returns:
        0 for MBIN, 1 for MTRE, 5 for MSV5, 6 for MSV6, or -1 for
        headerless files.  After this call *r.pos* points to the first byte
        past the header (i.e., the start of actual content).
    """
    if r.remaining() < 4:
        return -1

    start = r.pos
    magic = r.u32()

    if magic in (_MAGIC_MBIN, _MAGIC_MTRE):
        param_count = r.u32()
        # Peek at next uint32 to decide param style
        if r.remaining() < 4:
            return 0 if magic == _MAGIC_MBIN else 1
        param_hash_check = r.u32()
        # Seek back 4 because we only peeked
        r.pos -= 4
        if 0 < param_hash_check < 128:
            for _ in range(param_count):
                name_len = r.u32()
                r.skip(name_len)  # param name
                r.skip(4)         # param unknown
        else:
            r.skip(12 * param_count)
        return 0 if magic == _MAGIC_MBIN else 1

    if magic in (_MAGIC_MSV5, _MAGIC_MSV6):
        _file_size = r.u32()
        r.skip(8)  # unknown 8 bytes
        param_count = r.u32()
        r.skip(12 * param_count)
        return 5 if magic == _MAGIC_MSV5 else 6

    # Not a recognised magic -- might be a headerless file or a small value
    if magic <= 128:
        r.pos = start  # seek back to beginning
    else:
        r.pos = start  # try to parse from the start anyway
    return -1


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------

def parse_skeleton(
    data: bytes,
    version: int = 0,
    early_game_fix: int = 10,
    *,
    hash_db: Optional[Dict[int, str]] = None,
    model_scale: float = 1.0,
) -> Skeleton:
    """Parse a Telltale ``.skl`` skeleton file.

    Parameters
    ----------
    data:
        Raw file bytes.
    version:
        Game version number (``VerNum``).  0 for oldest games, higher values
        for newer engines.
    early_game_fix:
        The ``EarlyGameFix`` setting (1-3 for oldest string-name games,
        >= 4 for CRC64-hash games, 10 as a safe default for hash games).
    hash_db:
        Optional dictionary mapping CRC64 hash values to bone name strings.
        See :func:`load_hash_db`.
    model_scale:
        Multiplier applied to bone translation values (default 1.0).

    Returns
    -------
    Skeleton
        Parsed skeleton with bone hierarchy.
    """
    if hash_db is None:
        hash_db = {}

    r = _Reader(data)

    # --- MetaStream header ---------------------------------------------------
    _parse_metastream_header(r)

    # --- SKL name + version (same as d3dmesh name detection) -----------------
    # Read the name header so we advance past it.
    if r.remaining() >= 8:
        name_header_length = r.u32()
        name_length = r.u32()
        if name_length > name_header_length:
            r.pos -= 4
            name_length = name_header_length
        if name_length > 0 and name_length < 4096:
            _skl_name = r.string(name_length)
        else:
            _skl_name = ""
        # Version byte
        if r.remaining() >= 1:
            ver_byte = r.u8()
            # Version 0 detection: ASCII '0' or '1' => version 0
            if ver_byte in (0x30, 0x31):
                version = 0
            elif ver_byte != 0:
                version = ver_byte

    # --- Special fix for Strong Bad Ep. 2-5 ----------------------------------
    if version == 0 and 4 < early_game_fix < 8:
        r.skip(1)

    # --- BttF PS4 fix detection (version 17) ---------------------------------
    bttf_fix = False
    if version == 17 and r.remaining() > 0x28:
        save_pos = r.pos
        # Check uint32 at absolute offset 0x28 within the SKL data
        check_pos = save_pos
        if check_pos + 0x28 + 4 <= len(data):
            check_val = struct.unpack_from("<i", data, check_pos + 0x28)[0]
            if check_val == -1339414801:
                bttf_fix = True
        r.pos = save_pos

    # --- Bone data -----------------------------------------------------------
    if r.remaining() < 8:
        return Skeleton()

    _bone_file_size = r.u32()
    bone_count = r.u32()

    bones: List[Bone] = []
    use_string_names = (version == 0 and early_game_fix <= 3)
    use_hash_names = not use_string_names

    for _bone_idx in range(bone_count):
        bone_name = ""
        bone_hash: int = 0
        parent_name = ""

        # ---- Bone name -----------------------------------------------------
        if use_string_names:
            _bone_name_sect_length = r.u32()
            bone_name_length = r.u32()
            bone_name = r.string(bone_name_length)
        else:
            bone_hash_low = r.u32()
            bone_hash_high = r.u32()
            bone_hash = (bone_hash_high << 32) | bone_hash_low
            if version < 13:
                r.skip(4)  # uint32 padding
            bone_name = hash_db.get(bone_hash, f"bone_{bone_hash:016X}")

        # ---- Parent name / hash ---------------------------------------------
        if use_string_names:
            _parent_name_sect_length = r.u32()
            parent_name_length = r.u32()
            parent_name = r.string(parent_name_length)
        else:
            _parent_hash_low = r.u32()
            _parent_hash_high = r.u32()
            if version < 13:
                r.skip(4)  # float32 padding

        # ---- Parent index ---------------------------------------------------
        parent_index = r.i32()  # -1 = root

        # ---- Extra unknowns for v18+ / BttF fix ----------------------------
        if version >= 18 or bttf_fix:
            r.skip(12)  # 3x float32 unknowns

        # ---- Translation ----------------------------------------------------
        tx, ty, tz = r.f32(), r.f32(), r.f32()
        tx *= model_scale
        ty *= model_scale
        tz *= model_scale

        # ---- Rotation quaternion (negate W) ---------------------------------
        rx, ry, rz, rw = r.f32(), r.f32(), r.f32(), r.f32()
        rw = -rw  # W MUST BE NEGATED

        # ---- Misc per-bone data ---------------------------------------------
        _maybe_header = r.u32()
        _nothing3, _nothing4, _nothing5 = r.f32(), r.f32(), r.f32()
        _bone_q = r.f32()
        _nothing6, _nothing7, _nothing8 = r.f32(), r.f32(), r.f32()

        # ---- 3x3 rest matrix (row-major) ------------------------------------
        rest = r.f32x(9)

        # ---- IK constraints -------------------------------------------------
        _ik_header_length = r.u32()
        ik_count = r.u32()
        ik_list: List[IKConstraint] = []

        for _ in range(ik_count):
            ik_name = ""
            ik_hash: int = 0

            if version == 55:
                ik_hash_high = r.u32()
                ik_hash_low = r.u32()
                ik_hash = (ik_hash_high << 32) | ik_hash_low
                ik_name = hash_db.get(ik_hash, f"ik_{ik_hash:016X}")
            else:
                ik_name_length = r.u32()
                ik_name = r.string(ik_name_length)

            ik_influence = r.f32()
            ik_list.append(IKConstraint(
                name=ik_name,
                hash_value=ik_hash,
                influence=ik_influence,
            ))

        # ---- Extra padding for V0 EarlyGameFix > 4 -------------------------
        if version == 0 and early_game_fix > 4:
            r.skip(4)  # uint32 padding

        # ---- Extra data for version > 1 -------------------------------------
        if version > 1:
            _pi_land_length = r.u32()
            pi_amount_length = r.u32()
            for _ in range(pi_amount_length):
                r.skip(12)  # 3x float32
            _pi_header_length = r.u32()
            # 6x float32: minx, maxx, miny, maxy, minz, maxz
            r.skip(24)
            _pi_end = r.f32()

        # ---- Build bone -----------------------------------------------------
        bones.append(Bone(
            name=bone_name,
            hash_value=bone_hash,
            parent_index=parent_index,
            local_position=(tx, ty, tz),
            local_rotation=(rx, ry, rz, rw),
            rest_matrix=rest,
            ik_constraints=ik_list,
        ))

    return Skeleton(bones=bones)
