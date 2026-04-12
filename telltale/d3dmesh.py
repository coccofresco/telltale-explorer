"""
Telltale Games D3DMESH binary mesh parser -- versions 0 through 2.

Covers the older Telltale games:

* **Version 0 (MBIN)** -- Telltale Texas Hold'em, Bone, CSI 3/4,
  Sam & Max Seasons 1-2
* **Version 0.5 (ERTM/MTRE)** -- Strong Bad's CG4AP, Wallace & Gromit Ep. 1-3
* **Version 1 (MTRE)** -- Tales of Monkey Island, Back to the Future [PC],
  CSI: Deadly Intent / Fatal Conspiracy, Poker Night at the Inventory,
  Sam & Max Season 3, Wallace & Gromit Ep. 4  *(experimental / undocumented)*
* **Version 2 (MSV5)** -- Jurassic Park: The Game, Law & Order: Legacies

Usage::

    from telltale.d3dmesh import parse_d3dmesh

    with open("model.d3dmesh", "rb") as fh:
        mesh = parse_d3dmesh(fh.read(), early_game_fix=1)
    for sm in mesh.submeshes:
        print(sm.name, len(sm.vertices), "verts", len(sm.faces), "tris")

The *early_game_fix* parameter selects the sub-version variant:

=====  ============================================================
Value  Game(s)
=====  ============================================================
1      Texas Hold'em / Bone / CSI 3-4 / Sam & Max S1 / S2 Ep. 1-2
2      Sam & Max Season 2 Ep. 3-4
3      Sam & Max Season 2 Ep. 5
4      Strong Bad's CG4AP Ep. 1
5      Strong Bad's CG4AP Ep. 2
6      Strong Bad's CG4AP Ep. 3
7      Strong Bad's CG4AP Ep. 4
8      Strong Bad's CG4AP Ep. 5
9      Wallace & Gromit Ep. 1-3
10     Tales of Monkey Island (default) -- Version 1
=====  ============================================================

Reference implementation: *TelltaleGames_D3DMesh.ms* by Random Talking Bush.
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from telltale import metastream

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# T3IndexBuffer delta decoder
# ---------------------------------------------------------------------------

def _decode_face_indices(first_index: int, body: bytes) -> list:
    """Decode delta-compressed face indices from a T3IndexBuffer bitstream.

    The bitstream consists of groups, each with a header and per-index data:

    * **Group header** (11 bits): 4 bits *delta_width* + 7 bits *group_count*
    * **Per index** (1 + *delta_width* bits): 1 bit sign + *delta_width* bits
      unsigned magnitude.

    Each decoded delta is added to a running accumulator (seeded with
    *first_index*) to produce the output index.

    Reverse-engineered from ``T3IndexBuffer::Decompress`` in the iOS ARM
    build of Tales of Monkey Island (VA 0x24443c).
    """
    data = bytearray(body) + bytearray(16)  # padding for safe reads
    total_bits = len(body) * 8
    bit_pos = 0
    accumulator = first_index
    indices = [accumulator]

    def _read_bits(n):
        nonlocal bit_pos
        if n == 0:
            return 0
        result = 0
        for i in range(n):
            byte_idx = (bit_pos + i) >> 3
            bit_idx = (bit_pos + i) & 7
            if data[byte_idx] & (1 << bit_idx):
                result |= 1 << i
        bit_pos += n
        return result

    while bit_pos + 11 <= total_bits:
        delta_width = _read_bits(4)
        group_count = _read_bits(7)
        if group_count == 0:
            break
        bits_per_index = 1 + delta_width
        for _ in range(group_count):
            if bit_pos + bits_per_index > total_bits:
                break
            sign = _read_bits(1)
            value = _read_bits(delta_width) if delta_width > 0 else 0
            if sign:
                value = -value
            accumulator = (accumulator + value) & 0xFFFF
            indices.append(accumulator)

    return indices


# ---------------------------------------------------------------------------
# BinaryReader
# ---------------------------------------------------------------------------

class BinaryReader:
    """Lightweight binary reader over an in-memory bytes buffer.

    All multi-byte reads use **little-endian** byte order, matching the
    Telltale engine's native format on x86.
    """

    __slots__ = ('data', 'pos')

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    # -- raw read ----------------------------------------------------------

    def read(self, n: int) -> bytes:
        """Read *n* raw bytes and advance the position."""
        end = self.pos + n
        if end > len(self.data):
            raise EOFError(
                f"Attempted to read {n} bytes at offset {self.pos:#x}, "
                f"but only {len(self.data) - self.pos} bytes remain"
            )
        chunk = self.data[self.pos:end]
        self.pos = end
        return chunk

    # -- integer reads -----------------------------------------------------

    def read_u8(self) -> int:
        val = self.data[self.pos]
        self.pos += 1
        return val

    def read_u16(self) -> int:
        val = struct.unpack_from('<H', self.data, self.pos)[0]
        self.pos += 2
        return val

    def read_i16(self) -> int:
        val = struct.unpack_from('<h', self.data, self.pos)[0]
        self.pos += 2
        return val

    def read_u32(self) -> int:
        val = struct.unpack_from('<I', self.data, self.pos)[0]
        self.pos += 4
        return val

    def read_i32(self) -> int:
        val = struct.unpack_from('<i', self.data, self.pos)[0]
        self.pos += 4
        return val

    def read_u64(self) -> int:
        val = struct.unpack_from('<Q', self.data, self.pos)[0]
        self.pos += 8
        return val

    def read_i8(self) -> int:
        val = struct.unpack_from('<b', self.data, self.pos)[0]
        self.pos += 1
        return val

    # -- float reads -------------------------------------------------------

    def read_f32(self) -> float:
        val = struct.unpack_from('<f', self.data, self.pos)[0]
        self.pos += 4
        return val

    def read_f16(self) -> float:
        """Read a 16-bit IEEE 754 half-precision float."""
        raw = self.read_u16()
        sign = (raw >> 15) & 1
        exponent = (raw >> 10) & 0x1F
        fraction = raw & 0x3FF
        if exponent == 0:
            # Sub-normal or zero
            f = ((-1) ** sign) * (2 ** -14) * (fraction / 1024)
        elif exponent == 0x1F:
            f = float('-inf') if sign else float('inf')
            if fraction != 0:
                f = float('nan')
        else:
            f = ((-1) ** sign) * (2 ** (exponent - 15)) * (1 + fraction / 1024)
        return f

    # -- compound reads ----------------------------------------------------

    def read_vec3(self) -> Tuple[float, float, float]:
        """Read 3 consecutive float32 values as an (x, y, z) tuple."""
        x = self.read_f32()
        y = self.read_f32()
        z = self.read_f32()
        return (x, y, z)

    def read_quat(self) -> Tuple[float, float, float, float]:
        """Read 4 consecutive float32 values as an (x, y, z, w) tuple."""
        x = self.read_f32()
        y = self.read_f32()
        z = self.read_f32()
        w = self.read_f32()
        return (x, y, z, w)

    def read_string(self, length: int) -> str:
        """Read a fixed-length ASCII string."""
        raw = self.read(length)
        # Strip trailing NULs just in case
        return raw.rstrip(b'\x00').decode('ascii', errors='replace')

    # -- navigation --------------------------------------------------------

    def skip(self, n: int) -> None:
        self.pos += n

    def seek(self, pos: int) -> None:
        self.pos = pos

    def tell(self) -> int:
        return self.pos

    def peek_u32(self) -> int:
        """Read a uint32 without advancing the position."""
        val = struct.unpack_from('<I', self.data, self.pos)[0]
        return val

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def at_end(self) -> bool:
        return self.pos >= len(self.data)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class D3DMeshVertex:
    """A single mesh vertex with optional attributes."""
    position: Tuple[float, float, float]
    normal: Optional[Tuple[float, float, float]] = None
    uv: Optional[Tuple[float, float]] = None
    uv2: Optional[Tuple[float, float]] = None
    bone_indices: Optional[Tuple[int, int, int, int]] = None
    bone_weights: Optional[Tuple[float, float, float, float]] = None
    color: Optional[Tuple[float, float, float, float]] = None


@dataclass
class D3DMeshSubmesh:
    """One polygon group / material slot in the mesh."""
    name: str
    vertices: List[D3DMeshVertex] = field(default_factory=list)
    faces: List[Tuple[int, int, int]] = field(default_factory=list)
    material_name: Optional[str] = None
    bone_set_index: int = 0


@dataclass
class D3DMeshData:
    """Top-level container returned by :func:`parse_d3dmesh`."""
    name: str
    version: int
    bounding_box: Tuple[Tuple[float, float, float], Tuple[float, float, float]]
    submeshes: List[D3DMeshSubmesh] = field(default_factory=list)
    bone_names: List[List[str]] = field(default_factory=list)
    all_vertices: List[D3DMeshVertex] = field(default_factory=list)
    all_faces: List[Tuple[int, int, int]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _read_material_slot(r: BinaryReader) -> Optional[str]:
    """Read a single material name block common to V0/V0.5.

    Layout::

        uint32 header_length
        uint32 name_length_raw  (name_length = name_length_raw - 6)
        if header_length > 8:
            string name (name_length bytes)
            skip 6 bytes  (hash / padding)

    Returns the material name string, or None if the slot is empty.
    """
    header_length = r.read_u32()
    if header_length > 1000:
        raise ValueError(f"Material header length {header_length} looks wrong at offset {r.tell() - 4:#x}")
    name_length = r.read_u32() - 6
    if header_length > 8 and name_length > 0:
        name = r.read_string(name_length)
        r.skip(6)
        return name
    return None


def _hex_dump(data: bytes, offset: int, length: int = 64) -> str:
    """Return a hex-dump string for debugging."""
    chunk = data[offset:offset + length]
    hex_str = ' '.join(f'{b:02X}' for b in chunk)
    ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
    return f"[{offset:#06x}] {hex_str}  |{ascii_str}|"


# ---------------------------------------------------------------------------
# Version 0 (MBIN) parser
# ---------------------------------------------------------------------------

def _parse_v0(r: BinaryReader, early_game_fix: int) -> D3DMeshData:
    """Parse a Version 0 (MBIN) D3DMESH.

    EarlyGameFix mapping:
      1 = Texas Hold'em / Bone / CSI 3-4 / Sam & Max S1 / S2 Ep. 1-2
      2 = Sam & Max Season 2 Ep. 3-4
      3 = Sam & Max Season 2 Ep. 5
    """
    log.info("Parsing Version 0 (MBIN) mesh, EarlyGameFix=%d", early_game_fix)

    # -- Start marker detection -------------------------------------------
    r.seek(r.tell() - 1)  # back up one byte (we already read the version byte)
    header_check = r.read_u16()
    if header_check not in (0x3131, 0x3031, 0x3130, 0x3030):
        r.seek(r.tell() - 1)  # off by one, re-align
    log.debug("Model start = %#x", r.tell())

    # -- Bounding box -----------------------------------------------------
    bb_min = r.read_vec3()
    bb_max = r.read_vec3()
    log.debug("Bounding box: min=%s max=%s", bb_min, bb_max)

    # -- Submesh header ---------------------------------------------------
    head3a_sub_size = r.read_u32()
    poly_total = r.read_u32()

    if poly_total > 1000:
        log.warning("PolyTotal=%d looks wrong, seeking back 0x21 to retry", poly_total)
        r.seek(r.tell() - 0x21)
        bb_min = r.read_vec3()
        bb_max = r.read_vec3()
        head3a_sub_size = r.read_u32()
        poly_total = r.read_u32()

    if poly_total > 1000:
        raise ValueError(f"Submesh count {poly_total} is unreasonably large")
    log.info("Submesh count = %d", poly_total)

    # -- Per-submesh info -------------------------------------------------
    submesh_infos = []
    mat_plus = 0
    footer_plus = 0

    for idx in range(poly_total):
        log.debug("Submesh %d info start = %#x", idx, r.tell())
        info: dict = {}

        # Two name blocks
        name_header_length = r.read_u32() - 8
        if name_header_length > 1000:
            raise ValueError(f"Name header length {name_header_length + 8} at submesh {idx}")
        name_length = r.read_u32() - 4
        r.skip(name_header_length)

        name_header_length2 = r.read_u32() - 8
        if name_header_length2 > 1000:
            raise ValueError(f"Name header length2 {name_header_length2 + 8} at submesh {idx}")
        name_length2 = r.read_u32() - 4
        r.skip(name_header_length2)

        info['bone_set_num'] = r.read_u32() + 1
        info['single_bind_node'] = r.read_u32()
        info['vertex_min'] = r.read_u32() + 1
        info['vertex_max'] = r.read_u32() + 1
        facepoint_start = r.read_u32()
        info['polygon_start'] = (facepoint_start // 3) + 1
        polygon_count = r.read_u32()
        info['polygon_count'] = polygon_count
        info['facepoint_count'] = polygon_count * 3

        # Submesh name / material name block
        name_header3_length = r.read_u32()
        name3_length = r.read_u32()
        r.skip(name3_length)

        # Per-submesh bounding box
        _sub_bb_min = r.read_vec3()
        _sub_bb_max = r.read_vec3()

        # Material texture slots
        mat_name = _read_material_slot(r)  # Diffuse
        info['material_name'] = mat_name
        if mat_name:
            log.debug("  Diffuse: %s", mat_name)

        spec_name = _read_material_slot(r)  # Specular
        if spec_name:
            log.debug("  Specular: %s", spec_name)

        bake_name = _read_material_slot(r)  # Bake
        if bake_name:
            log.debug("  Bake: %s", bake_name)

        bump_name = _read_material_slot(r)  # Bump
        if bump_name:
            log.debug("  Bump: %s", bump_name)

        # EarlyGameFix-specific material slots
        if early_game_fix == 1:
            if idx == 0:
                mat_check = r.read_u16()
                r.seek(r.tell() - 2)
                if mat_check < 256:
                    mat_plus = 1

            if mat_plus == 1:
                tex4b = _read_material_slot(r)
                if tex4b:
                    log.debug("  Tex4B: %s", tex4b)

            footer_check = r.read_u8()
            if idx == 0:
                if footer_check != 0x30:
                    footer_plus = 1

            tex5 = _read_material_slot(r)
            if tex5:
                log.debug("  Tex5: %s", tex5)

            _env_value = r.read_u32()
            r.skip(5)
            header_check3 = r.read_u32()
            r.seek(r.tell() - 9)
            if header_check3 != 0x08:
                r.skip(1)
            r.skip(1)
            _float2 = r.read_f32()

            env_name = _read_material_slot(r)
            if env_name:
                log.debug("  Environment: %s", env_name)

        elif early_game_fix >= 2:
            tex5 = _read_material_slot(r)
            if tex5:
                log.debug("  Tex5: %s", tex5)
            r.skip(1)

            tex6 = _read_material_slot(r)
            if tex6:
                log.debug("  Tex6: %s", tex6)

            _env_value = r.read_u32()
            r.skip(2)
            _float2 = r.read_f32()

            env_name = _read_material_slot(r)
            if env_name:
                log.debug("  Environment: %s", env_name)

        # Post-material floats (9 floats = 3 vec3)
        for _ in range(9):
            r.read_f32()
        r.skip(1)

        if early_game_fix == 1:
            if mat_plus == 1:
                for _ in range(9):
                    r.read_f32()
            r.read_f32()
            r.read_f32()
            if mat_plus == 1:
                r.read_u32()
                r.skip(1)
        elif early_game_fix == 2:
            for _ in range(9):
                r.read_f32()
            r.read_f32()
            r.read_f32()
            r.skip(2)
            r.read_u32()
            r.read_u32()
            r.read_u32()
            r.skip(1)
        elif early_game_fix == 3:
            for _ in range(9):
                r.read_f32()
            r.read_f32()
            r.read_f32()
            r.skip(5)
            r.read_u32()
            r.read_u32()
            r.read_u32()
            r.skip(1)

        # Footer name blocks
        name_length_f = r.read_u32()
        if name_length_f > 1000:
            raise ValueError(f"Footer name length {name_length_f} too large")
        r.skip(name_length_f)

        if early_game_fix == 1:
            if footer_plus == 1:
                name_length_f2 = r.read_u32()
                if name_length_f2 > 1000:
                    raise ValueError(f"Footer name length2 {name_length_f2} too large")
                r.skip(name_length_f2)
        elif early_game_fix > 1:
            name_length_f2 = r.read_u32()
            if name_length_f2 > 1000:
                raise ValueError(f"Footer name length2 {name_length_f2} too large")
            r.skip(name_length_f2)

        submesh_infos.append(info)
        log.debug("  VertexRange=[%d,%d] PolyStart=%d PolyCount=%d BoneSet=%d",
                  info['vertex_min'], info['vertex_max'],
                  info['polygon_start'], info['polygon_count'],
                  info['bone_set_num'])

    # -- Bone ID sets -----------------------------------------------------
    log.debug("Bone IDs start = %#x", r.tell())
    id_header_length = r.read_u32() - 4
    bone_id_sets_count = r.read_u32()
    log.debug("Bone ID sets count = %d", bone_id_sets_count)

    bone_id_sets = []
    bone_id_offsets = []
    for s in range(bone_id_sets_count):
        bone_id_offsets.append(r.tell())
        bone_id_total = r.read_u32()
        bone_names = []
        for _ in range(bone_id_total):
            bid_header = r.read_u32()
            bid_name_len = r.read_u32()
            bname = r.read_string(bid_name_len)
            bone_names.append(bname)
            _terminator = r.read_u32()  # 0xFFFFFFFF
        bone_id_sets.append(bone_names)

    # -- Face data --------------------------------------------------------
    # Search for 0x65 marker
    while not r.at_end():
        b = r.read_u8()
        if b == 0x65:
            break
    r.skip(3)

    log.debug("Face info start = %#x", r.tell())
    face_count = r.read_u32()
    face_length = r.read_u32()
    log.debug("Face count = %d, face element size = %d", face_count, face_length)

    # Read raw face indices (1-based in MaxScript, we store 0-based)
    raw_faces = []
    for _ in range(face_count // 3):
        fa = r.read_u16() + 1
        fb = r.read_u16() + 1
        fc = r.read_u16() + 1
        raw_faces.append((fa, fb, fc))

    # -- Vertex buffers ---------------------------------------------------
    vert_array = []
    normal_array = []
    uv_array = []
    uv2_array = []
    weight_array = []
    bone_array = []
    color_array = []

    buffer_num = 0
    normal_layer = 1
    uv_layer = 1

    while not r.at_end():
        # Read buffer flag byte(s) -- skip 0x30 padding bytes
        buffer_flag = 0x30
        failsafe = 0
        while buffer_flag == 0x30 and not r.at_end():
            buffer_flag = r.read_u8()
            buffer_num += 1
            failsafe += 1
            if failsafe > 5:
                buffer_flag = None
                log.warning("Unexpected flag count at buffer %d", buffer_num)
                break

        if buffer_flag is None or r.at_end():
            break

        if r.remaining() < 10:
            break

        _flag_b = r.read_u8()
        buffer_count = r.read_u32()
        buffer_length = r.read_u32()
        buffer_type = r.read_u32()

        log.debug("Buffer: num=%d type=%d count=%d length=%d at %#x",
                  buffer_num, buffer_type, buffer_count, buffer_length, r.tell())

        # Buffer types:
        # 1 = positions, 2 = normals, 3 = UVs, 4 = weights,
        # 5 = bone IDs, 6 = vertex alphas

        if buffer_type == 1 or (buffer_type == 0 and buffer_num == 1):
            _flag_c = r.read_u8()
            for _ in range(buffer_count):
                vx = r.read_f32()
                vy = r.read_f32()
                vz = r.read_f32()
                vert_array.append((vx, vy, vz))

        elif buffer_type == 2 or (buffer_type == 0 and buffer_num in (2, 9)):
            _flag_c = r.read_u8()
            if buffer_type == 0 or buffer_type == 2:
                if buffer_type == 2:
                    # Compressed normals -- just skip
                    for _ in range(buffer_count):
                        r.read_u16()
                else:
                    for _ in range(buffer_count):
                        nx = r.read_f32()
                        ny = r.read_f32()
                        nz = r.read_f32()
                        normal_array.append((nx, ny, nz))
            normal_layer += 1

        elif buffer_type == 3 or (buffer_type == 0 and 4 < buffer_num < 9):
            _flag_c = r.read_u8()
            for _ in range(buffer_count):
                tu = r.read_f32()
                tv = (-r.read_f32()) + 1.0
                if uv_layer == 1:
                    uv_array.append((tu, tv))
                elif uv_layer == 2:
                    uv2_array.append((tu, tv))
            uv_layer += 1

        elif buffer_type == 4 or (buffer_type == 0 and buffer_num == 3):
            _flag_c = r.read_u8()
            for _ in range(buffer_count):
                w1 = r.read_f32()
                w2 = r.read_f32()
                w3 = r.read_f32()
                w4 = 0.0
                weight_array.append((w1, w2, w3, w4))

        elif buffer_type == 5 or (buffer_type == 0 and buffer_num == 4):
            _flag_c = r.read_u8()
            for _ in range(buffer_count):
                b1 = r.read_u8() // 4
                b2 = r.read_u8() // 4
                b3 = r.read_u8() // 4
                b4 = r.read_u8() // 4
                bone_array.append((b1, b2, b3, b4))

        elif buffer_type == 6 or (buffer_type == 0 and buffer_num == 10):
            _flag_c = r.read_u8()
            for _ in range(buffer_count):
                alpha = r.read_f32()
                color_array.append((255.0, 255.0, 255.0, alpha))

        else:
            log.warning("Unknown buffer type %d at offset %#x, stopping buffer parse",
                        buffer_type, r.tell())
            break

    # -- Fill defaults if missing -----------------------------------------
    if not bone_array:
        bone_array = [(0, 0, 0, 0)] * len(vert_array)
    if not weight_array:
        weight_array = [(1.0, 0.0, 0.0, 0.0)] * len(vert_array)
    if not uv_array:
        uv_array = [(0.0, 0.0)] * len(vert_array)

    # -- Build per-submesh output -----------------------------------------
    result = D3DMeshData(
        name='',  # filled by caller
        version=0,
        bounding_box=(bb_min, bb_max),
        bone_names=bone_id_sets,
    )

    for i, info in enumerate(submesh_infos):
        v_min = info['vertex_min']  # 1-based
        v_max = info['vertex_max']  # 1-based inclusive
        poly_start = info['polygon_start']  # 1-based
        poly_count = info['polygon_count']

        sm = D3DMeshSubmesh(
            name=info.get('material_name') or f"submesh_{i}",
            material_name=info.get('material_name'),
            bone_set_index=info['bone_set_num'] - 1,
        )

        # Gather per-submesh vertices (1-based -> 0-based)
        face_plus = len(result.all_vertices)
        for vi in range(v_min - 1, v_max):
            pos = vert_array[vi] if vi < len(vert_array) else (0, 0, 0)
            nrm = normal_array[vi] if vi < len(normal_array) else None
            uv = uv_array[vi] if vi < len(uv_array) else None
            uv2 = uv2_array[vi] if vi < len(uv2_array) else None
            bi = bone_array[vi] if vi < len(bone_array) else None
            bw = weight_array[vi] if vi < len(weight_array) else None
            col = color_array[vi] if vi < len(color_array) else None

            vtx = D3DMeshVertex(
                position=pos, normal=nrm, uv=uv, uv2=uv2,
                bone_indices=bi, bone_weights=bw, color=col,
            )
            sm.vertices.append(vtx)
            result.all_vertices.append(vtx)

        # Gather per-submesh faces
        for fi in range(poly_count):
            face_idx = poly_start - 1 + fi
            if face_idx < len(raw_faces):
                fa, fb, fc = raw_faces[face_idx]
                # Adjust to local submesh vertex indices
                adj = (fa - v_min + face_plus,
                       fb - v_min + face_plus,
                       fc - v_min + face_plus)
                sm.faces.append(adj)
                result.all_faces.append(adj)

        result.submeshes.append(sm)

    return result


# ---------------------------------------------------------------------------
# Version 0.5 (ERTM) parser
# ---------------------------------------------------------------------------

def _parse_v05(r: BinaryReader, early_game_fix: int) -> D3DMeshData:
    """Parse a Version 0.5 (ERTM/MTRE) D3DMESH.

    EarlyGameFix mapping:
      4  = Strong Bad Ep. 1
      5  = Strong Bad Ep. 2 (adds compression)
      6  = Strong Bad Ep. 3 (extra material slot)
      7  = Strong Bad Ep. 4 (another material slot)
      8  = Strong Bad Ep. 5 (changed material headers)
      9  = Wallace & Gromit Ep. 1-3 (hashed material headers)
    """
    log.info("Parsing Version 0.5 (ERTM) mesh, EarlyGameFix=%d", early_game_fix)

    # -- Bounding box -----------------------------------------------------
    bb_min = r.read_vec3()
    bb_max = r.read_vec3()
    log.debug("Bounding box: min=%s max=%s", bb_min, bb_max)

    # -- Submesh count ----------------------------------------------------
    head3a_sub_size = r.read_u32()
    poly_total = r.read_u32()

    if poly_total > 1000:
        log.warning("PolyTotal=%d looks wrong, seeking back 0x21 to retry", poly_total)
        r.seek(r.tell() - 0x21)
        bb_min = r.read_vec3()
        bb_max = r.read_vec3()
        head3a_sub_size = r.read_u32()
        poly_total = r.read_u32()

    if poly_total > 1000:
        raise ValueError(f"Submesh count {poly_total} is unreasonably large")
    log.info("Submesh count = %d", poly_total)

    # -- Per-submesh info -------------------------------------------------
    submesh_infos = []

    class TriStripInfo:
        def __init__(self, start=0, end=0):
            self.start = start
            self.end = end

    tristrip_infos = []

    for idx in range(poly_total):
        log.debug("Submesh %d info start = %#x", idx, r.tell())
        info: dict = {}

        # Name blocks
        if early_game_fix < 9:
            name_hdr_len = r.read_u32() - 8
            if name_hdr_len > 1000:
                raise ValueError(f"Name header too large: {name_hdr_len + 8}")
            _name_len = r.read_u32() - 4
            r.skip(name_hdr_len)

            name_hdr_len2 = r.read_u32() - 8
            if name_hdr_len2 > 1000:
                raise ValueError(f"Name header2 too large: {name_hdr_len2 + 8}")
            _name_len2 = r.read_u32() - 4
            r.skip(name_hdr_len2)
        else:
            # Wallace & Gromit -- hashed material type
            r.skip(0x0C)
            _mat_type_hash2 = r.read_u32()
            _mat_type_hash1 = r.read_u32()
            r.skip(4)

        info['bone_set_num'] = r.read_u32() + 1
        info['single_bind_node'] = r.read_u32()
        info['vertex_min'] = r.read_u32() + 1
        info['vertex_max'] = r.read_u32() + 1
        facepoint_start = r.read_u32() + 1
        info['facepoint_start'] = facepoint_start
        polygon_count = r.read_u32()
        info['polygon_count'] = polygon_count
        info['facepoint_count'] = polygon_count * 3

        name_hdr3_len = r.read_u32()
        name3_len = r.read_u32()
        r.skip(name3_len)

        _sub_bb_min = r.read_vec3()
        _sub_bb_max = r.read_vec3()

        # Wallace & Gromit extra floats before materials
        if early_game_fix == 9:
            _mat_ext_header = r.read_u32()
            for _ in range(4):
                r.read_f32()

        # Material slots (same structure as V0)
        mat_name = _read_material_slot(r)
        info['material_name'] = mat_name
        if mat_name:
            log.debug("  Diffuse: %s", mat_name)

        _spec = _read_material_slot(r)
        _tex3 = _read_material_slot(r)
        _bake = _read_material_slot(r)

        tex5_name = _read_material_slot(r)
        if tex5_name:
            if early_game_fix < 9:
                log.debug("  Gradient: %s", tex5_name)
            else:
                log.debug("  Bump: %s", tex5_name)

        if early_game_fix > 5:
            _tex5b = _read_material_slot(r)

        if early_game_fix > 6:
            _tex5c = _read_material_slot(r)

        r.skip(1)

        # Triangle strip info
        tri_strip_header = r.read_u32()
        tri_strip_groups = r.read_u32()
        tsi = TriStripInfo()
        if tri_strip_groups == 2:
            tsi.start = r.read_u16() + 1
            tsi.end = r.read_u16() + 1
        elif tri_strip_groups > 2:
            raise ValueError(f"TriStrip groups = {tri_strip_groups} > 2")
        tristrip_infos.append(tsi)

        _facepoint_end = r.read_u32()
        r.skip(2)
        _float2 = r.read_f32()

        if early_game_fix > 5:
            r.skip(1)

        env_name = _read_material_slot(r)
        if env_name:
            log.debug("  Environment: %s", env_name)

        # Post-material floats
        for _ in range(9):
            r.read_f32()
        r.skip(1)
        for _ in range(9):
            r.read_f32()
        r.read_f32()
        r.read_f32()
        r.skip(5)
        for _ in range(4):
            r.read_f32()
        r.read_u32()

        if early_game_fix > 7:
            r.read_f32()

        r.skip(1)
        name_len_f = r.read_u32()
        if name_len_f > 1000:
            raise ValueError(f"Footer name length {name_len_f} too large")
        r.skip(name_len_f)

        name_len_f2 = r.read_u32()
        if name_len_f2 > 1000:
            raise ValueError(f"Footer name length2 {name_len_f2} too large")
        r.skip(name_len_f2)

        submesh_infos.append(info)
        log.debug("  VertexRange=[%d,%d] FPStart=%d PolyCount=%d BoneSet=%d",
                  info['vertex_min'], info['vertex_max'],
                  info['facepoint_start'], info['polygon_count'],
                  info['bone_set_num'])

    # -- Bone ID sets -----------------------------------------------------
    id_header_length = r.read_u32() - 4
    bone_id_sets_count = r.read_u32()
    bone_id_sets = []
    bone_id_offsets = []

    for _ in range(bone_id_sets_count):
        bone_id_offsets.append(r.tell())
        bone_id_total = r.read_u32()
        names = []
        for _ in range(bone_id_total):
            _hdr = r.read_u32()
            name_len = r.read_u32()
            bname = r.read_string(name_len)
            names.append(bname)
            _terminator = r.read_u32()
        bone_id_sets.append(names)

    # -- Face data --------------------------------------------------------
    while not r.at_end():
        b = r.read_u8()
        if b == 0x65:
            break
    r.skip(3)

    face_count = r.read_u32()
    face_length = r.read_u32()
    realignment = (face_count * face_length) + r.tell()
    log.debug("Face count=%d, length=%d, data at %#x", face_count, face_length, r.tell())

    facepoint_array = []
    for _ in range(face_count):
        fp = r.read_u16() + 1
        facepoint_array.append(fp)

    r.seek(realignment)

    # -- Vertex buffers ---------------------------------------------------
    vert_array = []
    normal_array = []
    uv_array = []
    uv2_array = []
    weight_array = []
    bone_array = []
    color_array = []

    buffer_num = 0
    normal_layer = 1
    uv_layer = 1

    while not r.at_end():
        buffer_flag = 0x30
        failsafe = 0
        while buffer_flag == 0x30 and not r.at_end():
            buffer_flag = r.read_u8()
            buffer_num += 1
            failsafe += 1
            if failsafe > 5:
                buffer_flag = None
                break

        if buffer_flag is None or r.at_end():
            break
        if r.remaining() < 10:
            break

        _flag_b = r.read_u8()
        buffer_count = r.read_u32()
        buffer_length = r.read_u32()
        buffer_type = r.read_u32()

        log.debug("Buffer: num=%d type=%d count=%d at %#x",
                  buffer_num, buffer_type, buffer_count, r.tell())

        if buffer_type == 1 or (buffer_type == 0 and buffer_num == 1):
            compression_check = r.read_u16()
            if compression_check != 12337 or (compression_check == 12337 and buffer_count <= 768):
                # Uncompressed positions
                for _ in range(buffer_count):
                    vert_array.append(r.read_vec3())
            else:
                # Compressed positions (256-entry clamp table)
                log.debug("Compressed vertex buffer detected")
                clamp_min = []
                clamp_mult = []
                for _ in range(256):
                    vmin = r.read_vec3()
                    vmax = r.read_vec3()
                    mult = (vmax[0] - vmin[0], vmax[1] - vmin[1], vmax[2] - vmin[2])
                    clamp_min.append(vmin)
                    clamp_mult.append(mult)
                for _ in range(buffer_count):
                    vx_val = r.read_u8()
                    vy_val = r.read_u8()
                    vz_val = r.read_u8()
                    clamp_idx = r.read_u8() + 1
                    if clamp_idx > 256:
                        clamp_idx = 256
                    ci = clamp_idx - 1
                    vx = ((vx_val / 255.0) * clamp_mult[ci][0]) + clamp_min[ci][0]
                    vy = ((vy_val / 255.0) * clamp_mult[ci][1]) + clamp_min[ci][1]
                    vz = ((vz_val / 255.0) * clamp_mult[ci][2]) + clamp_min[ci][2]
                    vert_array.append((vx, vy, vz))

        elif buffer_type == 2 or (buffer_type == 0 and buffer_num in (2, 9, 11)):
            compression_check = r.read_u16()
            if buffer_type == 2:
                if compression_check != 12337:
                    for _ in range(buffer_count):
                        normal_array.append(r.read_vec3())
                else:
                    log.debug("Compressed normals, skipping")
                    for _ in range(buffer_count):
                        r.read_u16()
            else:
                for _ in range(buffer_count):
                    normal_array.append(r.read_vec3())
            normal_layer += 1

        elif buffer_type == 3 or (buffer_type == 0 and 4 < buffer_num < 9):
            _comp = r.read_u16()
            for _ in range(buffer_count):
                tu = r.read_f32()
                tv = (-r.read_f32()) + 1.0
                if uv_layer == 1:
                    uv_array.append((tu, tv))
                else:
                    uv2_array.append((tu, tv))
            uv_layer += 1

        elif buffer_type == 4 or (buffer_type == 0 and buffer_num == 3):
            _comp = r.read_u16()
            for _ in range(buffer_count):
                w1 = r.read_f32()
                w2 = r.read_f32()
                w3 = r.read_f32()
                weight_array.append((w1, w2, w3, 0.0))

        elif buffer_type == 5 or (buffer_type == 0 and buffer_num == 4):
            _comp = r.read_u16()
            for _ in range(buffer_count):
                b1 = r.read_u8() // 4
                b2 = r.read_u8() // 4
                b3 = r.read_u8() // 4
                b4 = r.read_u8() // 4
                bone_array.append((b1, b2, b3, b4))

        elif buffer_type == 6 or (buffer_type == 0 and buffer_num == 10):
            _comp = r.read_u16()
            for _ in range(buffer_count):
                alpha = r.read_f32()
                color_array.append((255.0, 255.0, 255.0, alpha))

        else:
            log.warning("Unknown buffer type %d, stopping", buffer_type)
            break

    # -- Defaults ---------------------------------------------------------
    if not bone_array:
        bone_array = [(0, 0, 0, 0)] * len(vert_array)
    if not weight_array:
        weight_array = [(1.0, 0.0, 0.0, 0.0)] * len(vert_array)
    if not uv_array:
        uv_array = [(0.0, 0.0)] * len(vert_array)

    # -- Build output (with triangle strip handling) ----------------------
    result = D3DMeshData(
        name='',
        version=0,
        bounding_box=(bb_min, bb_max),
        bone_names=bone_id_sets,
    )

    for i, info in enumerate(submesh_infos):
        v_min = info['vertex_min']
        v_max = info['vertex_max']
        fp_start = info['facepoint_start']
        fp_count = info['facepoint_count']
        poly_count = info['polygon_count']

        sm = D3DMeshSubmesh(
            name=info.get('material_name') or f"submesh_{i}",
            material_name=info.get('material_name'),
            bone_set_index=info['bone_set_num'] - 1,
        )

        # Build triangle list faces from facepoints
        local_faces = []
        face_num = 1
        fa = fb = fc = 0
        for y_idx in range(fp_start - 1, fp_start - 1 + fp_count):
            if y_idx >= len(facepoint_array):
                break
            if face_num == 1:
                fa = facepoint_array[y_idx]
            elif face_num == 2:
                fb = facepoint_array[y_idx]
            elif face_num == 3:
                fc = facepoint_array[y_idx]
                local_faces.append((fa, fb, fc))
                face_num = 0
            face_num += 1

        # Handle triangle strip portion
        tsi = tristrip_infos[i]
        if tsi.start != 0 and tsi.end != 0:
            start_direction = 1
            face_direction = start_direction
            strip_idx = tsi.start + 2  # 1-based
            if strip_idx - 2 >= 1 and strip_idx - 1 >= 1:
                f1 = facepoint_array[strip_idx - 3]  # Convert to 0-based
                f2 = facepoint_array[strip_idx - 2]
                while strip_idx <= tsi.end and strip_idx - 1 < len(facepoint_array):
                    f3 = facepoint_array[strip_idx - 1]
                    face_direction *= -1
                    if f1 != f2 and f2 != f3 and f3 != f1:
                        if face_direction > 0:
                            local_faces.append((f3, f2, f1))
                        else:
                            local_faces.append((f2, f3, f1))
                        poly_count += 1
                    f1 = f2
                    f2 = f3
                    strip_idx += 1

        # Build submesh vertices and faces
        face_plus = len(result.all_vertices)
        for vi in range(v_min - 1, v_max):
            pos = vert_array[vi] if vi < len(vert_array) else (0, 0, 0)
            nrm = normal_array[vi] if vi < len(normal_array) else None
            uv = uv_array[vi] if vi < len(uv_array) else None
            uv2 = uv2_array[vi] if vi < len(uv2_array) else None
            bi = bone_array[vi] if vi < len(bone_array) else None
            bw = weight_array[vi] if vi < len(weight_array) else None
            col = color_array[vi] if vi < len(color_array) else None

            vtx = D3DMeshVertex(
                position=pos, normal=nrm, uv=uv, uv2=uv2,
                bone_indices=bi, bone_weights=bw, color=col,
            )
            sm.vertices.append(vtx)
            result.all_vertices.append(vtx)

        for face in local_faces:
            adj = (face[0] - v_min + face_plus,
                   face[1] - v_min + face_plus,
                   face[2] - v_min + face_plus)
            sm.faces.append(adj)
            result.all_faces.append(adj)

        result.submeshes.append(sm)

    return result


# ---------------------------------------------------------------------------
# Version 1 (MTRE) parser -- EXPERIMENTAL / UNDOCUMENTED
# ---------------------------------------------------------------------------

def _parse_v1(r: BinaryReader, early_game_fix: int) -> D3DMeshData:
    """Parse a Version 1 (MTRE) D3DMESH.

    This version is used by Tales of Monkey Island, Back to the Future [PC],
    CSI: Deadly Intent / Fatal Conspiracy, Poker Night at the Inventory,
    Sam & Max Season 3, and Wallace & Gromit Ep. 4.

    **This format is not fully documented.**  The original MaxScript importer
    by Random Talking Bush does not support it either.  This parser implements
    a best-guess approach: it attempts to locate recognisable structures
    (bounding box, submesh headers, face data, vertex buffers) by scanning
    for known byte patterns and applying heuristics from the V0.5 parser.

    When parsing fails or encounters unknown data, detailed hex dumps and
    offset information are logged at DEBUG level to aid reverse engineering.
    """
    log.warning("Version 1 (MTRE) parser is EXPERIMENTAL -- data may be incomplete or incorrect")

    data_start = r.tell()
    log.info("V1 data starts at offset %#x, %d bytes remaining", data_start, r.remaining())

    # Log a hex dump of the first 256 bytes for reverse engineering
    dump_len = min(256, r.remaining())
    log.debug("First %d bytes of V1 payload:\n%s", dump_len,
              _hex_dump(r.data, data_start, dump_len))

    # -- Try to find bounding box -----------------------------------------
    # V1 likely starts similarly to V0.5: bounding box followed by submesh
    # header.  We try the V0.5 layout first.

    bb_min = r.read_vec3()
    bb_max = r.read_vec3()

    # Sanity check: bounding box floats should be reasonable
    def _bb_sane(v):
        return all(abs(c) < 100000 for c in v)

    if not (_bb_sane(bb_min) and _bb_sane(bb_max)):
        log.warning("Bounding box values look unreasonable: min=%s max=%s", bb_min, bb_max)
        log.debug("Hex at data_start:\n%s", _hex_dump(r.data, data_start, 64))

    log.debug("V1 bounding box: min=%s max=%s", bb_min, bb_max)

    # -- Try to read submesh header (like V0.5) ---------------------------
    head3a = r.read_u32()
    poly_total = r.read_u32()

    if poly_total > 1000:
        log.warning("poly_total=%d too large, trying -0x21 rewind", poly_total)
        r.seek(r.tell() - 0x21)
        bb_min = r.read_vec3()
        bb_max = r.read_vec3()
        head3a = r.read_u32()
        poly_total = r.read_u32()

    if poly_total > 1000 or poly_total == 0:
        log.error("Cannot determine submesh count (got %d). "
                  "Returning empty mesh for V1.", poly_total)
        return D3DMeshData(
            name='', version=1,
            bounding_box=(bb_min, bb_max),
        )

    log.info("V1 submesh count = %d", poly_total)

    # -- Attempt to parse per-submesh info (V0.5 layout) ------------------
    submesh_infos = []
    parse_ok = True

    for idx in range(poly_total):
        log.debug("V1 submesh %d starts at %#x", idx, r.tell())
        info: dict = {}

        try:
            # Try reading name blocks like V0.5 / V0
            name_hdr_len = r.read_u32() - 8
            if name_hdr_len < 0 or name_hdr_len > 1000:
                raise ValueError(f"bad name_hdr_len {name_hdr_len + 8}")
            _name_len = r.read_u32() - 4
            r.skip(name_hdr_len)

            name_hdr_len2 = r.read_u32() - 8
            if name_hdr_len2 < 0 or name_hdr_len2 > 1000:
                raise ValueError(f"bad name_hdr_len2 {name_hdr_len2 + 8}")
            _name_len2 = r.read_u32() - 4
            r.skip(name_hdr_len2)

            info['bone_set_num'] = r.read_u32() + 1
            info['single_bind_node'] = r.read_u32()
            info['vertex_min'] = r.read_u32() + 1
            info['vertex_max'] = r.read_u32() + 1
            facepoint_start = r.read_u32()
            info['polygon_start'] = (facepoint_start // 3) + 1
            info['polygon_count'] = r.read_u32()
            info['facepoint_count'] = info['polygon_count'] * 3

            name_hdr3_len = r.read_u32()
            name3_len = r.read_u32()
            r.skip(name3_len)

            _sub_bb_min = r.read_vec3()
            _sub_bb_max = r.read_vec3()

            # Try reading material slots
            try:
                mat_name = _read_material_slot(r)
                info['material_name'] = mat_name
            except (ValueError, struct.error):
                info['material_name'] = None
                log.debug("Could not read material slot at %#x", r.tell())

            submesh_infos.append(info)
            log.debug("  V1 submesh %d: verts=[%d,%d] polys=%d",
                      idx, info['vertex_min'], info['vertex_max'],
                      info['polygon_count'])

        except (ValueError, struct.error, EOFError) as e:
            log.warning("V1 submesh %d parse failed at %#x: %s", idx, r.tell(), e)
            parse_ok = False
            break

    if not parse_ok or not submesh_infos:
        log.error("V1 submesh parsing failed. Attempting face/vertex scan...")
        # Try to scan for face data (0x65 marker) and vertex buffers
        r.seek(data_start)

    # -- Scan for face data (0x30 0x65 marker) ----------------------------
    # The marker is: 0x30 (MetaStream bool false) + 0x65 (T3IndexBuffer
    # format code for uint16) + 3 padding bytes, followed by:
    #   u32 FC  -- total byte count of the face data block
    #   u32 FL  -- always 1 (byte multiplier)
    # Inside the FC-byte block:
    #   u16 first_index  -- first triangle index (delta accumulator seed)
    #   u32 body_size    -- byte count of the compressed bitstream
    #   body_size bytes  -- delta-compressed index bitstream
    #
    # Bitstream format (groups):
    #   [4 bits: delta_width] [7 bits: group_count]
    #   Per index: [1 bit: sign] [delta_width bits: value]
    #   Decoded: accumulator += (sign ? -value : +value)
    #
    # Reverse-engineered from iOS ARM binary T3IndexBuffer::Decompress.
    face_marker_pos = None
    scan_pos = r.tell()
    scan_data = r.data[scan_pos:]
    for offset in range(len(scan_data) - 13):
        if scan_data[offset] == 0x30 and scan_data[offset + 1] == 0x65:
            test_fc = struct.unpack_from('<I', scan_data, offset + 5)[0]
            test_fl = struct.unpack_from('<I', scan_data, offset + 9)[0]
            if 0 < test_fc < 1000000 and test_fl == 1:
                face_marker_pos = scan_pos + offset
                break

    raw_faces = []
    if face_marker_pos is not None:
        r.seek(face_marker_pos + 5)  # skip 0x30 0x65 + 3 padding bytes
        face_block_size = r.read_u32()
        _face_length = r.read_u32()  # always 1
        face_block_start = r.tell()

        first_index = r.read_u16()
        body_size = r.read_u32()
        body = r.read(body_size)

        log.debug("V1 face marker at %#x: FC=%d, first_index=%d, body=%dB",
                  face_marker_pos, face_block_size, first_index, body_size)

        # Decode delta-compressed face indices
        indices = _decode_face_indices(first_index, body)
        log.debug("V1 decoded %d face indices", len(indices))

        # Convert flat index list to triangle list (1-based for V1 pipeline)
        for i in range(0, len(indices) - 2, 3):
            raw_faces.append((indices[i] + 1, indices[i + 1] + 1, indices[i + 2] + 1))

        # Position reader at the end of the face block for vertex buffers
        r.seek(face_block_start + face_block_size)
    else:
        log.warning("Could not locate face data marker in V1 mesh")

    # -- Scan for vertex buffers ------------------------------------------
    # V1 vertex buffer format (different from V0/V0.5):
    #   The first VB header is embedded inside the face block, immediately
    #   after the compressed index data.  Each VB header is 16 bytes:
    #     u32 count   -- number of elements
    #     u32 stride  -- bytes per element (12 for vec3, 8 for vec2)
    #     u32 type    -- 1=positions, 2=normals, 3=UVs, 4=weights, 5=bones
    #     u32 flags   -- typically 0
    #   Vertex DATA for the first buffer starts at face_block_start +
    #   face_block_size (i.e. right after the face block boundary).
    #   Subsequent VB headers follow immediately after each VB data block,
    #   with no padding or 0x30 marker bytes between them.
    vert_array = []
    normal_array = []
    uv_array = []
    weight_array = []
    bone_array = []

    buffer_num = 0
    uv_layer = 1

    if face_marker_pos is not None:
        # Locate the first VB header: it sits inside the face block,
        # right after the compressed body data.
        face_data_consumed = 2 + 4 + body_size  # first_index(u16) + body_size(u32) + body
        vb_hdr_pos = face_block_start + face_data_consumed

        # Vertex DATA starts after the full 16-byte VB header.
        # The VB header is 16 bytes (count + stride + type + flags),
        # but the face_block_size only covers up to 15 of those bytes
        # (the 16th byte is just past the face block boundary).
        # So the actual data starts at vb_hdr_pos + 16.
        vb_data_pos = vb_hdr_pos + 16

        # Try the new V1 VB format first.  If the header at vb_hdr_pos
        # gives sane values, use the new format; otherwise fall back to
        # the legacy V0/V0.5 scan.
        use_v1_vb_format = False
        if vb_hdr_pos + 16 <= len(r.data):
            peek_count = struct.unpack_from('<I', r.data, vb_hdr_pos)[0]
            peek_stride = struct.unpack_from('<I', r.data, vb_hdr_pos + 4)[0]
            peek_type = struct.unpack_from('<I', r.data, vb_hdr_pos + 8)[0]
            if (0 < peek_count <= 100000
                    and peek_stride in (4, 8, 12, 16, 24, 32)
                    and 1 <= peek_type <= 10):
                use_v1_vb_format = True
                log.debug("V1 VB format detected: first header at %#x "
                          "(count=%d stride=%d type=%d)",
                          vb_hdr_pos, peek_count, peek_stride, peek_type)

        if use_v1_vb_format:
            # --- New V1 vertex buffer parsing ---
            # Read the first VB header (embedded in face block).
            r.seek(vb_hdr_pos)
            # Data for the first buffer starts at vb_data_pos.
            first_vb = True

            while r.remaining() >= 16:
                vb_count = r.read_u32()
                vb_stride = r.read_u32()
                vb_type = r.read_u32()
                vb_flags = r.read_u32()

                # Sanity: stop if values look unreasonable
                if vb_count == 0 or vb_count > 100000:
                    break
                if vb_stride == 0 or vb_stride > 128:
                    break
                if vb_type > 20:
                    break

                buffer_num += 1

                if first_vb:
                    # The first buffer's DATA starts at vb_data_pos,
                    # not immediately after the header (header is in
                    # the face block; data is after the face block).
                    r.seek(vb_data_pos)
                    first_vb = False

                data_bytes = vb_count * vb_stride
                log.debug("V1 VB #%d: type=%d count=%d stride=%d at %#x",
                          buffer_num, vb_type, vb_count, vb_stride, r.tell())

                try:
                    if vb_type == 1:  # positions (vec3 float32)
                        for _ in range(vb_count):
                            vert_array.append(r.read_vec3())

                    elif vb_type == 2:  # normals / tangents (vec3 float32)
                        if not normal_array:
                            for _ in range(vb_count):
                                normal_array.append(r.read_vec3())
                        else:
                            # Second type-2 buffer = tangents; skip
                            r.skip(data_bytes)

                    elif vb_type == 3:  # UVs (vec2 float32)
                        if uv_layer == 1:
                            for _ in range(vb_count):
                                tu = r.read_f32()
                                tv = (-r.read_f32()) + 1.0
                                uv_array.append((tu, tv))
                        else:
                            # Second UV set; skip for now
                            r.skip(data_bytes)
                        uv_layer += 1

                    elif vb_type == 4:  # bone weights
                        for _ in range(vb_count):
                            w1 = r.read_f32()
                            w2 = r.read_f32()
                            w3 = r.read_f32()
                            weight_array.append((w1, w2, w3, 0.0))

                    elif vb_type == 5:  # bone indices
                        for _ in range(vb_count):
                            b1 = r.read_u8() // 4
                            b2 = r.read_u8() // 4
                            b3 = r.read_u8() // 4
                            b4 = r.read_u8() // 4
                            bone_array.append((b1, b2, b3, b4))

                    else:
                        log.debug("V1: skipping unknown VB type %d (%d bytes)",
                                  vb_type, data_bytes)
                        r.skip(data_bytes)

                except (struct.error, EOFError) as e:
                    log.warning("V1 VB read error at buffer %d: %s",
                                buffer_num, e)
                    break
        else:
            # --- Legacy V0/V0.5-style vertex buffer scan (fallback) ---
            r.seek(vb_data_pos)
            while not r.at_end():
                buffer_flag = 0x30
                failsafe = 0
                while buffer_flag == 0x30 and not r.at_end():
                    buffer_flag = r.read_u8()
                    buffer_num += 1
                    failsafe += 1
                    if failsafe > 5:
                        buffer_flag = None
                        break

                if buffer_flag is None or r.at_end():
                    break
                if r.remaining() < 10:
                    break

                try:
                    _flag_b = r.read_u8()
                    buffer_count = r.read_u32()
                    buffer_length = r.read_u32()
                    buffer_type = r.read_u32()
                except (struct.error, EOFError):
                    break

                log.debug("V1 buffer (legacy): num=%d type=%d count=%d "
                          "len=%d at %#x",
                          buffer_num, buffer_type, buffer_count,
                          buffer_length, r.tell())

                try:
                    if buffer_type == 1 or (buffer_type == 0 and buffer_num == 1):
                        comp_check = r.read_u16()
                        if comp_check != 12337 or buffer_count <= 768:
                            for _ in range(buffer_count):
                                vert_array.append(r.read_vec3())
                        else:
                            clamp_min = []
                            clamp_mult = []
                            for _ in range(256):
                                vmin = r.read_vec3()
                                vmax = r.read_vec3()
                                mult = (vmax[0] - vmin[0],
                                        vmax[1] - vmin[1],
                                        vmax[2] - vmin[2])
                                clamp_min.append(vmin)
                                clamp_mult.append(mult)
                            for _ in range(buffer_count):
                                vx_val = r.read_u8()
                                vy_val = r.read_u8()
                                vz_val = r.read_u8()
                                ci = r.read_u8()
                                vx = ((vx_val / 255.0) * clamp_mult[ci][0]) + clamp_min[ci][0]
                                vy = ((vy_val / 255.0) * clamp_mult[ci][1]) + clamp_min[ci][1]
                                vz = ((vz_val / 255.0) * clamp_mult[ci][2]) + clamp_min[ci][2]
                                vert_array.append((vx, vy, vz))

                    elif buffer_type == 2 or (buffer_type == 0 and buffer_num in (2, 9, 11)):
                        comp_check = r.read_u16()
                        if buffer_type == 2 and comp_check == 12337:
                            for _ in range(buffer_count):
                                r.read_u16()
                        else:
                            for _ in range(buffer_count):
                                normal_array.append(r.read_vec3())

                    elif buffer_type == 3 or (buffer_type == 0 and 4 < buffer_num < 9):
                        r.read_u16()
                        for _ in range(buffer_count):
                            tu = r.read_f32()
                            tv = (-r.read_f32()) + 1.0
                            uv_array.append((tu, tv))
                        uv_layer += 1

                    elif buffer_type == 4 or (buffer_type == 0 and buffer_num == 3):
                        r.read_u16()
                        for _ in range(buffer_count):
                            w1 = r.read_f32()
                            w2 = r.read_f32()
                            w3 = r.read_f32()
                            weight_array.append((w1, w2, w3, 0.0))

                    elif buffer_type == 5 or (buffer_type == 0 and buffer_num == 4):
                        r.read_u16()
                        for _ in range(buffer_count):
                            b1 = r.read_u8() // 4
                            b2 = r.read_u8() // 4
                            b3 = r.read_u8() // 4
                            b4 = r.read_u8() // 4
                            bone_array.append((b1, b2, b3, b4))

                    elif buffer_type == 6 or (buffer_type == 0 and buffer_num == 10):
                        r.read_u16()
                        for _ in range(buffer_count):
                            r.read_f32()

                    else:
                        log.debug("Unknown V1 buffer type %d, stopping",
                                  buffer_type)
                        break

                except (struct.error, EOFError) as e:
                    log.warning("V1 buffer read error: %s", e)
                    break

    # -- Defaults ---------------------------------------------------------
    if not bone_array:
        bone_array = [(0, 0, 0, 0)] * len(vert_array)
    if not weight_array:
        weight_array = [(1.0, 0.0, 0.0, 0.0)] * len(vert_array)
    if not uv_array:
        uv_array = [(0.0, 0.0)] * len(vert_array)

    # -- Build output -----------------------------------------------------
    result = D3DMeshData(
        name='', version=1,
        bounding_box=(bb_min, bb_max),
    )

    if submesh_infos and raw_faces:
        # If we successfully parsed submesh info, use it
        for i, info in enumerate(submesh_infos):
            v_min = info['vertex_min']
            v_max = info['vertex_max']
            poly_start = info['polygon_start']
            poly_count = info['polygon_count']

            sm = D3DMeshSubmesh(
                name=info.get('material_name') or f"submesh_{i}",
                material_name=info.get('material_name'),
                bone_set_index=info['bone_set_num'] - 1,
            )

            face_plus = len(result.all_vertices)
            for vi in range(v_min - 1, min(v_max, len(vert_array))):
                pos = vert_array[vi] if vi < len(vert_array) else (0, 0, 0)
                nrm = normal_array[vi] if vi < len(normal_array) else None
                uv = uv_array[vi] if vi < len(uv_array) else None
                bi = bone_array[vi] if vi < len(bone_array) else None
                bw = weight_array[vi] if vi < len(weight_array) else None

                vtx = D3DMeshVertex(
                    position=pos, normal=nrm, uv=uv,
                    bone_indices=bi, bone_weights=bw,
                )
                sm.vertices.append(vtx)
                result.all_vertices.append(vtx)

            for fi in range(poly_count):
                fidx = poly_start - 1 + fi
                if fidx < len(raw_faces):
                    fa, fb, fc = raw_faces[fidx]
                    adj = (fa - v_min + face_plus,
                           fb - v_min + face_plus,
                           fc - v_min + face_plus)
                    sm.faces.append(adj)
                    result.all_faces.append(adj)

            result.submeshes.append(sm)
    else:
        # Fallback: single submesh with all data
        sm = D3DMeshSubmesh(name="mesh", material_name=None)

        for vi in range(len(vert_array)):
            vtx = D3DMeshVertex(
                position=vert_array[vi],
                normal=normal_array[vi] if vi < len(normal_array) else None,
                uv=uv_array[vi] if vi < len(uv_array) else None,
                bone_indices=bone_array[vi] if vi < len(bone_array) else None,
                bone_weights=weight_array[vi] if vi < len(weight_array) else None,
            )
            sm.vertices.append(vtx)
            result.all_vertices.append(vtx)

        for face in raw_faces:
            # Convert 1-based to 0-based
            adj = (face[0] - 1, face[1] - 1, face[2] - 1)
            sm.faces.append(adj)
            result.all_faces.append(adj)

        result.submeshes.append(sm)

    log.info("V1 parse complete: %d vertices, %d faces, %d submeshes",
             len(result.all_vertices), len(result.all_faces), len(result.submeshes))

    return result


# ---------------------------------------------------------------------------
# Version 2 (MSV5) parser
# ---------------------------------------------------------------------------

# Texture slot names for Version 2
_V2_TEX_SLOTS = (
    'diffuse', 'specular', 'detail_diffuse', 'detail_bump',
    'bake', 'bump', 'tex7', 'tex8', 'gradient', 'environment', 'sss',
)


def _parse_v2(r: BinaryReader) -> D3DMeshData:
    """Parse a Version 2 (MSV5) D3DMESH -- Jurassic Park / Law & Order."""
    log.info("Parsing Version 2 (MSV5) mesh")

    # -- Skip 5 bytes after version byte ----------------------------------
    r.skip(5)
    log.debug("Model start = %#x", r.tell())

    # -- Bounding box -----------------------------------------------------
    bb_min = r.read_vec3()
    bb_max = r.read_vec3()
    log.debug("Bounding box: min=%s max=%s", bb_min, bb_max)

    # -- Skip variable-length header A ------------------------------------
    header_a_length = r.read_u32() - 4
    r.skip(header_a_length)

    # -- Submesh count ----------------------------------------------------
    head3a_sub_size = r.read_u32()
    poly_total = r.read_u32()
    log.info("Submesh count = %d", poly_total)

    # -- Per-submesh info -------------------------------------------------
    submesh_infos = []
    mat_colors = []

    for idx in range(poly_total):
        log.debug("V2 submesh %d info start = %#x", idx, r.tell())
        info: dict = {}

        r.skip(0x18)  # 24 bytes unknown
        info['bone_set_num'] = r.read_u32() + 1
        r.skip(0x08)
        info['vertex_min'] = r.read_u32() + 1
        info['vertex_max'] = r.read_u32() + 1
        facepoint_start = r.read_u32()
        info['polygon_start'] = (facepoint_start // 3) + 1
        polygon_count = r.read_u32()
        info['polygon_count'] = polygon_count
        info['facepoint_count'] = polygon_count * 3

        # Per-submesh bounding box
        _sub_bb_min = r.read_vec3()
        _sub_bb_max = r.read_vec3()

        # Extra floats
        _extra = r.read_vec3()

        # Header + unknown floats
        _header_len = r.read_u32()
        _unk_f1 = r.read_f32()
        _unk_f2 = r.read_f32()
        _unk_f3 = r.read_f32()
        _unk_f4 = r.read_f32()

        info['mat_num'] = r.read_u32() + 1
        r.skip(0x1C)  # 28 bytes unknown

        # -- 11 material texture slots ------------------------------------
        tex_names = {}
        for slot_idx, slot_name in enumerate(_V2_TEX_SLOTS):
            if slot_idx == 9:
                # Environment slot has 0x19 bytes between gradient and itself
                r.skip(0x19)
            if slot_idx == 10:
                # SSS slot has 0xB8 bytes between environment and itself
                r.skip(0xB8)

            mat_hdr_len = r.read_u32()
            mat_name_len = r.read_u32() - 6
            if mat_hdr_len > 8 and mat_name_len > 0:
                mat_name = r.read_string(mat_name_len)
                tex_names[slot_name] = mat_name
                log.debug("  %s: %s", slot_name.title(), mat_name)
                r.skip(6)

        info['tex_names'] = tex_names
        info['material_name'] = tex_names.get('diffuse')

        # Material colour
        _byte_pad = r.read_u8()
        color_r = r.read_f32()
        color_g = r.read_f32()
        color_b = r.read_f32()
        color_a = r.read_f32()
        r.skip(0x08)
        mat_colors.append((color_r, color_g, color_b))

        submesh_infos.append(info)
        log.debug("  V2 submesh %d: verts=[%d,%d] polys=%d mat=%d",
                  idx, info['vertex_min'], info['vertex_max'],
                  info['polygon_count'], info['mat_num'])

    # -- Skip header B ----------------------------------------------------
    header_b_size = r.read_u32() - 4
    r.skip(header_b_size)

    # -- Bone ID sets (CRC64 hashes) --------------------------------------
    log.debug("Bone IDs (CRC64) start = %#x", r.tell())
    id_header_length = r.read_u32() - 4
    bone_id_sets_count = r.read_u32()
    log.debug("Bone ID sets count = %d", bone_id_sets_count)

    bone_id_sets = []
    bone_id_offsets = []

    for _ in range(bone_id_sets_count):
        bone_id_offsets.append(r.tell())
        bone_id_total = r.read_u32()
        hashes = []
        for _ in range(bone_id_total):
            hash_low = r.read_u32()
            hash_high = r.read_u32()
            _padding = r.read_u32()
            hash_val = (hash_high << 32) | hash_low
            hashes.append(f"0x{hash_val:016X}")
        bone_id_sets.append(hashes)

    # -- Skip headers D through N -----------------------------------------
    for hdr_name in ('D', 'E'):
        size = r.read_u32() - 4
        log.debug("Header %s: size=%d at %#x", hdr_name, size + 4, r.tell() - 4)
        r.skip(size)

    # Header F: skip 0x11 bytes
    log.debug("Header F at %#x", r.tell())
    r.skip(0x11)

    # Header G: material group (texture name list)
    log.debug("Header G (material groups) at %#x", r.tell())
    mat_group_end = r.tell() + r.read_u32()
    mat_group_count = r.read_u32()
    tex_name_array = []

    for _ in range(mat_group_count):
        mat_sec_len = r.read_u32()
        mat_name_len = r.read_u32() - 6
        if mat_name_len > 0:
            mat_name = r.read_string(mat_name_len)
            tex_name_array.append(mat_name)
        else:
            tex_name_array.append('')
        r.skip(6)
        for _ in range(6):  # 2x vec3
            r.read_f32()
        hdr_len = r.read_u32() - 4
        r.skip(hdr_len)
        r.skip(6)

    # Skip headers H through N
    for hdr_name in ('H', 'I', 'J', 'K', 'L', 'M', 'N'):
        size = r.read_u32() - 4
        log.debug("Header %s: size=%d", hdr_name, size + 4)
        r.skip(size)

    # UV multipliers
    _byte_pad = r.read_u8()
    _byte_pad2 = r.read_u8()
    r.skip(0x0C)

    uv1_x_mult = r.read_f32()
    uv1_y_mult = r.read_f32()
    uv3_x_mult = r.read_f32()
    uv3_y_mult = r.read_f32()
    uv2_x_mult = r.read_f32()
    uv2_y_mult = r.read_f32()
    log.debug("UV multipliers: UV1=(%f,%f) UV2=(%f,%f) UV3=(%f,%f)",
              uv1_x_mult, uv1_y_mult, uv2_x_mult, uv2_y_mult,
              uv3_x_mult, uv3_y_mult)

    # Skip headers O and P
    for hdr_name in ('O', 'P'):
        size = r.read_u32() - 4
        log.debug("Header %s: size=%d", hdr_name, size + 4)
        r.skip(size)

    _byte_pad = r.read_u8()
    _byte_pad2 = r.read_u8()
    _unknown = r.read_u32()

    # -- Face data --------------------------------------------------------
    log.debug("Face info start = %#x", r.tell())
    face_count = r.read_u32()
    r.skip(8)  # unknown

    raw_faces = []
    for _ in range(face_count // 3):
        fa = r.read_u16() + 1
        fb = r.read_u16() + 1
        fc = r.read_u16() + 1
        raw_faces.append((fa, fb, fc))
    log.debug("Read %d triangles", len(raw_faces))

    # -- Vertex buffer with attribute descriptors -------------------------
    log.debug("Vertex buffer start = %#x", r.tell())
    vert_count = r.read_u32()
    vert_length = r.read_u32()
    r.skip(0x0C)

    _vert_header_length = r.read_u32()

    # 13 attribute descriptors, each 3x uint32: (offset, count, format)
    attr_names = [
        'position', 'uv1', 'normals', 'weights', 'bones',
        'unknown1', 'colors', 'binormals', 'tangents',
        'uv2', 'uv3', 'uv4', 'unknown2',
    ]

    attrs = {}
    for name in attr_names:
        offset = r.read_u32()
        count = r.read_u32()
        fmt = r.read_u32()
        attrs[name] = {'offset': offset, 'count': count, 'format': fmt}
        if fmt > 0:
            log.debug("  Attr %-12s: offset=%d count=%d format=%d", name, offset, count, fmt)

    # Format codes:
    # 0 = absent, 1 = float32, 2 = signed byte, 3 = unsigned byte,
    # 4 = signed short, 5 = unsigned short, 8 = signed byte (alt),
    # 11 = half float

    # -- Read interleaved vertices ----------------------------------------
    log.debug("Vertex data start = %#x", r.tell())

    vert_array = []
    normal_array = []
    uv_array = []
    uv2_array = []
    uv3_array = []
    weight_array = []
    bone_array = []
    color_array = []

    pos_fmt = attrs['position']['format']
    uv_fmt = attrs['uv1']['format']
    norm_fmt = attrs['normals']['format']
    weight_fmt = attrs['weights']['format']
    bones_fmt = attrs['bones']['format']
    colors_fmt = attrs['colors']['format']
    unk1_fmt = attrs['unknown1']['format']
    binorm_fmt = attrs['binormals']['format']
    tang_fmt = attrs['tangents']['format']
    uv2_fmt = attrs['uv2']['format']
    uv3_fmt = attrs['uv3']['format']
    uv4_fmt = attrs['uv4']['format']
    unk2_fmt = attrs['unknown2']['format']

    for vi in range(vert_count):
        # Position (always format 1 = 3x float32)
        if pos_fmt == 1:
            vx = r.read_f32()
            vy = r.read_f32()
            vz = r.read_f32()
            vert_array.append((vx, vy, vz))
        else:
            raise ValueError(f"Unknown position format {pos_fmt}")

        # UV1
        if uv_fmt == 0:
            uv_array.append((0.0, 0.0))
        elif uv_fmt == 1:
            tu = r.read_f32()
            tv = (-r.read_f32()) + 1.0
            uv_array.append((tu, tv))
        elif uv_fmt == 4:
            tu = (r.read_i16() / 32767.0) * uv1_x_mult
            tv = (-(r.read_i16() / 32767.0) * uv1_y_mult) + 1.0
            uv_array.append((tu, tv))
        elif uv_fmt == 5:
            tu = (r.read_u16() / 65535.0) * uv1_x_mult
            tv = (-(r.read_u16() / 65535.0) * uv1_y_mult) + 1.0
            uv_array.append((tu, tv))
        elif uv_fmt == 11:
            tu = r.read_f16() * 2.0
            tv = (-(r.read_f16() * 2.0)) + 1.0
            uv_array.append((tu, tv))

        # UV2
        if uv2_fmt > 0:
            if uv2_fmt == 1:
                tu2 = r.read_f32()
                tv2 = (-r.read_f32()) + 1.0
                uv2_array.append((tu2, tv2))
            elif uv2_fmt == 4:
                tu2 = (r.read_i16() / 32767.0) * uv2_x_mult
                tv2 = (-(r.read_i16() / 32767.0) * uv2_y_mult) + 1.0
                uv2_array.append((tu2, tv2))
            elif uv2_fmt == 5:
                tu2 = (r.read_u16() / 65535.0) * uv2_x_mult
                tv2 = (-(r.read_u16() / 65535.0) * uv2_y_mult) + 1.0
                uv2_array.append((tu2, tv2))
            elif uv2_fmt == 11:
                tu2 = r.read_f16() * 2.0
                tv2 = (-(r.read_f16() * 2.0)) + 1.0
                uv2_array.append((tu2, tv2))

        # UV3
        if uv3_fmt > 0:
            if uv3_fmt == 1:
                tu3 = r.read_f32()
                tv3 = (-r.read_f32()) + 1.0
                uv3_array.append((tu3, tv3))
            elif uv3_fmt == 4:
                tu3 = (r.read_i16() / 32767.0) * uv3_x_mult
                tv3 = (-(r.read_i16() / 32767.0) * uv3_y_mult) + 1.0
                uv3_array.append((tu3, tv3))
            elif uv3_fmt == 5:
                tu3 = (r.read_u16() / 65535.0) * uv3_x_mult
                tv3 = (-(r.read_u16() / 65535.0) * uv3_y_mult) + 1.0
                uv3_array.append((tu3, tv3))
            elif uv3_fmt == 11:
                tu3 = r.read_f16() * 2.0
                tv3 = (-(r.read_f16() * 2.0)) + 1.0
                uv3_array.append((tu3, tv3))

        # UV4 (break on presence -- same as MaxScript)
        if uv4_fmt > 0:
            if uv4_fmt == 1:
                r.read_f32()
                r.read_f32()
            elif uv4_fmt in (4, 5):
                r.read_u16()
                r.read_u16()
            elif uv4_fmt == 11:
                r.read_u16()
                r.read_u16()

        # Bones
        if bones_fmt == 0:
            bone_array.append((0, 0, 0, 0))
        elif bones_fmt == 3:
            b1 = r.read_u8() // 4
            b2 = r.read_u8() // 4
            b3 = r.read_u8() // 4
            b4 = r.read_u8() // 4
            bone_array.append((b1, b2, b3, b4))
        elif bones_fmt == 8:
            b1 = r.read_u8() // 3
            b2 = r.read_u8() // 3
            b3 = r.read_u8() // 3
            b4 = r.read_u8() // 3
            bone_array.append((b1, b2, b3, b4))
        else:
            raise ValueError(f"Unknown bones format {bones_fmt}")

        # Weights
        if weight_fmt == 0:
            weight_array.append((1.0, 0.0, 0.0, 0.0))
        elif weight_fmt == 1:
            w1 = r.read_f32()
            w2 = r.read_f32()
            w3 = r.read_f32()
            weight_array.append((w1, w2, w3, 0.0))
        elif weight_fmt == 4:
            w1 = r.read_i16() / 32767.0
            w2 = r.read_i16() / 32767.0
            w3 = r.read_i16() / 32767.0
            w4 = r.read_i16() / 32767.0
            weight_array.append((w1, w2, w3, w4))
        elif weight_fmt == 5:
            w1 = r.read_u16() / 65535.0
            w2 = r.read_u16() / 65535.0
            w3 = r.read_u16() / 65535.0
            w4 = r.read_u16() / 65535.0
            weight_array.append((w1, w2, w3, w4))
        else:
            raise ValueError(f"Unknown weights format {weight_fmt}")

        # Colors
        if colors_fmt == 1:
            cr = r.read_f32() * 255.0
            cg = r.read_f32() * 255.0
            cb = r.read_f32() * 255.0
            ca = r.read_f32()
            color_array.append((cr, cg, cb, ca))
        elif colors_fmt == 3:
            cr = float(r.read_u8())
            cg = float(r.read_u8())
            cb = float(r.read_u8())
            ca = r.read_u8() / 255.0
            color_array.append((cr, cg, cb, ca))
        elif colors_fmt != 0:
            raise ValueError(f"Unknown colors format {colors_fmt}")

        # Unknown1
        if unk1_fmt > 0:
            if unk1_fmt == 1:
                r.read_f32()

        # Normals
        if norm_fmt == 2:
            nx = r.read_i8() / 127.0
            ny = r.read_i8() / 127.0
            nz = r.read_i8() / 127.0
            _nq = r.read_i8() / 127.0
            normal_array.append((nx, ny, nz))
        elif norm_fmt == 4:
            nx = r.read_i16() / 32767.0
            ny = r.read_i16() / 32767.0
            nz = r.read_i16() / 32767.0
            _nq = r.read_i16() / 32767.0
            normal_array.append((nx, ny, nz))
        elif norm_fmt != 0:
            raise ValueError(f"Unknown normals format {norm_fmt}")

        # Binormals
        if binorm_fmt == 2:
            r.read_i8(); r.read_i8(); r.read_i8(); r.read_i8()
        elif binorm_fmt == 4:
            r.read_i16(); r.read_i16(); r.read_i16(); r.read_i16()

        # Tangents
        if tang_fmt == 2:
            r.read_i8(); r.read_i8(); r.read_i8(); r.read_i8()
        elif tang_fmt == 4:
            r.read_i16(); r.read_i16(); r.read_i16(); r.read_i16()

        # Unknown2 (break on presence -- same as MaxScript)
        if unk2_fmt > 0:
            log.warning("Unknown2 attribute present (fmt=%d), stopping vertex read", unk2_fmt)
            break

    log.debug("Read %d vertices", len(vert_array))

    # -- Build output -----------------------------------------------------
    result = D3DMeshData(
        name='', version=2,
        bounding_box=(bb_min, bb_max),
        bone_names=bone_id_sets,
    )

    for i, info in enumerate(submesh_infos):
        v_min = info['vertex_min']
        v_max = info['vertex_max']
        poly_start = info['polygon_start']
        poly_count = info['polygon_count']

        sm = D3DMeshSubmesh(
            name=info.get('material_name') or f"submesh_{i}",
            material_name=info.get('material_name'),
            bone_set_index=info['bone_set_num'] - 1,
        )

        face_plus = len(result.all_vertices)
        for vi in range(v_min - 1, min(v_max, len(vert_array))):
            pos = vert_array[vi] if vi < len(vert_array) else (0, 0, 0)
            nrm = normal_array[vi] if vi < len(normal_array) else None
            uv = uv_array[vi] if vi < len(uv_array) else None
            uv2 = uv2_array[vi] if vi < len(uv2_array) else None
            bi = bone_array[vi] if vi < len(bone_array) else None
            bw = weight_array[vi] if vi < len(weight_array) else None
            col = color_array[vi] if vi < len(color_array) else None

            vtx = D3DMeshVertex(
                position=pos, normal=nrm, uv=uv, uv2=uv2,
                bone_indices=bi, bone_weights=bw, color=col,
            )
            sm.vertices.append(vtx)
            result.all_vertices.append(vtx)

        for fi in range(poly_count):
            fidx = poly_start - 1 + fi
            if fidx < len(raw_faces):
                fa, fb, fc = raw_faces[fidx]
                adj = (fa - v_min + face_plus,
                       fb - v_min + face_plus,
                       fc - v_min + face_plus)
                sm.faces.append(adj)
                result.all_faces.append(adj)

        result.submeshes.append(sm)

    log.info("V2 parse complete: %d vertices, %d faces, %d submeshes",
             len(result.all_vertices), len(result.all_faces), len(result.submeshes))

    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_d3dmesh(data: bytes, early_game_fix: int = 10) -> D3DMeshData:
    """Parse a Telltale D3DMESH file (versions 0 through 2).

    Parameters
    ----------
    data : bytes
        Raw file content of a ``.d3dmesh`` file.
    early_game_fix : int
        Sub-version selector for the older games.  See the module docstring
        for the mapping.  Defaults to 10 (Tales of Monkey Island / Version 1).

    Returns
    -------
    D3DMeshData
        Parsed mesh geometry, submeshes, materials, and bone data.

    Raises
    ------
    ValueError
        If the file is malformed or uses an unsupported version.
    """
    # -- MetaStream header ------------------------------------------------
    meta_header = metastream.parse_header(data)
    log.debug("MetaStream format: %s, payload at offset %d",
              meta_header.version, meta_header.data_offset)

    r = BinaryReader(data)
    # Advance past the MetaStream header to the actual payload.
    if meta_header.data_offset > 0:
        r.seek(meta_header.data_offset)

    # -- Name and version -------------------------------------------------
    name_header_length = r.read_u32()
    name_length = r.read_u32()
    if name_length > name_header_length:
        log.debug("Fixing name offset: name_length %d > name_header_length %d",
                  name_length, name_header_length)
        r.seek(r.tell() - 4)  # seek back 4 bytes
        name_length = name_header_length

    mesh_name = r.read_string(name_length)
    log.info("Mesh name: %s", mesh_name)

    version_byte = r.read_u8()
    log.debug("Raw version byte: %d (0x%02X)", version_byte, version_byte)

    # Version 0 games use ASCII '0' (0x30) or '1' (0x31)
    if version_byte == 0x30 or version_byte == 0x31:
        version = 0
        is_rigged = (version_byte == 0x31)
        log.debug("Version 0 detected (rigged=%s)", is_rigged)
    else:
        version = version_byte
        is_rigged = False

    log.info("D3DMESH version = %d, EarlyGameFix = %d", version, early_game_fix)

    # -- Dispatch to version-specific parser ------------------------------
    if version == 0 and early_game_fix < 4:
        result = _parse_v0(r, early_game_fix)
    elif version == 0 and early_game_fix >= 4 and early_game_fix <= 9:
        result = _parse_v05(r, early_game_fix)
    elif version == 0 and early_game_fix >= 10:
        # EarlyGameFix 10 = Tales of Monkey Island = Version 1
        result = _parse_v1(r, early_game_fix)
    elif version == 1:
        result = _parse_v1(r, early_game_fix)
    elif version == 2:
        result = _parse_v2(r)
    else:
        raise ValueError(
            f"Unsupported D3DMESH version {version}. "
            f"This parser covers versions 0 through 2 only."
        )

    result.name = mesh_name
    result.version = version if version != 0 or early_game_fix < 10 else 1

    log.info("Parse complete: '%s' v%d -- %d submeshes, %d total vertices, %d total faces",
             result.name, result.version, len(result.submeshes),
             len(result.all_vertices), len(result.all_faces))

    return result
