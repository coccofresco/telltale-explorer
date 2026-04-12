"""
Parse Legacy D3DTX texture files (Telltale Games).

Handles the "Legacy" D3DTX format used by pre-Walking-Dead-era titles
including Tales of Monkey Island, Wallace & Gromit, Sam & Max, Strong Bad,
and other early Telltale games.

Provides DDS conversion by constructing a standard 128-byte DDS header
prepended to the raw pixel data.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# MetaStream header magic values (little-endian uint32)
# ---------------------------------------------------------------------------
_MAGIC_MBIN = 0x4D42494E  # "MBIN"
_MAGIC_MTRE = 0x4D545245  # "MTRE"
_MAGIC_MSV5 = 0x4D535635  # "MSV5"
_MAGIC_MSV6 = 0x4D535636  # "MSV6"

# ---------------------------------------------------------------------------
# D3D / DDS format constants
# ---------------------------------------------------------------------------

# FourCC codes used in the D3DFormat field
DXT1 = 0x31545844  # "DXT1"
DXT3 = 0x33545844  # "DXT3"
DXT5 = 0x35545844  # "DXT5"

# Uncompressed integer format codes observed in legacy files
# (these are D3DFMT_* values from DirectX 9)
_D3DFMT_A8R8G8B8 = 21
_D3DFMT_X8R8G8B8 = 22
_D3DFMT_A4R4G4B4 = 23
_D3DFMT_A1R5G5B5 = 25
_D3DFMT_R5G6B5   = 23
_D3DFMT_L8       = 50
_D3DFMT_A8L8     = 51
_D3DFMT_A8       = 28

# DDS magic
_DDS_MAGIC = 0x20534444  # "DDS "

# DDS header flags
_DDSD_CAPS        = 0x00000001
_DDSD_HEIGHT      = 0x00000002
_DDSD_WIDTH       = 0x00000004
_DDSD_PIXELFORMAT = 0x00001000
_DDSD_MIPMAPCOUNT = 0x00020000
_DDSD_LINEARSIZE  = 0x00080000
_DDS_HEADER_FLAGS = (_DDSD_CAPS | _DDSD_HEIGHT | _DDSD_WIDTH |
                     _DDSD_PIXELFORMAT | _DDSD_MIPMAPCOUNT | _DDSD_LINEARSIZE)

# DDS pixel format flags
_DDPF_ALPHAPIXELS = 0x00000001
_DDPF_FOURCC      = 0x00000004
_DDPF_RGB         = 0x00000040

# DDS caps flags
_DDSCAPS_TEXTURE  = 0x00001000
_DDSCAPS_MIPMAP   = 0x00400000
_DDSCAPS_COMPLEX  = 0x00000008


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class D3DTXTexture:
    """Parsed legacy D3DTX texture."""

    name: str = ""
    import_name: str = ""

    # Flags / properties
    has_texture_data: bool = True
    is_mip_mapped: bool = False
    is_wrap_u: bool = False
    is_wrap_v: bool = False
    is_filtered: bool = False
    embed_mipmaps: bool = False
    tool_props: int = 0

    # Image dimensions and format
    num_mip_levels: int = 1
    d3d_format: int = 0
    width: int = 0
    height: int = 0
    flags: int = 0

    # Sampler state
    sampler_state_block_size: int = 0
    sampler_state: int = 0

    # Raw pixel data (everything after the header)
    pixel_data: bytes = b""

    # For informational purposes
    header_size: int = 0


@dataclass
class _ParseState:
    """Mutable offset tracker for sequential reads."""
    data: bytes
    pos: int = 0

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def skip(self, n: int) -> None:
        self.pos += n

    def read_bytes(self, n: int) -> bytes:
        end = self.pos + n
        chunk = self.data[self.pos:end]
        self.pos = end
        return chunk

    def u8(self) -> int:
        val = self.data[self.pos]
        self.pos += 1
        return val

    def u16(self) -> int:
        val = struct.unpack_from("<H", self.data, self.pos)[0]
        self.pos += 2
        return val

    def u32(self) -> int:
        val = struct.unpack_from("<I", self.data, self.pos)[0]
        self.pos += 4
        return val

    def i32(self) -> int:
        val = struct.unpack_from("<i", self.data, self.pos)[0]
        self.pos += 4
        return val

    def f32(self) -> float:
        val = struct.unpack_from("<f", self.data, self.pos)[0]
        self.pos += 4
        return val

    def read_string(self) -> str:
        """Read a length-prefixed string (uint32 length + chars)."""
        length = self.u32()
        if length == 0 or length > 0x10000:
            return ""
        raw = self.data[self.pos:self.pos + length]
        self.pos += length
        return raw.decode("ascii", errors="replace").rstrip("\x00")

    def read_block_string(self) -> str:
        """Read a block-size-prefixed string (block_size uint32 + string)."""
        _block_size = self.i32()
        return self.read_string()


# ---------------------------------------------------------------------------
# MetaStream header parsing (shared with skeleton.py)
# ---------------------------------------------------------------------------

def _parse_metastream_header(r: _ParseState) -> int:
    """Skip past the MetaStream header.  Returns header type code."""
    if r.remaining() < 4:
        return -1

    start = r.pos
    magic = r.u32()

    if magic in (_MAGIC_MBIN, _MAGIC_MTRE):
        param_count = r.u32()
        if r.remaining() < 4:
            return 0 if magic == _MAGIC_MBIN else 1
        param_hash_check = r.u32()
        r.pos -= 4  # peek
        if 0 < param_hash_check < 128:
            for _ in range(param_count):
                name_len = r.u32()
                r.skip(name_len)
                r.skip(4)
        else:
            r.skip(12 * param_count)
        return 0 if magic == _MAGIC_MBIN else 1

    if magic in (_MAGIC_MSV5, _MAGIC_MSV6):
        _file_size = r.u32()
        r.skip(8)
        param_count = r.u32()
        r.skip(12 * param_count)
        return 5 if magic == _MAGIC_MSV5 else 6

    # Headerless / unknown
    if magic <= 128:
        r.pos = start
    else:
        r.pos = start
    return -1


# ---------------------------------------------------------------------------
# Legacy D3DTX parser
# ---------------------------------------------------------------------------

def parse_d3dtx(data: bytes) -> D3DTXTexture:
    """Parse a legacy D3DTX texture file.

    This implementation targets the Tales of Monkey Island / Wallace & Gromit
    era layout.  It handles both the "with sampler state" variant (Puzzle Agent
    onwards) and the earlier variant (Sam & Max S1, Strong Bad, Monkey Island).

    Parameters
    ----------
    data:
        Raw file bytes of the ``.d3dtx`` file.

    Returns
    -------
    D3DTXTexture
        Parsed texture metadata and pixel data.
    """
    tex = D3DTXTexture()
    r = _ParseState(data)

    # --- MetaStream header ---------------------------------------------------
    _parse_metastream_header(r)

    # --- Detect whether the sampler state block is present -------------------
    # The sampler state block starts with a uint32 value of 8.  If the first
    # value is 8, we treat it as a sampler-state-bearing variant (Puzzle Agent
    # and later).  Otherwise we fall back to the Monkey Island era layout.
    if r.remaining() < 4:
        return tex

    peek_val = struct.unpack_from("<i", r.data, r.pos)[0]

    has_sampler_state = (peek_val == 8)

    if has_sampler_state:
        # -- Puzzle Agent / CSI Fatal / BTTF / Poker Night 1 era ----
        tex.sampler_state_block_size = r.i32()  # should be 8
        tex.sampler_state = r.u32()

        # Name
        tex.name = r.read_block_string()

        # Import name
        tex.import_name = r.read_block_string()

        # Tool props
        tex.tool_props = r.u8()

        # Flags
        tex.has_texture_data = bool(r.u8())
        tex.is_mip_mapped = bool(r.u8())

        # Newer variants drop wrap/filter/embed; some keep embed
        # We try to read embed_mipmaps if present
        tex.embed_mipmaps = bool(r.u8())

        # Core texture info
        tex.num_mip_levels = r.u32()
        tex.d3d_format = r.u32()
        tex.width = r.u32()
        tex.height = r.u32()

    else:
        # -- Monkey Island / Wallace & Gromit / Sam & Max era --------
        # name_block_size + name
        tex.name = r.read_block_string()

        # import_name_block_size + import_name
        tex.import_name = r.read_block_string()

        # Boolean flags
        tex.has_texture_data = bool(r.u8())
        tex.is_mip_mapped = bool(r.u8())
        tex.is_wrap_u = bool(r.u8())
        tex.is_wrap_v = bool(r.u8())
        tex.is_filtered = bool(r.u8())
        tex.embed_mipmaps = bool(r.u8())

        # Core texture info
        tex.num_mip_levels = r.u32()
        tex.d3d_format = r.u32()
        tex.width = r.u32()
        tex.height = r.u32()

    # Try to read flags if they look plausible
    if r.remaining() >= 4:
        maybe_flags = struct.unpack_from("<I", r.data, r.pos)[0]
        # Flags are typically small values (bitmask of a few bits)
        if maybe_flags <= 0xFF:
            tex.flags = r.u32()

    # Record where the header ended
    tex.header_size = r.pos

    # --- Pixel data ----------------------------------------------------------
    # For a simple implementation, treat everything remaining as pixel data.
    # More advanced parsers would skip Wii/TPL/JPEG data sections.
    tex.pixel_data = r.data[r.pos:]

    return tex


# ---------------------------------------------------------------------------
# DDS conversion
# ---------------------------------------------------------------------------

def _compute_linear_size(width: int, height: int, d3d_format: int) -> int:
    """Compute the linear size of the top-level mip for DDS."""
    if d3d_format in (DXT1,):
        block_w = max(1, (width + 3) // 4)
        block_h = max(1, (height + 3) // 4)
        return block_w * block_h * 8
    if d3d_format in (DXT3, DXT5):
        block_w = max(1, (width + 3) // 4)
        block_h = max(1, (height + 3) // 4)
        return block_w * block_h * 16
    # Uncompressed -- assume 32-bit ARGB
    return width * height * 4


def _build_pixel_format(d3d_format: int) -> bytes:
    """Build the 32-byte DDS_PIXELFORMAT structure."""
    # struct DDS_PIXELFORMAT {
    #   uint32 dwSize;          // always 32
    #   uint32 dwFlags;
    #   uint32 dwFourCC;
    #   uint32 dwRGBBitCount;
    #   uint32 dwRBitMask;
    #   uint32 dwGBitMask;
    #   uint32 dwBBitMask;
    #   uint32 dwABitMask;
    # }
    if d3d_format == DXT1:
        return struct.pack("<II4sIIIII",
                           32, _DDPF_FOURCC, b"DXT1", 0, 0, 0, 0, 0)
    if d3d_format == DXT3:
        return struct.pack("<II4sIIIII",
                           32, _DDPF_FOURCC, b"DXT3", 0, 0, 0, 0, 0)
    if d3d_format == DXT5:
        return struct.pack("<II4sIIIII",
                           32, _DDPF_FOURCC, b"DXT5", 0, 0, 0, 0, 0)
    # Uncompressed ARGB8
    return struct.pack("<IIIIIIII",
                       32,
                       _DDPF_RGB | _DDPF_ALPHAPIXELS,
                       0,           # no fourCC
                       32,          # bits per pixel
                       0x00FF0000,  # R mask
                       0x0000FF00,  # G mask
                       0x000000FF,  # B mask
                       0xFF000000)  # A mask


def convert_to_dds(texture: D3DTXTexture) -> bytes:
    """Convert a parsed D3DTXTexture to a DDS file in memory.

    Constructs a 128-byte DDS header followed by the raw pixel data.

    Parameters
    ----------
    texture:
        A previously parsed :class:`D3DTXTexture`.

    Returns
    -------
    bytes
        Complete DDS file contents.
    """
    width = texture.width
    height = texture.height
    mip_count = max(1, texture.num_mip_levels)
    linear_size = _compute_linear_size(width, height, texture.d3d_format)

    # Caps
    if mip_count > 1:
        caps1 = _DDSCAPS_TEXTURE | _DDSCAPS_MIPMAP | _DDSCAPS_COMPLEX
    else:
        caps1 = _DDSCAPS_TEXTURE

    pixel_format = _build_pixel_format(texture.d3d_format)

    # DDS header = 4 bytes magic + 124 bytes header = 128 bytes total
    #
    # Header layout (124 bytes):
    #   uint32 dwSize           = 124
    #   uint32 dwFlags
    #   uint32 dwHeight
    #   uint32 dwWidth
    #   uint32 dwPitchOrLinearSize
    #   uint32 dwDepth
    #   uint32 dwMipMapCount
    #   uint32 dwReserved1[11]  (44 bytes)
    #   DDS_PIXELFORMAT         (32 bytes)
    #   uint32 dwCaps
    #   uint32 dwCaps2
    #   uint32 dwCaps3
    #   uint32 dwCaps4
    #   uint32 dwReserved2

    header = struct.pack("<I", _DDS_MAGIC)
    header += struct.pack("<I", 124)          # dwSize
    header += struct.pack("<I", _DDS_HEADER_FLAGS)
    header += struct.pack("<I", height)
    header += struct.pack("<I", width)
    header += struct.pack("<I", linear_size)
    header += struct.pack("<I", 0)            # dwDepth
    header += struct.pack("<I", mip_count)
    header += b"\x00" * 44                    # dwReserved1[11]
    header += pixel_format                    # 32 bytes
    header += struct.pack("<I", caps1)
    header += struct.pack("<I", 0)            # dwCaps2
    header += struct.pack("<I", 0)            # dwCaps3
    header += struct.pack("<I", 0)            # dwCaps4
    header += struct.pack("<I", 0)            # dwReserved2

    assert len(header) == 128, f"DDS header is {len(header)} bytes, expected 128"

    return header + texture.pixel_data


def save_as_dds(texture: D3DTXTexture, output_path: str) -> None:
    """Convert a D3DTX texture to DDS and write to disk.

    Parameters
    ----------
    texture:
        Parsed texture object.
    output_path:
        Destination file path (should end in ``.dds``).
    """
    dds_data = convert_to_dds(texture)
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "wb") as fh:
        fh.write(dds_data)
