"""
MetaStream container header parser for Telltale Games files.

Parses the MetaStream header that appears at the beginning of most Telltale
asset files (.d3dmesh, .skl, .d3dtx, .prop, .landb, etc.).  The header
identifies the serialized class types and their versions, as well as the
sizes of the data sections (for MSV5/MSV6).

Supported header versions
-------------------------
- **MBIN** (magic ``MBIN`` / ``0x4D42494E``) -- earliest games (Bone, early Sam & Max)
- **MTRE** (stored as ``ERTM`` in LE, i.e. ``0x4D545245`` on disk) -- Sam & Max S2 through TWD S1
- **MSV5** (stored as ``5VSM``) -- Puzzle Agent era through early TWAU
- **MSV6** (stored as ``6VSM``) -- Wolf Among Us onward

All multi-byte integers are little-endian.

Usage::

    from telltale.metastream import parse_header, MetaStreamHeader

    # From a file path
    header = parse_header("path/to/file.d3dmesh")

    # From raw bytes
    header = parse_header(raw_bytes)

    # From an open binary stream
    with open("file.prop", "rb") as f:
        header = parse_header(f)

    print(header.version)       # e.g. "MSV6"
    print(header.data_offset)   # byte offset where payload starts
    for class_id, ver in header.classes:
        print(f"  class={class_id:#018x}, version={ver}")
"""

from __future__ import annotations

import io
import logging
import struct
from dataclasses import dataclass, field
from typing import BinaryIO, List, Tuple, Union

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Binary reader helper
# ---------------------------------------------------------------------------

class BinaryReader:
    """Thin wrapper around a readable binary stream for structured reads.

    All reads are little-endian, matching Telltale's on-disk format.
    """

    def __init__(self, stream: BinaryIO) -> None:
        self._stream = stream

    # -- position helpers ---------------------------------------------------

    @property
    def pos(self) -> int:
        return self._stream.tell()

    def tell(self) -> int:
        return self._stream.tell()

    def seek(self, offset: int, whence: int = 0) -> None:
        self._stream.seek(offset, whence)

    def skip(self, n: int) -> None:
        self._stream.seek(n, 1)

    # -- primitive reads (little-endian) ------------------------------------

    def read_bytes(self, n: int) -> bytes:
        data = self._stream.read(n)
        if len(data) < n:
            raise EOFError(
                f"Expected {n} bytes at offset {self.pos - len(data)}, "
                f"got {len(data)}"
            )
        return data

    def read_uint8(self) -> int:
        return struct.unpack("<B", self.read_bytes(1))[0]

    read_u8 = read_uint8

    def read_uint16(self) -> int:
        return struct.unpack("<H", self.read_bytes(2))[0]

    read_u16 = read_uint16

    def read_uint32(self) -> int:
        return struct.unpack("<I", self.read_bytes(4))[0]

    # Alias used by the older API expected by other modules in the project.
    read_u32 = read_uint32

    def read_int8(self) -> int:
        return struct.unpack("<b", self.read_bytes(1))[0]

    read_i8 = read_int8

    def read_int16(self) -> int:
        return struct.unpack("<h", self.read_bytes(2))[0]

    read_i16 = read_int16

    def read_int32(self) -> int:
        return struct.unpack("<i", self.read_bytes(4))[0]

    read_i32 = read_int32

    def read_int64(self) -> int:
        return struct.unpack("<q", self.read_bytes(8))[0]

    read_i64 = read_int64

    def read_uint64(self) -> int:
        return struct.unpack("<Q", self.read_bytes(8))[0]

    read_u64 = read_uint64

    def read_float32(self) -> float:
        return struct.unpack("<f", self.read_bytes(4))[0]

    read_f32 = read_float32

    def read_float64(self) -> float:
        return struct.unpack("<d", self.read_bytes(8))[0]

    read_f64 = read_float64

    def pad_align(self, alignment: int) -> int:
        """Advance pos to the next multiple of *alignment* (skips padding bytes)."""
        rem = self.pos % alignment
        if rem:
            self.skip(alignment - rem)
        return self.pos

    def peek_uint32(self) -> int:
        """Read a uint32 without advancing the stream position."""
        val = self.read_uint32()
        self._stream.seek(-4, 1)
        return val

    # Alias for backward compatibility.
    peek_u32 = peek_uint32

    def read_string(self, length: int) -> str:
        """Read *length* raw bytes and decode as ASCII."""
        raw = self.read_bytes(length)
        return raw.rstrip(b"\x00").decode("ascii", errors="replace")


# ---------------------------------------------------------------------------
# Magic constants (as uint32 values obtained by reading the on-disk bytes
# with struct.unpack("<I", ...)).
#
#   On disk     bytes          struct("<I")
#   -------     -----          -----------
#   "MBIN"      4D 42 49 4E    0x4E49424D
#   "ERTM"      45 52 54 4D    0x4D545245   (MTRE stored reversed)
#   "5VSM"      35 56 53 4D    0x4D535635   (MSV5 stored reversed)
#   "6VSM"      36 56 53 4D    0x4D535636   (MSV6 stored reversed)
# ---------------------------------------------------------------------------

MAGIC_MBIN = struct.unpack("<I", b"MBIN")[0]   # 0x4E49424D
MAGIC_MTRE = struct.unpack("<I", b"ERTM")[0]   # 0x4D545245
MAGIC_MSV5 = struct.unpack("<I", b"5VSM")[0]   # 0x4D535635
MAGIC_MSV6 = struct.unpack("<I", b"6VSM")[0]   # 0x4D535636

# Lookup by raw 4-byte magic (both natural and reversed orderings) for
# convenience when the caller has raw bytes instead of a uint32.
MAGICS_BY_BYTES = {
    b"MBIN": "MBIN",
    b"NIBM": "MBIN",
    b"MTRE": "MTRE",
    b"ERTM": "MTRE",
    b"MSV5": "MSV5",
    b"5VSM": "MSV5",
    b"MSV6": "MSV6",
    b"6VSM": "MSV6",
}


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class MetaStreamHeader:
    """Parsed result of a MetaStream container header.

    Attributes
    ----------
    version : str
        One of ``"MBIN"``, ``"MTRE"``, ``"MSV5"``, ``"MSV6"``, or ``"NONE"``
        if the magic could not be recognised.
    classes : list of (name_or_hash, version) tuples
        Each entry is a ``(identifier, version_crc)`` pair.  *identifier* is
        either a ``str`` (class name, for MBIN/MTRE unhashed entries) or an
        ``int`` (CRC64 hash, for MTRE hashed entries and MSV5/MSV6).
    default_size : int
        Size of the default (main) data section in bytes.  Always 0 for
        MBIN and MTRE.
    debug_size : int
        Size of the debug data section.  Always 0 for MBIN and MTRE.
    async_size : int
        Size of the async data section.  Always 0 for MBIN and MTRE.
    data_offset : int
        Byte offset in the original stream where the actual payload data
        starts (i.e. immediately after the header).
    """

    version: str = "NONE"
    classes: List[Tuple[Union[str, int], int]] = field(default_factory=list)
    default_size: int = 0
    debug_size: int = 0
    async_size: int = 0
    data_offset: int = 0


# ---------------------------------------------------------------------------
# Internal parsers
# ---------------------------------------------------------------------------

def _parse_mbin(reader: BinaryReader) -> MetaStreamHeader:
    """Parse an MBIN header (magic already consumed)."""
    param_count = reader.read_uint32()
    classes: List[Tuple[Union[str, int], int]] = []

    if param_count > 0:
        # Peek at the first uint32 to decide between string and skip formats.
        peeked = reader.peek_uint32()
        if 0 < peeked < 128:
            # String format: length-prefixed name + uint32 unknown/version
            for _ in range(param_count):
                name_length = reader.read_uint32()
                name = reader.read_string(name_length)
                version = reader.read_uint32()
                classes.append((name, version))
        else:
            # Hashed / opaque format: 12 bytes (uint64 hash + uint32 ver,
            # or three unknown uint32s) per entry.
            for _ in range(param_count):
                reader.skip(12)

    log.debug("MBIN: %d params, payload at offset %d", param_count, reader.pos)
    return MetaStreamHeader(
        version="MBIN",
        classes=classes,
        default_size=0,
        debug_size=0,
        async_size=0,
        data_offset=reader.pos,
    )


def _parse_mtre(reader: BinaryReader) -> MetaStreamHeader:
    """Parse an MTRE header (magic already consumed)."""
    class_count = reader.read_uint32()
    classes: List[Tuple[Union[str, int], int]] = []

    for _ in range(class_count):
        peeked = reader.peek_uint32()
        if peeked > 128:
            # Hashed format: uint64 CRC64 + uint32 version
            class_crc64 = reader.read_uint64()
            class_version = reader.read_uint32()
            classes.append((class_crc64, class_version))
        else:
            # String format: uint32 name_length + name + uint32 version
            name_length = reader.read_uint32()
            class_name = reader.read_string(name_length)
            class_version = reader.read_uint32()
            classes.append((class_name, class_version))

    log.debug("MTRE: %d classes, payload at offset %d", class_count, reader.pos)
    return MetaStreamHeader(
        version="MTRE",
        classes=classes,
        default_size=0,
        debug_size=0,
        async_size=0,
        data_offset=reader.pos,
    )


def _parse_msv(reader: BinaryReader, version_str: str) -> MetaStreamHeader:
    """Parse an MSV5 or MSV6 header (magic already consumed).

    Layout after the magic::

        uint32  default_section_size   (high bit = compressed flag)
        uint32  debug_section_size     (high bit = compressed flag)
        uint32  async_section_size     (high bit = compressed flag)
        uint32  class_count
        for each class:
            uint64  class_crc64
            uint32  class_version
    """
    default_size = reader.read_uint32()
    debug_size = reader.read_uint32()
    async_size = reader.read_uint32()

    # High bit (0x80000000) indicates the section is compressed.
    # Strip the flag for the raw size value.
    default_size &= 0x7FFFFFFF
    debug_size &= 0x7FFFFFFF
    async_size &= 0x7FFFFFFF

    class_count = reader.read_uint32()
    classes: List[Tuple[Union[str, int], int]] = []

    for _ in range(class_count):
        class_crc64 = reader.read_uint64()
        class_version = reader.read_uint32()
        classes.append((class_crc64, class_version))

    log.debug(
        "%s: %d classes, sections=%d/%d/%d, payload at offset %d",
        version_str, class_count, default_size, debug_size, async_size,
        reader.pos,
    )
    return MetaStreamHeader(
        version=version_str,
        classes=classes,
        default_size=default_size,
        debug_size=debug_size,
        async_size=async_size,
        data_offset=reader.pos,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_header(source: Union[bytes, BinaryIO, str]) -> MetaStreamHeader:
    """Parse a MetaStream header from *source*.

    Parameters
    ----------
    source : bytes, file-like, or str/path
        If *bytes*, it is wrapped in ``io.BytesIO``.  If a *str*, it is
        treated as a file path and opened in binary mode.  Otherwise it must
        be a readable binary stream positioned at the start of the header.

    Returns
    -------
    MetaStreamHeader
        The parsed header.  If the magic cannot be recognised, a header with
        ``version="NONE"`` and ``data_offset=0`` is returned.
    """
    close_after = False
    if isinstance(source, bytes):
        stream: BinaryIO = io.BytesIO(source)
    elif isinstance(source, str):
        stream = open(source, "rb")
        close_after = True
    else:
        stream = source

    try:
        reader = BinaryReader(stream)
        magic = reader.read_uint32()

        if magic == MAGIC_MBIN:
            return _parse_mbin(reader)
        elif magic == MAGIC_MTRE:
            return _parse_mtre(reader)
        elif magic == MAGIC_MSV5:
            return _parse_msv(reader, "MSV5")
        elif magic == MAGIC_MSV6:
            return _parse_msv(reader, "MSV6")
        else:
            log.debug("Unrecognised MetaStream magic: 0x%08X", magic)
            return MetaStreamHeader(version="NONE", data_offset=0)
    finally:
        if close_after:
            stream.close()


def parse_header_from_file(filepath: str) -> MetaStreamHeader:
    """Convenience wrapper: parse a MetaStream header from a file path."""
    return parse_header(filepath)
