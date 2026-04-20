"""
Intrinsic primitive decoders for Telltale MetaStream.

Registers every fixed-size and length-prefixed intrinsic used in
.chore / .ptable / .anm into two places:

  1. ``telltale.metaclass._REGISTRY`` — under crc64_str(name) keys,
     so ``get_by_hash`` / ``get_by_name`` resolve every intrinsic.
  2. This module's ``_DECODERS`` dict — keyed by the same crc64
     hash, with a ``decode(reader, stream_version) -> value``
     callable per type.

Phase 3-02 (math) and 3-03 (Handle) import this module's
``register(name, decoder)`` helper to add their types into the
same shared tables.

Name convention (verified against TelltaleToolLib/ToolLibrary/
TelltaleToolLibrary.cpp::TelltaleToolLib_MakeInternalTypeName
lines 925-957): the MSVC ``typeid(T).name()`` string has
``"class "``, ``"struct "``, ``"enum "``, ``"std::"`` and ALL
spaces stripped.  ``std::basic_string<...>`` is replaced with
``"String"``.  CRC64 is case-insensitive (telltale.crc64.crc64_str
lowercases before hashing).

Empirical cross-check: crc64_str("CompressedPhonemeKeys") ==
0x3d2dbf388bfde0a4 matches the on-disk type hash of that class
in every EP1 anm header (verified against parse_anm.parse_header).
"""

from __future__ import annotations

import logging
from typing import Any, Callable

from telltale.crc64 import crc64_str
from telltale.metaclass import MetaClassDescription, _REGISTRY
from telltale.metastream import MetaStreamReader

log = logging.getLogger(__name__)

DecoderFn = Callable[[MetaStreamReader, int], Any]

_DECODERS: dict[int, DecoderFn] = {}
_HASH_TO_NAME: dict[int, str] = {}


def register(name: str, decoder: DecoderFn, decoder_only: bool = False) -> int:
    """Register *decoder* under ``crc64_str(name)`` in the shared tables.

    Always inserts into ``_DECODERS`` and ``_HASH_TO_NAME``.

    If ``decoder_only=False`` (default), also inserts a bare
    ``MetaClassDescription`` (members=[], dataclass_cls=None) into
    ``telltale.metaclass._REGISTRY``.  This is what intrinsic
    registration uses — the intrinsic has no Python dataclass.

    If ``decoder_only=True``, leaves ``_REGISTRY`` untouched.  This
    is what Plans 03-02 (math) and 03-03 (Handle) use after their
    own ``@meta_class``-decorated dataclass has ALREADY populated
    ``_REGISTRY`` with a full MetaClassDescription (dataclass_cls
    set, members list populated).  Overwriting that entry with a
    bare one would drop the dataclass binding.

    Returns the computed type_hash.  Raises ``ValueError`` on a
    CRC64 collision with a different name.  Re-registering the
    same name silently overwrites the decoder (idempotent for
    module reimport).
    """
    type_hash = crc64_str(name)
    existing = _HASH_TO_NAME.get(type_hash)
    if existing is not None and existing != name:
        raise ValueError(
            f"CRC64 collision at {type_hash:#018x}: "
            f"existing={existing!r}, new={name!r}"
        )
    _HASH_TO_NAME[type_hash] = name
    _DECODERS[type_hash] = decoder

    if not decoder_only:
        # Mirror into telltale.metaclass._REGISTRY so get_by_hash /
        # get_by_name resolve for intrinsics too.  No dataclass
        # backing -> dataclass_cls=None.
        existing_desc = _REGISTRY.get(type_hash)
        if existing_desc is None or existing_desc.name == name:
            _REGISTRY[type_hash] = MetaClassDescription(
                name=name,
                type_hash=type_hash,
                version_crc=None,
                members=[],
                dataclass_cls=None,
            )
        else:
            raise ValueError(
                f"CRC64 collision in _REGISTRY at {type_hash:#018x}: "
                f"existing={existing_desc.name!r}, new={name!r}"
            )
    return type_hash


def get_decoder_by_hash(type_hash: int) -> DecoderFn | None:
    """Return the decoder for the given CRC64 type hash, or None."""
    return _DECODERS.get(type_hash)


def get_decoder_by_name(name: str) -> DecoderFn | None:
    """Return the decoder for the given type name (hashed internally), or None."""
    return _DECODERS.get(crc64_str(name))


# ---- individual decoders -------------------------------------------

def _decode_bool(r: MetaStreamReader, sv: int) -> bool:
    return r.read_uint8() != 0


def _decode_int8(r: MetaStreamReader, sv: int) -> int:
    return r.read_int8()


def _decode_int16(r: MetaStreamReader, sv: int) -> int:
    return r.read_int16()


def _decode_int32(r: MetaStreamReader, sv: int) -> int:
    return r.read_int32()


def _decode_int64(r: MetaStreamReader, sv: int) -> int:
    return r.read_int64()


def _decode_uint8(r: MetaStreamReader, sv: int) -> int:
    return r.read_uint8()


def _decode_uint16(r: MetaStreamReader, sv: int) -> int:
    return r.read_uint16()


def _decode_uint32(r: MetaStreamReader, sv: int) -> int:
    return r.read_uint32()


def _decode_uint64(r: MetaStreamReader, sv: int) -> int:
    return r.read_uint64()


def _decode_float(r: MetaStreamReader, sv: int) -> float:
    return r.read_float32()


def _decode_double(r: MetaStreamReader, sv: int) -> float:
    return r.read_float64()


def _decode_flags(r: MetaStreamReader, sv: int) -> int:
    # Flags is a u32 wrapper; return the raw value.
    return r.read_uint32()


def decode_symbol(
    reader: MetaStreamReader,
    stream_version: int,
    include_mtre_debug_strlen: bool = False,
) -> int:
    """Decode a Telltale Symbol (u64 CRC64).

    Per TTL Meta.cpp::serialize_Symbol (lines 724-749) the modern
    wire format is just a u64.  HOWEVER, when a Symbol appears as
    the KEY of a Map<Symbol, V> in MTRE (stream version < 5), the
    container framing appends a u32 empty-debug-string-length = 0
    (empirically confirmed on all 74 EP1 ptables in parse_ptable.py).
    Phase 4 (containers) will set ``include_mtre_debug_strlen=True``
    when walking Map<Symbol, ...> keys in MTRE; the bare intrinsic
    decoder registered under ``"Symbol"`` does NOT read the trailing
    u32.
    """
    crc = reader.read_uint64()
    if include_mtre_debug_strlen:
        dbg = reader.read_uint32()
        if dbg != 0:
            raise ValueError(
                f"Expected 0 trailing debug-strlen after Symbol, got {dbg}"
            )
    return crc


def _decode_symbol_bare(r: MetaStreamReader, sv: int) -> int:
    return decode_symbol(r, sv, include_mtre_debug_strlen=False)


def decode_string(reader: MetaStreamReader, stream_version: int) -> str:
    """Decode a Telltale String: u32 length + raw ASCII bytes.

    Per TTL Meta.cpp::serialize_String (lines 929-948): no trailing
    NUL, no padAlign.  Empirically validated in parse_ptable.py.
    Decodes as latin1 (tolerant of non-ASCII filename bytes; matches
    parse_ptable convention).
    """
    length = reader.read_uint32()
    if length == 0:
        return ""
    return reader.read_bytes(length).decode("latin1")


def _decode_string(r: MetaStreamReader, sv: int) -> str:
    return decode_string(r, sv)


# Public aliases for direct use by external callers (e.g. Plan 03-03 Handle).
decode_bool = _decode_bool
decode_int8 = _decode_int8
decode_int16 = _decode_int16
decode_int32 = _decode_int32
decode_int64 = _decode_int64
decode_uint8 = _decode_uint8
decode_uint16 = _decode_uint16
decode_uint32 = _decode_uint32
decode_uint64 = _decode_uint64
decode_float = _decode_float
decode_double = _decode_double
decode_flags = _decode_flags


# ---- registration --------------------------------------------------

# (name, decoder) — canonical name first, aliases follow.
# Names are derived from TTL MetaInitialize.h DEFINET invocations
# after TelltaleToolLib_MakeInternalTypeName stripping.
_INTRINSICS: list[tuple[str, DecoderFn]] = [
    # Signed integers — MSVC typeid names after stripping
    ("bool",            _decode_bool),
    ("__int8",          _decode_int8),      # signed char alias
    ("int8",            _decode_int8),      # alias
    ("short",           _decode_int16),     # MetaInitialize.h:36 DEFINET(short, i16)
    ("int16",           _decode_int16),     # alias
    ("int",             _decode_int32),     # MetaInitialize.h:43 DEFINET(int, i32)
    ("int32",           _decode_int32),     # alias
    ("__int32",         _decode_int32),     # MetaInitialize.h:93 DEFINET(__int32, ...)
    ("long",            _decode_int32),     # MetaInitialize.h:50 DEFINET(long, long)
    ("__int64",         _decode_int64),     # MetaInitialize.h:79 DEFINET(__int64, __int64)
    ("int64",           _decode_int64),     # alias

    # Unsigned integers
    ("unsigned__int8",  _decode_uint8),     # MetaInitialize.h:100 after stripping
    ("uint8",           _decode_uint8),     # alias
    ("unsignedchar",    _decode_uint8),     # typeid(unsigned char) alias
    ("ushort",          _decode_uint16),    # MetaInitialize.h:29 DEFINET(ushort, u16)
    ("uint16",          _decode_uint16),    # alias
    ("unsignedshort",   _decode_uint16),    # typeid(unsigned short) after stripping
    ("unsigned__int32", _decode_uint32),    # MetaInitialize.h:86 after stripping
    ("uint32",          _decode_uint32),    # alias
    ("uint",            _decode_uint32),    # per MKNAME lines in MetaInitialize.h
    ("unsignedint",     _decode_uint32),    # typeid(unsigned int) after stripping
    ("u64",             _decode_uint64),    # MetaInitialize.h:57 DEFINET(u64, u64)
    ("unsigned__int64", _decode_uint64),    # MetaInitialize.h after stripping
    ("uint64",          _decode_uint64),    # alias

    # Floats
    ("float",           _decode_float),
    ("double",          _decode_double),

    # Wrappers
    ("Flags",           _decode_flags),
    ("Symbol",          _decode_symbol_bare),
    ("String",          _decode_string),
]


def register_intrinsics() -> None:
    """Idempotent registration of all intrinsics into _DECODERS
    and telltale.metaclass._REGISTRY."""
    for name, decoder in _INTRINSICS:
        register(name, decoder)
    log.debug("registered %d intrinsic aliases", len(_INTRINSICS))


register_intrinsics()
