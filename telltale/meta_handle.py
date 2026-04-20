"""
Handle<T> registration for Telltale MetaStream.

Authoritative reference: TelltaleToolLib/ToolLibrary/Types/
HandleObjectInfo.h lines 21-39 (HandleBase::MetaOperation_SerializeAsync).
On read:
    if stream_version >= 5: read u64 Symbol CRC (MSV5+)
    else:                   read length-prefixed String (MTRE)

In MTRE the decoded string is an asset filename (e.g.
``"guybrush_idle.anm"``).  The in-memory CRC is computed via
``crc64_str`` of that filename.  In MSV5+ the u64 is read directly
(filename is not recoverable from the stream).

Handle<T> is a template with many concrete instantiations.  Rather
than creating one dataclass per T, we use a single ``Handle`` class
and register its decoder under every concrete template-name hash
(Handle<PropertySet>, Handle<Animation>, etc.).  This is the same
pattern TTL uses internally -- the serialization is identical across
all T.

Registration detail
-------------------
*  ``@meta_class("HandleBase")`` inserts a ``MetaClassDescription``
   into ``telltale.metaclass._REGISTRY`` with ``dataclass_cls=Handle``
   and the members declared via ``meta_member``.

*  ``register_handles()`` adds each concrete ``Handle<T>`` name into
   both ``_REGISTRY`` (with ``dataclass_cls=Handle``) and
   ``telltale.meta_intrinsics._DECODERS`` (with ``decode_handle``).

*  ``HANDLE_TEMPLATE_PARAMS`` lists every T to register.  Minimum
   per 03-CONTEXT.md is the first six; the rest are added for
   Phase 4+ coverage.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from telltale.crc64 import crc64_str
from telltale.metaclass import meta_class, meta_member, _REGISTRY, MetaClassDescription
from telltale.meta_intrinsics import (
    register, decode_string, decode_symbol,
)
from telltale.metastream import MetaStreamReader

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Handle dataclass
# ---------------------------------------------------------------------------

@meta_class("HandleBase")
@dataclass
class Handle:
    """In-memory representation of any Handle<T> instantiation.

    All concrete Handle<T> template instantiations share this single
    Python class -- the serialization format is identical for every T.

    Attributes
    ----------
    object_name_crc:
        CRC64 of the asset filename.  Always populated.  In MSV5+
        (stream_version >= 5) this is read directly from the wire;
        in MTRE it is computed from the decoded filename via
        ``crc64_str``.
    object_name_str:
        The raw asset filename as decoded from the stream.  Populated
        only in the MTRE branch (stream_version < 5).  ``None`` for
        MSV5+ decodes where only the CRC is available.
    """
    object_name_crc: int = meta_member("mObjectName", int)
    object_name_str: Optional[str] = meta_member(
        "mObjectName_str", str, min_version=-1
    )


# ---------------------------------------------------------------------------
# Decoder
# ---------------------------------------------------------------------------

def decode_handle(reader: MetaStreamReader, stream_version: int) -> Handle:
    """Decode a Handle<T> from the reader.

    Branches on stream_version per
    HandleBase::MetaOperation_SerializeAsync (HandleObjectInfo.h lines
    21-39):

        stream_version >= 5 (MSV5+):
            Read u64 Symbol CRC directly from wire.
            ``object_name_str`` stays ``None`` -- the filename is not
            present in the stream.

        stream_version < 5 (MTRE / MBIN):
            Read a u32-length-prefixed String (the asset filename).
            Compute ``crc64_str(name)`` for ``object_name_crc``.

    Parameters
    ----------
    reader:
        ``MetaStreamReader`` positioned at the start of the Handle
        payload.  MUST NOT have a block-size prefix already consumed;
        the block framing is the caller's responsibility (the MTRE
        container wraps each Handle member in begin_block/end_block).
    stream_version:
        The MetaStream file version (from
        ``MetaStreamReader.stream_version``).  The branch pivot is 5.
    """
    if stream_version >= 5:
        # MSV5+ -- bare u64 Symbol CRC, filename not recoverable.
        crc = decode_symbol(reader, stream_version)
        return Handle(object_name_crc=crc, object_name_str=None)
    else:
        # MTRE / MBIN -- u32-prefixed String (asset filename).
        name = decode_string(reader, stream_version)
        crc = crc64_str(name) if name else 0
        return Handle(object_name_crc=crc, object_name_str=name)


# ---------------------------------------------------------------------------
# Template parameter list
# ---------------------------------------------------------------------------

# Minimum per 03-CONTEXT.md: first six entries.
# Additional entries (Chore, T3Texture, D3DMesh, PhonemeTable, Rules)
# are pre-registered for Phase 4+ to avoid deferred insertions there.
HANDLE_TEMPLATE_PARAMS: list[str] = [
    # Core Chore / Agent / PropertySet surface (required by 03-CONTEXT.md)
    "PropertySet",
    "Animation",
    "WalkBoxes",
    "Scene",
    "ChoreResource",
    "SoundData",
    # Additional TMI-era usage (verified in MetaInitialize.h):
    "Chore",         # ptable AnimOrChore.mhChore
    "T3Texture",     # DCArray<Handle<T3Texture>> in scene
    "D3DMesh",       # referenced in D3DMesh subsystem
    "PhonemeTable",  # KeyframedValue<Handle<PhonemeTable>> in chore
    "Rules",         # List<Handle<Rules>>
]


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def register_handles() -> None:
    """Idempotent registration of Handle<T> decoders for every T
    in ``HANDLE_TEMPLATE_PARAMS``.

    For each T inserts:

    * An entry in ``telltale.meta_intrinsics._DECODERS`` pointing at
      ``decode_handle`` (keyed by ``crc64_str("Handle<{T}>")``.
    * An entry in ``telltale.metaclass._REGISTRY`` with
      ``dataclass_cls=Handle`` (so ``get_by_name`` returns a useful
      description).

    ``HandleBase`` was already registered in ``_REGISTRY`` by the
    ``@meta_class("HandleBase")`` decorator above.  Its decoder entry
    in ``_DECODERS`` is added here separately (the decorator only
    populates ``_REGISTRY``).
    """
    # Wire the HandleBase decoder (decorator handled _REGISTRY already).
    register("HandleBase", decode_handle, decoder_only=True)

    for t in HANDLE_TEMPLATE_PARAMS:
        name = f"Handle<{t}>"
        type_hash = crc64_str(name)

        # Insert into _REGISTRY with dataclass_cls=Handle.
        # Do not call register(..., decoder_only=False) here -- that
        # would overwrite any existing entry with a bare description.
        # Instead manipulate _REGISTRY directly so we can set
        # dataclass_cls=Handle on newly created entries.
        existing = _REGISTRY.get(type_hash)
        if existing is None:
            _REGISTRY[type_hash] = MetaClassDescription(
                name=name,
                type_hash=type_hash,
                version_crc=None,
                members=[],
                dataclass_cls=Handle,
            )
        else:
            # Preserve the existing description; ensure dataclass_cls
            # is set to Handle if it is currently None.
            if existing.dataclass_cls is None:
                existing.dataclass_cls = Handle

        # Insert the decoder entry into _DECODERS without touching
        # _REGISTRY again (decoder_only=True).
        register(name, decode_handle, decoder_only=True)

    log.debug(
        "registered decode_handle for %d Handle<T> params + HandleBase",
        len(HANDLE_TEMPLATE_PARAMS),
    )


# Run at import time (idempotent -- re-import safe).
register_handles()
