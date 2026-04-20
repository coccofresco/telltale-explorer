"""
MetaClass reflection registry for Telltale MetaStream decoding.

This module translates TelltaleToolLib's ``MetaClassDescription`` +
``MetaMemberDescription`` C++ structures into a pure-Python runtime type
system keyed by CRC64 of the lowercased class name (Telltale's Symbol hash,
see ``telltale.crc64.crc64_str``).

Reflection model
----------------
A Telltale MetaStream file carries a header listing ``(class_name_hash,
version)`` pairs for every class serialised in the payload.  The decoder
must look up each class by hash, iterate its members in declaration order,
apply version-gating rules, and either read or skip each member's block.

This module provides the primitives for that lookup:

* ``@meta_class("ClassName")`` — decorator that registers a Python
  ``@dataclass`` against ``_REGISTRY`` keyed by ``crc64_str("ClassName")``.
  The decorator is transparent: it returns ``cls`` unchanged.

* ``meta_member(name, ttype, flags, min_version)`` — ``dataclasses.field``
  factory.  Stores a ``MetaMember`` sentinel in the field's ``metadata``
  dict under key ``"meta"`` so the decorator can harvest members in
  declaration order via ``dataclasses.fields()``.

* ``get_by_hash(crc64_hash)`` — looks up ``_REGISTRY``; returns ``None``
  on a miss (never raises).  The ``None`` contract is load-bearing: it lets
  callers fall through to ``MetaStreamReader.skip_block()`` (the
  INFRA-04 skip-unknown-members escape hatch from Phase 1) without a
  try/except.

* ``get_by_name(name)`` — convenience wrapper that hashes internally.

* ``is_member_disabled(member, stream_version)`` — mirrors
  ``Meta_IsMemberDisabled`` from TelltaleToolLib/ToolLibrary/Meta.cpp line
  1525.  Branch order: flag-bit check first, then ``min_version > stream_version``.

* ``is_member_blocking_disabled(member)`` — returns True iff the member
  carries ``MetaFlag_MetaSerializeBlockingDisabled``, meaning the decoder
  should NOT wrap the member's bytes in a ``begin_block`` / ``end_block``
  size-prefix.

No walk/decode logic lives here.  Primitive registration (Phase 3), container
types (Phase 4), PropertySet (Phase 5), and Chore sub-structs (Phase 7) are
separate concerns.  This module has no dependencies on ``telltale.metastream``
or ``telltale.validation`` — it is consumed by them (and by future decoders),
never the reverse.
"""

from __future__ import annotations

import dataclasses
import logging
from dataclasses import dataclass, field
from typing import Any

from telltale.crc64 import crc64_str

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Flag constants
# Authoritative source: TelltaleToolLib/ToolLibrary/Meta.hpp enum MetaFlag
# (lines 963-965).  Values are 1 and 2 — NOT bit-shifts 1<<1 and 1<<2.
# ---------------------------------------------------------------------------

MetaFlag_MetaSerializeDisable: int = 1
"""Member is never serialised (always skip on read AND write)."""

MetaFlag_MetaSerializeBlockingDisabled: int = 2
"""Member bytes are NOT wrapped in a begin_block / end_block size prefix."""


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class MetaMember:
    """Immutable descriptor for one serialised member of a MetaClass.

    Mirrors the fields of ``MetaMemberDescription`` in Meta.hpp that are
    relevant for decode dispatch and version gating:

    Attributes
    ----------
    name:
        Canonical member name string (as declared in TTL source).
    ttype:
        Python type or forward-reference string for the member's value type.
        Phase 3+ will resolve forward strings against the registry.
    flags:
        Bitmask of ``MetaFlag_*`` constants.  Default 0 (no flags).
    min_version:
        Minimum stream version at which this member is included.  -1 (default)
        means the member is always included regardless of stream version.
    """

    name: str
    ttype: Any          # type | str forward-ref (for recursive types in later phases)
    flags: int = 0
    min_version: int = -1


@dataclass
class MetaClassDescription:
    """Runtime descriptor for a Telltale MetaClass.

    Mirrors the fields of ``MetaClassDescription`` in Meta.hpp that are
    needed for MetaStream decode dispatch:

    Attributes
    ----------
    name:
        Class name string (not lowercased — preserves the original casing for
        display; the registry key uses the lowercased CRC64).
    type_hash:
        ``crc64_str(name)`` — the 64-bit hash used as the registry key and
        present in MetaStream headers.
    version_crc:
        Optional ``SerializedVersionInfo`` CRC.  Populated by Phase 3+ when
        the class carries a versioned schema; ``None`` until then.
    members:
        Ordered list of ``MetaMember`` descriptors, in declaration order.
        Phase 3+ walkers iterate this list to dispatch each member's decoder.
    dataclass_cls:
        The Python ``@dataclass`` class that was decorated with
        ``@meta_class``.  ``None`` for classes registered programmatically
        without a backing dataclass.
    """

    name: str
    type_hash: int
    version_crc: int | None = None
    members: list[MetaMember] = field(default_factory=list)
    dataclass_cls: type | None = None


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_REGISTRY: dict[int, MetaClassDescription] = {}
"""Module-level registry keyed by crc64_str(class_name).

Phase 3+ modules populate this by importing their decoder modules (which
trigger ``@meta_class`` registration as a side effect of import).  Do NOT
add a reset/clear helper — registration is persistent across the process
lifetime by design.
"""


# ---------------------------------------------------------------------------
# Field factory
# ---------------------------------------------------------------------------

def meta_member(
    name: str,
    ttype: Any,
    flags: int = 0,
    min_version: int = -1,
) -> Any:
    """Declare a MetaStream-serialised member on a ``@meta_class`` dataclass.

    Returns a ``dataclasses.field()`` with ``default=None`` (so the host
    dataclass can be instantiated without arguments in tests) and a
    ``metadata`` dict that carries a ``MetaMember`` sentinel under the key
    ``"meta"``.

    The ``@meta_class`` decorator walks ``dataclasses.fields(cls)`` and
    harvests every field whose ``metadata`` contains ``"meta"``, in
    declaration order, to build the ``members`` list of the
    ``MetaClassDescription``.

    Parameters
    ----------
    name:
        Canonical member name (as in TTL source).
    ttype:
        Type or forward-reference string for this member's value.
    flags:
        Bitmask of ``MetaFlag_*`` constants (default 0).
    min_version:
        Minimum stream version required for this member (default -1 = always).
    """
    return field(
        default=None,
        metadata={"meta": MetaMember(name=name, ttype=ttype, flags=flags, min_version=min_version)},
    )


# ---------------------------------------------------------------------------
# Registration decorator
# ---------------------------------------------------------------------------

def meta_class(name: str):
    """Register a Python dataclass as a Telltale ``MetaClassDescription``.

    Keys the registry by ``crc64_str(name)`` — Telltale's lowercased-name
    Symbol CRC64 (see ``telltale.crc64.crc64_str``).  The decorator is
    transparent: it returns ``cls`` unchanged so downstream code sees the
    original dataclass.

    Raises ``ValueError`` on a genuine CRC64 collision (different class names
    hashing to the same value).  Re-registering the same name silently
    overwrites the previous entry (idempotent for module reimports).

    Parameters
    ----------
    name:
        Class name as it appears in the Telltale MetaStream header.  Casing
        is preserved in ``MetaClassDescription.name``; ``crc64_str`` handles
        lowercasing before hashing.
    """
    def _register(cls: type) -> type:
        members: list[MetaMember] = []
        for f in dataclasses.fields(cls):
            meta = f.metadata.get("meta")
            if isinstance(meta, MetaMember):
                members.append(meta)

        type_hash = crc64_str(name)
        desc = MetaClassDescription(
            name=name,
            type_hash=type_hash,
            version_crc=None,
            members=members,
            dataclass_cls=cls,
        )

        existing = _REGISTRY.get(type_hash)
        if existing is not None and existing.name != name:
            raise ValueError(
                f"CRC64 collision at {type_hash:#018x}: "
                f"existing={existing.name!r}, new={name!r}"
            )

        _REGISTRY[type_hash] = desc
        log.debug(
            "meta_class registered: %s -> %#018x (%d members)",
            name,
            type_hash,
            len(members),
        )
        return cls

    return _register


# ---------------------------------------------------------------------------
# Lookups
# ---------------------------------------------------------------------------

def get_by_hash(crc64_hash: int) -> MetaClassDescription | None:
    """Look up a registered class by its CRC64 type hash.

    Returns ``None`` on a miss — never raises.  The ``None`` contract lets
    MetaStream walker callers fall through to ``MetaStreamReader.skip_block()``
    (the INFRA-04 skip-unknown-members escape hatch from Phase 1) without
    requiring a try/except around every member dispatch.

    Parameters
    ----------
    crc64_hash:
        64-bit CRC64 hash, typically read directly from a MetaStream header
        class-entry or from a member type descriptor.
    """
    return _REGISTRY.get(crc64_hash)


def get_by_name(name: str) -> MetaClassDescription | None:
    """Look up a registered class by its canonical class name.

    Hashes ``name`` internally via ``crc64_str`` before looking up in
    ``_REGISTRY``.  Returns ``None`` on a miss (never raises).

    Parameters
    ----------
    name:
        Class name string (casing is ignored — ``crc64_str`` lowercases).
    """
    return _REGISTRY.get(crc64_str(name))


# ---------------------------------------------------------------------------
# Version-gating predicates
# ---------------------------------------------------------------------------

def is_member_disabled(member: MetaMember, stream_version: int) -> bool:
    """Return True if this member should be skipped for the given stream version.

    Mirrors ``Meta_IsMemberDisabled`` from
    TelltaleToolLib/ToolLibrary/Meta.cpp lines 1525-1530, preserving the
    exact branch order:

    1. Flag-bit check: ``member.flags & MetaFlag_MetaSerializeDisable``.
    2. If not yet disabled and ``member.min_version != -1``: disable when
       ``member.min_version > stream_version`` (strict ``>``, not ``>=``).

    Parameters
    ----------
    member:
        The ``MetaMember`` descriptor to test.
    stream_version:
        Version integer from ``MetaStreamReader.stream_version`` (Phase 1).
        Pass -1 when no version information is available (conservative —
        causes min_version-gated members to be disabled).
    """
    disable = bool(member.flags & MetaFlag_MetaSerializeDisable)
    if not disable and member.min_version != -1 and member.min_version > stream_version:
        disable = True
    return disable


def is_member_blocking_disabled(member: MetaMember) -> bool:
    """Return True if the member's bytes are NOT wrapped in a size-prefix block.

    Tests ``member.flags & MetaFlag_MetaSerializeBlockingDisabled``.  When
    True, Phase 5+ walkers must read the member inline without calling
    ``MetaStreamReader.begin_block`` / ``end_block``.

    Mirrors the blocking-branch check from TTL Meta.hpp struct
    ``MetaMemberDescription`` (the ``mFlags & MetaFlag_MetaSerializeBlockingDisabled``
    branch in the serialise loop).

    Parameters
    ----------
    member:
        The ``MetaMember`` descriptor to test.
    """
    return bool(member.flags & MetaFlag_MetaSerializeBlockingDisabled)
