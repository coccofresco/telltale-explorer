"""
Container decoders for Telltale MetaStream (DCArray / Set / List / SArray / Map).

This module covers Phase 4. Plan 04-01 ships everything except Map;
Plan 04-02 layers the Map<K,V> decoder + MTRE Symbol-key debug-strlen branch.
Plan 04-03 wires PhonemeEntry registration and proves the pipeline on all 74 EP1 ptables.

On-disk frames (reversed from TelltaleToolLib/ToolLibrary/Types/*.h):

    DCArray<T>  [u32 count][u32 inner_block_size][count*elem]<end>
    Set<T>      [u32 count][count*elem]                     (NO inner block)
    List<T>     [u32 count][count*elem]                     (NO inner block)
    SArray<T,N> [u32 inner_block_size][N*elem]              (NO count prefix; N is static)
    Map<K,V>    [u32 count][count*(K,V)]                    (NO inner block; see Plan 04-02)

The inner-block wrapper for DCArray/SArray is MetaStream::BeginObject(name, true)
which calls BeginBlock (Meta.cpp lines 595-599). Set/List/Map do NOT call BeginObject.

dispatch_container(name, reader, stream_version) is the public entry point:
    - Parses "DCArray<Vector3>", "Map<Symbol,V>", "SArray<int,4>" via _parse_container_name
    - Resolves inner element decoder(s) via telltale.meta_intrinsics.get_decoder_by_name
    - Returns None (never raises) when the container kind or inner type is unresolved;
      caller falls back to MetaStreamReader.skip_block() per INFRA-04.
"""
from __future__ import annotations

import logging
from typing import Any, List, Optional, Tuple

from telltale.meta_intrinsics import get_decoder_by_name, DecoderFn, decode_symbol
from telltale.metastream import MetaStreamReader

log = logging.getLogger(__name__)

_CONTAINER_KINDS = frozenset({"DCArray", "Map", "Set", "SArray", "List"})


def _parse_container_name(name: str) -> Tuple[Optional[str], List[str]]:
    """Split a stripped TTL template name into (kind, [inner_args]).

    Uses bracket-balance (NOT regex) so nested templates parse correctly.
    Returns (None, []) when *name* has no '<' (not a template).
    Raises ValueError on unbalanced brackets or trailing data after '>'.

    Examples::

        "DCArray<Vector3>"           -> ("DCArray", ["Vector3"])
        "Map<Symbol,PhonemeEntry>"   -> ("Map",     ["Symbol", "PhonemeEntry"])
        "Map<Symbol, DCArray<Vector3>>" -> ("Map",  ["Symbol", "DCArray<Vector3>"])
        "Set<Handle<PropertySet>>"   -> ("Set",     ["Handle<PropertySet>"])
        "SArray<int,4>"              -> ("SArray",  ["int", "4"])
        "int"                        -> (None, [])
    """
    lt = name.find("<")
    if lt < 0:
        return (None, [])
    kind = name[:lt]
    # Walk with a depth counter starting after the initial '<'.
    depth = 1
    start = lt + 1
    args: List[str] = []
    i = start
    n = len(name)
    while i < n and depth > 0:
        c = name[i]
        if c == "<":
            depth += 1
        elif c == ">":
            depth -= 1
            if depth == 0:
                arg = name[start:i].strip()
                if arg:
                    args.append(arg)
                # Trailing data after the matching '>' is invalid.
                if i + 1 != n:
                    raise ValueError(
                        f"Trailing data after template close in {name!r}: "
                        f"{name[i + 1:]!r}"
                    )
        elif c == "," and depth == 1:
            args.append(name[start:i].strip())
            start = i + 1
        i += 1
    if depth != 0:
        raise ValueError(f"Unbalanced brackets in {name!r}")
    return (kind, args)


def decode_dcarray(
    reader: MetaStreamReader,
    stream_version: int,
    elem_decoder: Optional[DecoderFn],
) -> Optional[List[Any]]:
    """Decode DCArray<T>: [u32 count][u32 inner_block_size][count*elem]<end>.

    Authoritative TTL frame: DCArray<T>::MetaOperation_SerializeAsync
    (TelltaleToolLib/ToolLibrary/Types/DCArray.h lines 51-101). The ``size``
    is serialized BEFORE BeginObject("DCArray", true), which wraps only the
    elements in a begin_block/end_block pair.

    Returns a list of decoded elements, or None if *elem_decoder* is None.
    The sanity cap (0x10000) mirrors the ``TelltaleToolLib_RaiseError`` guard
    at DCArray.h line 71; a ``ValueError`` is raised on overflow since this
    decoder is read-only.
    """
    if elem_decoder is None:
        return None
    count = reader.read_uint32()
    if count > 0x10000:
        raise ValueError(
            f"DCArray count {count:#x} exceeds TTL sanity limit 0x10000"
        )
    reader.begin_block()
    out: List[Any] = [elem_decoder(reader, stream_version) for _ in range(count)]
    reader.end_block()
    return out


def decode_set(
    reader: MetaStreamReader,
    stream_version: int,
    elem_decoder: Optional[DecoderFn],
) -> Optional[set]:
    """Decode Set<T>: [u32 count][count*elem].  NO inner block wrapper.

    Authoritative TTL frame: Set<T>::MetaOperation_SerializeAsync
    (TelltaleToolLib/ToolLibrary/Types/Set.h lines 21-42). The TTL code
    does not call BeginObject for Set/List/Map.

    Returns a set of decoded elements, or None if *elem_decoder* is None.
    """
    if elem_decoder is None:
        return None
    count = reader.read_uint32()
    out: set = set()
    for _ in range(count):
        out.add(elem_decoder(reader, stream_version))
    return out


def decode_list(
    reader: MetaStreamReader,
    stream_version: int,
    elem_decoder: Optional[DecoderFn],
) -> Optional[List[Any]]:
    """Decode List<T>: [u32 count][count*elem].  NO inner block wrapper.

    Authoritative TTL frame: List<T>::MetaOperation_SerializeAsync
    (TelltaleToolLib/ToolLibrary/Types/List.h lines 21-42). Identical
    wire format to Set; only the in-memory container differs.

    Returns a list of decoded elements, or None if *elem_decoder* is None.
    """
    if elem_decoder is None:
        return None
    count = reader.read_uint32()
    return [elem_decoder(reader, stream_version) for _ in range(count)]


def decode_sarray(
    reader: MetaStreamReader,
    stream_version: int,
    elem_decoder: Optional[DecoderFn],
    count: int,
) -> Optional[List[Any]]:
    """Decode SArray<T, N>: [u32 inner_block_size][N*elem].

    *count* is the static template argument N, parsed from the container
    name by the caller. Authoritative TTL frame:
    SArray<T,N>::MetaOperation_SerializeAsync (SArray.h lines 35-56).
    No count prefix on the wire — N is a compile-time constant.

    Returns a list of exactly *count* elements, or None if *elem_decoder*
    is None.
    """
    if elem_decoder is None:
        return None
    reader.begin_block()
    out = [elem_decoder(reader, stream_version) for _ in range(count)]
    reader.end_block()
    return out


def _resolve_inner(
    inner_name: str,
    stream_version: int,
) -> Optional[DecoderFn]:
    """Resolve an inner-type name to a decoder callable.

    Tries the flat registry first (covers intrinsics, math types, registered
    dataclasses, and Handle<T> concretizations from Phase 3-03). Falls back
    to a recursive dispatch_container wrapper when *inner_name* is itself a
    container template (e.g. DCArray<Vector3> inside Map<Symbol, DCArray<Vector3>>).

    Returns None for truly unknown names so callers can skip_block per INFRA-04.
    """
    dec = get_decoder_by_name(inner_name)
    if dec is not None:
        return dec
    kind, _ = _parse_container_name(inner_name)
    if kind in _CONTAINER_KINDS:
        # Recursive wrapper. Captures inner_name by closure; stream_version
        # is read from the caller each invocation to stay consistent under nesting.
        def _nested(r: MetaStreamReader, sv: int) -> Any:
            return dispatch_container(inner_name, r, sv)
        return _nested
    return None


def decode_map(
    reader: MetaStreamReader,
    stream_version: int,
    key_decoder: Optional[DecoderFn],
    value_decoder: Optional[DecoderFn],
    *,
    mtre_symbol_key_debug_strlen: bool = False,
) -> Any:
    """Decode Map<K,V>: [u32 count][count*(K,V)].  NO container-level block wrapper.

    Authoritative TTL frame: Map<K,V>::MetaOperation_SerializeAsync
    (TelltaleToolLib/ToolLibrary/Types/Map.h lines 29-58). TTL code calls
    serialize_uint32 for size then iterates key/value serializers in order;
    NO BeginObject/BeginBlock around the pairs.

    When mtre_symbol_key_debug_strlen=True, consume a trailing u32=0 after
    EACH Symbol KEY (not after each value). This is the MTRE debug-info
    artifact empirically observed on all 74 ep1 ``.ptable`` files
    (parse_ptable.py lines 78-83). In that mode key_decoder is IGNORED — we
    call decode_symbol(..., include_mtre_debug_strlen=True) directly so the
    bare registered Symbol decoder stays MTRE-free.

    Return type:
      - dict[K, V]           when all keys are hashable and unique
      - list[tuple[K, V]]    when any key is unhashable (Handle, dataclass, etc.)

    Duplicate keys raise ValueError under the dict path; under the list-of-
    tuples fallback duplicates are preserved in order.

    Returns None if either key_decoder or value_decoder is None (when not
    using the implicit MTRE Symbol key path). In MTRE mode only value_decoder
    None triggers a None return.
    """
    if value_decoder is None:
        return None
    if not mtre_symbol_key_debug_strlen and key_decoder is None:
        return None

    count = reader.read_uint32()
    out_dict: dict = {}
    out_list: Optional[list] = None  # fallback when a key is unhashable

    for _ in range(count):
        if mtre_symbol_key_debug_strlen:
            key = decode_symbol(reader, stream_version, include_mtre_debug_strlen=True)
        else:
            key = key_decoder(reader, stream_version)  # type: ignore[misc]
        value = value_decoder(reader, stream_version)

        if out_list is not None:
            out_list.append((key, value))
            continue

        try:
            if key in out_dict:
                raise ValueError(f"Duplicate key in Map: {key!r}")
            out_dict[key] = value
        except TypeError:
            # Unhashable key — promote everything collected so far to a list.
            out_list = list(out_dict.items())
            out_list.append((key, value))
            out_dict = {}  # drained

    return out_list if out_list is not None else out_dict


def dispatch_container(
    name: str,
    reader: MetaStreamReader,
    stream_version: int,
) -> Any:
    """Parse *name* as a TTL template and dispatch to the matching decoder.

    Returns ``None`` when:

    * *name* has no ``<`` (not a template, e.g. ``"Vector3"``).
    * The parsed kind is not one of ``DCArray / Set / List / SArray / Map``.
    * Any required inner element decoder is unresolved.

    The caller is expected to fall back to
    :meth:`MetaStreamReader.skip_block` on a ``None`` return per INFRA-04.

    Inner-type resolution uses ``_resolve_inner`` which tries the flat decoder
    registry first, then falls back to a recursive ``dispatch_container``
    wrapper for container templates — enabling nested types like
    ``Map<Symbol, DCArray<Vector3>>`` and ``DCArray<DCArray<int>>`` without
    pre-registering every concretization.
    """
    try:
        kind, args = _parse_container_name(name)
    except ValueError:
        log.warning("dispatch_container: malformed template name %r", name)
        return None

    if kind is None or kind not in _CONTAINER_KINDS:
        return None

    if kind == "DCArray":
        if len(args) != 1:
            log.warning("DCArray expects 1 type arg, got %r", args)
            return None
        return decode_dcarray(reader, stream_version, _resolve_inner(args[0], stream_version))

    if kind == "Set":
        if len(args) != 1:
            log.warning("Set expects 1 type arg, got %r", args)
            return None
        return decode_set(reader, stream_version, _resolve_inner(args[0], stream_version))

    if kind == "List":
        if len(args) != 1:
            log.warning("List expects 1 type arg, got %r", args)
            return None
        return decode_list(reader, stream_version, _resolve_inner(args[0], stream_version))

    if kind == "SArray":
        if len(args) != 2:
            log.warning("SArray expects 2 type args, got %r", args)
            return None
        try:
            n = int(args[1])
        except ValueError:
            log.warning("SArray N arg is not an integer: %r", args[1])
            return None
        return decode_sarray(reader, stream_version, _resolve_inner(args[0], stream_version), n)

    if kind == "Map":
        if len(args) != 2:
            log.warning("Map expects 2 type args, got %r", args)
            return None
        k_name, v_name = args
        k_dec = _resolve_inner(k_name, stream_version)
        v_dec = _resolve_inner(v_name, stream_version)
        if v_dec is None:
            return None
        # Auto-enable MTRE Symbol-key debug-strlen framing.
        auto_mtre = (k_name == "Symbol") and (stream_version <= 4)
        if not auto_mtre and k_dec is None:
            return None
        return decode_map(
            reader, stream_version, k_dec, v_dec,
            mtre_symbol_key_debug_strlen=auto_mtre,
        )

    # Unreachable — guarded by _CONTAINER_KINDS membership check above.
    return None  # pragma: no cover
