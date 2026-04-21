# CHORE — Choreography Files (full decoder)

**Status:** v1.2 complete — 1929 / 1929 EP1 chores parse cleanly (0 misaligned).
iOS-grounded schema from Tales of Monkey Island ARM32 binary (VA 0x00205788).

Choreography files tie together animations, dialog, audio and cameras for
cutscenes and per-agent behaviours. This document describes the FULL on-disk
schema as decoded by `telltale.chore.parse_chore`. For the v1.1 surface-level
scraper (still shipped as the CLI entry point), see
[`inspect_chore.py`](#cli--inspect_chorepy).

---

## Quick start

```python
from telltale.chore import parse_chore, extract_handles

chore = parse_chore("path/to/my.chore")
print(chore.mName, chore.mLength, len(chore.resources), len(chore.agents))
for handle in extract_handles(chore, path="path/to/my.chore"):
    print(handle)
```

`extract_handles(chore, path=path)` returns a sorted, deduplicated list of
every asset reference found in the decoded struct (Handle fields, scene file,
resource groups, dependency names) plus a raw-scan supplement for opaque
PAL constraint-graph blobs. Passing `path=` guarantees a strict superset of
the v1.1 `inspect_chore` handle output for all 1929 EP1 files.

### Public names exported from `telltale.chore`

| Name | Type | Description |
|------|------|-------------|
| `parse_chore(path)` | function | Main entry point; accepts `str` or `pathlib.Path`. |
| `extract_handles(chore, path=None)` | function | Returns every Handle-typed string in the decoded `Chore`. |
| `validate_chores(paths)` | function | Corpus harness; returns `ChoreValidationReport`. |
| `Chore` | dataclass | Top-level choreography struct (12 fields + resources + agents). |
| `ChoreResource` | dataclass | One entry from the ChoreResource post-loop. |
| `ChoreAgent` | dataclass | One entry from the ChoreAgent post-loop. |

---

## On-disk layout

Chore files are MetaStream containers (`MTRE` / `MSV5` / `MSV6`) wrapping a
`Chore` struct of 12 top-level members followed by a custom post-loop that
serializes `mNumResources` × `ChoreResource` and `mNumAgents` × `ChoreAgent`.

### MetaStream container

`telltale.metastream.MetaStreamReader` (Phase 1) handles all four MetaStream
variants:

| Magic (on-disk LE) | Canonical name | Notes |
|--------------------|----------------|-------|
| `ERTM` (0x4D545245) | MTRE | Sam & Max S2 through TWD S1; used by all EP1 chores |
| `5VSM` | MSV5 | Puzzle Agent era; per-member block-size prefixes |
| `6VSM` | MSV6 | Wolf Among Us onward |
| `MBIN` | MBIN | Earliest Telltale titles; not seen in EP1 chores |

The header encodes a list of `(class_name_crc64, serialized_version)` pairs for
every class serialized in the payload. After the header, `MetaStreamReader`
maintains a block stack: each `begin_block()` call reads a 4-byte little-endian
size prefix (MSV5/MSV6) or is a no-op (MTRE), and `end_block()` seeks to the
end of that block. This block-stack mechanism is how unknown fields are skipped
gracefully.

### Field-walk authority

The iOS binary is the authoritative source of field-walk order
(see [`CHORE_DISASM.md`](./CHORE_DISASM.md)). `Chore::MetaOperation_Serialize`
(iOS VA `0x00205788`, symbol
`__ZN5Chore23MetaOperation_SerializeEPvPK20MetaClassDescriptionPK21MetaMemberDescriptionS0_`)
performs a SINGLE `bl` to `Meta::MetaOperation_SerializeAsync` (VA `0x001E99CC`)
for the 12-member default walk, then two custom post-loops. Where TelltaleToolLib
disagrees with iOS, iOS wins (standing project decision; `PROJECT.md`).

---

## MetaClass reflection model

The Telltale MetaClass system (mirrored in `telltale.metaclass`) provides:

- **`@meta_class("ClassName")`** — registers a `@dataclass` in `_REGISTRY`
  keyed by `crc64_str("ClassName")` (CRC64 of the lowercased name).
- **`meta_member(name, ttype, flags, min_version)`** — `dataclasses.field`
  factory that stores a `MetaMember` sentinel in the field's `metadata` dict,
  so member declaration order can be recovered at runtime.
- **`_REGISTRY`** — `dict[int, MetaClassEntry]` mapping CRC64 hashes to
  registered dataclasses and their member lists.
- **`_DECODERS`** — `dict[int, Callable]` mapping CRC64 hashes to decoder
  functions (registered via `telltale.meta_intrinsics.register`).
- **`get_by_hash(crc64_hash)`** — returns `None` on miss (never raises);
  callers fall through to `MetaStreamReader.skip_block()`.

The MetaStream file header's class-entry list is matched against `_REGISTRY`
at parse time. Unknown class hashes fall through to `skip_block()` via
`get_by_hash`'s `None` contract.

### Intrinsics and math types

`telltale.meta_intrinsics` registers leaf decoders for:
`String` (blocked length-prefixed latin-1), `Symbol` (CRC64 u64),
`int` / `float` / `bool` (u32, f32, u8 respectively), `Flags` (u32).

`telltale.meta_math` registers: `Vector3` (3 × f32), `Quaternion` (4 × f32),
`Transform` (Quaternion + Vector3 = 7 × f32), `Color` (4 × f32).

### Handle<T> version branch

`telltale.meta_handle.decode_handle` reads a `Handle<T>` reference. The
branch is governed by `stream_version`:

- **MTRE (sv ≤ 3):** `mhObject` is stored as a plain blocked `String` — the
  filename of the referenced asset (e.g. `"sk15_run.anm"`).
- **MSV5/MSV6 (sv ≥ 5):** `mhObject` is stored as a `Handle` struct with
  `object_name_str`, backed by `HandleObjectInfo`.

`extract_handles` handles both representations: the plain-string MTRE case is
harvested explicitly; the Handle-struct MSV5 case is harvested by the recursive
`_walk_for_handles` walker.

### Generic containers

`telltale.meta_containers.dispatch_container` resolves container types by
canonical name string:

| Container type | Wire framing | Notes |
|---------------|--------------|-------|
| `DCArray<T>` | outer block + u32 count + N × T | `T` may itself be blocked |
| `Map<K, V>` | outer block + u32 count + N × (K + V) | MTRE: Symbol keys have debug strlen prefix |
| `SArray<T, N>` | outer block + N inline T | Fixed-count variant |
| `Set<T>` | outer block + u32 count + N × T | Ordered set |
| `List<T>` | outer block + u32 count + N × T | Doubly-linked list (serialized like DCArray) |

In MTRE (sv ≤ 4), `decode_map` automatically enables the debug-strlen prefix
for `Symbol` keys: each key begins with a 4-byte strlen + that many ASCII
bytes (the CRC source string), followed by the 8-byte CRC64 value.

---

## `Chore` — 12 top-level fields

Field-walk order: iOS `Chore::InternalGetMetaClassDescription` (VA `0x000B609C`)
registers members in exact declaration order matching `Chore.h:422-433`. The
default walk dispatches through `Meta::MetaOperation_SerializeAsync`
(VA `0x001E99CC`). No field-order drift vs TelltaleToolLib was observed.

Python dataclass: `telltale.meta_chore.Chore` (re-exported via `telltale.chore`).

### 1. `mName` — String (blocked)

**Purpose:** Display name of the choreography (e.g. `"adv_dock_seagull_idleB"`).
Decoded by `decode_string(reader, sv)`: a begin_block/end_block envelope
wrapping a u32 strlen + strlen bytes of latin-1.

- **Wire:** blocked String
- **Python field:** `Chore.mName: str`
- **TTL:** `Chore.h:422`
- **iOS:** dispatched via `Meta::MetaOperation_SerializeAsync` (VA `0x001E99CC`), field order 1

### 2. `mFlags` — Flags (u32 or u8 in MTRE)

**Purpose:** Bitmask of choreography behaviour flags (e.g. loop, solo, hold).

- **Wire (MSV5/MSV6):** blocked u32
- **Wire (MTRE non-hint):** raw u8 at byte 0 of the post-mName unframed scalar run
  (13-byte run: `u8 mFlags + f32 mLength + i32 mNumResources + i32 mNumAgents`)
- **Wire (MTRE hint):** absent from wire — defaulted to 0
- **Python field:** `Chore.mFlags: int`
- **TTL:** `Chore.h:423`
- **iOS:** field order 2 in default member walk

### 3. `mLength` — float

**Purpose:** Duration of the choreography in seconds.

- **Wire (MSV5/MSV6):** blocked f32
- **Wire (MTRE non-hint):** raw f32 at bytes 1-4 of the unframed scalar run
- **Wire (MTRE hint):** absent from wire — defaulted to 0.0
- **Python field:** `Chore.mLength: float`
- **TTL:** `Chore.h:424`
- **iOS:** field order 3 in default member walk

### 4. `mNumResources` — int32

**Purpose:** Count of `ChoreResource` entries to follow in the custom post-loop.
Used by the decoder to drive `for i in range(chore.mNumResources): ...`.

- **Wire (MSV5/MSV6):** blocked i32
- **Wire (MTRE non-hint):** raw i32 at bytes 5-8 of the unframed scalar run
- **Wire (MTRE hint):** absent from wire — defaulted to 0
- **Python field:** `Chore.mNumResources: int`
- **TTL:** `Chore.h:425`
- **iOS:** `ldr r3, [r2, #0xc]` in loop-bound check for ChoreResource post-loop (VA `0x00205934`)

### 5. `mNumAgents` — int32

**Purpose:** Count of `ChoreAgent` entries to follow after all ChoreResource entries.

- **Wire (MSV5/MSV6):** blocked i32
- **Wire (MTRE non-hint):** raw i32 at bytes 9-12 of the unframed scalar run
- **Wire (MTRE hint):** absent from wire — defaulted to 0
- **Python field:** `Chore.mNumAgents: int`
- **TTL:** `Chore.h:426`
- **iOS:** `ldr r3, [r2, #0x10]` in loop-bound check for ChoreAgent post-loop (VA `0x00205B48`)

### 6. `mEditorProps` — PropertySet

**Purpose:** Editor-only metadata (key-value store). Keys are Symbol CRC64s;
values are typed variants (`int`, `float`, `bool`, `Vector3`, `Handle`, and
others). See the [PropertySet section](#propertyset-value-variants) below.

Decoded by `telltale.meta_propertyset.decode_propertyset`.

- **Wire:** blocked PropertySet (FORMAT A or B depending on stream version)
- **Python field:** `Chore.mEditorProps: Any` (a `PropertySet` dataclass)
- **TTL:** `Chore.h:427`
- **iOS:** field order 6 in default member walk
- **MTRE complication:** MTRE non-hint chores use FORMAT B with `mPropVersion=1`
  which omits the padding byte that FORMAT B normally skips. The decoder recovers
  via try/except: if `decode_propertyset` raises, the block stack is drained and
  the reader seeks to `end_abs`, yielding an empty `PropertySet(mPropVersion=0, mPropertyFlags=0)`.

### 7. `mChoreSceneFile` — String (blocked)

**Purpose:** Path to the scene asset this choreography targets
(e.g. `"adv_ocean_act3.scene"`). Semantically a handle reference — included
in `extract_handles` output.

- **Wire (MSV5/MSV6):** blocked String
- **Wire (MTRE non-hint):** follows the `'30 31'` 2-byte marker after mEditorProps; decoded via `_mtre_read_string_block`
- **Wire (MTRE hint):** decoded via partial strlen reconstruction from the split block boundary
- **Python field:** `Chore.mChoreSceneFile: str`
- **TTL:** `Chore.h:428`
- **iOS:** field order 7 in default member walk

### 8. `mRenderDelay` — int32

**Purpose:** Render delay in milliseconds (typically 0 or small positive integer).

- **Wire (MSV5/MSV6):** blocked i32
- **Wire (MTRE):** raw i32 immediately following `mChoreSceneFile` block
- **Python field:** `Chore.mRenderDelay: int`
- **TTL:** `Chore.h:429`
- **iOS:** field order 8 in default member walk

### 9. `mSynchronizedToLocalization` — LocalizeInfo

**Purpose:** Localization synchronization metadata (mFlags u32). Governs
whether the chore's timing is locked to localized audio.

Decoded by `telltale.meta_chore_leaves.decode_localize_info`.

- **Wire (MSV5/MSV6):** blocked LocalizeInfo struct (mFlags u32 inside a block)
- **Wire (MTRE):** part of the 22-byte constant tail (fields 9–12 combined);
  decoded as `LocalizeInfo(mFlags=0)` default
- **Python field:** `Chore.mSynchronizedToLocalization: LocalizeInfo`
- **TTL:** `Chore.h:430`
- **iOS:** field order 9 in default member walk

### 10. `mDependencies` — DependencyLoader\<1\>

**Purpose:** Declares asset dependencies by name. The decoder populates
`mpResNames: list[str]` which `extract_handles` includes in handle output.

`DependencyLoader<1>` carries `MetaFlag_Memberless` — it manages its own
framing internally (no outer `begin_block`/`end_block` from the caller in
MSV5/MSV6; the decoder internally reads a blocked String list).

- **Wire (MSV5/MSV6):** custom-framed (Memberless flag); internally a blocked list of Strings
- **Wire (MTRE):** part of the 22-byte constant tail — decoded as `DependencyLoader1()` default
- **Python field:** `Chore.mDependencies: DependencyLoader1`
- **TTL:** `Chore.h:431`
- **iOS:** field order 10 in default member walk

### 11. `mToolProps` — ToolProps

**Purpose:** Tool-layer properties (optional inline `PropertySet`). Contains
`mbHasProps: bool` + a conditional `PropertySet` payload when true.

`ToolProps` has a custom serializer: inline u8 `mbHasProps` followed by the
`PropertySet` only when `mbHasProps == 1`.

- **Wire (MSV5/MSV6):** blocked ToolProps (inner custom framing)
- **Wire (MTRE):** part of the 22-byte constant tail — decoded as `ToolProps(mbHasProps=False)` default
- **Python field:** `Chore.mToolProps: ToolProps`
- **TTL:** `Chore.h:432`
- **iOS:** field order 11 in default member walk

### 12. `mWalkPaths` — Map\<Symbol, WalkPath\>

**Purpose:** Named walk/movement paths attached to the choreography. Each
`WalkPath` contains a polymorphic `mPath` field that dispatches to one of:
`PathSegment`, `HermiteCurvePathSegment`, or `AnimationDrivenPathSegment`.

Decoded by `dispatch_container("Map<Symbol, WalkPath>", reader, sv)`.
MTRE streams auto-enable debug-strlen for `Symbol` keys.

- **Wire (MSV5/MSV6):** blocked `Map<Symbol, WalkPath>` (N × (Symbol + WalkPath))
- **Wire (MTRE):** part of the 22-byte constant tail — decoded as `{}` default (empty map)
- **Python field:** `Chore.mWalkPaths: dict`
- **TTL:** `Chore.h:433`
- **iOS:** field order 12 in default member walk; `mWalkPaths order confirmed` (CHORE_DISASM.md)

---

## `ChoreResource` — 21 fields

iOS VA: `PerformMetaSerialize<ChoreResource>` at `0x002089D0`, invoked from
`Chore::MetaOperation_Serialize` (VA `0x00205788`) in the custom post-loop.
`ChoreResource::MetaOperation_Serialize` (VA `0x002113E0`) calls
`Meta::MetaOperation_SerializeAsync` (VA `0x001E99CC`) then handles the
MSV1 embedded-object branch at VA `0x00211494`.

Python dataclass: `telltale.meta_chore.ChoreResource`.

**No `BeginBlock`/`EndBlock` calls wrap the entire ChoreResource** — all fields
are inline MTRE framing. Individual fields in MSV5/MSV6 are each block-wrapped
by the standard MetaClass member walk.

**Not serialized (runtime-only):** `mpChore` (Chore.h:268, back-pointer),
`mhObjectEmbedded` (Chore.h:277), `mhObjectDesc` (Chore.h:278).

| # | Field | Type | Wire | TTL |
|---|-------|------|------|-----|
| 1 | `mVersion` | int32 | blocked i32 (MSV), raw u32 (MTRE) | Chore.h:269 |
| 2 | `mResName` | Symbol (u64) | blocked u64 (MSV), absent (MTRE — stored as 0) | Chore.h:270 |
| 3 | `mResLength` | float | blocked f32 (MSV), raw f32 (MTRE) | Chore.h:271 |
| 4 | `mPriority` | int32 | blocked i32 (MSV), raw u32 (MTRE) | Chore.h:272 |
| 5 | `mFlags` | Flags (u32) | blocked u32 (MSV), raw u32 (MTRE, low word) | Chore.h:273 |
| 6 | `mResourceGroup` | String | blocked String (MSV), block-wrapped String (MTRE) | Chore.h:274 |
| 7 | `mhObject` | HandleBase | blocked Handle (MSV), block-wrapped String (MTRE) | Chore.h:275 |
| 8 | `mControlAnimation` | Animation | `skip_block` — see note below | Chore.h:280 |
| 9 | `mBlocks` | DCArray\<Block\> | blocked DCArray (MSV), block-wrapped (MTRE) | Chore.h:281 |
| 10 | `mbNoPose` | bool | blocked u8 (MSV), raw ASCII byte (MTRE) | Chore.h:282 |
| 11 | `mbEmbedded` | bool | blocked u8 (MSV), raw ASCII byte (MTRE) | Chore.h:283 |
| 12 | `mbEnabled` | bool | blocked u8 (MSV), raw ASCII byte (MTRE) | Chore.h:284 |
| 13 | `mbIsAgentResource` | bool | blocked u8 (MSV), raw ASCII byte (MTRE) | Chore.h:285 |
| 14 | `mbViewGraphs` | bool | blocked u8 (MSV), raw ASCII byte (MTRE) | Chore.h:286 |
| 15 | `mbViewEmptyGraphs` | bool | blocked u8 (MSV), raw ASCII byte (MTRE) | Chore.h:287 |
| 16 | `mbViewProperties` | bool | blocked u8 (MSV), raw ASCII byte (MTRE) | Chore.h:288 |
| 17 | `mbViewResourceGroups` | bool | blocked u8 (MSV), raw ASCII byte (MTRE) | Chore.h:289 |
| 18 | `mResourceProperties` | PropertySet | blocked PropertySet (MSV), skip_block (MTRE) | Chore.h:290 |
| 19 | `mResourceGroupInclude` | Map\<Symbol,float\> | blocked Map (MSV), skip_block (MTRE) | Chore.h:291 |
| 20 | `mAAStatus` | AutoActStatus | blocked AutoActStatus (MSV), custom tail (MTRE) | Chore.h:292 |

**`mControlAnimation` (field 8) scope boundary:** This field is a full embedded
`Animation` object (CTK / CompressedKeys infrastructure). The Chore decoder
calls `reader.skip_block()` on it — the block's byte extent is consumed but
the content is not decoded. Downstream consumers that need the animation bytes
can snapshot `reader.pos` before the skip. For the full Animation wire format
see [`FORMAT_ANIMATION.md`](./FORMAT_ANIMATION.md).

**MTRE `mAAStatus` (field 20) — PAL resources:** For ordinary resources the
MTRE tail is `[u32=0 placeholder][inner_bsz][if inner_bsz >= 4: (inner_bsz-4) bytes]`.
Resources with a "Procedural Look At" (PAL) constraint graph have `inner_bsz > 0xFFFF`
(the first 4 bytes of a type CRC, e.g. `0xcc33a947`). The decoder scans forward
to locate the next valid structure boundary by simulating all `mNumAgents` agent
decodes from each candidate position and requiring the chain end exactly at EOF.

**`mhObject` embedded-object branch (iOS VA `0x00211494`):** In MSV5/MSV6 streams,
when `mbEmbedded == true` (ldrb at offset `0x6D`), the decoder reads a `Symbol`
type-name, instantiates the class via `MetaClassDescription::New`, and serializes
the nested object via `PerformMetaOperation(0x14)`. In the MTRE path this branch
is not reached — `mhObject` is a plain blocked String filename.

---

## `ChoreAgent` — 7 fields

iOS VA: `PerformMetaSerialize<ChoreAgent>` at `0x00208980`, invoked from
`Chore::MetaOperation_Serialize` (VA `0x00205788`) in the custom post-loop.

`ChoreAgent::MetaOperation_Serialize` (VA `0x0020B714`) is a **5-instruction
stub** that unconditionally calls `Meta::MetaOperation_SerializeAsync`
(VA `0x001E99CC`) and returns — no custom post-walk code, no version gates,
no block-wrapping.

Python dataclass: `telltale.meta_chore.ChoreAgent`.

| # | Field | Type | Wire | TTL |
|---|-------|------|------|-----|
| 1 | (internal) `mpChore` | back-pointer | NOT serialized | Chore.h:353 |
| 2 | `mAgentName` | String | blocked String (MSV), block-wrapped String (MTRE; bsz=0 for anonymous) | Chore.h:366 |
| 3 | `mAABinding` | ActorAgentBinding | blocked (MSV), absent MTRE wire | Chore.h:370 |
| 4 | `mFlags` | Flags (u32) | blocked u32 (MSV), raw u32 ONLY for named agents (MTRE heuristic) | Chore.h:367 |
| 5 | `mResources` | DCArray\<int\> | blocked DCArray\<int\> (MSV), block-wrapped (MTRE) | Chore.h:368 |
| 6 | `mAttachment` | Attachment | blocked Attachment (MSV), skip_block (MTRE) | Chore.h:369 |
| 7 | `mAgentEnabledRule` | Rule | blocked Rule (MSV), absent MTRE wire | Chore.h:371 |

**MTRE registration order note:** iOS `ChoreAgent::InternalGetMetaClassDescription`
(VA `0x0020808C`) registers `mAABinding` at struct offset `0x08` immediately after
`mAgentName` — before `mFlags` (offset `0x18`). The standard MetaClass walker
serializes in registration order, so on MSV5/MSV6 the wire order is
`mAgentName → mAABinding → mFlags → mResources → mAttachment → mAgentEnabledRule`.

**MTRE `mFlags` heuristic:** In MTRE streams, `mFlags` is present in the wire
only for named agents in certain SVI configurations. Detection: peek the u32 after
`mAgentName`; if it is a valid `DCArray<int>` block-size (`bsz == 4` OR
`bsz >= 8 AND (bsz-8) % 4 == 0 AND bsz <= 2048`), the next field IS `mResources`
and `mFlags` is absent. Otherwise the u32 is `mFlags` and `mResources` bsz follows.

**`mAABinding` conditional:** `ActorAgentBinding` is absent from the MTRE wire in
all EP1 chores (confirmed by the 5-instruction iOS stub at VA `0x0020B714`).
In MSV5/MSV6 it is serialized as a blocked struct containing agent binding data.

---

## Custom post-loop

After `Meta::MetaOperation_SerializeAsync` completes the 12-member default walk,
two custom loops run. These loops are NOT part of the default MetaClass path
(TTL `Chore.h:601-647` comment: `"DO NOT ADD TO THIS, USE FUNCTIONS"`).

**ChoreResource loop:** VA `0x0020584C` → calls
`PerformMetaSerialize<ChoreResource>` (VA `0x002089D0`). Loop count = `mNumResources`
(read from Chore offset `0x0c` at runtime: `ldr r3, [r2, #0xc]`, VA `0x00205934`).

**ChoreAgent loop:** VA `0x00205988` → calls
`PerformMetaSerialize<ChoreAgent>` (VA `0x00208980`). Loop count = `mNumAgents`
(read from Chore offset `0x10` at runtime: `ldr r3, [r2, #0x10]`, VA `0x00205B48`).

**No outer count written.** `mNumResources` and `mNumAgents` are already in the
stream as fields 4 and 5 of the default walk. The post-loops do NOT write a
separate u32 count before iterating — the counts are read directly from the
in-memory Chore object at runtime.

**No block wrap around the loop.** There are no `BeginBlock`/`EndBlock` calls
framing the entire resource list or agent list. Elements are serialized back-to-back
as a flat sequence.

**Per-element framing:** `PerformMetaSerialize<ChoreResource/ChoreAgent>` →
`PerformMetaOperation(opcode=0x14)` → element `MetaOperation_Serialize` → inline
default walk. No block header separates elements.

**MTRE vs MSV5 difference:** In MSV5/MSV6 each member of ChoreResource and
ChoreAgent is individually block-wrapped by the standard MetaClass walker.
In MTRE (sv ≤ 3) bytes flow contiguously without per-member block headers.
The `ChoreResource::MetaOperation_Serialize` version gate at VA `0x0021144C`
(`cmp r3, #1`) separates the two paths only for `mVersion` / `mhObject`
embedded-write logic — NOT for block-wrapping.

---

## MTRE layout variants

Three layout variants exist in the EP1 corpus:

### Variant A — hint chores (MTRE, class_count == 4, true hint)

Known files: `guybrush_hint_usenose_*`, `glassblowermechanisms` (4 total EP1).
Classes registered: `Chore`, `PropertySet`, `Flags`, `Symbol` (exactly 4).

**Fields 2–5 (`mFlags`, `mLength`, `mNumResources`, `mNumAgents`) are ABSENT
from the wire.** After `mName`, the next bytes are the `mEditorProps` block-size
prefix (a small u32 with bytes 1–3 == `0x00`).

Detection: `class_count == 4 AND sv <= 3` AND `peek_4[1:] == b'\x00\x00\x00'`.

### Variant B — non-hint chores (MTRE, class_count ≥ 5)

The vast majority of EP1 chores. Fields 2–5 are present as a 13-byte unframed
scalar run immediately after `mName`: `u8 + f32 + i32 + i32` (no block headers).

Detection: `class_count > 4 AND sv <= 3`.

Fields 9–12 (`mSynchronizedToLocalization`, `mDependencies`, `mToolProps`,
`mWalkPaths`) are present as a constant 22-byte tail in all EP1 non-hint MTRE
chores. The sequence encodes default/empty values for all four fields. The
decoder skips these 22 bytes and returns constructed defaults.

### Variant C — 4-class non-hint (MTRE, class_count == 4, non-hint)

Two known EP1 files:
- `env_voodooladyinterior_use_bookshelf_e12_668.chore`
- `layout_voodooladyinterior_voodoolady.chore`

Distinguisher from Variant A: peek `_4[1:]` is NOT `b'\x00\x00\x00'` (the float
bytes of `mLength` are non-zero). Treated identically to Variant B by the decoder.

---

## PropertySet value variants

`PropertySet` is decoded by `telltale.meta_propertyset.decode_propertyset`.
Keys are `Symbol` CRC64s. Values are typed and dispatched by their type hash.

### Wire format variants

**FORMAT A (MTRE, peek_uint32() == 8):**
```
u32 mPropVersion_block_size = 8
u32 mPropVersion            (version number)
u32 mPropertyFlags_block_size = 8
u32 mPropertyFlags
```
Followed by a custom section with a type-map and value sequence.

**FORMAT B (MSV5+, peek_uint32() != 8):**
```
u32 mPropVersion            (inline, no block header)
u32 mPropertyFlags
<1 byte padding in MTRE when mPropVersion == 0; absent when mPropVersion == 1>
```
Followed by the custom section.

### Known value type CRCs (EP1 corpus)

| Type | Python result |
|------|---------------|
| `int` / `long` | Python `int` |
| `float` | Python `float` |
| `bool` | Python `bool` |
| `Vector3` | `Vector3(x, y, z)` dataclass |
| `String` | Python `str` |
| `Symbol` | Python `int` (CRC64) |
| `Handle<T>` | `Handle` dataclass with `object_name_str` |
| `KeyframedValue<float>` | `KeyframedValue` dataclass with sample list |
| `KeyframedValue<bool>` | `KeyframedValue` dataclass |
| `KeyframedValue<int>` | `KeyframedValue` dataclass |
| `KeyframedValue<Vector3>` | `KeyframedValue` dataclass |
| unknown hash | `UnknownPropertyValue(type_hash, raw_bytes)` sentinel |

`UnknownPropertyValue` is a sentinel dataclass (not an error). The decoder
logs a WARNING and continues, preserving the unknown block bytes for inspection.

### KeyframedValue\<T\> wire format

```
u32  block_size
u32  num_samples
per sample:
    f32  time
    T    value   (wire size depends on T)
```

`KeyframedValue<float>` / `<bool>` / `<int>` carry 4-byte value payloads per
sample. `KeyframedValue<Vector3>` carries 12 bytes per sample (3 × f32).

---

## Schema drift notes

- **`SerializedVersionInfo` CRC:** TMI ships `1830510796` as the per-class
  version CRC for `Chore`. This value appears in the MTRE class-entry list
  and is used to gate version-conditional field reads.

- **MTRE 4-class hint scoping:** EP1 hint chores omit `mFlags`, `mLength`,
  `mNumResources`, `mNumAgents` from the wire. Gate: `class_count == 4 AND sv <= 3`
  AND peek discriminant (see Variant A above). 4 files in EP1 corpus.

- **22-byte constant tail:** In all EP1 MTRE non-hint chores, fields 9–12
  (`mSynchronizedToLocalization` through `mWalkPaths`) are encoded as a
  constant 22-byte sequence beginning `00 18 25 76 74 6c 8a 14 87 ...`.
  The 8-byte sub-sequence `18 25 76 74 6c 8a 14 87` does not match any known
  Telltale type CRC64 in the registry. The sequence encodes default/empty values
  for all four fields and is treated as opaque by the decoder.

- **CRC `0x87148a6c74762518`:** Appears as an 8-byte tail in the 22-byte
  constant block of EP1 non-hint chores. Purpose unresolved; treated as opaque.

- **MTRE `mResName` absent:** In MTRE EP1 chores, `mResName` (Symbol u64,
  `ChoreResource` field 2) is absent from the wire. Stored as `0` in the
  decoded dataclass.

---

## CLI — `inspect_chore.py`

`inspect_chore.py` was rewritten in Plan 08-03 to run on top of
`telltale.chore.parse_chore`. The v1.1 surface-level hand-rolled scanner
has been removed.

```python
from inspect_chore import inspect, ChoreSurface

c = inspect("path/to/file.chore")
c.name          # from chore.mName (decoded by parse_chore)
c.handles       # from extract_handles(chore, path=path) — superset of v1.1
c.flags         # from chore.mFlags (correctly decoded)
c.length        # from chore.mLength (correctly decoded)
c.num_resources # from chore.mNumResources
c.num_agents    # from chore.mNumAgents
```

**CLI stability mode:** Handle-set superset (case-insensitive). Strict bytewise
equality with v1.1 is not achievable because v1.1 read `mFlags`, `mLength`,
`mNumResources`, `mNumAgents` at wrong byte offsets (raw reads without MetaStream
block framing). The new decoder produces correct values; v1.1 values were
documented as "best-effort" in the original module docstring.

New handle counts vs v1.1 (50-file sample): +1,934 total instances (+8.6%),
+1,862 unique handles (+41%). Every v1.1 handle (case-insensitive) is present
in the new output.

---

## Validation

### VALIDATE-04: Full-corpus parse

```
1929 / 1929 EP1 chores parse cleanly (0 misaligned)
```

Run by `scripts/validate_full_corpus.py` + asserted by
`tests/test_chore_full_corpus.py::test_full_corpus_clean`.

The `validate_chores(paths)` function (public API) drives this:
```python
from telltale.chore import validate_chores
report = validate_chores(list_of_paths)
print(report.summary())  # "1929 / 1929 clean"
```

`ChoreValidationReport` (in `telltale.validation`) records per-file
clean/misalignment status with the misalignment reason string.

### VALIDATE-05: Handle-graph superset

```
0 / 1929 handle-superset failures
```

For every EP1 chore:
```
{h for h in extract_handles(chore, path) if h.endswith(PLAUSIBLE_EXTS)}
    ⊇ set(inspect_chore_v11.inspect(path).handles)
```

Asserted by `tests/test_chore_full_corpus.py::test_handle_graph_superset`.

### INFRA-05: MetaStreamReader unification

All three legacy parsers now route through `telltale.metastream.MetaStreamReader`:

| Parser | Plan | Status |
|--------|------|--------|
| `parse_ptable.py` | 08-02 | 74 / 74 EP1 ptables clean |
| `parse_anm_values.py` | 08-04 | ≥ 4726 / 4733 EP1 anms (99.9%) |
| `telltale/skeleton.py` | 08-04 | 65 / 65 skeleton fixtures match |

`telltale/skeleton.py` `_parse_metastream_header` replaced by a 4-line shim
calling `telltale.metastream.parse_header`. All four hand-rolled magic constants
(`_MAGIC_MBIN`, `_MAGIC_MTRE`, `_MAGIC_MSV5`, `_MAGIC_MSV6`) removed.

Test suite gate: **327 passed, 2 skipped** (Plan 08-03 baseline).

---

## Related docs

- [`CHORE_DISASM.md`](./CHORE_DISASM.md) — iOS disassembly of
  `Chore::MetaOperation_Serialize` (VA `0x00205788`); authoritative field-walk
  table, ChoreResource / ChoreAgent field-walk tables, post-loop framing details.
  Generated by `scripts/disasm_chore.py` from `altre_versioni/MonkeyIsland101`
  ARM32 slice.

- [`FORMAT_ANIMATION.md`](./FORMAT_ANIMATION.md) — `Animation` wire format
  (CTK / CompressedKeys infrastructure). Relevant because `ChoreResource::mControlAnimation`
  is an embedded `Animation` object that the Chore decoder skips. Consumers needing
  animation bytes should seek to the block start before the skip.

- [`FORMAT_PHONEME_TABLE.md`](./FORMAT_PHONEME_TABLE.md) — `PhonemeTable`
  decoder. Rewired to `MetaStreamReader` in Plan 08-02 (INFRA-05 first slice,
  74/74 EP1 ptables).

- [`FORMAT_SKELETON.md`](./FORMAT_SKELETON.md) — `Skeleton` decoder.
  `telltale/skeleton.py` `_parse_metastream_header` rewired to
  `telltale.metastream.parse_header` in Plan 08-04 (INFRA-05 third slice).

- `telltale/meta_chore.py` — Internal implementation (decoders for all three
  iOS layout variants + full MSV5/MSV6 path + PAL mAAStatus scanner).

- `telltale/meta_propertyset.py` — `PropertySet` decoder (FORMAT A / B variants,
  `KeyframedValue<T>`, `UnknownPropertyValue` sentinel).

- `telltale/meta_chore_leaves.py` — Leaf type decoders: `LocalizeInfo`,
  `Attachment`, `ToolProps`, `AutoActStatus`, `ActorAgentBinding`, `Rule`,
  `WalkPath`, `DependencyLoader1`, `Block`.

- `telltale/metastream.py` — `MetaStreamReader` and `parse_header`; Phase 1
  foundation consumed by all format decoders in this library.
