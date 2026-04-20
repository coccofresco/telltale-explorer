# Scripts — Overview

Command-line entry points and library modules added in the
skeleton / animation / phoneme phase.

## Entry points

| Script                           | Purpose                                                              |
|----------------------------------|----------------------------------------------------------------------|
| `extract.py`                     | TTARCH list / extract — unchanged from the mesh phase.               |
| `export_mesh_glb.py`             | D3DMESH → glTF (now with bone-palette-aware submesh parsing).        |
| `export_skeleton_glb.py`         | SKL → glTF skeleton-only (joints + rest pose).                       |
| `export_rigged_glb.py`           | D3DMESH + SKL → skinned glTF (per-vertex bone weights).              |
| `export_animated_glb.py`         | D3DMESH + SKL + ANM → animated glTF (KFV + CTK channels).            |
| `decode_d3dtx.py`                | D3DTX → PNG (DXT/RGBA decoders).                                     |
| `scan_ptable.py`                 | Mine a TTARCH pack for `*.ptable` files and dump them.               |
| `parse_anm_values.py <anm> [--all]` | Human-readable dump of every animated channel in an .anm file.    |
| `parse_ptable.py <ptable>...`    | Dump a .ptable as `phoneme_id → anim_name`.                          |
| `inspect_chore.py <chore>...`    | Surface info for a .chore (name + referenced assets).                |

## Library modules

### `telltale/` — pre-existing core helpers

`ttarch`, `metastream`, `d3dmesh`, `d3dtx`, `blowfish`, `crc64`,
`skeleton`.

The mesh-phase work is untouched except:

- `telltale/skeleton.py` — drop the redundant name-prefix read (SKL has
  no name block in TMI era) and stop negating the quaternion W (RTB's
  MaxScript negates it to compensate for 3DS Max's convention; modern
  math libs do not).

### New format decoders

- **`parse_anm.py`** — ANM container header + type-table + value-offset
  search. Exposes `parse_header(data) → AnimHeader`.
- **`parse_ctk.py`** — Decoders for the two-buffer compressed families
  (`CompressedTransformKeys`, `CompressedPhonemeKeys`,
  `CompressedTimeKeys`). Plus helpers for the compact
  `u8[+u16]` size-prefix reader used by several types.
- **`parse_compressed_keys.py`** — Standalone decoder for the template
  `CompressedKeys<T>` family (Vector3, Quaternion, Transform).
- **`parse_ptable.py`** — `.ptable` → `PhonemeTable(name, entries)`.
- **`parse_anm_values.py`** — Full multi-value .anm walker. Routes each
  value to the right decoder; returns `DecodedValue(type_name, name_hash,
  flags, value_type, stream_offset, stream_size, samples)`.
- **`inspect_chore.py`** — Surface-level `.chore` inspection
  (`ChoreSurface.handles`).

## Validation

Every decoder is validated against the extracted ep1 asset set
(reconstructable from the original game using `scan_ptable.py` and
`extract.py`):

| Module                  | Coverage                                                       |
|-------------------------|----------------------------------------------------------------|
| `parse_ptable`          | 74 / 74 (888 entries, 100% CRC-matched keys)                   |
| `parse_compressed_keys` | 202 / 202 first-type CK anms with valid monotonic timestamps   |
| `parse_anm_values`      | 4 726 / 4 733 (99.9%); 100% sample population for all types except CompressedVector3Keys2 |
| `inspect_chore`         | 1 929 / 1 929 (22 528 handle refs, 2 145 unique anims)         |

See `docs/FORMAT_*.md` for the on-disk schemas.

## Dependencies

Pure Python standard library. Bone-name resolution uses
`BoneNames.HashDB` from [TelltaleToolLib](https://github.com/LucasSaragosa/TelltaleToolLib)
(not shipped here); decoding works without it (unresolved hashes are
kept as raw `0x...` strings).
