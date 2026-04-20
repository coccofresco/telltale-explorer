# SKL — Skeleton Format

Reverse-engineered against the 64 Tales of Monkey Island EP1 skeletons
(1520 bones total). All bone names resolve via the runtime hash database.

## File layout

```
MetaStream header              # "ERTM" / "MTRE" container (v3)
u32 bone_file_size             # bytes from here to EOF (incl. this field)
u32 bone_count
for each bone:
    u64 name_hash              # CRC64 of bone name (case-insensitive)
    u32 0                      # padding
    u64 parent_hash            # 0 for root; sentinel 0x7dc5...8012 also root
    u32 0                      # padding
    f32 tx, ty, tz             # translation (multiplied by model scale)
    f32 rx, ry, rz, rw         # rotation quaternion (standard math convention)
    u32 block_size             # size of remaining per-bone block
    # block_size bytes of per-bone metadata:
    # - 12 bytes flags / skin info
    # - 16 bytes bind-pose matrix (engine-space)
    # - variable: constraint data when flag bit set
```

Parent linkage is by CRC64 hash; children reference their parent's name
hash. A root bone has `parent_hash = 0` or the sentinel
`0x7dc5f26128ec8012` (which is also used by Animation channels to mean
"world / relativeNode").

## Quirks

- **Quaternion W is NOT negated** on read. RTB's MaxScript negates W to
  compensate for 3DS Max's reversed quaternion multiplication; glTF,
  Blender, and most math libraries use the standard convention.
- **No name string is stored** — only the CRC64. Bone names come from a
  separate hash database (`BoneNames.HashDB` in the TelltaleToolLib
  project, not shipped here).

## Reader

`telltale/skeleton.py::parse_skeleton(data, version=0, early_game_fix=10,
model_scale=1.0)` returns a list of `Bone(name_hash, parent_hash, trans,
rot, local_matrix)` entries in serialization order.
