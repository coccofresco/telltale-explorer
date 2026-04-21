# Telltale Explorer

Python toolkit for extracting and converting assets from Telltale Games archives,
with focus on **Tales of Monkey Island** (2009) and the D3DMESH V1 format era.

**Pure Python, no external dependencies.**

## Features

- **TTARCH archive extraction** — 66 Telltale games supported (PC, Wii, iOS, PS3)
- **D3DMESH → glTF 2.0** — meshes with submeshes, materials, bone palettes and embedded textures
- **D3DTX → PNG** — DXT1/DXT3/DXT5 and RGBA8 texture decoding
- **SKL → glTF** — skeleton-only and fully-skinned `D3DMESH + SKL` export
- **ANM → glTF animation channels** — `KeyframedValue<T>` and `CompressedTransformKeys` wired into the animated export
- **Full .anm value walker** — 99.9 % of Tales of Monkey Island EP1 anims
  (`SingleValue<T>`, `CompressedKeys<Vector3/Quaternion/Transform/float/Bool>`,
  `CompressedTransformKeys`, `CompressedPhonemeKeys`, …) decoded with per-sample values
- **`.ptable` (phoneme table) decoder** — closes the lip-sync pipeline
- **`.chore` full structural decoder** — every field of every nested sub-struct decoded into Python dataclasses; 1929/1929 Tales of Monkey Island EP1 chores parse cleanly
- **Generic MetaStream + MetaClass reflection reader** — reusable block-safe reader with CRC64-keyed type registry, primitive / math / Handle / container / PropertySet / Chore-leaf decoders; ready for `.scene` / `.prop` / other Telltale formats

## Quick Start

### Meshes and textures

```bash
# Mesh → glTF with textures
python export_mesh_glb.py path/to/mesh.d3dmesh --textures path/to/textures/

# Texture → PNG
python decode_d3dtx.py path/to/texture.d3dtx output.png

# TTARCH browse / extract
python extract.py list    archive.ttarch --game monkeyisland101
python extract.py extract archive.ttarch --game monkeyisland101 --output out/
```

### Skeleton + skinning

```bash
# Skeleton only
python export_skeleton_glb.py path/to/char.skl -o char_skeleton.glb

# Skinned mesh (auto-loads sibling .skl if present)
python export_rigged_glb.py path/to/char.d3dmesh --textures textures/ -o char_rigged.glb
```

### Animation

```bash
# Full animated export: mesh + skeleton + anim, into a single .glb
python export_animated_glb.py char.d3dmesh char_walk.anm \
    --textures textures/ --hashdb hashdb/BoneNames.HashDB -o char_walk.glb

# Decode an .anm and list every channel
python parse_anm_values.py path/to/anim.anm [--all]
```

### Phonemes / lip-sync

```bash
# Extract all .ptable files from a TTARCH data pack
python scan_ptable.py

# Dump a single phoneme table: phoneme_id → anim filename
python parse_ptable.py path/to/sk03_elaine.ptable
```

### Choreography

```bash
# Full structural decode: 12 top-level fields + ChoreResource / ChoreAgent loops
python -c "from telltale.chore import parse_chore; c = parse_chore('file.chore'); print(c)"

# Handle-graph inspection (rewritten on parse_chore — strict superset of v1.1 output)
python inspect_chore.py path/to/file.chore
```

## Supported Games (D3DMESH V1)

| Game | Year | Status |
|------|------|--------|
| Tales of Monkey Island (5 episodes) | 2009 | Fully tested — meshes + skeletons + animations |
| Sam & Max Season 3: The Devil's Playhouse | 2010 | Expected compatible |
| Back to the Future: The Game | 2010-2011 | Expected compatible |
| Wallace & Gromit Episode 4 | 2009 | Expected compatible |
| CSI: Deadly Intent / Fatal Conspiracy | 2009-2010 | Expected compatible |
| Poker Night at the Inventory | 2010 | Expected compatible |

The TTARCH extractor supports the full Telltale catalog (66 game IDs).

## Documentation

Format specifications and script reference live under [`docs/`](docs/):

- [`docs/FORMAT_SKELETON.md`](docs/FORMAT_SKELETON.md) — `.skl` skeleton layout
- [`docs/FORMAT_ANIMATION.md`](docs/FORMAT_ANIMATION.md) — `.anm` container + every value-type wire format
- [`docs/FORMAT_PHONEME_TABLE.md`](docs/FORMAT_PHONEME_TABLE.md) — `.ptable` schema + lip-sync pipeline
- [`docs/FORMAT_CHOREOGRAPHY.md`](docs/FORMAT_CHOREOGRAPHY.md) — `.chore` full schema (MetaStream + MetaClass + 12 Chore fields + 21 ChoreResource + 7 ChoreAgent + PropertySet + leaves)
- [`docs/CHORE_DISASM.md`](docs/CHORE_DISASM.md) — iOS ARM32 disasm artifact for `Chore::MetaOperation_Serialize` (VA `0x00205788`)
- [`docs/SCRIPTS.md`](docs/SCRIPTS.md) — CLI / module overview
- [`CONTRIBUTION_RTB.md`](CONTRIBUTION_RTB.md) — D3DMESH V1 format spec (submitted to [RTB-3DSMax-Scripts#9](https://github.com/RandomTBush/RTB-3DSMax-Scripts/issues/9))

## Architecture

```
extract.py                   TTARCH extraction CLI
scan_ptable.py               Bulk .ptable extractor from TTARCH packs

export_mesh_glb.py           D3DMESH → glTF 2.0 (meshes + textures + bone palettes)
export_skeleton_glb.py       SKL → glTF armature
export_rigged_glb.py         D3DMESH + SKL → skinned glTF
export_animated_glb.py       D3DMESH + SKL + ANM → animated glTF
decode_d3dtx.py              D3DTX → PNG

parse_anm.py                 ANM container + type-table parser
parse_ctk.py                 CompressedTransformKeys / CompressedPhonemeKeys decoders
parse_compressed_keys.py     CompressedKeys<Vector3/Quaternion/Transform> decoders
parse_anm_values.py          Multi-value .anm walker (routes every type to its decoder)
parse_ptable.py              PhonemeTable (.ptable) decoder
inspect_chore.py             .chore handle-graph inspector (built on telltale.chore)

scripts/
  disasm_chore.py            iOS ARM32 disasm tool (capstone) — Chore::MetaOperation_Serialize

telltale/                    Library modules
  ttarch.py                  TTARCH archive reader + Blowfish key DB
  metastream.py              MetaStream container + MetaStreamReader (block-stack, format_version)
  metaclass.py               CRC64-keyed @meta_class / meta_member registry + version gating
  meta_intrinsics.py         bool / int* / uint* / float / double / Flags / Symbol / String decoders
  meta_math.py               Vector2/3/4, Quaternion, Color, Transform (iOS 28 B layout)
  meta_handle.py             Handle<T> MTRE / MSV5+ version-branching decoder (11 template params)
  meta_containers.py         DCArray / Map / Set / SArray / List dispatcher with nested templates
  meta_propertyset.py        PropertySet FORMAT A/B decoder + KeyframedValue<T> wrappers
  meta_ptable.py             PhonemeTable::PhonemeEntry + AnimOrChore decoders
  meta_chore_leaves.py       16 Chore leaf types (LocalizeInfo, DependencyLoader, ToolProps, WalkPath, Rule, ...)
  meta_chore.py              Chore / ChoreResource / ChoreAgent + decode_chore + parse_chore + validate_chores
  chore.py                   Public API: parse_chore, Chore, ChoreResource, ChoreAgent, extract_handles
  validation.py              ChoreValidationReport (corpus-wide clean / misalignment tracking)
  d3dmesh.py                 D3DMESH format helpers
  d3dtx.py                   D3DTX format helpers
  blowfish.py                Blowfish encryption for TTARCH
  crc64.py                   CRC64 ECMA-182 hashing (case-insensitive for Symbols)
  skeleton.py                .skl skeleton parser (rewired onto MetaStreamReader in v1.2)
```

## Roadmap

- [x] TTARCH extraction (all platforms)
- [x] D3DMESH geometry with submeshes and bone palettes
- [x] D3DTX texture decoding (DXT1/3/5 + RGBA8)
- [x] Multi-texture materials (diffuse + normal + specular + lightmap)
- [x] glTF 2.0 export with embedded textures
- [x] Skeleton (.skl) → glTF joints
- [x] Bone weights in glTF
- [x] Animation (.anm) → glTF animations (CTK + KFV channels)
- [x] Full multi-value .anm walker (99.9 % EP1 coverage)
- [x] Phoneme table (.ptable) decoder
- [x] Choreography (.chore) surface inspection
- [x] Full `.chore` structural decoder (nested PropertySet / HandleObjectInfo) — 1929/1929 EP1 clean
- [x] Generic MetaStream + MetaClass reflection reader
- [ ] `CompressedVector3Keys2` inner bit-stream
- [ ] Scene (.scene) + props (.prop) → glTF scene graph

## Credits

Format reverse engineering based on analysis of:

- [RTB-3DSMax-Scripts](https://github.com/RandomTBush/RTB-3DSMax-Scripts) by Random Talking Bush
- [TelltaleToolLib](https://github.com/LucasSaragosa/TelltaleToolLib) by Lucas Saragosa

## License

MIT
