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
- **`.chore` surface inspector** — extract the resource-handle graph from any chore file

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
# Surface-level chore inspection: name + referenced resources
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
- [`docs/FORMAT_CHOREOGRAPHY.md`](docs/FORMAT_CHOREOGRAPHY.md) — `.chore` schema + surface-inspector scope
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
inspect_chore.py             .chore surface inspector (handle graph)

telltale/                    Library modules
  ttarch.py                  TTARCH archive reader + Blowfish key DB
  metastream.py              MetaStream (ERTM/MSV5/MSV6) header parser
  d3dmesh.py                 D3DMESH format helpers
  d3dtx.py                   D3DTX format helpers
  blowfish.py                Blowfish encryption for TTARCH
  crc64.py                   CRC64 ECMA-182 hashing (case-insensitive for Symbols)
  skeleton.py                .skl skeleton parser
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
- [ ] `CompressedVector3Keys2` inner bit-stream
- [ ] Full `.chore` structural decoder (nested PropertySet / HandleObjectInfo)
- [ ] Scene (.scene) + props (.prop) → glTF scene graph

## Credits

Format reverse engineering based on analysis of:

- [RTB-3DSMax-Scripts](https://github.com/RandomTBush/RTB-3DSMax-Scripts) by Random Talking Bush
- [TelltaleToolLib](https://github.com/LucasSaragosa/TelltaleToolLib) by Lucas Saragosa

## License

MIT
