# Telltale Explorer

Python toolkit for extracting and converting assets from Telltale Games archives,
with focus on **Tales of Monkey Island** (2009) and the D3DMESH V1 format era.

**Pure Python, no external dependencies.**

## Features

- **TTARCH archive extraction** — 66 Telltale games supported (PC, Wii, iOS, PS3)
- **D3DMESH → glTF 2.0** — meshes with submeshes, materials, and embedded textures
- **D3DTX → PNG** — DXT1/DXT3/DXT5 and RGBA8 texture decoding

## Quick Start

### Export a mesh with textures
```bash
python export_mesh_glb.py path/to/mesh.d3dmesh --textures path/to/textures/
```

### Convert a texture
```bash
python decode_d3dtx.py path/to/texture.d3dtx output.png
```

### Extract from TTARCH archive
```bash
python extract.py list archive.ttarch --game monkeyisland101
python extract.py extract archive.ttarch --game monkeyisland101 --output output_dir/
```

## Supported Games (D3DMESH V1)

| Game | Year | Status |
|------|------|--------|
| Tales of Monkey Island (5 episodes) | 2009 | Fully tested (358/358 meshes) |
| Sam & Max Season 3: The Devil's Playhouse | 2010 | Expected compatible |
| Back to the Future: The Game | 2010-2011 | Expected compatible |
| Wallace & Gromit Episode 4 | 2009 | Expected compatible |
| CSI: Deadly Intent / Fatal Conspiracy | 2009-2010 | Expected compatible |
| Poker Night at the Inventory | 2010 | Expected compatible |

The TTARCH extractor supports the full Telltale catalog (66 game IDs).

## Documentation

- [`CONTRIBUTION_RTB.md`](CONTRIBUTION_RTB.md) — D3DMESH V1 format specification (submitted to [RTB-3DSMax-Scripts#9](https://github.com/RandomTBush/RTB-3DSMax-Scripts/issues/9))

## Architecture

```
extract.py              CLI for TTARCH extraction
export_mesh_glb.py      D3DMESH → glTF 2.0 (.glb) with textures (self-contained)
decode_d3dtx.py         D3DTX → PNG texture decoder
telltale/               Library modules
  ttarch.py             TTARCH archive reader + decryption
  metastream.py         MetaStream (ERTM/MSV5/MSV6) header parser
  d3dmesh.py            D3DMESH format helpers
  d3dtx.py              D3DTX format helpers
  blowfish.py           Blowfish encryption for TTARCH
  crc64.py              CRC64 hashing (ECMA-182)
  skeleton.py           SKL skeleton parser (WIP)
```

## Roadmap

- [x] TTARCH extraction (all platforms)
- [x] D3DMESH geometry with submeshes
- [x] D3DTX texture decoding (DXT1/3/5 + RGBA8)
- [x] Multi-texture materials (diffuse + normal + specular + lightmap)
- [x] glTF 2.0 export with embedded textures
- [ ] Skeleton (.skl) → glTF joints
- [ ] Bone weights in glTF
- [ ] Animation (.anm) → glTF animations
- [ ] Scene (.scene) + props (.prop) → glTF scene graph

## Credits

Format reverse engineering based on analysis of:
- [RTB-3DSMax-Scripts](https://github.com/RandomTBush/RTB-3DSMax-Scripts) by Random Talking Bush
- [TelltaleToolLib](https://github.com/LucasSaragosa/TelltaleToolLib) by Lucas Saragosa

## License

MIT
