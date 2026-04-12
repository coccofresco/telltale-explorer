# D3DMESH Version 1 (ERTM) — Tales of Monkey Island / BttF / S&M S3

## Overview

This documents the D3DMESH format for **Version 1 (ERTM header)**, which is currently
**unsupported** in RTB-3DSMax-Scripts. This version covers:

- Tales of Monkey Island (2009) — all 5 episodes
- Back to the Future: The Game (2010-2011)
- Sam & Max Season 3: The Devil's Playhouse (2010)
- CSI: Deadly Intent / Fatal Conspiracy (2009-2010)
- Poker Night at the Inventory (2010)
- Wallace & Gromit Episode 4 (2009)

The version byte is `0x01` (decimal 1), immediately after the mesh name string.
The MetaStream header is MTRE (same as V0.5 Strong Bad / W&G Ep. 1-3).

Version 1 sits between V0.5 (ERTM, EarlyGameFix 4-9) and V2 (MSV5, Jurassic Park).
It is structurally closer to V0.5 than to V2.

---

## Key Differences from V0.5 (Strong Bad / W&G)

| Feature | V0.5 (Strong Bad/W&G) | V1 (ToMI/BttF/S&M3) |
|---|---|---|
| Name blocks in submesh | String names or hashes by EarlyGameFix | Always CRC64 hashes (12 bytes each) |
| Material texture slots | 5-7 slots with complex conditional layout | Simplified: name_len(u32) + name, sequential |
| Vertex buffer headers | Flag byte + count + length + type | count(u32) + stride(u32) + type(u32) + flags(u32) = 16 bytes |
| Vertex compression | CompressionCheck(u16) + optional compression | None on PC (raw float32); compressed on Wii/PS3 |
| Face data | Raw face point indices in FacePoint_array | Delta-compressed bitstream (always, FL=1 on PC) |
| Triangle strip info | TriStripGroups/TriStripStart/TriStripEnd | mTriStrips field in 0x31 block; extra indices after nprim*3 |
| Post-submesh structure | Conditional material slots + footer names | 0x31 marker + block_size + block_data + 162 bytes post-block |
| Multi-texture per submesh | Up to 6 named slots (Diffuse/Spec/Bake/Bump/Gradient/Env) | 1-3 sequential name refs (Diffuse + optional Lightmap + optional Bump/Spec) |

---

## File Structure

```
[MTRE Header]              — magic "ERTM"(LE), class_count, CRC64 class entries
[Mesh Name]                — name_hdr_len(u32), name_len(u32), name(ASCII), version_byte(0x01)
[Skip 4 bytes]             — marker u32 (0x30000000 or 0x31000000)
[Bounding Box]             — 6 × float32 (minX, minY, minZ, maxX, maxY, maxZ)
[head3a_size]              — u32, total byte size of TriangleSet block
[PolyTotal]                — u32, number of TriangleSets (submeshes)
[TriangleSet × PolyTotal]  — variable-length structs
[Intermediate Data]        — bone ID sets, material slots, section markers
[Face Section]             — 0x30, 0x65, padding(3), FaceCount(u32), FaceLength(u32)
[Face Data]                — first_index(u16), body_size(u32), delta-compressed body
[Vertex Buffers]           — chain of typed buffers (positions, normals, UVs, etc.)
```

---

## MTRE Header

Same as V0.5:
```
uint32      Magic           — "ERTM" (0x4552544D LE)
uint32      ParamCount
For each param:
  uint32    ParamHashCheck  — if > 128: read as CRC64(8) + version(4) = 12 bytes
                            — if ≤ 128: name_len(4) + name(N) + version(4)
```

---

## Mesh Name and Version

```
uint32      D3DNameHeaderLength
uint32      D3DNameLength
            if D3DNameLength > D3DNameHeaderLength:
                seek back 4, use D3DNameHeaderLength as length
char[N]     D3DName
uint8       VerNum          — value 0x01 (decimal 1)
```

---

## After Version Byte

```
uint32      Marker          — 0x30000000 or 0x31000000 (skip)
float32×6   BoundingBox     — minX, minY, minZ, maxX, maxY, maxZ
uint32      Head3ASubSize   — total byte size of all TriangleSet data
uint32      PolyTotal       — number of TriangleSets
```

---

## Per-TriangleSet Structure

Each TriangleSet has a fixed header followed by variable-length texture and material data.

### Fixed Header (84 bytes + mat_block)

```
Offset  Size    Field
+0      12      CRC block 1: CRC64(8) + version(4) — material type hash
+12     12      CRC block 2: CRC64(8) + version(4) — material type hash
+24     4       BoneSetNum - 1 (u32, add 1 for 1-based)
+28     4       SingleBindNode (u32)
+32     4       VertexMin (u32, 0-based — add 1 for MaxScript)
+36     4       VertexMax (u32, 0-based — add 1 for MaxScript)
+40     4       FacepointStart (u32, index into decoded face array)
                PolygonStart = FacepointStart / 3 + 1
+44     4       PolygonCount (u32, number of triangles)
                FacepointCount = PolygonCount * 3
+48     12      CRC block 3: CRC64(8) + version(4)
+60     24      Sub bounding box: 6 × float32
+84     4       mat_block_len (u32, typically 20)
+88     N       mat_data (mat_block_len bytes): 4 floats + tex_total(u32)
```

### Texture References (after mat_data)

Textures are stored sequentially. The **first** is always the diffuse material.
Subsequent textures are lightmaps, bump maps, or specular maps.

```
Texture 1 (Diffuse — always present):
  uint32    tex_name_len
  char[N]   tex_name        — e.g. "tile_flotsamdock_a.d3dtx"

[separator: 2-3 pairs of (u32, u32) material slot data]

Texture 2 (Lightmap/Bump/Spec — optional):
  uint32    tex_total_len   — equals name_len + 8
  uint32    tex_name_len
  char[N]   tex_name        — e.g. "adv_flotsamtownbeach_meshesb_000.d3dtx"

[optional: more separator + Texture 3]
```

Texture classification by name:
- First texture (slot 0) → **Diffuse** (always)
- `bmap_*_bump` → **Normal/Bump Map**
- `map_*_spec` / `*specular*` → **Specular Map**
- `*_alp` / `*_alpha` → **Alpha/Opacity Map**
- `adv_*_meshes*_NNN` → **Lightmap Atlas** (pre-baked lighting)

Character meshes (sk_*): 1 texture (diffuse only).
Environment meshes (adv_*, obj_*): 2-3 textures (diffuse + lightmap ± bump/spec).

### Variable Tail (after all textures)

```
[remaining material slot data]
0x31        MetaStream marker byte (within ~200 bytes of last texture)
uint32      block_size      — 8 for list-only, 12 when mTriStrips > 0

Block data (block_size bytes):
  uint32    mTriStrips      — 0 for triangle list, >0 for extra strip data
  [if mTriStrips > 0: 4 bytes strip boundary data (2 × uint16)]
  uint32    FacePointEnd    — total index count (>= PolygonCount * 3)

162 bytes   post-block data (octree, transforms — skip)
```

**Important**: `FacePointEnd` may be larger than `PolygonCount * 3`.
The first `PolygonCount * 3` indices are a **triangle list** (the primary geometry).
The remaining `FacePointEnd - PolygonCount * 3` indices are extra strip/fan data
within the same submesh (small fan triangles for edge geometry).

### Advancing to Next TriangleSet

After the 162-byte post-block, the next TriangleSet's CRC block 1 begins.
The total struct size varies due to texture name lengths. For robust parsing,
scan for the 0x31 marker within 200 bytes of the last texture name end,
then advance by `1 + 4 + block_size + 162` to reach the next struct.

If the 0x31 scan fails, use `Head3ASubSize / PolyTotal` as average struct size fallback.

---

## Face Data Section

### Face Marker Detection

Scan for byte sequence: `0x30 0x65` with valid FaceCount and FaceLength.

```
uint8       0x30            — section type marker
uint8       0x65            — mFormat (GFXPlatformFormat for uint16)
uint8×3     0x00 0x00 0x00  — padding
uint32      FaceCount       — mCount: total number of face indices
uint32      FaceLength      — mFlags: 1 = compressed, 0 = raw
```

### Compressed Face Data (FaceLength == 1)

```
uint16      FirstIndex      — seed value for delta accumulator
uint32      BodySize        — byte count of compressed body
uint8[N]    Body            — N = BodySize, delta-compressed bitstream
```

### Delta Decompression Algorithm

Verified against iOS ARM disassembly of `T3IndexBuffer::Decompress`.

```maxscript
-- MaxScript pseudocode for face index decompression
fn DecompressFaceIndices firstIndex bodyBytes mCount = (
    local indices = #(firstIndex)
    local accumulator = firstIndex
    local bitPos = 0
    local totalBits = bodyBytes.count * 8

    while bitPos + 11 <= totalBits AND indices.count < mCount do (
        local deltaWidth = ReadBitsLSB bodyBytes bitPos 4
        bitPos += 4
        local groupCount = ReadBitsLSB bodyBytes bitPos 7
        bitPos += 7
        if groupCount == 0 then exit

        for j = 1 to groupCount while indices.count < mCount do (
            if bitPos + 1 + deltaWidth > totalBits then exit
            local sign = ReadBitsLSB bodyBytes bitPos 1
            bitPos += 1
            local magnitude = if deltaWidth > 0 then ReadBitsLSB bodyBytes bitPos deltaWidth else 0
            bitPos += deltaWidth
            local delta = if sign == 1 then -magnitude else magnitude
            accumulator = bit.and (accumulator + delta) 0xFFFF
            append indices accumulator
        )
    )
    return indices
)
```

The bit reader reads LSB-first from little-endian bytes:
```maxscript
fn ReadBitsLSB data bitOffset numBits = (
    local result = 0
    for i = 0 to numBits - 1 do (
        local byteIdx = (bitOffset + i) / 8 + 1  -- 1-based for MaxScript
        local bitIdx = mod (bitOffset + i) 8
        if bit.get data[byteIdx] (bitIdx + 1) then
            result = bit.or result (bit.shift 1 i)
    )
    return result
)
```

### Raw Face Data (FaceLength == 0)

```
For FaceCount times:
    uint16      FacePoint (add 1 for MaxScript 1-based indexing)
```

### Quad Shortcut

When BodySize == 4 and FirstIndex == 0: use implicit quad triangulation `[1,2,3, 3,2,4]`.

---

## Vertex Buffers

Immediately after the face data body. **All VBs have 16-byte headers.**

```
uint32      Count           — vertex count (same for all buffers)
uint32      Stride          — bytes per vertex
uint32      Type            — attribute type
uint32      Flags           — always 0 on PC V1
uint8[N]    Data            — N = Count × Stride
```

Buffers appear in this order (chain continues while Count matches):

| Type | Stride | Attribute | MaxScript usage |
|------|--------|-----------|-----------------|
| 1 | 12 | Positions | 3 × float32 (X, Y, Z) |
| 2 | 12 | Normals (first) | 3 × float32 (NX, NY, NZ), normalize |
| 4 | 12 | Weights | 3 × float32 (W1, W2, W3; W4 = 1-W1-W2-W3) |
| 5 | 4 | Bone IDs | 4 × uint8 |
| 3 | 8 | UVs | 2 × float32 (U, V). **V = (-V) + 1** for 3DS Max / OBJ |
| 2 | 12 | Tangents (second) | 3 × float32 (skip or use for tangent space) |

**Note**: V1 uses raw float32 for ALL vertex attributes on PC. No compression.
Console versions (Wii, PS3) use compressed vertices — see iOS binary analysis for
`VertexDecompressPosition` / `VertexDecompressNormal` algorithms.

---

## Triangle Assembly

For each submesh, build triangles from the decoded face index array:

### Triangle List (primary geometry)

```maxscript
for y = 1 to PolygonCount do (
    local idx = FacepointStart + (y - 1) * 3
    local fa = FacePoint_array[idx + 1] + 1   -- +1 for MaxScript 1-based
    local fb = FacePoint_array[idx + 2] + 1
    local fc = FacePoint_array[idx + 3] + 1
    -- Skip degenerate triangles (A==C padding pattern)
    if fa != fb AND fb != fc AND fa != fc then
        face = [fa, fb, fc]
)
```

Degenerate triangles with pattern (A, B, A) are intentional separators in the
serialized format. Skip them — they have zero area.

### Extra Strip/Fan (if FacePointEnd > PolygonCount * 3)

The indices from `FacepointStart + PolygonCount * 3` to `FacepointStart + FacePointEnd`
encode small triangle fans as strips. Process as triangle strip:

```maxscript
local stripStart = FacepointStart + PolygonCount * 3
local stripEnd = FacepointStart + FacePointEnd
FaceDirection = 1
f1 = FacePoint_array[stripStart + 1] + 1
f2 = FacePoint_array[stripStart + 2] + 1
for idx = stripStart + 3 to stripEnd do (
    f3 = FacePoint_array[idx] + 1
    FaceDirection *= -1
    if f1 != f2 AND f2 != f3 AND f3 != f1 then (
        if FaceDirection > 0 then
            face = [f3, f2, f1]
        else
            face = [f2, f3, f1]
    )
    f1 = f2
    f2 = f3
)
```

**Note on winding**: The standard `FaceDirection` alternation may produce inverted
faces at degenerate restart boundaries. For correct results, use vertex normals
to determine winding: compute the face normal (cross product), compare with
average vertex normal, flip if they disagree.

---

## D3DTX Texture Formats (V1 era)

Textures use ERTM header + DXT/RGBA pixel data.

| Format Code | FourCC | BPP | Usage |
|-------------|--------|-----|-------|
| — | DXT1 | 4 | Diffuse color, specular, lightmaps |
| — | DXT5 | 8 | Lightmap atlases (some with alpha) |
| 0x33 | (none) | 32 | RGBA8 uncompressed — normal/bump maps |

A `mip_count` u32 appears immediately before the DXT fourcc.
Some lightmap textures have `mip_count = 1` (no mipmap chain).
Pixel data occupies the **end** of the file: `data_start = file_size - total_mip_size`.

---

## Tested Coverage

- 358/358 meshes from EP1 parse and export successfully
- 356/358 exact submesh count match with file header
- 1085 textures in EP1 TX archive (DXT1, DXT5, RGBA8)
- Verified against iOS ARM binary (`T3IndexBuffer::Decompress`, `BitBufferReadOffset`)
- Verified 70/70 triangle match between PC compressed and iOS raw indices (fx_bubble)
- Full vertex coverage (5639/5639 for sk20_guybrush)
- Zero topological anomalies in triangle list interpretation

---

## Reference Implementation

Python reference implementation: https://github.com/coccofresco/telltale-explorer

- `export_mesh_v2.py` — D3DMESH parser (submesh detection, index decoding, VB reading)
- `export_mesh_glb.py` — glTF 2.0 exporter with embedded textures
- `decode_d3dtx.py` — DXT1/DXT3/DXT5/RGBA8 texture decoder
- `FORMAT_D3DMESH_V1.md` — complete format specification
- `FORMAT_D3DTX.md` — texture format specification
- `IOS_BINARY_ANALYSIS.md` — iOS ARM disassembly of key engine functions
