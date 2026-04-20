# ANM — Animation Format

Skeletal and property animations for Tales of Monkey Island. The container
is a `MetaStream` (ERTM) wrapping an `Animation` struct.

`parse_anm_values.walk_anm(data)` decodes **99.9%** of ep1 anms (4726/4733)
with 100% per-value decoding for every type except `CompressedVector3Keys2`
(outer skip only; inner bit-stream not yet reversed).

## Top-level `Animation` layout

```
u32  mVersion                  # 4 or 5
u32  mFlags
u64  mName                     # Symbol CRC64
u32  padding
f32  mAdditiveMask
f32  mLength                   # seconds
u32  block_size                # MetaStream BeginBlock prefix
# --- inside the block:
u32  totalNumOfInterfaces      # total animated channels
u32  dataBufferSize             # AnimationValueSerializeContext pool size
u32  animValueTypes            # number of distinct value types
per type:
    u64 typeHash               # CRC64 of class name
    u32 pad
    u16 valuesOfType
    u16 typeVersion
# --- per-value SerializeIn bodies, in type-declaration then value order
for each value:
    <type-specific body>
# --- per-value mFlags (u32), same order
for each value: u32 mFlags     # high byte = ValueType enum
if total_values > 0:
    u16 zero
# --- per-value mName (Symbol), same order
for each value:
    u64 mName                  # CRC64
    u32 0                      # empty-debug-string trailer (stream v < 5)
```

`ValueType` (high byte of `mFlags`): 1 Time, 2 Weight, 3 Skeletal,
4 Mover, 5 Property, 6 AdditiveMask, 8 SkeletonPose.

## Value-type bodies (stream bytes consumed per value)

| Type                         | Stream bytes                                            |
|------------------------------|---------------------------------------------------------|
| CompressedKeys<Vector3>      | `2 + count*16 + ⌈count/4⌉`                             |
| CompressedKeys<Quaternion>   | `2 + count*20 + ⌈count/4⌉`                             |
| CompressedKeys<Transform>    | `2 + count*32 + ⌈count/4⌉`   (28 B per T + 4 B time)   |
| CompressedKeys<float>        | `2 + count*8  + ⌈count/4⌉`                             |
| CompressedKeys<Bool>         | `2 + count*5  + ⌈count/4⌉`                             |
| SingleValue<Transform>       | 28       (Quat 16 + Vec3 12, padAlign NOT serialized)  |
| SingleValue<Quaternion>      | 16                                                      |
| SingleValue<Vector3>         | 12                                                      |
| SingleValue<Float>           | 4                                                       |
| SingleValue<Bool>            | 1                                                       |
| SingleVector3Value           | 4        (uniform/isotropic: x = y = z = scalar)        |
| CompressedTransformKeys      | two size-prefixed blocks + bit-stream (see CTK below)  |
| CompressedPhonemeKeys        | two size-prefixed blocks + bit-stream (see Phoneme)    |
| CompressedVector3Keys2       | two size-prefixed blocks; inner bit-stream unreversed  |

## `CompressedKeys<T>` wire format

```
u16 count
per sample:
    T    value             # 12 B Vector3, 16 B Quaternion, 28 B Transform, 4 B float, 1 B Bool
    f32  time
u8[⌈count/4⌉] flags        # 2 bits per sample; semantics unclear (likely
                           #   interpolation kind). Zero-filled in decoder.
```

Despite the name, this is **not** compressed — it's raw interleaved
`(value, time)` pairs with a small trailing bitmask.

## CTK and Phoneme (`CompressedTransformKeys`, `CompressedPhonemeKeys`)

These use the **two-buffer** size-prefix layout:

```
u8  size1 (or 0xff + u16 extended size1)
... size1 bytes of primary bit-stream data
u8  size2 (or 0xff + u16 extended size2)
... size2 bytes of time-key bit-stream
```

The primary stream holds per-bone quaternion+vector deltas over blocks
(CTK) or per-block phoneme fade envelopes (Phoneme). The secondary stream
holds per-sample f32 times, optionally delta-compressed. See
`parse_ctk.decode_ctk` and `parse_ctk.decode_phoneme_keys`.

`CompressedVector3Keys2` shares the same two-buffer outer layout (verified
via iOS disasm of the `SerializeIn` symbol), but its inner post-processing
in 0x1fee2c hasn't been reversed yet — the walker skips it cleanly.

## Animation-level symbols (not bones)

Some value channels target engine pseudo-nodes rather than skeleton bones.
These CRC64s are recognised by `parse_ctk.ANIMATION_SYMBOLS`:

```
0x7DC5F26128EC8012  relativeNode       (world/mover target)
0xE469742866DA9111  absoluteNode       (object-local target)
0x5838DDBED0B5F83D  Phoneme
0x284A26CDA9E45D2D  Field of View
0x8535A38D15763109  Render Axis Scale
0x9C3C5C9DCB9E790E  Runtime: Visible
```

## Readers

| Script                         | Purpose                                                        |
|--------------------------------|----------------------------------------------------------------|
| `parse_anm.py`                 | Header + type-table parsing. Exposes `parse_header(data)`.     |
| `parse_compressed_keys.py`     | Standalone `CompressedKeys<Vector3/Quaternion/Transform>` decoder. |
| `parse_ctk.py`                 | `decode_ctk`, `decode_time_keys`, `decode_phoneme_keys`, size-prefix reader. |
| `parse_anm_values.py`          | Full multi-value walker. Routes CTK/Phoneme/CV3K2 to their decoders; populates samples. |

## CLI

```bash
python parse_anm_values.py path/to/anim.anm [--all]
```

Lists every channel: type, `ValueType`, bone target (resolved via hash DB
+ `ANIMATION_SYMBOLS`), and per-channel sample count. `--all` dumps every
channel; default shows the first 8.

## Validation

- 202 / 202 first-type `CompressedKeys<Vector3/Quaternion>` anms decode
  with monotonically non-decreasing timestamps inside `[0, anim_length]`.
- 4726 / 4733 ep1 anms fully walked. Residuals: 5 legitimately-empty
  anims and 2 older `KeyframedValue<T>`-only anms served by the separate
  `export_animated_glb.py` KFV path.
