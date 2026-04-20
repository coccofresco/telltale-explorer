"""Telltale CompressedTransformKeys / CompressedPhonemeKeys decoders.

Wire formats reverse-engineered from the Tales of Monkey Island iOS
binary. Produces per-sample decoded Transforms (quaternion + vec3) and
phoneme keys (fade/hold envelopes) from the raw bit-stream buffers.

Also exposes `decode_time_keys` for the paired time-axis stream and
`read_size_prefix` for the compact u8[+u16] size convention used across
several value types. See docs/FORMAT_ANIMATION.md.
"""
from __future__ import annotations
import struct
from dataclasses import dataclass


# Constants extracted from __TEXT VAs
CTK_RANGE_TABLE = [
    0.01, 0.05, 0.1, 0.5, 0.7, 0.8, 1.0, 1.5,
    2.0, 3.0, 4.0, 5.5, 7.0, 8.5, 10.0, 0.5,
]
TIME_RANGE_TABLE = [
    0.1, 1.0 / 6.0, 1.0 / 3.0, 0.5,
    2.0 / 3.0, 1.0, 2.0, 0.01,
]


class BitStream:
    """Little-endian 32-bit-word bit stream, matching BitBufferReadOffset."""

    def __init__(self, data: bytes):
        # Pad generously so any overrun returns zeros instead of
        # crashing. The iOS runtime zero-initializes meta-pool memory,
        # so a decoder that reads past the end sees zeros there.
        # 256 bytes is far more than any valid CTK read could need.
        self._buf = bytes(data) + b"\x00" * 256
        self._len_bits = len(data) * 8
        self.pos = 0

    def _word_at(self, off: int) -> int:
        """Read a u32 at byte `off`, returning 0 past the buffer tail."""
        if off + 4 > len(self._buf):
            # Read whatever bytes remain, treat missing as zero.
            chunk = self._buf[off:off + 4]
            if len(chunk) == 0:
                return 0
            return int.from_bytes(chunk + b"\x00" * (4 - len(chunk)), "little")
        return struct.unpack_from("<I", self._buf, off)[0]

    def peek(self, bit_pos: int, n: int) -> int:
        if n <= 0:
            return 0
        word_off = (bit_pos >> 5) << 2
        shift = bit_pos & 0x1F
        room = 32 - shift
        first = min(room, n)
        if first == 32:
            mask_first = 0xFFFFFFFF
        else:
            mask_first = (1 << first) - 1
        w0 = self._word_at(word_off)
        result = (w0 >> shift) & mask_first
        remaining = n - first
        if remaining > 0:
            w1 = self._word_at(word_off + 4)
            mask_rem = (1 << remaining) - 1
            result |= (w1 & mask_rem) << first
        return result

    def read(self, n: int) -> int:
        v = self.peek(self.pos, n)
        self.pos += n
        return v

    def align_u32(self) -> None:
        self.pos = (self.pos + 31) & ~31

    def read_f32_aligned(self) -> float:
        self.align_u32()
        u = self.read(32)
        return struct.unpack("<f", struct.pack("<I", u & 0xFFFFFFFF))[0]


def _decompress_bounds(q: int, bits: int, f: float) -> float:
    """Clamp(q * f / mask, 0, f) with saturation at endpoints. (DecompressBounds 3-arg)"""
    if bits <= 0:
        return 0.0
    mask = (1 << bits) - 1
    if q == mask:
        return f
    if q == 0:
        return 0.0
    val = (q & mask) * f / mask
    if val < 0.0:
        val = 0.0
    elif val > f:
        val = f
    return val


def _time_combine(q: int, bits: int, f: float, sign_flag: int) -> float:
    """Matches time_combine @ 0x1FD338."""
    if bits <= 0:
        return 0.0
    mask = (1 << bits) - 1
    if sign_flag == 0:
        return f * q / mask if mask else 0.0
    # signed: range [-f, +f]
    return -f + 2.0 * f * q / mask if mask else -f


@dataclass
class CTKSample:
    time: float
    quat: tuple[float, float, float, float]  # (x, y, z, w), unit-length
    vec3: tuple[float, float, float]


def _normalize_quat(q: tuple[float, float, float, float]) -> tuple[float, float, float, float]:
    """Normalize to unit length; zero-quat falls back to identity (0,0,0,1)."""
    mag_sq = q[0] * q[0] + q[1] * q[1] + q[2] * q[2] + q[3] * q[3]
    if mag_sq < 1e-10:
        return (0.0, 0.0, 0.0, 1.0)
    inv = 1.0 / (mag_sq ** 0.5)
    return (q[0] * inv, q[1] * inv, q[2] * inv, q[3] * inv)


def decode_ctk(buf: bytes, verbose: bool = False, return_bits: bool = False):
    """Decode a complete CTK raw bit buffer into a list of samples.

    The buffer contains ONLY the CTK data; time info is in a separate
    CompressedTimeKeys buffer and must be decoded in parallel.
    For this first validation, we produce samples with placeholder times.
    """
    bs = BitStream(buf)

    # ---- Fixed header (absolute bit positions) --------------------------
    sample_count = bs.peek(0, 14)
    ksizes = [bs.peek(14 + 3 * i, 3) for i in range(7)]
    bits_for_range = bs.peek(35, 4)
    mode = bs.peek(39, 4)
    header2 = bs.peek(43, 3)
    init_flag = bs.peek(46, 2)

    if verbose:
        print(f"  sample_count = {sample_count}")
        print(f"  ksizes       = {ksizes}")
        print(f"  bits_for_range = {bits_for_range}")
        print(f"  mode = {mode}  range_scale = {CTK_RANGE_TABLE[mode]}")
        print(f"  header2 = {header2}  init_flag = {init_flag}")

    # ---- State -----------------------------------------------------------
    # The runtime engine uses 4 rolling "slots" for keyframe interpolation
    # during playback; for extraction we only need the decoded keyframe
    # itself, which lives at CTK+0xbc (`current` below).
    current = [0.0] * 7

    samples: list[CTKSample] = []

    bs.pos = 49  # main stream starts at bit 49 (after 14 sc + 33 hdr + 1 pad + 1 flag)

    # Block state
    block_remaining = 0
    cur_blob = [0] * 7
    cur_range = 0.0
    cur_delta_flag = 0

    for sample_i in range(sample_count):
        if block_remaining <= 0:
            # -------- Read new block header from main stream --------
            cur_delta_flag = bs.read(1)
            cur_blob = [bs.read(ksizes[i]) for i in range(7)]
            block_max = bs.read(header2 + 1) + 1  # at least 1 sample

            if all(b == 0 for b in cur_blob):
                cur_range = 0.0
            elif mode == 15:
                cur_range = bs.read_f32_aligned()
            else:
                q = bs.read(bits_for_range)
                cur_range = _decompress_bounds(q, bits_for_range, CTK_RANGE_TABLE[mode])
            block_remaining = block_max

            if verbose:
                print(f"  [block @ bit {bs.pos}] flag={cur_delta_flag} "
                      f"blob={cur_blob} max={block_max} range={cur_range:.4f}")

        # -------- Read one sample: 7 quantized values + decompress --------
        raws = [bs.read(cur_blob[i]) for i in range(7)]
        decoded = [0.0] * 7
        for i in range(7):
            bc = cur_blob[i]
            if bc > 0 and cur_range != 0.0:
                mask = (1 << bc) - 1
                q = raws[i] & mask
                decoded[i] = cur_range * (2.0 * q / mask - 1.0)

        # -------- Compose onto running state --------
        # cur_delta_flag==0: replace current with decoded (absolute keyframe)
        # cur_delta_flag==1: current += decoded (delta on top of previous)
        if cur_delta_flag == 0:
            current = decoded[:]
        else:
            current = [current[j] + decoded[j] for j in range(7)]

        samples.append(CTKSample(
            time=float(sample_i),  # placeholder — until time stream is decoded
            quat=_normalize_quat(tuple(current[:4])),
            vec3=tuple(current[4:]),
        ))
        block_remaining -= 1

    if verbose:
        print(f"  stream consumed {bs.pos} of {len(buf)*8} bits "
              f"({bs.pos/8:.1f} / {len(buf)} bytes)")

    if return_bits:
        return samples, bs.pos
    return samples


def try_decode_at(data: bytes, off: int, max_size: int = 2048) -> tuple[list[CTKSample], int] | None:
    """Attempt to decode a CTK buffer starting at file offset `off`.

    Returns (samples, bytes_consumed) on success, or None if the header
    doesn't look like a valid CTK buffer. Used by the scan locator to
    find CTK buffers in files where the value-interface wrapper format
    is not (yet) understood.
    """
    if off + 8 > len(data):
        return None
    size = min(max_size, len(data) - off)
    # Quick header sanity check (cheap rejection)
    bs = BitStream(data[off:off + size])
    sample_count = bs.peek(0, 14)
    if not (1 <= sample_count <= 10000):
        return None
    ksizes = [bs.peek(14 + 3 * i, 3) for i in range(7)]
    if any(k > 7 for k in ksizes):
        return None  # 3-bit values max 7, but allowing headroom
    # Try decoding
    try:
        samples = decode_ctk(data[off:off + size], verbose=False)
    except (IndexError, struct.error):
        return None
    if len(samples) != sample_count:
        return None
    # Roughly estimate bytes consumed (bits/8 rounded up, then round to 4).
    # The decoder's final bs.pos is internal — re-run to get it.
    bs2 = BitStream(data[off:off + size])
    _ = decode_ctk(bytes(bs2._buf[:size]), verbose=False)  # warms caches only
    return samples, 0  # consumed size TBD — caller can try next plausible boundary


@dataclass
class AnimValueMeta:
    """Per-instance metadata from the ANM trailer."""
    flags: int           # u32 mFlags (high byte = ValueType enum)
    value_type: int      # mFlags >> 24
    bone_hash: int       # u64 Symbol (bone name CRC64)


# Well-known non-bone symbols used as animation channel targets in
# Tales of Monkey Island. These aren't skeletal bones — they're
# animation-graph nodes or runtime properties. CRC64 values sourced
# by matching against ASCII strings in the iOS runtime binary.
ANIMATION_SYMBOLS: dict[int, str] = {
    0x7DC5F26128EC8012: 'relativeNode',
    0xE469742866DA9111: 'absoluteNode',
    0x5838DDBED0B5F83D: 'Phoneme',
    0x284A26CDA9E45D2D: 'Field of View',
    0x8535A38D15763109: 'Render Axis Scale',
    0x9C3C5C9DCB9E790E: 'Runtime: Visible',
}


@dataclass
class PhonemeSample:
    time: float
    phoneme_id: int                   # u32 (low half of a Symbol CRC64)
    fade_in_time: float
    hold_time: float
    fade_out_time: float
    target_contribution: float


def decode_phoneme_keys(
    buf: bytes, f_range: float = 1.0, verbose: bool = False
) -> list[PhonemeSample]:
    """Decode a CompressedPhonemeKeys buffer.

    Wire format (reverse-engineered from CompressedPhonemeKeys::ReadBlock @
    0x001fbb28 and DecompressSample @ 0x001fb7b0 in the Tales of Monkey
    Island iOS binary):

      bits  0..13  sample_count (u14)
      bits 14..16  ksize_0..4 (3 bits each, per-field bit-count widths)
      bits 29..31  padding
      bit  32+     main stream (SetPosition(32) in Initialize)

    Per block:
      ksize_0..3 bits → bit_count[0..3]
      ksize_4 + 1 bits → block_max
      32 bits aligned to next word boundary → phoneme_id (u32)

    Per sample in block, for i in 0..2 (fadeIn, hold, fadeOut):
        q = read(bit_count[i])
        value[i] = f_range * q / mask     if bc > 0
        value[i] = default[i]             otherwise
      where default = [f_range, 0.0, f_range]

    For i == 3 (contribution), the formula is simpler (no f_range scale):
        q = read(bit_count[3])
        value[3] = q / mask               if bc > 0
        value[3] = 1.0                    otherwise

    `f_range` is the float argument passed by ComputeValue to
    DecompressSample (s16 from stack). Defaults to 1.0, which means
    fadeIn/fadeOut/hold are in [0, 1] seconds. Actual value read from
    ComputeValue context (caller passes something like `animLength` or
    a fixed timebase).
    """
    bs = BitStream(buf)
    sample_count = bs.peek(0, 14)
    ksizes = [bs.peek(14 + 3 * i, 3) for i in range(5)]
    bs.pos = 32  # Initialize calls SetPosition(32)

    if verbose:
        print(f"  sample_count = {sample_count}")
        print(f"  ksizes       = {ksizes}")

    samples: list[PhonemeSample] = []
    block_remaining = 0
    block_phoneme_id = 0
    block_bit_counts = [0, 0, 0, 0]

    # Defaults from DecompressSample initialization block (0x1fb7e8..0x1fb7f4):
    #   out[+0x08] (fadeIn)       = s16 (f_range)
    #   out[+0x0c] (hold)         = s10 (const 0.0 from PC+0x10c literal pool)
    #   out[+0x10] (fadeOut)      = s16 (f_range)
    #   out[+0x14] (contribution) = 1.0 (hardcoded 0x3f800000)
    defaults = [f_range, 0.0, f_range, 1.0]

    for si in range(sample_count):
        if block_remaining <= 0:
            block_bit_counts = [bs.read(ksizes[i]) for i in range(4)]
            block_max = bs.read(ksizes[4] + 1) + 1
            bs.align_u32()
            block_phoneme_id = bs.read(32)
            block_remaining = block_max
            if verbose:
                print(f"  [block] bc={block_bit_counts} max={block_max} "
                      f"phoneme=0x{block_phoneme_id:08x}")

        raws = [bs.read(bc) for bc in block_bit_counts]
        values = list(defaults)
        for i in range(4):
            bc = block_bit_counts[i]
            if bc <= 0:
                continue
            mask = (1 << bc) - 1
            q = raws[i] & mask
            if mask == 0:
                continue
            if i == 3:
                # Contribution uses bare q/mask (no f_range multiplier)
                values[3] = q / mask
            else:
                # fadeIn / hold / fadeOut use f_range * q/mask
                values[i] = f_range * q / mask

        samples.append(PhonemeSample(
            time=float(si),
            phoneme_id=block_phoneme_id,
            fade_in_time=values[0],
            hold_time=values[1],
            fade_out_time=values[2],
            target_contribution=values[3],
        ))
        block_remaining -= 1

    return samples


def parse_anm_trailer(
    data: bytes, total_instances: int, file_end: int | None = None
) -> list[AnimValueMeta]:
    """Parse the per-instance metadata trailer of an ANM file.

    Layout (reverse-engineered from Animation::MetaOperation_Serialize):
        u32 mFlags × N_instances         (high byte = ValueType enum)
        u16 symbol-table-count X         (= 0 for direct-Symbol path, path 2)
        (u64 bone_hash + u32 padding) × N_instances     (= 12N bytes)

    For version > 2 ANMs (the common case), total trailer size is
        4N + 2 + 12N = 16N + 2 bytes.

    The function returns one AnimValueMeta per instance, in the same
    order they were serialized (matching walk_ctk_values output indexing).
    """
    if file_end is None:
        file_end = len(data)
    # Trailer starts at file_end - (16*N + 2)
    trailer_size = 16 * total_instances + 2
    trailer_start = file_end - trailer_size
    if trailer_start < 0:
        raise ValueError(
            f"ANM trailer wouldn't fit: need {trailer_size} bytes, "
            f"file has {file_end}"
        )

    mflags_start = trailer_start
    bone_table_start = mflags_start + 4 * total_instances + 2
    out: list[AnimValueMeta] = []
    for i in range(total_instances):
        flags = struct.unpack_from('<I', data, mflags_start + i * 4)[0]
        bone_hash = struct.unpack_from('<Q', data, bone_table_start + i * 12)[0]
        out.append(AnimValueMeta(
            flags=flags,
            value_type=flags >> 24,
            bone_hash=bone_hash,
        ))
    return out


def decode_time_keys(buf: bytes, sample_count: int) -> list[float]:
    """Decode a CompressedTimeKeys buffer into a list of keyframe times.

    Derived from disasm of CompressedTimeKeys::ReadDelta (0x1fd398) and
    AdvanceToTime (0x1fd3dc) in the Tales of Monkey Island iOS binary.

    Returns `sample_count` f32 time values in ascending order.
    An empty buffer produces defaults (see iOS ReadDelta initializer).
    """
    bs = BitStream(buf)
    # Initial state set by ReadDelta (0x1fd398):
    current_time = -1.0 / 30.0
    next_time = -1.0 / 30.0
    start_time = 1.0 / 30.0
    block_remaining = 1   # this[0x25]
    bits_per_delta = 0
    sign_flag = 0
    range_val = 0.0

    # Fixed-position header values (loaded once)
    Y_width = bs.peek(0, 3)     # width of bits_per_delta
    Z_width = bs.peek(3, 3)     # width of block_max - 1
    bits_for_range = bs.peek(6, 4)
    mode = bs.peek(10, 3)

    bs.pos = 13   # main stream starts here (SetPosition(13) in ReadDelta)

    times: list[float] = []
    for _ in range(sample_count):
        block_remaining -= 1
        if block_remaining <= 0:
            # Read new block header
            sign_flag = bs.read(1)
            bits_per_delta = bs.read(Y_width)
            W = bs.read(Z_width + 1)
            block_remaining = W + 1
            if bits_per_delta > 0:
                if mode == 7:
                    range_val = bs.read_f32_aligned()
                else:
                    q = bs.read(bits_for_range)
                    range_val = _decompress_bounds(
                        q, bits_for_range, TIME_RANGE_TABLE[mode]
                    )
            else:
                range_val = 0.0
        # Read one delta
        q = bs.read(bits_per_delta)
        delta = _time_combine(q, bits_per_delta, range_val, sign_flag)
        if sign_flag != 0:
            start_time = start_time + delta
            next_time = next_time + start_time
        else:
            start_time = delta
            next_time = next_time + delta
        times.append(next_time)
    return times


def read_size_prefix(data: bytes, pos: int) -> tuple[int, int]:
    """Read the MetaStream 'compact size' format at `pos`.

    Returns (size, new_pos). If the byte is 0xff, an additional u16
    follows; otherwise the byte value itself is the size. Matches
    CTK::SerializeIn and CompressedTimeKeys::SerializeIn in the iOS
    binary (both call 0x1ea218 then optionally 0x1ea190).
    """
    b = data[pos]
    if b == 0xff:
        size = struct.unpack_from('<H', data, pos + 1)[0]
        return size, pos + 3
    return b, pos + 1


def walk_ctk_values(
    data: bytes, value_start: int, count: int
) -> list[tuple[int, int, int, int]]:
    """Walk `count` consecutive CompressedTransformKeys values.

    Each value in the ANM stream consists of:
        [size_byte (u8/u16) | CTK_N_bytes | time_size_byte | time_M_bytes]
    no inter-value wrapper, no outer/inner size envelope.

    Returns [(ctk_start, ctk_size, time_start, time_size), ...].
    """
    out: list[tuple[int, int, int, int]] = []
    pos = value_start
    for _ in range(count):
        ctk_size, p = read_size_prefix(data, pos)
        ctk_start = p
        p += ctk_size
        time_size, p = read_size_prefix(data, p)
        time_start = p
        p += time_size
        out.append((ctk_start, ctk_size, time_start, time_size))
        pos = p
    return out


# CompressedKeys<T>::SerializeIn wire format (per disasm of
# 0x00432870 for Vector3 and 0x004427c8 for Quaternion):
#     u16 count
#     count * sizeof(T) bytes    (raw sample values)
#     count * 4 bytes            (f32 times per sample)
#     ceil(count / 4) bytes      (per-sample flag bitmap, 2 bits each)
_CK_SAMPLE_SIZES = {
    'CompressedKeys<Vector3>': 12,
    'CompressedKeys<Quaternion>': 16,
    'CompressedKeys<Polar>': 8,
    'CompressedKeys<Color>': 16,
    'CompressedKeys<float>': 4,
    'CompressedKeys<bool>': 1,
    'CompressedKeys<int>': 4,
    'CompressedKeys<Transform>': 32,
}


# SingleValue<T>::MetaOperation_Serialize dispatches straight to the
# per-type serializer for the inner field — no size prefix, no timing.
# Inner field sizes come from the type descriptors in TelltaleToolLib.
_SINGLE_VALUE_SIZES = {
    'SingleValue<Transform>': 32,   # Quaternion(16) + Vector3(12) + padAlign(4)
    'SingleValue<Quaternion>': 16,
    'SingleValue<Vector3>': 12,
    'SingleValue<Polar>': 8,
    'SingleValue<Color>': 16,
    'SingleValue<float>': 4,
    'SingleValue<bool>': 1,
    'SingleValue<int>': 4,
}


def skip_compressed_keys(data: bytes, pos: int, sample_size: int) -> int:
    """Return the byte offset immediately after one CompressedKeys<T> value."""
    count = struct.unpack_from('<H', data, pos)[0]
    bitmap = (count + 3) // 4
    total = 2 + count * sample_size + count * 4 + bitmap
    return pos + total


# Hash → type name map for types we can skip but don't know yet.
# Populated empirically from the ANM files we've seen.
_KNOWN_UNKNOWN_HASHES: dict[int, str] = {
    0x9A946F2A83FC7658: 'CompressedKeys<Quaternion>',
    0x108A4BDBA5C4323C: 'CompressedKeys<Vector3>',
    0xC0E90B6129B2DADA: 'CompressedKeys<bool>',
    0xCECACE3A835CB7EE: 'SingleValue<Quaternion>',
    0x0C1E84D6FF72CE80: 'SingleValue<Transform>',
}


# Types that use the "two-pool" wire format: [size | data | time_size | time_data]
# (same as CTK). Found by disassembling each type's SerializeIn in the iOS binary.
_CTK_LIKE_TYPES = {
    'CompressedTransformKeys',
    'CompressedPhonemeKeys',
}


def skip_ctk_like(data: bytes, pos: int) -> int:
    """Skip one value that serializes like CTK (size+data+time_size+time_data)."""
    size1, p = read_size_prefix(data, pos)
    p += size1
    size2, p = read_size_prefix(data, p)
    p += size2
    return p


def find_ctk_start(data: bytes, value_start: int, types: list) -> int | None:
    """Given the ordered types list, compute where the first CTK value begins.

    Advances past any preceding non-CTK types using known structural
    readers. Returns None if we hit a type we don't know how to skip.
    """
    pos = value_start
    for t in types:
        if t.name == 'CompressedTransformKeys':
            return pos
        # Map from hash if t.name is '?'
        name = t.name
        if name == '?' and t.hash in _KNOWN_UNKNOWN_HASHES:
            name = _KNOWN_UNKNOWN_HASHES[t.hash]
        if name in _CTK_LIKE_TYPES:
            # Same wire format as CTK — skip via two-pool reader.
            for _ in range(t.count):
                pos = skip_ctk_like(data, pos)
            continue
        sample_sz = _CK_SAMPLE_SIZES.get(name)
        if sample_sz is not None:
            for _ in range(t.count):
                pos = skip_compressed_keys(data, pos, sample_sz)
            continue
        sv_sz = _SINGLE_VALUE_SIZES.get(name)
        if sv_sz is not None:
            pos += t.count * sv_sz
            continue
        return None  # unknown type, cannot skip blindly
    return pos  # no CTK in this file


def scan_sized_ctks(
    data: bytes, start: int = 0, end: int | None = None, slack: int = 8
) -> list[tuple[int, int, int, list[CTKSample]]]:
    """Scan for CTK buffers preceded by a size-prefix byte.

    The Telltale format prefixes each CTK buffer with a single byte
    indicating its allocation size (or 0xFF + u16 for extended).
    This scanner finds positions where:
      * The previous byte could be a plausible size prefix
      * Decoding N samples succeeds
      * Consumed bytes ≤ prefix byte ≤ consumed + slack

    Returns (offset, size_byte, samples_count, samples) per hit.
    """
    if end is None:
        end = len(data)
    hits: list[tuple[int, int, int, list[CTKSample]]] = []
    for off in range(max(start, 1), end - 10):
        try:
            bs = BitStream(data[off:off + 512])
            sc = bs.peek(0, 14)
            if not (1 <= sc <= 2000):
                continue
            ks = [bs.peek(14 + 3 * i, 3) for i in range(7)]
            if any(k > 6 for k in ks):
                continue
            samples, bits = decode_ctk(
                data[off:off + 4096], return_bits=True
            )
            if len(samples) != sc or bits < 30:
                continue
            bc = (bits + 7) // 8
            prev = data[off - 1]
            if prev >= 12 and bc <= prev <= bc + slack:
                hits.append((off, prev, sc, samples))
        except Exception:
            continue
    return hits


def walk_ctk_pool(
    data: bytes, pool_start: int, pool_size: int
) -> list[tuple[int, int, list[CTKSample], int]]:
    """Walk a contiguous CTK pool.

    Assumes the pool is a bump-allocated sequence of CTK buffers with
    size-aligned-to-4. Starts at `pool_start`, consumes `pool_size`
    bytes total. Each successfully decoded CTK advances the cursor by
    `ceil(bits_consumed / 8)` rounded up to the next 4-byte boundary.

    Returns [(file_offset, sample_count, samples, bytes_consumed), ...].
    """
    hits: list[tuple[int, int, list[CTKSample], int]] = []
    cursor = pool_start
    pool_end = pool_start + pool_size
    while cursor < pool_end:
        window = data[cursor:pool_end]
        if len(window) < 8:
            break
        # Quick cheap rejection
        try:
            bs = BitStream(window)
            sample_count = bs.peek(0, 14)
            if not (1 <= sample_count <= 2000):
                return hits  # stop on first misaligned entry
            ksizes = [bs.peek(14 + 3 * i, 3) for i in range(7)]
            if any(k > 6 for k in ksizes):
                return hits
            samples, bits = decode_ctk(window, verbose=False, return_bits=True)
        except Exception:
            return hits
        if len(samples) != sample_count:
            return hits
        bytes_consumed = (bits + 7) // 8
        # Align to 4-byte boundary for next allocation
        aligned = (bytes_consumed + 3) & ~3
        hits.append((cursor, sample_count, samples, aligned))
        cursor += aligned
    return hits


if __name__ == "__main__":
    import sys
    import os

    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        print("usage:")
        print("  parse_ctk.py <anm_file>")
        print("     → scan file for all size-prefixed CTK buffers and dump a summary")
        print("  parse_ctk.py <anm_file> <offset> [size]")
        print("     → decode a single CTK buffer at a specific offset")
        sys.exit(0)

    path = args[0]
    with open(path, "rb") as f:
        data = f.read()

    if len(args) >= 2:
        off = int(args[1], 0)
        size = int(args[2], 0) if len(args) > 2 else (len(data) - off)
        buf = data[off:off + size]
        print(f"=== {path} (ctk buffer @ 0x{off:x}, {len(buf)} B) ===")
        samples = decode_ctk(buf, verbose=True)
        print(f"\n  Decoded {len(samples)} samples:")
        for i, s in enumerate(samples):
            q = s.quat
            v = s.vec3
            print(f"    [{i}] quat=({q[0]:+.4f},{q[1]:+.4f},{q[2]:+.4f},{q[3]:+.4f})"
                  f"  vec3=({v[0]:+.4f},{v[1]:+.4f},{v[2]:+.4f})")
    else:
        # Full-file scan mode
        print(f"=== {os.path.basename(path)} ({len(data)} B) ===")

        # Quick type-declaration check — avoid scanning pure-KFV files
        # where the heuristic produces false positives.
        try:
            from parse_anm import parse_header
            h = parse_header(data)
            ctk_count = sum(t.count for t in h.types
                            if 'CompressedTransform' in t.name)
            kfv_count = sum(t.count for t in h.types if 'Keyframed' in t.name)
            print(f"  declared: {ctk_count} CTK, {kfv_count} KFV "
                  f"({h.total_interfaces} values total)")
        except Exception:
            ctk_count = -1
            kfv_count = -1

        hits = scan_sized_ctks(data)
        print(f"Found {len(hits)} size-prefixed hits"
              f"{' — ALL FALSE POSITIVES (no CTK declared)' if ctk_count == 0 else ''}:\n")
        total_samples = 0
        for off, size_byte, sc, samples in hits:
            ksizes_line = ""
            total_samples += sc
            print(f"  @ 0x{off:04x}: size_byte={size_byte:3d}B  "
                  f"samples={sc:4d}  first_quat="
                  f"({samples[0].quat[0]:+.3f},"
                  f"{samples[0].quat[1]:+.3f},"
                  f"{samples[0].quat[2]:+.3f},"
                  f"{samples[0].quat[3]:+.3f})")
        print(f"\nTotal: {total_samples} samples across {len(hits)} CTK channels")
