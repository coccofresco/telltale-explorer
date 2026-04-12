#!/usr/bin/env python3
"""
D3DTX Texture Decoder — Tales of Monkey Island
Extracts DXT1/DXT3/DXT5 texture data and converts to PNG.

Pure Python — no external dependencies.
"""
import struct, os


def decode_d3dtx(data):
    """
    Parse a D3DTX file and return (width, height, format_name, rgba_pixels).
    rgba_pixels is a flat list of (r, g, b, a) tuples, row by row, top to bottom.
    Only decodes the largest mip level.

    Supported formats:
    - DXT1, DXT3, DXT5 (block-compressed)
    - Raw RGBA8 (format code 0x33, used for normal/bump maps)
    """
    # Try DXT first
    dxt_off = data.find(b'DXT')
    if dxt_off >= 0:
        return _decode_dxt_texture(data, dxt_off)

    # Try raw RGBA8 (format code 0x33 = 51)
    return _decode_raw_texture(data)


def _decode_dxt_texture(data, dxt_off):
    dxt_type = data[dxt_off:dxt_off + 4]
    width = struct.unpack_from('<I', data, dxt_off + 4)[0]
    height = struct.unpack_from('<I', data, dxt_off + 8)[0]

    if width == 0 or height == 0 or width > 8192 or height > 8192:
        raise ValueError(f"Invalid dimensions: {width}x{height}")

    if dxt_type == b'DXT1':
        bpb = 8
    elif dxt_type in (b'DXT3', b'DXT5'):
        bpb = 16
    else:
        raise ValueError(f"Unsupported DXT format: {dxt_type}")

    # Read mip count from the u32 right before the DXT fourcc
    mip_count = struct.unpack_from('<I', data, dxt_off - 4)[0] if dxt_off >= 4 else 0
    if mip_count < 1 or mip_count > 20:
        # Fallback: compute full mipmap chain
        total_mip = _calc_block_mip_total(width, height, bpb)
    else:
        # Use only the specified number of mip levels
        total_mip = _calc_block_mip_total_n(width, height, bpb, mip_count)

    dxt_data_start = len(data) - total_mip
    if dxt_data_start < 0:
        raise ValueError(f"File too small for {width}x{height} mipmaps")

    base_size = max(1, width // 4) * max(1, height // 4) * bpb
    block_data = data[dxt_data_start:dxt_data_start + base_size]

    if dxt_type == b'DXT1':
        pixels = _decode_dxt1(block_data, width, height)
    elif dxt_type == b'DXT5':
        pixels = _decode_dxt5(block_data, width, height)
    else:
        pixels = _decode_dxt3(block_data, width, height)

    return width, height, dxt_type.decode('ascii'), pixels


def _decode_raw_texture(data):
    """Decode raw uncompressed RGBA8 texture (format code 0x33)."""
    # Find the format code and dimensions by scanning after the name
    # Pattern: name_len(u32) + name + versioning + format_code(u32) + width(u32) + height(u32)
    # We detect raw format by trying RGBA8 mipmap sizes against file size.

    # Parse past ERTM header
    if data[:4] == b'ERTM':
        cc = struct.unpack_from('<I', data, 4)[0]
        pos = 8
        for _ in range(cc):
            if struct.unpack_from('<I', data, pos)[0] > 128:
                pos += 12
            else:
                pos += 4 + struct.unpack_from('<I', data, pos)[0] + 4
    else:
        pos = 0

    # Skip name
    if pos + 4 > len(data):
        raise ValueError("File too small")
    nl = struct.unpack_from('<I', data, pos)[0]
    if nl > 200:
        raise ValueError("Invalid name length")
    pos += 4 + nl

    # Scan for dimensions: look for two consecutive power-of-2 u32 values
    # where the RGBA8 mipmap total matches the remaining file size
    width = height = 0
    for probe in range(pos, min(pos + 80, len(data) - 8)):
        w = struct.unpack_from('<I', data, probe)[0]
        h = struct.unpack_from('<I', data, probe + 4)[0]
        if 4 <= w <= 4096 and 4 <= h <= 4096 and (w & (w - 1)) == 0 and (h & (h - 1)) == 0:
            total = _calc_rgba_mip_total(w, h)
            header_size = len(data) - total
            if 50 < header_size < 500:
                width, height = w, h
                break

    if width == 0:
        raise ValueError("Could not determine dimensions for raw texture")

    total_mip = _calc_rgba_mip_total(width, height)
    data_start = len(data) - total_mip
    base_size = width * height * 4

    pixels = []
    for i in range(width * height):
        off = data_start + i * 4
        r, g, b, a = data[off], data[off + 1], data[off + 2], data[off + 3]
        pixels.append((r, g, b, a))

    return width, height, 'RGBA8', pixels


def _calc_block_mip_total(w, h, bpb):
    total = 0
    while w >= 1 and h >= 1:
        total += max(1, w // 4) * max(1, h // 4) * bpb
        if w == 1 and h == 1:
            break
        w = max(1, w // 2)
        h = max(1, h // 2)
    return total


def _calc_block_mip_total_n(w, h, bpb, n):
    """Calculate total block mipmap size for exactly n levels."""
    total = 0
    for _ in range(n):
        total += max(1, w // 4) * max(1, h // 4) * bpb
        if w == 1 and h == 1:
            break
        w = max(1, w // 2)
        h = max(1, h // 2)
    return total


def _calc_rgba_mip_total(w, h):
    total = 0
    while w >= 1 and h >= 1:
        total += w * h * 4
        if w == 1 and h == 1:
            break
        w = max(1, w // 2)
        h = max(1, h // 2)
    return total


def _rgb565_to_rgba(c):
    r = ((c >> 11) & 0x1F) * 255 // 31
    g = ((c >> 5) & 0x3F) * 255 // 63
    b = (c & 0x1F) * 255 // 31
    return (r, g, b, 255)


def _decode_dxt1(block_data, width, height):
    pixels = [(0, 0, 0, 255)] * (width * height)
    bw = max(1, width // 4)
    bh = max(1, height // 4)
    off = 0

    for by in range(bh):
        for bx in range(bw):
            if off + 8 > len(block_data):
                break
            c0 = struct.unpack_from('<H', block_data, off)[0]
            c1 = struct.unpack_from('<H', block_data, off + 2)[0]
            bits = struct.unpack_from('<I', block_data, off + 4)[0]
            off += 8

            r0, g0, b0, _ = _rgb565_to_rgba(c0)
            r1, g1, b1, _ = _rgb565_to_rgba(c1)

            palette = [(r0, g0, b0, 255), (r1, g1, b1, 255)]
            if c0 > c1:
                palette.append(((2 * r0 + r1) // 3, (2 * g0 + g1) // 3, (2 * b0 + b1) // 3, 255))
                palette.append(((r0 + 2 * r1) // 3, (g0 + 2 * g1) // 3, (b0 + 2 * b1) // 3, 255))
            else:
                palette.append(((r0 + r1) // 2, (g0 + g1) // 2, (b0 + b1) // 2, 255))
                palette.append((0, 0, 0, 0))  # transparent

            for py in range(4):
                for px in range(4):
                    x = bx * 4 + px
                    y = by * 4 + py
                    if x < width and y < height:
                        idx = (bits >> (2 * (py * 4 + px))) & 0x3
                        pixels[y * width + x] = palette[idx]

    return pixels


def _decode_dxt5(block_data, width, height):
    pixels = [(0, 0, 0, 255)] * (width * height)
    bw = max(1, width // 4)
    bh = max(1, height // 4)
    off = 0

    for by in range(bh):
        for bx in range(bw):
            if off + 16 > len(block_data):
                break

            # Alpha block (8 bytes)
            a0 = block_data[off]
            a1 = block_data[off + 1]
            abits = 0
            for i in range(6):
                abits |= block_data[off + 2 + i] << (8 * i)

            a_palette = [a0, a1]
            if a0 > a1:
                for i in range(1, 7):
                    a_palette.append(((7 - i) * a0 + i * a1) // 7)
            else:
                for i in range(1, 5):
                    a_palette.append(((5 - i) * a0 + i * a1) // 5)
                a_palette.extend([0, 255])

            # Color block (8 bytes, same as DXT1)
            c0 = struct.unpack_from('<H', block_data, off + 8)[0]
            c1 = struct.unpack_from('<H', block_data, off + 10)[0]
            bits = struct.unpack_from('<I', block_data, off + 12)[0]
            off += 16

            r0, g0, b0, _ = _rgb565_to_rgba(c0)
            r1, g1, b1, _ = _rgb565_to_rgba(c1)
            palette = [
                (r0, g0, b0), (r1, g1, b1),
                ((2 * r0 + r1) // 3, (2 * g0 + g1) // 3, (2 * b0 + b1) // 3),
                ((r0 + 2 * r1) // 3, (g0 + 2 * g1) // 3, (b0 + 2 * b1) // 3),
            ]

            for py in range(4):
                for px in range(4):
                    x = bx * 4 + px
                    y = by * 4 + py
                    if x < width and y < height:
                        cidx = (bits >> (2 * (py * 4 + px))) & 0x3
                        aidx = (abits >> (3 * (py * 4 + px))) & 0x7
                        r, g, b = palette[cidx]
                        a = a_palette[aidx]
                        pixels[y * width + x] = (r, g, b, a)

    return pixels


def _decode_dxt3(block_data, width, height):
    pixels = [(0, 0, 0, 255)] * (width * height)
    bw = max(1, width // 4)
    bh = max(1, height // 4)
    off = 0

    for by in range(bh):
        for bx in range(bw):
            if off + 16 > len(block_data):
                break

            # Alpha (8 bytes, 4 bits per pixel)
            alpha_data = block_data[off:off + 8]

            # Color block
            c0 = struct.unpack_from('<H', block_data, off + 8)[0]
            c1 = struct.unpack_from('<H', block_data, off + 10)[0]
            bits = struct.unpack_from('<I', block_data, off + 12)[0]
            off += 16

            r0, g0, b0, _ = _rgb565_to_rgba(c0)
            r1, g1, b1, _ = _rgb565_to_rgba(c1)
            palette = [
                (r0, g0, b0), (r1, g1, b1),
                ((2 * r0 + r1) // 3, (2 * g0 + g1) // 3, (2 * b0 + b1) // 3),
                ((r0 + 2 * r1) // 3, (g0 + 2 * g1) // 3, (b0 + 2 * b1) // 3),
            ]

            for py in range(4):
                for px in range(4):
                    x = bx * 4 + px
                    y = by * 4 + py
                    if x < width and y < height:
                        cidx = (bits >> (2 * (py * 4 + px))) & 0x3
                        # 4-bit alpha
                        abyte = alpha_data[(py * 4 + px) // 2]
                        if (py * 4 + px) % 2 == 0:
                            a = (abyte & 0xF) * 17
                        else:
                            a = (abyte >> 4) * 17
                        r, g, b = palette[cidx]
                        pixels[y * width + x] = (r, g, b, a)

    return pixels


def pixels_to_png(pixels, width, height, path):
    """Write RGBA pixels to PNG. Pure Python, no dependencies."""
    import zlib

    def _chunk(chunk_type, data):
        c = chunk_type + data
        crc = zlib.crc32(c) & 0xFFFFFFFF
        return struct.pack('>I', len(data)) + c + struct.pack('>I', crc)

    # IHDR
    ihdr = struct.pack('>IIBBBBB', width, height, 8, 6, 0, 0, 0)  # 8bit RGBA

    # IDAT — raw pixel rows with filter byte 0 (None) per row
    raw = bytearray()
    for y in range(height):
        raw.append(0)  # filter: None
        for x in range(width):
            r, g, b, a = pixels[y * width + x]
            raw.extend([r, g, b, a])

    compressed = zlib.compress(bytes(raw), 9)

    with open(path, 'wb') as f:
        f.write(b'\x89PNG\r\n\x1a\n')
        f.write(_chunk(b'IHDR', ihdr))
        f.write(_chunk(b'IDAT', compressed))
        f.write(_chunk(b'IEND', b''))


def convert_d3dtx_to_png(input_path, output_path=None):
    """Convert a D3DTX file to PNG."""
    if output_path is None:
        output_path = os.path.splitext(input_path)[0] + '.png'

    with open(input_path, 'rb') as f:
        data = f.read()

    width, height, fmt, pixels = decode_d3dtx(data)
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    pixels_to_png(pixels, width, height, output_path)

    print(f"{os.path.basename(input_path)}: {width}x{height} {fmt} -> {output_path} "
          f"({os.path.getsize(output_path)} bytes)")
    return width, height, fmt


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print("Usage: python decode_d3dtx.py <input.d3dtx> [output.png]")
        sys.exit(1)
    convert_d3dtx_to_png(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
