#!/usr/bin/env python3
"""
D3DMESH V1 → glTF 2.0 (.glb) Exporter — Tales of Monkey Island

Exports mesh with:
- One primitive per TriangleSet (submesh) with its own material
- Materials named after the original texture (ready for future texture linking)
- Positions, normals, UVs
- Vertex weights + bone indices (stored, ready for future skeleton linking)

Usage: python export_mesh_glb.py <input.d3dmesh> [output.glb]
"""
import struct, sys, os, math, json


# =========================================================================
# D3DMESH parsing core (ERTM header, submeshes, face decoder)
# =========================================================================

def parse_ertm_header(data):
    """Parse ERTM header, return offset to mesh payload."""
    if data[0:4] != b'ERTM':
        return 0
    class_count = struct.unpack_from('<I', data, 4)[0]
    pos = 8
    for _ in range(class_count):
        if struct.unpack_from('<I', data, pos)[0] > 128:
            pos += 12
        else:
            pos += 4 + struct.unpack_from('<I', data, pos)[0] + 4
    return pos


def find_face_marker(data):
    """Find the face section marker (0x30 0x65 with compressed flag)."""
    for i in range(len(data) - 13):
        if data[i] == 0x30 and data[i + 1] == 0x65:
            fc = struct.unpack_from('<I', data, i + 5)[0]
            fl = struct.unpack_from('<I', data, i + 9)[0]
            if 0 < fc < 10000000 and fl in (0, 1):
                return i, fc, fl
    return -1, 0, 0


def decode_face_indices(first_index, body):
    """Delta-compressed face index decoder (matches iOS T3IndexBuffer::Decompress)."""
    padded = bytearray(body) + bytearray(16)
    total_bits = len(body) * 8
    bit_pos = 0
    acc = first_index
    indices = [acc]

    def rb(n):
        nonlocal bit_pos
        r = 0
        for i in range(n):
            if padded[(bit_pos + i) >> 3] & (1 << ((bit_pos + i) & 7)):
                r |= 1 << i
        bit_pos += n
        return r

    while bit_pos + 11 <= total_bits:
        dw = rb(4)
        gc = rb(7)
        if gc == 0:
            break
        for _ in range(gc):
            if bit_pos + 1 + dw > total_bits:
                break
            s = rb(1)
            m = rb(dw) if dw > 0 else 0
            acc = (acc + (-m if s else m)) & 0xFFFF
            indices.append(acc)
    return indices


def parse_submeshes(data, data_offset, face_marker_pos):
    """Parse TriangleSet array. Returns list of (start, nprim3, 'list'[, full_count])."""
    try:
        return _parse_submeshes_inner(data, data_offset, face_marker_pos)
    except (struct.error, IndexError, ValueError):
        return []


def parse_submeshes_with_palette_idx(data, data_offset):
    """Parse submesh array returning (submesh_block_end, [(bone_palette_idx, start_idx, nprim), ...]).

    The field at +24 in each TriangleSet struct is mBonePaletteIndex
    (identified via iOS binary MetaClassDescription at file offset 0x5547c0).
    """
    try:
        return _parse_submeshes_with_palette_inner(data, data_offset)
    except (struct.error, IndexError, ValueError):
        return 0, []


def _parse_submeshes_with_palette_inner(data, data_offset):
    pos = data_offset
    dlen = len(data)
    if pos + 8 > dlen:
        return 0, []
    name_hdr_len = struct.unpack_from('<I', data, pos)[0]
    name_len = struct.unpack_from('<I', data, pos + 4)[0]
    if name_len > name_hdr_len:
        name_len = name_hdr_len
        name_start = pos + 4
    else:
        name_start = pos + 8
    if name_len > 256 or name_start + name_len + 1 > dlen:
        return 0, []
    pos = name_start + name_len + 1 + 28
    if pos + 8 > dlen:
        return 0, []
    head3a_size = struct.unpack_from('<I', data, pos)[0]
    submesh_count = struct.unpack_from('<I', data, pos + 4)[0]
    submesh_block_end = pos + 4 + head3a_size
    pos += 8
    if submesh_count == 0 or submesh_count > 500:
        return 0, []
    avg_struct_size = head3a_size // submesh_count if submesh_count > 0 else 0
    results = []
    for _ in range(submesh_count):
        struct_start = pos
        if pos + 24 + 24 > dlen:
            break
        bone_pal = struct.unpack_from('<I', data, struct_start + 24)[0]
        pos += 24
        start_index = struct.unpack_from('<I', data, pos + 16)[0]
        nprim = struct.unpack_from('<I', data, pos + 20)[0]
        pos += 24
        results.append((bone_pal, start_index, nprim))
        if pos + 36 + 4 > dlen:
            break
        pos += 36
        mat_block_len = struct.unpack_from('<I', data, pos)[0]
        if mat_block_len > 50000 or pos + 4 + mat_block_len > dlen:
            break
        pos += 4 + mat_block_len
        if pos + 4 > dlen:
            break
        tex_name_len = struct.unpack_from('<I', data, pos)[0]
        if tex_name_len > 1000 or pos + 4 + tex_name_len > dlen:
            break
        pos += 4 + tex_name_len
        advanced = False
        scan_limit = min(pos + 200, submesh_block_end, dlen)
        for scan in range(pos, scan_limit):
            if data[scan] == 0x31 and scan + 5 <= dlen:
                block_size = struct.unpack_from('<I', data, scan + 1)[0]
                if 4 <= block_size <= 512 and scan + 1 + 4 + block_size + 162 <= dlen:
                    pos = scan + 1 + 4 + block_size + 162
                    advanced = True
                    break
        if not advanced:
            if avg_struct_size > 0:
                pos = struct_start + avg_struct_size
            else:
                break
    return submesh_block_end, results


def parse_bone_palettes(data, start_offset):
    """Parse the bone palette section at start_offset.

    Layout (v1 ERTM, hashed bones):
        u32 0 (separator?)
        u32 palette_section_size
        u32 num_palettes
        for each palette:
            u32 bone_count
            for each bone:
                u32 hash_low
                u32 hash_high
                u32 padding

    Returns list-of-lists of 64-bit hashes.
    """
    try:
        p = start_offset + 4  # skip separator
        section_size = struct.unpack_from('<I', data, p)[0]; p += 4
        num_palettes = struct.unpack_from('<I', data, p)[0]; p += 4
        if num_palettes > 64 or section_size > 65536:
            return []
        palettes = []
        for _ in range(num_palettes):
            cnt = struct.unpack_from('<I', data, p)[0]; p += 4
            if cnt > 256:
                return []
            bones = []
            for _ in range(cnt):
                low, high = struct.unpack_from('<II', data, p); p += 8
                p += 4  # padding
                bones.append((high << 32) | low)
            palettes.append(bones)
        return palettes
    except (struct.error, IndexError):
        return []


def _parse_submeshes_inner(data, data_offset, face_marker_pos):
    pos = data_offset
    dlen = len(data)
    if pos + 8 > dlen:
        return []
    name_hdr_len = struct.unpack_from('<I', data, pos)[0]
    name_len = struct.unpack_from('<I', data, pos + 4)[0]
    if name_len > name_hdr_len:
        name_len = name_hdr_len
        name_start = pos + 4
    else:
        name_start = pos + 8
    if name_len > 256 or name_start + name_len + 1 > dlen:
        return []
    pos = name_start + name_len + 1 + 28
    if pos + 8 > dlen:
        return []
    head3a_size = struct.unpack_from('<I', data, pos)[0]
    submesh_count = struct.unpack_from('<I', data, pos + 4)[0]
    submesh_block_end = pos + 4 + head3a_size
    pos += 8
    if submesh_count == 0 or submesh_count > 500:
        return []
    avg_struct_size = head3a_size // submesh_count if submesh_count > 0 else 0
    results = []
    for i in range(submesh_count):
        struct_start = pos
        if pos + 24 + 24 > dlen:
            break
        pos += 24
        start_index = struct.unpack_from('<I', data, pos + 16)[0]
        nprim = struct.unpack_from('<I', data, pos + 20)[0]
        pos += 24
        results.append((start_index, nprim))
        if pos + 36 + 4 > dlen:
            break
        pos += 36
        mat_block_len = struct.unpack_from('<I', data, pos)[0]
        if mat_block_len > 50000 or pos + 4 + mat_block_len > dlen:
            break
        pos += 4 + mat_block_len
        if pos + 4 > dlen:
            break
        tex_name_len = struct.unpack_from('<I', data, pos)[0]
        if tex_name_len > 1000 or pos + 4 + tex_name_len > dlen:
            break
        pos += 4 + tex_name_len
        advanced = False
        scan_limit = min(pos + 200, submesh_block_end, dlen)
        for scan in range(pos, scan_limit):
            if data[scan] == 0x31 and scan + 5 <= dlen:
                block_size = struct.unpack_from('<I', data, scan + 1)[0]
                if 4 <= block_size <= 512 and scan + 1 + 4 + block_size + 162 <= dlen:
                    pos = scan + 1 + 4 + block_size + 162
                    advanced = True
                    break
        if not advanced:
            if avg_struct_size > 0:
                pos = struct_start + avg_struct_size
            else:
                break
    if not results:
        return []
    submeshes = []
    for i, (start, nprim) in enumerate(results):
        list_count = nprim * 3
        full_count = results[i + 1][0] - start if i + 1 < len(results) else list_count
        if full_count - list_count > 2:
            submeshes.append((start, list_count, 'list', full_count))
        else:
            submeshes.append((start, list_count, 'list'))
    return submeshes


def build_triangles(indices, vc, submeshes=None, positions=None, normals=None):
    """Returns list of (a, b, c, submesh_index) tuples."""
    tris = []
    if submeshes is None:
        for j in range(0, (len(indices) // 3) * 3, 3):
            a, b, c = indices[j], indices[j + 1], indices[j + 2]
            if a != b and b != c and a != c and a < vc and b < vc and c < vc:
                tris.append((a, b, c, 0))
        return tris
    use_normals = (positions is not None and normals is not None
                   and len(positions) >= vc and len(normals) >= vc)
    for si, sm in enumerate(submeshes):
        start, list_count = sm[0], sm[1]
        full_count = sm[3] if len(sm) > 3 else list_count
        sub = indices[start:start + list_count]
        for j in range(0, len(sub) - 2, 3):
            a, b, c = sub[j], sub[j + 1], sub[j + 2]
            if a != b and b != c and a != c and a < vc and b < vc and c < vc:
                tris.append((a, b, c, si))
        if full_count > list_count:
            extra = indices[start + list_count:start + full_count]
            for j in range(len(extra) - 2):
                a, b, c = extra[j], extra[j + 1], extra[j + 2]
                if a == b or b == c or a == c:
                    continue
                if a >= vc or b >= vc or c >= vc:
                    continue
                if use_normals:
                    pa, pb, pc = positions[a], positions[b], positions[c]
                    ux, uy, uz = pb[0]-pa[0], pb[1]-pa[1], pb[2]-pa[2]
                    vx, vy, vz = pc[0]-pa[0], pc[1]-pa[1], pc[2]-pa[2]
                    fx = uy*vz - uz*vy
                    fy = uz*vx - ux*vz
                    fz = ux*vy - uy*vx
                    na, nb, nc = normals[a], normals[b], normals[c]
                    if (fx*(na[0]+nb[0]+nc[0]) + fy*(na[1]+nb[1]+nc[1])
                            + fz*(na[2]+nb[2]+nc[2])) < 0:
                        a, b = b, a
                else:
                    if j % 2 == 1:
                        a, b = b, a
                tris.append((a, b, c, si))
    return tris

# =========================================================================
# glTF 2.0 binary writer
# =========================================================================

def _write_glb(json_dict, bin_data, path):
    """Write a .glb file (binary glTF 2.0)."""
    json_raw = json.dumps(json_dict, separators=(',', ':')).encode('utf-8')
    # JSON chunk padded with spaces (0x20) per spec
    r = len(json_raw) % 4
    json_bytes = json_raw + b' ' * (4 - r) if r else json_raw
    # BIN chunk padded with zero bytes
    r = len(bin_data) % 4
    bin_bytes = bin_data + b'\x00' * (4 - r) if r else bin_data

    total = 12 + 8 + len(json_bytes) + 8 + len(bin_bytes)
    with open(path, 'wb') as f:
        # Header
        f.write(b'glTF')                              # magic
        f.write(struct.pack('<I', 2))                  # version
        f.write(struct.pack('<I', total))              # total length
        # JSON chunk
        f.write(struct.pack('<I', len(json_bytes)))    # chunk length
        f.write(struct.pack('<I', 0x4E4F534A))         # type: JSON
        f.write(json_bytes)
        # BIN chunk
        f.write(struct.pack('<I', len(bin_bytes)))
        f.write(struct.pack('<I', 0x004E4942))         # type: BIN
        f.write(bin_bytes)


def _accessor(buf_view, comp_type, count, acc_type, min_vals=None, max_vals=None):
    a = {"bufferView": buf_view, "componentType": comp_type,
         "count": count, "type": acc_type}
    if min_vals is not None:
        a["min"] = min_vals
    if max_vals is not None:
        a["max"] = max_vals
    return a


# =========================================================================
# Read mesh data (same as v2 but returns all VB types)
# =========================================================================

def read_mesh_data(data):
    """Returns (indices, positions, normals, uvs, weights, bone_ids, vc, submeshes)."""
    marker, fc, fl = find_face_marker(data)
    if marker < 0:
        return None

    fs = marker + 13
    fi = struct.unpack_from('<H', data, fs)[0]
    bs = struct.unpack_from('<I', data, fs + 2)[0]
    body = data[fs + 6:fs + 6 + bs]

    if fl == 0:
        indices = [struct.unpack_from('<H', data, fs + j * 2)[0] for j in range(fc)]
    elif bs == 4 and fi == 0:
        indices = [0, 1, 2, 2, 1, 3]
    else:
        indices = decode_face_indices(fi, body)

    vb_start = fs + 6 + bs
    vc = struct.unpack_from('<I', data, vb_start)[0]
    positions, normals, uvs, weights, bone_ids = [], [], [], [], []
    first_norm = True
    p = vb_start

    while p < len(data) - 16:
        cnt = struct.unpack_from('<I', data, p)[0]
        stride = struct.unpack_from('<I', data, p + 4)[0]
        vtype = struct.unpack_from('<I', data, p + 8)[0]
        if not (cnt == vc and stride in [4, 8, 12, 16, 20, 24, 28, 32] and 0 < vtype <= 10):
            break
        d = p + 16
        if vtype == 1 and stride == 12:
            for vi in range(cnt):
                x, y, z = struct.unpack_from('<fff', data, d + vi * 12)
                positions.append((x, y, z))
        elif vtype == 2 and stride == 12 and first_norm:
            first_norm = False
            for vi in range(cnt):
                nx, ny, nz = struct.unpack_from('<fff', data, d + vi * 12)
                l = math.sqrt(nx * nx + ny * ny + nz * nz)
                normals.append((nx / l, ny / l, nz / l) if l > 0 else (0, 1, 0))
        elif vtype == 3 and stride == 8:
            for vi in range(cnt):
                u, v = struct.unpack_from('<ff', data, d + vi * 8)
                uvs.append((u, v))  # glTF uses same UV convention as D3D (no flip)
        elif vtype == 4 and stride == 12 and not weights:
            for vi in range(cnt):
                w = struct.unpack_from('<fff', data, d + vi * 12)
                weights.append(w)
        elif vtype == 5 and stride == 4 and not bone_ids:
            for vi in range(cnt):
                b = struct.unpack_from('<4B', data, d + vi * 4)
                bone_ids.append(b)
        p = d + cnt * stride

    if not positions:
        return None

    data_offset = parse_ertm_header(data)
    submeshes = parse_submeshes(data, data_offset, marker) if data_offset > 0 else []

    return indices, positions, normals, uvs, weights, bone_ids, vc, submeshes


# =========================================================================
# Build glTF structure
# =========================================================================

def export_glb(input_path, output_path=None, texture_dir=None):
    """
    Export D3DMESH to glTF 2.0 (.glb).
    If texture_dir is provided and contains .d3dtx files matching the material
    names, they are decoded and embedded as PNG textures in the glb.
    """
    if output_path is None:
        output_path = os.path.splitext(input_path)[0] + '.glb'

    with open(input_path, 'rb') as f:
        data = f.read()

    name = os.path.splitext(os.path.basename(input_path))[0]

    result = read_mesh_data(data)
    if result is None:
        print(f"[SKIP] {name}")
        return False

    indices, positions, normals, uvs, weights, bone_ids, vc, submeshes = result
    triangles = build_triangles(indices, vc, submeshes or None, positions, normals)

    if not triangles:
        print(f"[SKIP] {name}: no triangles")
        return False

    # Group triangles by submesh index
    from collections import defaultdict, OrderedDict
    groups = defaultdict(list)
    for a, b, c, si in triangles:
        groups[si].append((a, b, c))

    # Collect texture names per submesh from parser for material naming
    # Re-parse to get texture names
    tex_names = _get_texture_names(data, parse_ertm_header(data), find_face_marker(data)[0])

    # Build binary buffer
    buf = bytearray()
    buffer_views = []
    accessors = []

    def add_buffer_view(blob, target=None):
        offset = len(buf)
        buf.extend(blob)
        # Pad to 4 bytes
        while len(buf) % 4:
            buf.append(0)
        bv = {"buffer": 0, "byteOffset": offset, "byteLength": len(blob)}
        if target:
            bv["target"] = target
        idx = len(buffer_views)
        buffer_views.append(bv)
        return idx

    # Vertex attributes (shared across all primitives)
    # POSITION
    pos_blob = bytearray()
    xs, ys, zs = [], [], []
    for x, y, z in positions:
        pos_blob.extend(struct.pack('<fff', x, y, z))
        xs.append(x); ys.append(y); zs.append(z)
    pos_bv = add_buffer_view(bytes(pos_blob), target=34962)
    pos_acc = len(accessors)
    accessors.append(_accessor(pos_bv, 5126, vc, "VEC3",
                               [min(xs), min(ys), min(zs)],
                               [max(xs), max(ys), max(zs)]))

    # NORMAL
    norm_acc = None
    if normals:
        norm_blob = bytearray()
        for nx, ny, nz in normals:
            norm_blob.extend(struct.pack('<fff', nx, ny, nz))
        norm_bv = add_buffer_view(bytes(norm_blob), target=34962)
        norm_acc = len(accessors)
        accessors.append(_accessor(norm_bv, 5126, vc, "VEC3"))

    # TEXCOORD_0
    uv_acc = None
    if uvs:
        uv_blob = bytearray()
        for u, v in uvs:
            uv_blob.extend(struct.pack('<ff', u, v))
        uv_bv = add_buffer_view(bytes(uv_blob), target=34962)
        uv_acc = len(accessors)
        accessors.append(_accessor(uv_bv, 5126, vc, "VEC2"))

    # Load and embed textures if texture_dir is provided
    images = []       # glTF image objects
    textures = []     # glTF texture objects
    samplers = []     # glTF sampler objects
    tex_to_gltf_idx = {}  # texture name -> glTF texture index

    if texture_dir:
        try:
            from decode_d3dtx import decode_d3dtx, pixels_to_png
        except ImportError:
            texture_dir = None  # can't decode without the module

    if texture_dir:
        try:
            import zlib
        except ImportError:
            texture_dir = None

    def _embed_texture(tex_name):
        """Decode a d3dtx and embed it as PNG in the glTF buffer. Returns texture index or None."""
        if tex_name in tex_to_gltf_idx:
            return tex_to_gltf_idx[tex_name]
        if not texture_dir:
            return None
        d3dtx_path = os.path.join(texture_dir, tex_name + '.d3dtx')
        if not os.path.exists(d3dtx_path):
            return None
        try:
            with open(d3dtx_path, 'rb') as f:
                tex_data = f.read()
            tw, th, tfmt, pixels = decode_d3dtx(tex_data)

            raw = bytearray()
            for y in range(th):
                raw.append(0)
                for x in range(tw):
                    r, g, b, a = pixels[y * tw + x]
                    raw.extend([r, g, b, a])
            compressed = zlib.compress(bytes(raw), 9)

            def _png_chunk(ctype, cdata):
                c = ctype + cdata
                crc = zlib.crc32(c) & 0xFFFFFFFF
                return struct.pack('>I', len(cdata)) + c + struct.pack('>I', crc)

            png_buf = bytearray()
            png_buf.extend(b'\x89PNG\r\n\x1a\n')
            png_buf.extend(_png_chunk(b'IHDR', struct.pack('>IIBBBBB', tw, th, 8, 6, 0, 0, 0)))
            png_buf.extend(_png_chunk(b'IDAT', compressed))
            png_buf.extend(_png_chunk(b'IEND', b''))

            if not samplers:
                samplers.append({
                    "magFilter": 9729, "minFilter": 9987,
                    "wrapS": 10497, "wrapT": 10497,
                })

            img_bv = add_buffer_view(bytes(png_buf))
            img_idx = len(images)
            images.append({"bufferView": img_bv, "mimeType": "image/png", "name": tex_name})
            tex_idx = len(textures)
            textures.append({"source": img_idx, "sampler": 0})
            tex_to_gltf_idx[tex_name] = tex_idx
            return tex_idx
        except Exception:
            return None

    # Per-submesh index buffers + primitives
    primitives = []
    materials = []
    mat_name_to_idx = {}

    for si in sorted(groups.keys()):
        tris = groups[si]

        # Index buffer for this submesh
        idx_blob = bytearray()
        for a, b, c in tris:
            idx_blob.extend(struct.pack('<HHH', a, b, c))
        idx_bv = add_buffer_view(bytes(idx_blob), target=34963)
        idx_acc = len(accessors)
        all_idx = [v for tri in tris for v in tri]
        accessors.append(_accessor(idx_bv, 5123, len(all_idx), "SCALAR",
                                   [min(all_idx)], [max(all_idx)]))

        # Material — look up all texture slots for this submesh
        tex_info = tex_names.get(si, {}) if tex_names else {}
        if isinstance(tex_info, str):
            tex_info = {'diffuse': tex_info}  # legacy compat
        diffuse_name = tex_info.get('diffuse', name)
        normal_name = tex_info.get('normal')
        spec_name = tex_info.get('specular')

        # Material key: combination of all texture names
        mat_key = (diffuse_name, normal_name, spec_name)
        if mat_key not in mat_name_to_idx:
            mat_name_to_idx[mat_key] = len(materials)
            mat = {"name": diffuse_name, "pbrMetallicRoughness": {
                "metallicFactor": 0.0, "roughnessFactor": 0.8
            }}

            # Diffuse / base color
            diffuse_idx = _embed_texture(diffuse_name)
            if diffuse_idx is not None:
                mat["pbrMetallicRoughness"]["baseColorTexture"] = {"index": diffuse_idx}
            else:
                mat["pbrMetallicRoughness"]["baseColorFactor"] = [0.8, 0.8, 0.8, 1.0]

            # Normal map
            if normal_name:
                normal_idx = _embed_texture(normal_name)
                if normal_idx is not None:
                    mat["normalTexture"] = {"index": normal_idx}

            # Specular → approximate via metallicRoughness texture
            if spec_name:
                spec_idx = _embed_texture(spec_name)
                if spec_idx is not None:
                    mat["pbrMetallicRoughness"]["metallicRoughnessTexture"] = {"index": spec_idx}
                    mat["pbrMetallicRoughness"]["metallicFactor"] = 1.0

            materials.append(mat)
        mat_idx = mat_name_to_idx[mat_key]

        prim = {
            "attributes": {"POSITION": pos_acc},
            "indices": idx_acc,
            "material": mat_idx,
        }
        if norm_acc is not None:
            prim["attributes"]["NORMAL"] = norm_acc
        if uv_acc is not None:
            prim["attributes"]["TEXCOORD_0"] = uv_acc
        primitives.append(prim)

    # Assemble glTF JSON
    gltf = {
        "asset": {"version": "2.0", "generator": "telltale_extractor"},
        "scene": 0,
        "scenes": [{"nodes": [0]}],
        "nodes": [{"mesh": 0, "name": name}],
        "meshes": [{"name": name, "primitives": primitives}],
        "materials": materials,
        "accessors": accessors,
        "bufferViews": buffer_views,
        "buffers": [{"byteLength": len(buf)}],
    }
    if images:
        gltf["images"] = images
    if textures:
        gltf["textures"] = textures
    if samplers:
        gltf["samplers"] = samplers

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    _write_glb(gltf, bytes(buf), output_path)

    n_tris = sum(len(groups[si]) for si in groups)
    n_tex = len(images)
    tex_info = f", {n_tex} textures" if n_tex else ""
    print(f"{name}: {vc} verts, {n_tris} tris, {len(primitives)} submeshes, "
          f"{len(materials)} materials{tex_info} -> {output_path} "
          f"({os.path.getsize(output_path)} bytes)")
    return True


def _classify_texture(name, slot_index):
    """Classify a texture name into a material slot.
    slot_index: 0=first texture in TriangleSet, 1+=subsequent.
    """
    low = name.lower()
    if '_bump' in low or low.startswith('bmap_'):
        return 'normal'
    if '_spec' in low or 'specular' in low:
        return 'specular'
    if '_alp.' in low or '_alp_' in low or '_alpha' in low:
        return 'alpha'
    # First texture in a TriangleSet is always the diffuse material.
    # Subsequent textures with generic names (like lightmap atlases) are lightmaps.
    if slot_index == 0:
        return 'diffuse'
    return 'lightmap'


def _get_texture_names(data, data_offset, face_marker_pos):
    """
    Extract texture names per submesh from TriangleSet structs.
    Returns dict: submesh_index -> {'diffuse': name, 'normal': name, 'specular': name, ...}
    Each TriangleSet may have 1-3 texture references (diffuse, specular, bump).
    """
    tex_map = {}
    try:
        pos = data_offset
        dlen = len(data)
        if pos + 8 > dlen:
            return tex_map
        nhl = struct.unpack_from('<I', data, pos)[0]
        nl = struct.unpack_from('<I', data, pos + 4)[0]
        if nl > nhl:
            nl = nhl; ns = pos + 4
        else:
            ns = pos + 8
        if nl > 256 or ns + nl + 1 > dlen:
            return tex_map
        pos = ns + nl + 1 + 28
        if pos + 8 > dlen:
            return tex_map
        head3a_size = struct.unpack_from('<I', data, pos)[0]
        sc = struct.unpack_from('<I', data, pos + 4)[0]
        submesh_block_end = pos + 4 + head3a_size
        pos += 8
        if sc == 0 or sc > 500:
            return tex_map
        avg = head3a_size // sc if sc else 0

        for i in range(sc):
            struct_start = pos
            if pos + 48 + 36 + 4 > dlen:
                break
            pos += 24 + 24 + 36  # CRC1+2 + geometry + CRC3 + SubBB
            mbl = struct.unpack_from('<I', data, pos)[0]
            if mbl > 50000 or pos + 4 + mbl > dlen:
                break
            pos += 4 + mbl

            # Read ALL texture references for this TriangleSet
            textures = {}
            for _tex_slot in range(4):  # max 4 textures per submesh
                if pos + 4 > dlen:
                    break
                tnl = struct.unpack_from('<I', data, pos)[0]
                if tnl == 0 or tnl > 200 or pos + 4 + tnl > dlen:
                    break
                tex = data[pos + 4:pos + 4 + tnl].rstrip(b'\x00').decode('ascii', errors='replace')
                if '.d3dtx' not in tex:
                    break
                tex_clean = tex.replace('.d3dtx', '')
                slot = _classify_texture(tex_clean, _tex_slot)
                textures[slot] = tex_clean
                pos += 4 + tnl

                # After each texture name there may be a small header/separator
                # before the next texture name. Scan ahead for the next name_len.
                # Skip bytes until we find a plausible next name_len or hit 0x31.
                found_next = False
                for probe in range(pos, min(pos + 40, submesh_block_end, dlen)):
                    if probe + 4 > dlen:
                        break
                    # Check if this looks like a next texture name_len
                    next_tnl = struct.unpack_from('<I', data, probe)[0]
                    if 8 < next_tnl < 200 and probe + 4 + next_tnl <= dlen:
                        candidate = data[probe + 4:probe + 4 + next_tnl]
                        if b'.d3dtx' in candidate and all(32 <= b < 127 for b in candidate.rstrip(b'\x00')):
                            pos = probe
                            found_next = True
                            break
                    # Check for 0x31 marker (end of texture section)
                    if data[probe] == 0x31:
                        break
                if not found_next:
                    break

            if textures:
                tex_map[i] = textures

            # Advance past variable tail using 0x31 marker
            advanced = False
            scan_limit = min(pos + 200, submesh_block_end, dlen)
            for scan in range(pos, scan_limit):
                if data[scan] == 0x31 and scan + 5 <= dlen:
                    bs = struct.unpack_from('<I', data, scan + 1)[0]
                    if 4 <= bs <= 512 and scan + 1 + 4 + bs + 162 <= dlen:
                        pos = scan + 1 + 4 + bs + 162
                        advanced = True
                        break
            if not advanced:
                pos = struct_start + avg if avg else pos + 300
    except (struct.error, IndexError):
        pass
    return tex_map


# =========================================================================
# CLI
# =========================================================================
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python export_mesh_glb.py <input.d3dmesh> [output.glb]")
        print("       python export_mesh_glb.py <input.d3dmesh> --textures <dir_with_d3dtx>")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = None
    texture_dir = None

    args = sys.argv[2:]
    i = 0
    while i < len(args):
        if args[i] == '--textures' and i + 1 < len(args):
            texture_dir = args[i + 1]; i += 2
        elif args[i] == '--dir' and i + 1 < len(args):
            base = os.path.splitext(os.path.basename(input_path))[0]
            output_path = os.path.join(args[i + 1], base + '.glb'); i += 2
        elif not output_path:
            output_path = args[i]; i += 1
        else:
            i += 1

    export_glb(input_path, output_path, texture_dir=texture_dir)
