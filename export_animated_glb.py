"""Export a Telltale D3DMESH + companion SKL + ANM as a single animated .glb.

Builds on export_rigged_glb.py (mesh + skeleton + per-vertex skinning) and
adds glTF animation channels decoded from the ANM.

Sample layouts (decoded empirically from walk/run anims, confirmed vs SKL
rest pose):
    KFV<Transform>: 41B = [4 mTime] + [9 meta] + [16 Quat] + [12 Vec3]
    KFV<Quaternion>: 25B = [4 mTime] + [5 meta] + [16 Quat]
    KFV<Vector3>:    21B = [4 mTime] + [5 meta] + [12 Vec3]

For bones other than root, the Vec3 in KFV<Transform> is an engine-internal
unit direction (not joint-local translation), so we only emit rotation for
non-root bones. Root translation comes from the separate Mover Vector3.

Usage:
    python export_animated_glb.py <mesh.d3dmesh> <anim.anm>
         [--skl sibling.skl] [--textures dir] [-o out.glb]
"""
from __future__ import annotations

import argparse
import json
import os
import struct
import sys

from export_mesh_glb import (
    read_mesh_data, build_triangles, parse_ertm_header, find_face_marker,
    parse_submeshes_with_palette_idx, parse_bone_palettes,
    _get_texture_names, _write_glb, _accessor,
)
from export_skeleton_glb import (
    trs_to_mat4, mat4_mul, mat4_invert_rigid, mat4_identity,
)
from telltale.skeleton import parse_skeleton, load_hash_db
from parse_anm import parse_header as parse_anm_header
from parse_ctk import (
    decode_ctk, decode_time_keys, walk_ctk_values, find_ctk_start,
    parse_anm_trailer,
)


# Sentinel bone hash used by Telltale to mark "world/root" (parent of root
# bone, target of Mover channels) — not a real bone, filtered from animation.
_SENTINEL_BONE_HASH = 0x7DC5F26128EC8012


def _decode_samples(anm_data: bytes, value, sample_body_offset: int,
                    sample_size: int, count: int, value_type: str):
    """Decode all samples of a value channel. Returns list of (time, data)."""
    out = []
    # value_type maps to byte layout:
    #   Transform:  [4 time][9 meta][16 quat][12 vec3]
    #   Quaternion: [4 time][5 meta][16 quat]
    #   Vector3:    [4 time][5 meta][12 vec3]
    for i in range(count):
        base = sample_body_offset + i * sample_size
        t = struct.unpack_from('<f', anm_data, base)[0]
        if value_type == 'Transform':
            q = struct.unpack_from('<4f', anm_data, base + 13)
            v = struct.unpack_from('<3f', anm_data, base + 29)
            out.append((t, q, v))
        elif value_type == 'Quaternion':
            q = struct.unpack_from('<4f', anm_data, base + 9)
            out.append((t, q, None))
        elif value_type == 'Vector3':
            v = struct.unpack_from('<3f', anm_data, base + 9)
            out.append((t, None, v))
    return out


def _extract_value_body(anm_data: bytes, value):
    """Return (samples_offset_after_header, per_sample_size, count, val_type_short)."""
    p = value.start_offset + 24  # skip 24B outer header (out_sz + inn_sz + hash + pad + flags)

    if 'Transform' in value.type_name:
        # mMinVal Transform in a block (size u32 + 28 bytes), mMaxVal same
        min_sz = struct.unpack_from('<I', anm_data, p)[0]
        p += min_sz
        max_sz = struct.unpack_from('<I', anm_data, p)[0]
        p += max_sz
        # mSamples block (size u32 + count u32 + samples)
        samp_sz = struct.unpack_from('<I', anm_data, p)[0]
        cnt = struct.unpack_from('<I', anm_data, p + 4)[0]
        return (p + 8, 41, cnt, 'Transform')

    if 'Quaternion' in value.type_name:
        # mMinVal/mMaxVal RAW 16 bytes each (no block header)
        p += 16 + 16
        samp_sz = struct.unpack_from('<I', anm_data, p)[0]
        cnt = struct.unpack_from('<I', anm_data, p + 4)[0]
        return (p + 8, 25, cnt, 'Quaternion')

    if 'Vector3' in value.type_name:
        # mMinVal/mMaxVal RAW 12 bytes each
        p += 12 + 12
        samp_sz = struct.unpack_from('<I', anm_data, p)[0]
        cnt = struct.unpack_from('<I', anm_data, p + 4)[0]
        return (p + 8, 21, cnt, 'Vector3')

    return (0, 0, 0, '?')


def _sanitize(s: str) -> str:
    return s.replace('\x00', '')


def export_animated(
    mesh_path: str, skl_path: str, anm_path: str, output_path: str,
    texture_dir: str | None = None, hashdb_path: str | None = None,
):
    # --- Load mesh ---------------------------------------------------------
    with open(mesh_path, 'rb') as f:
        mesh_data = f.read()
    name = os.path.splitext(os.path.basename(mesh_path))[0]
    result = read_mesh_data(mesh_data)
    if result is None:
        raise RuntimeError(f"failed to parse mesh: {mesh_path}")
    indices, positions, normals, uvs, weights, bone_ids, vc, submeshes = result
    triangles = build_triangles(indices, vc, submeshes or None, positions, normals)

    from collections import defaultdict
    groups = defaultdict(list)
    for a, b, c, si in triangles:
        groups[si].append((a, b, c))

    data_off = parse_ertm_header(mesh_data)
    tex_names = _get_texture_names(mesh_data, data_off, find_face_marker(mesh_data)[0])
    submesh_end, submesh_palette_info = parse_submeshes_with_palette_idx(mesh_data, data_off)
    palettes = parse_bone_palettes(mesh_data, submesh_end) if submesh_end else []
    submesh_bone_palette = [e[0] for e in submesh_palette_info]

    # --- Load skeleton -----------------------------------------------------
    hash_db = load_hash_db(hashdb_path) if hashdb_path and os.path.exists(hashdb_path) else {}
    with open(skl_path, 'rb') as f:
        skl_data = f.read()
    skel = parse_skeleton(skl_data, version=0, early_game_fix=10, hash_db=hash_db)
    bones = skel.bones
    nbones = len(bones)
    if nbones == 0:
        raise RuntimeError(f"skeleton empty: {skl_path}")
    hash_to_bone_idx = {b.hash_value: i for i, b in enumerate(bones)}

    world = [mat4_identity() for _ in range(nbones)]
    for i, b in enumerate(bones):
        local = trs_to_mat4(b.local_position, b.local_rotation)
        if b.parent_index >= 0:
            world[i] = mat4_mul(world[b.parent_index], local)
        else:
            world[i] = local
    ibms = [mat4_invert_rigid(w) for w in world]

    # --- Load ANM ----------------------------------------------------------
    with open(anm_path, 'rb') as f:
        anm_data = f.read()
    anm_header = parse_anm_header(anm_data)
    anm_name = os.path.splitext(os.path.basename(anm_path))[0]

    # Decode each channel's samples and route them to glTF targets:
    # - KFV<Transform> targeting a known bone → rotation channel for that joint
    # - KFV<Quaternion> targeting sentinel → rotation channel on armature root
    # - KFV<Vector3> targeting sentinel → translation channel on armature root
    rotation_channels: dict[int, list] = {}    # joint_idx -> samples [(t, (qx,qy,qz,qw))]
    translation_channels: dict[int, list] = {} # joint_idx -> samples [(t, (tx,ty,tz))]
    arm_root_rotation: list = []
    arm_root_translation: list = []

    for v in anm_header.values:
        body_off, samp_sz, cnt, vtype = _extract_value_body(anm_data, v)
        if samp_sz == 0 or cnt == 0:
            continue
        samples = _decode_samples(anm_data, v, body_off, samp_sz, cnt, vtype)

        if vtype == 'Transform':
            joint = hash_to_bone_idx.get(v.name_hash)
            if joint is None:
                continue
            rotation_channels[joint] = [(t, q) for t, q, _ in samples]
            # Root bone: also include translation (for non-root bones the Vec3
            # is an engine-internal unit direction, not real translation).
            if bones[joint].parent_index < 0:
                translation_channels[joint] = [(t, vv) for t, _, vv in samples]
        elif vtype == 'Quaternion' and v.name_hash == _SENTINEL_BONE_HASH:
            arm_root_rotation = [(t, q) for t, q, _ in samples]
        elif vtype == 'Vector3' and v.name_hash == _SENTINEL_BONE_HASH:
            arm_root_translation = [(t, vv) for t, _, vv in samples]

    # CTK path: CompressedTransformKeys bit-packed keyframes.
    # Per-instance bone association comes from the ANM trailer which has
    # an N-entry bone-hash table, in 1:1 correspondence with the instance
    # order from the serialization loop (type-grouped).
    ctk_type_entry = next(
        (t for t in anm_header.types if 'CompressedTransform' in t.name),
        None,
    )
    if ctk_type_entry:
        ctk_start = find_ctk_start(anm_data, anm_header.types_end_offset,
                                   anm_header.types)
        if ctk_start is not None:
            # Parse trailer bone-hash map for all instances
            try:
                trailer_metas = parse_anm_trailer(
                    anm_data, anm_header.total_interfaces,
                )
            except Exception:
                trailer_metas = []
            # Compute where CTK instances start in the instance list
            ctk_first_idx = 0
            for t in anm_header.types:
                if 'CompressedTransform' in t.name:
                    break
                ctk_first_idx += t.count

            ctk_values = walk_ctk_values(anm_data, ctk_start, ctk_type_entry.count)
            for i, (cs, cz, ts, tz) in enumerate(ctk_values):
                try:
                    samples = decode_ctk(anm_data[cs:cs+cz])
                    times = decode_time_keys(anm_data[ts:ts+tz], len(samples))
                except Exception:
                    continue
                if not samples:
                    continue
                # Resolve target bone via trailer; fall back to sequential.
                bone_hash = None
                if trailer_metas:
                    meta_idx = ctk_first_idx + i
                    if meta_idx < len(trailer_metas):
                        bone_hash = trailer_metas[meta_idx].bone_hash
                joint = (
                    hash_to_bone_idx.get(bone_hash) if bone_hash is not None else None
                )
                if joint is None:
                    continue  # bone not in this skeleton — skip channel
                rot_samples = [(t, s.quat) for t, s in zip(times, samples)]
                if joint not in rotation_channels:
                    rotation_channels[joint] = rot_samples
                if bones[joint].parent_index < 0 and joint not in translation_channels:
                    translation_channels[joint] = [
                        (t, s.vec3) for t, s in zip(times, samples)
                    ]

    # ======================================================================
    # Build binary buffer + accessors
    # ======================================================================
    buf = bytearray()
    buffer_views: list[dict] = []
    accessors: list[dict] = []

    def add_view(blob, target=None):
        off = len(buf)
        buf.extend(blob)
        while len(buf) % 4:
            buf.append(0)
        bv = {"buffer": 0, "byteOffset": off, "byteLength": len(blob)}
        if target is not None:
            bv["target"] = target
        idx = len(buffer_views)
        buffer_views.append(bv)
        return idx

    # POSITION / NORMAL / UV --------------------------------------------------
    pos_blob = bytearray()
    xs, ys, zs = [], [], []
    for x, y, z in positions:
        pos_blob.extend(struct.pack('<fff', x, y, z))
        xs.append(x); ys.append(y); zs.append(z)
    pos_bv = add_view(bytes(pos_blob), target=34962)
    pos_acc = len(accessors)
    accessors.append(_accessor(pos_bv, 5126, vc, "VEC3",
                               [min(xs), min(ys), min(zs)],
                               [max(xs), max(ys), max(zs)]))

    norm_acc = None
    if normals:
        norm_blob = bytearray()
        for nx, ny, nz in normals:
            norm_blob.extend(struct.pack('<fff', nx, ny, nz))
        norm_bv = add_view(bytes(norm_blob), target=34962)
        norm_acc = len(accessors)
        accessors.append(_accessor(norm_bv, 5126, vc, "VEC3"))

    uv_acc = None
    if uvs:
        uv_blob = bytearray()
        for u, v in uvs:
            uv_blob.extend(struct.pack('<ff', u, v))
        uv_bv = add_view(bytes(uv_blob), target=34962)
        uv_acc = len(accessors)
        accessors.append(_accessor(uv_bv, 5126, vc, "VEC2"))

    # JOINTS_0 / WEIGHTS_0 ---------------------------------------------------
    hash_to_skel = {b.hash_value: i for i, b in enumerate(bones)}
    palette_to_skel = [[hash_to_skel.get(h, 0) for h in pal] for pal in palettes]

    vertex_submesh = [-1] * vc
    for si, (_p, _si, _n) in enumerate(submesh_palette_info):
        for a, b, c in groups.get(si, []):
            for vi in (a, b, c):
                if 0 <= vi < vc and vertex_submesh[vi] < 0:
                    vertex_submesh[vi] = si

    has_skin = bool(bone_ids) and bool(weights) and bool(palette_to_skel)
    joints_blob = bytearray(); weights_blob = bytearray()
    for vi in range(vc):
        si = vertex_submesh[vi]
        pal_idx = submesh_bone_palette[si] if 0 <= si < len(submesh_bone_palette) else 0
        lut = palette_to_skel[pal_idx] if 0 <= pal_idx < len(palette_to_skel) else []
        if has_skin and vi < len(bone_ids) and vi < len(weights):
            raw = bone_ids[vi]
            b0, b1, b2, b3 = raw[0] >> 2, raw[1] >> 2, raw[2] >> 2, raw[3] >> 2
            j = [0, 0, 0, 0]
            if lut:
                j[0] = lut[b0] if b0 < len(lut) else 0
                j[1] = lut[b1] if b1 < len(lut) else 0
                j[2] = lut[b2] if b2 < len(lut) else 0
                j[3] = lut[b3] if b3 < len(lut) else 0
            w1, w2, w3 = weights[vi]
            w4 = max(0.0, 1.0 - w1 - w2 - w3)
            if w4 < 1e-6: w4 = 0.0
            ws = [w1, w2, w3, w4]
            seen = {}
            for k in range(4):
                if ws[k] <= 1e-6: continue
                if j[k] in seen:
                    ws[seen[j[k]]] += ws[k]; ws[k] = 0.0
                else:
                    seen[j[k]] = k
            for k in range(4):
                if ws[k] <= 1e-6:
                    ws[k] = 0.0; j[k] = 0
            total = sum(ws)
            if total > 0:
                ws = [w / total for w in ws]
            else:
                ws = [1.0, 0.0, 0.0, 0.0]; j = [0, 0, 0, 0]
        else:
            j = [0, 0, 0, 0]; ws = [1.0, 0.0, 0.0, 0.0]
        joints_blob.extend(struct.pack('<4H', *j))
        weights_blob.extend(struct.pack('<4f', *ws))
    j_bv = add_view(bytes(joints_blob), target=34962)
    j_acc = len(accessors)
    accessors.append(_accessor(j_bv, 5123, vc, "VEC4"))
    w_bv = add_view(bytes(weights_blob), target=34962)
    w_acc = len(accessors)
    accessors.append(_accessor(w_bv, 5126, vc, "VEC4"))

    # Inverse bind matrices --------------------------------------------------
    ibm_blob = bytearray()
    for m in ibms:
        ibm_blob.extend(struct.pack('<16f', *m))
    ibm_bv = add_view(bytes(ibm_blob))
    ibm_acc = len(accessors)
    accessors.append({"bufferView": ibm_bv, "componentType": 5126,
                      "count": nbones, "type": "MAT4"})

    # Textures (same as export_rigged_glb.py) -------------------------------
    images: list = []; textures: list = []; samplers: list = []
    tex_to_gltf_idx: dict = {}
    if texture_dir:
        try:
            import zlib
            from decode_d3dtx import decode_d3dtx
        except ImportError:
            texture_dir = None

    def _embed_texture(tex_name):
        if tex_name in tex_to_gltf_idx: return tex_to_gltf_idx[tex_name]
        if not texture_dir: return None
        p = os.path.join(texture_dir, tex_name + '.d3dtx')
        if not os.path.exists(p): return None
        try:
            with open(p, 'rb') as f: td = f.read()
            tw, th, _fmt, pix = decode_d3dtx(td)
            raw = bytearray()
            for yy in range(th):
                raw.append(0)
                for xx in range(tw):
                    r, g, b, a = pix[yy * tw + xx]
                    raw.extend([r, g, b, a])
            comp = zlib.compress(bytes(raw), 9)
            def ch(ty, d):
                c = ty + d
                return struct.pack('>I', len(d)) + c + struct.pack('>I', zlib.crc32(c) & 0xFFFFFFFF)
            png = bytearray(b'\x89PNG\r\n\x1a\n')
            png.extend(ch(b'IHDR', struct.pack('>IIBBBBB', tw, th, 8, 6, 0, 0, 0)))
            png.extend(ch(b'IDAT', comp)); png.extend(ch(b'IEND', b''))
            if not samplers:
                samplers.append({"magFilter": 9729, "minFilter": 9987,
                                 "wrapS": 10497, "wrapT": 10497})
            bv_idx = add_view(bytes(png))
            images.append({"bufferView": bv_idx, "mimeType": "image/png", "name": tex_name})
            textures.append({"source": len(images) - 1, "sampler": 0})
            idx = len(textures) - 1
            tex_to_gltf_idx[tex_name] = idx
            return idx
        except Exception:
            return None

    # Per-submesh primitives + materials ------------------------------------
    primitives = []; materials = []; mat_key_to_idx: dict = {}
    for si in sorted(groups.keys()):
        tris = groups[si]
        idx_blob = bytearray()
        for a, b, c in tris:
            idx_blob.extend(struct.pack('<HHH', a, b, c))
        idx_bv = add_view(bytes(idx_blob), target=34963)
        idx_acc = len(accessors)
        flat = [v for t in tris for v in t]
        accessors.append(_accessor(idx_bv, 5123, len(flat), "SCALAR",
                                   [min(flat)], [max(flat)]))
        tex_info = tex_names.get(si, {}) if tex_names else {}
        if isinstance(tex_info, str): tex_info = {"diffuse": tex_info}
        dn = tex_info.get('diffuse', name); nn = tex_info.get('normal'); sn = tex_info.get('specular')
        key = (dn, nn, sn)
        if key not in mat_key_to_idx:
            mat_key_to_idx[key] = len(materials)
            mat = {"name": dn, "pbrMetallicRoughness": {
                "metallicFactor": 0.0, "roughnessFactor": 0.8}}
            di = _embed_texture(dn)
            if di is not None: mat["pbrMetallicRoughness"]["baseColorTexture"] = {"index": di}
            else: mat["pbrMetallicRoughness"]["baseColorFactor"] = [0.8, 0.8, 0.8, 1.0]
            if nn:
                ni = _embed_texture(nn)
                if ni is not None: mat["normalTexture"] = {"index": ni}
            if sn:
                si2 = _embed_texture(sn)
                if si2 is not None:
                    mat["pbrMetallicRoughness"]["metallicRoughnessTexture"] = {"index": si2}
                    mat["pbrMetallicRoughness"]["metallicFactor"] = 1.0
            materials.append(mat)
        mat_idx = mat_key_to_idx[key]
        prim = {
            "attributes": {"POSITION": pos_acc, "JOINTS_0": j_acc, "WEIGHTS_0": w_acc},
            "indices": idx_acc, "material": mat_idx,
        }
        if norm_acc is not None: prim["attributes"]["NORMAL"] = norm_acc
        if uv_acc is not None: prim["attributes"]["TEXCOORD_0"] = uv_acc
        primitives.append(prim)

    # ======================================================================
    # Build nodes + skin + mesh (same structure as rigged exporter)
    # ======================================================================
    nodes: list = []
    children_of: list = [[] for _ in range(nbones)]
    root_bones: list = []
    for i, b in enumerate(bones):
        if b.parent_index >= 0:
            children_of[b.parent_index].append(i)
        else:
            root_bones.append(i)
    for i, b in enumerate(bones):
        node = {
            "name": _sanitize(b.name),
            "translation": [float(v) for v in b.local_position],
            "rotation": [float(v) for v in b.local_rotation],
        }
        if children_of[i]:
            node["children"] = children_of[i]
        nodes.append(node)

    armature_root = nbones
    nodes.append({"name": f"{name}_armature", "children": root_bones})
    mesh_node = nbones + 1
    nodes.append({"name": name, "mesh": 0, "skin": 0})

    skin = {"joints": list(range(nbones)),
            "inverseBindMatrices": ibm_acc, "skeleton": armature_root}

    # ======================================================================
    # Animation channels + samplers
    # ======================================================================
    anim_channels: list = []
    anim_samplers: list = []

    def _add_rotation_sampler(samples):
        """Add a rotation sampler: input = times, output = quaternions."""
        times_blob = bytearray()
        vals_blob = bytearray()
        times = sorted(set(round(t, 6) for t, _ in samples))
        # Keep original order — walk.anm is already time-ordered
        ts = [t for t, _ in samples]
        qs = [q for _, q in samples]
        for t in ts:
            times_blob.extend(struct.pack('<f', float(t)))
        for q in qs:
            vals_blob.extend(struct.pack('<4f', *[float(x) for x in q]))
        t_bv = add_view(bytes(times_blob))
        t_acc = len(accessors)
        accessors.append(_accessor(t_bv, 5126, len(ts), "SCALAR",
                                   [min(ts)], [max(ts)]))
        v_bv = add_view(bytes(vals_blob))
        v_acc = len(accessors)
        accessors.append(_accessor(v_bv, 5126, len(qs), "VEC4"))
        sampler_idx = len(anim_samplers)
        anim_samplers.append({"input": t_acc, "output": v_acc, "interpolation": "LINEAR"})
        return sampler_idx

    def _add_translation_sampler(samples):
        times_blob = bytearray(); vals_blob = bytearray()
        ts = [t for t, _ in samples]
        vs = [v for _, v in samples]
        for t in ts:
            times_blob.extend(struct.pack('<f', float(t)))
        for v in vs:
            vals_blob.extend(struct.pack('<3f', *[float(x) for x in v]))
        t_bv = add_view(bytes(times_blob))
        t_acc = len(accessors)
        accessors.append(_accessor(t_bv, 5126, len(ts), "SCALAR",
                                   [min(ts)], [max(ts)]))
        v_bv = add_view(bytes(vals_blob))
        v_acc = len(accessors)
        accessors.append(_accessor(v_bv, 5126, len(vs), "VEC3"))
        s_idx = len(anim_samplers)
        anim_samplers.append({"input": t_acc, "output": v_acc, "interpolation": "LINEAR"})
        return s_idx

    # Per-bone rotation channels (skip channels with 0 samples)
    for joint, samples in rotation_channels.items():
        if not samples: continue
        s_idx = _add_rotation_sampler(samples)
        anim_channels.append({
            "sampler": s_idx,
            "target": {"node": joint, "path": "rotation"},
        })

    # Root translation channel (if present on a root bone)
    for joint, samples in translation_channels.items():
        if not samples: continue
        s_idx = _add_translation_sampler(samples)
        anim_channels.append({
            "sampler": s_idx,
            "target": {"node": joint, "path": "translation"},
        })

    # Mover Vector3 on armature root
    if arm_root_translation:
        s_idx = _add_translation_sampler(arm_root_translation)
        anim_channels.append({
            "sampler": s_idx,
            "target": {"node": armature_root, "path": "translation"},
        })
    # Mover Quaternion on armature root
    if arm_root_rotation:
        s_idx = _add_rotation_sampler(arm_root_rotation)
        anim_channels.append({
            "sampler": s_idx,
            "target": {"node": armature_root, "path": "rotation"},
        })

    animations = []
    if anim_channels:
        animations.append({
            "name": anm_name,
            "channels": anim_channels,
            "samplers": anim_samplers,
        })

    gltf = {
        "asset": {"version": "2.0", "generator": "telltale-explorer"},
        "scene": 0,
        "scenes": [{"nodes": [armature_root, mesh_node]}],
        "nodes": nodes,
        "skins": [skin],
        "meshes": [{"name": name, "primitives": primitives}],
        "materials": materials,
        "accessors": accessors,
        "bufferViews": buffer_views,
        "buffers": [{"byteLength": len(buf)}],
    }
    if animations: gltf["animations"] = animations
    if images: gltf["images"] = images
    if textures: gltf["textures"] = textures
    if samplers: gltf["samplers"] = samplers

    os.makedirs(os.path.dirname(os.path.abspath(output_path)) or ".", exist_ok=True)
    _write_glb(gltf, bytes(buf), output_path)

    n_tris = sum(len(g) for g in groups.values())
    n_ch = len(anim_channels)
    print(f"{name} + {anm_name}: {vc}v, {n_tris}t, {nbones} bones, "
          f"{n_ch} anim channels, {len(images)} tex -> {output_path} "
          f"({os.path.getsize(output_path)} bytes)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mesh")
    ap.add_argument("anm")
    ap.add_argument("--skl", default=None)
    ap.add_argument("--textures", default=None)
    ap.add_argument("--hashdb", default="hashdb/BoneNames.HashDB")
    ap.add_argument("-o", "--output", default=None)
    args = ap.parse_args()
    skl = args.skl or os.path.splitext(args.mesh)[0] + ".skl"
    if not os.path.exists(skl):
        sys.exit(f"no SKL found: {skl}")
    out = args.output or os.path.splitext(args.mesh)[0] + "_animated.glb"
    export_animated(mesh_path=args.mesh, skl_path=skl, anm_path=args.anm,
                    output_path=out, texture_dir=args.textures,
                    hashdb_path=args.hashdb)


if __name__ == "__main__":
    main()
