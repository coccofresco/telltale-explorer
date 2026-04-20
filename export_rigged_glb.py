"""Export a Telltale D3DMESH + companion SKL to a rigged glTF 2.0 .glb.

Proper per-vertex skinning: each submesh has a BonePaletteIndex (found at
offset +24 in the TriangleSet struct via iOS binary MetaClassDescription),
selecting one of the bone palettes parsed from the section right after the
submesh array. Per-vertex bone IDs are palette-local (raw byte / 4) and get
remapped through that palette to skeleton joint indices.

Usage:
    python export_rigged_glb.py <input.d3dmesh> [-o output.glb]
                                 [--skl sibling.skl]
                                 [--hashdb hashdb/BoneNames.HashDB]
                                 [--textures extracted/ep1_textures]
"""
from __future__ import annotations

import argparse
import json
import os
import struct
import sys

# Reuse mesh + glb utilities from the static exporter
from export_mesh_glb import (
    read_mesh_data,
    build_triangles,
    parse_ertm_header,
    find_face_marker,
    parse_submeshes_with_palette_idx,
    parse_bone_palettes,
    _get_texture_names,
    _write_glb,
    _accessor,
)
from export_skeleton_glb import (
    trs_to_mat4,
    mat4_mul,
    mat4_invert_rigid,
    mat4_identity,
)
from telltale.skeleton import parse_skeleton, load_hash_db


def _sanitize(s: str) -> str:
    return s.replace("\x00", "")


def export_rigged(
    mesh_path: str,
    skl_path: str,
    output_path: str,
    texture_dir: str | None = None,
    hashdb_path: str | None = None,
):
    # ------------------------------------------------------------------
    # Load mesh
    # ------------------------------------------------------------------
    with open(mesh_path, "rb") as f:
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
    tex_names = _get_texture_names(mesh_data, data_off,
                                   find_face_marker(mesh_data)[0])

    # ------------------------------------------------------------------
    # Skinning metadata: per-submesh bone-palette index + the palette list
    # ------------------------------------------------------------------
    submesh_end, submesh_palette_info = parse_submeshes_with_palette_idx(mesh_data, data_off)
    palettes = parse_bone_palettes(mesh_data, submesh_end) if submesh_end else []
    submesh_bone_palette = [entry[0] for entry in submesh_palette_info]

    # ------------------------------------------------------------------
    # Load skeleton
    # ------------------------------------------------------------------
    hash_db = load_hash_db(hashdb_path) if hashdb_path and os.path.exists(hashdb_path) else {}
    with open(skl_path, "rb") as f:
        skl_data = f.read()
    skel = parse_skeleton(skl_data, version=0, early_game_fix=10, hash_db=hash_db)
    bones = skel.bones
    nbones = len(bones)
    if nbones == 0:
        raise RuntimeError(f"skeleton has no bones: {skl_path}")

    # World-space matrices → inverse bind matrices
    world = [mat4_identity() for _ in range(nbones)]
    for i, b in enumerate(bones):
        local = trs_to_mat4(b.local_position, b.local_rotation)
        if b.parent_index >= 0:
            world[i] = mat4_mul(world[b.parent_index], local)
        else:
            world[i] = local
    ibms = [mat4_invert_rigid(w) for w in world]

    # ------------------------------------------------------------------
    # Build binary buffer + accessors
    # ------------------------------------------------------------------
    buf = bytearray()
    buffer_views: list[dict] = []
    accessors: list[dict] = []

    def add_view(blob: bytes, target: int | None = None) -> int:
        off = len(buf)
        buf.extend(blob)
        while len(buf) % 4:
            buf.append(0)
        bv: dict = {"buffer": 0, "byteOffset": off, "byteLength": len(blob)}
        if target is not None:
            bv["target"] = target
        idx = len(buffer_views)
        buffer_views.append(bv)
        return idx

    # POSITION
    pos_blob = bytearray()
    xs, ys, zs = [], [], []
    for x, y, z in positions:
        pos_blob.extend(struct.pack("<fff", x, y, z))
        xs.append(x); ys.append(y); zs.append(z)
    pos_bv = add_view(bytes(pos_blob), target=34962)
    pos_acc = len(accessors)
    accessors.append(_accessor(pos_bv, 5126, vc, "VEC3",
                               [min(xs), min(ys), min(zs)],
                               [max(xs), max(ys), max(zs)]))

    # NORMAL
    norm_acc = None
    if normals:
        norm_blob = bytearray()
        for nx, ny, nz in normals:
            norm_blob.extend(struct.pack("<fff", nx, ny, nz))
        norm_bv = add_view(bytes(norm_blob), target=34962)
        norm_acc = len(accessors)
        accessors.append(_accessor(norm_bv, 5126, vc, "VEC3"))

    # TEXCOORD_0
    uv_acc = None
    if uvs:
        uv_blob = bytearray()
        for u, v in uvs:
            uv_blob.extend(struct.pack("<ff", u, v))
        uv_bv = add_view(bytes(uv_blob), target=34962)
        uv_acc = len(accessors)
        accessors.append(_accessor(uv_bv, 5126, vc, "VEC2"))

    # ------------------------------------------------------------------
    # Build JOINTS_0 / WEIGHTS_0 via per-submesh palette remap
    # ------------------------------------------------------------------
    hash_to_skel = {b.hash_value: i for i, b in enumerate(bones)}
    # Map each palette index (submesh group) to an array that translates
    # palette-local bone_id -> skeleton joint index (0 fallback if missing).
    palette_to_skel: list[list[int]] = []
    for pal in palettes:
        palette_to_skel.append([hash_to_skel.get(h, 0) for h in pal])

    # Determine each vertex's submesh: scan each submesh's index range and
    # mark visited vertices with the submesh index. First writer wins for
    # any shared vertex.
    vertex_submesh = [-1] * vc
    for si, (_pal_idx, start_idx, nprim) in enumerate(submesh_palette_info):
        # Triangles are emitted in groups[si]; use those indices for coverage.
        for a, b, c in groups.get(si, []):
            for v in (a, b, c):
                if 0 <= v < vc and vertex_submesh[v] < 0:
                    vertex_submesh[v] = si

    has_skin_data = bool(bone_ids) and bool(weights) and bool(palette_to_skel)

    joints_blob = bytearray()
    weights_blob = bytearray()
    for vi in range(vc):
        si = vertex_submesh[vi]
        pal_idx = submesh_bone_palette[si] if 0 <= si < len(submesh_bone_palette) else 0
        lut = palette_to_skel[pal_idx] if 0 <= pal_idx < len(palette_to_skel) else []

        if has_skin_data and vi < len(bone_ids) and vi < len(weights):
            raw = bone_ids[vi]  # 4 bytes, each is palette_idx * 4
            b0, b1, b2, b3 = (raw[0] >> 2, raw[1] >> 2, raw[2] >> 2, raw[3] >> 2)
            j = [0, 0, 0, 0]
            if lut:
                j[0] = lut[b0] if b0 < len(lut) else 0
                j[1] = lut[b1] if b1 < len(lut) else 0
                j[2] = lut[b2] if b2 < len(lut) else 0
                j[3] = lut[b3] if b3 < len(lut) else 0
            w1, w2, w3 = weights[vi]
            w4 = 1.0 - w1 - w2 - w3
            if w4 < 1e-6:
                w4 = 0.0
            ws_list = [w1, w2, w3, w4]
            # Merge duplicate joints by summing their weights into the first
            # occurrence, then zeroing the rest. glTF requires unique joint
            # indices per vertex among slots with non-zero weight.
            seen: dict[int, int] = {}
            for k in range(4):
                if ws_list[k] <= 1e-6:
                    continue
                if j[k] in seen:
                    ws_list[seen[j[k]]] += ws_list[k]
                    ws_list[k] = 0.0
                else:
                    seen[j[k]] = k
            # Zero-weight slots must have joint 0.
            for k in range(4):
                if ws_list[k] <= 1e-6:
                    ws_list[k] = 0.0
                    j[k] = 0
            total = sum(ws_list)
            if total > 0:
                ws_list = [w / total for w in ws_list]
            else:
                ws_list = [1.0, 0.0, 0.0, 0.0]
                j = [0, 0, 0, 0]
            ws = tuple(ws_list)
        else:
            j = [0, 0, 0, 0]
            ws = (1.0, 0.0, 0.0, 0.0)

        joints_blob.extend(struct.pack("<4H", *j))
        weights_blob.extend(struct.pack("<4f", *ws))

    j_bv = add_view(bytes(joints_blob), target=34962)
    j_acc = len(accessors)
    accessors.append(_accessor(j_bv, 5123, vc, "VEC4"))

    w_bv = add_view(bytes(weights_blob), target=34962)
    w_acc = len(accessors)
    accessors.append(_accessor(w_bv, 5126, vc, "VEC4"))

    # Inverse bind matrices
    ibm_blob = bytearray()
    for m in ibms:
        ibm_blob.extend(struct.pack("<16f", *m))
    ibm_bv = add_view(bytes(ibm_blob))
    ibm_acc = len(accessors)
    accessors.append({
        "bufferView": ibm_bv, "componentType": 5126,
        "count": nbones, "type": "MAT4",
    })

    # ------------------------------------------------------------------
    # Textures (embed d3dtx as PNG) — unchanged from static exporter
    # ------------------------------------------------------------------
    images: list[dict] = []
    textures: list[dict] = []
    samplers: list[dict] = []
    tex_to_gltf_idx: dict[str, int] = {}

    if texture_dir:
        try:
            import zlib
            from decode_d3dtx import decode_d3dtx
        except ImportError:
            texture_dir = None

    def _embed_texture(tex_name: str):
        if tex_name in tex_to_gltf_idx:
            return tex_to_gltf_idx[tex_name]
        if not texture_dir:
            return None
        d3dtx_path = os.path.join(texture_dir, tex_name + ".d3dtx")
        if not os.path.exists(d3dtx_path):
            return None
        try:
            with open(d3dtx_path, "rb") as f:
                tex_data = f.read()
            tw, th, _fmt, pixels = decode_d3dtx(tex_data)
            raw = bytearray()
            for yy in range(th):
                raw.append(0)
                for xx in range(tw):
                    r, g, b, a = pixels[yy * tw + xx]
                    raw.extend([r, g, b, a])
            compressed = zlib.compress(bytes(raw), 9)

            def chunk(ctype: bytes, cdata: bytes) -> bytes:
                c = ctype + cdata
                crc = zlib.crc32(c) & 0xFFFFFFFF
                return struct.pack(">I", len(cdata)) + c + struct.pack(">I", crc)

            png_buf = bytearray()
            png_buf.extend(b"\x89PNG\r\n\x1a\n")
            png_buf.extend(chunk(b"IHDR", struct.pack(">IIBBBBB", tw, th, 8, 6, 0, 0, 0)))
            png_buf.extend(chunk(b"IDAT", compressed))
            png_buf.extend(chunk(b"IEND", b""))

            if not samplers:
                samplers.append({
                    "magFilter": 9729, "minFilter": 9987,
                    "wrapS": 10497, "wrapT": 10497,
                })
            img_bv_idx = add_view(bytes(png_buf))
            img_idx = len(images)
            images.append({"bufferView": img_bv_idx, "mimeType": "image/png", "name": tex_name})
            tex_idx = len(textures)
            textures.append({"source": img_idx, "sampler": 0})
            tex_to_gltf_idx[tex_name] = tex_idx
            return tex_idx
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Primitives (per-submesh index buffers + materials)
    # ------------------------------------------------------------------
    primitives = []
    materials = []
    mat_name_to_idx: dict[tuple, int] = {}

    for si in sorted(groups.keys()):
        tris = groups[si]
        idx_blob = bytearray()
        for a, b, c in tris:
            idx_blob.extend(struct.pack("<HHH", a, b, c))
        idx_bv = add_view(bytes(idx_blob), target=34963)
        idx_acc = len(accessors)
        flat = [v for t in tris for v in t]
        accessors.append(_accessor(idx_bv, 5123, len(flat), "SCALAR",
                                   [min(flat)], [max(flat)]))

        tex_info = tex_names.get(si, {}) if tex_names else {}
        if isinstance(tex_info, str):
            tex_info = {"diffuse": tex_info}
        diffuse_name = tex_info.get("diffuse", name)
        normal_name = tex_info.get("normal")
        spec_name = tex_info.get("specular")

        mat_key = (diffuse_name, normal_name, spec_name)
        if mat_key not in mat_name_to_idx:
            mat_name_to_idx[mat_key] = len(materials)
            mat: dict = {"name": diffuse_name, "pbrMetallicRoughness": {
                "metallicFactor": 0.0, "roughnessFactor": 0.8
            }}
            d_idx = _embed_texture(diffuse_name)
            if d_idx is not None:
                mat["pbrMetallicRoughness"]["baseColorTexture"] = {"index": d_idx}
            else:
                mat["pbrMetallicRoughness"]["baseColorFactor"] = [0.8, 0.8, 0.8, 1.0]
            if normal_name:
                n_idx = _embed_texture(normal_name)
                if n_idx is not None:
                    mat["normalTexture"] = {"index": n_idx}
            if spec_name:
                s_idx = _embed_texture(spec_name)
                if s_idx is not None:
                    mat["pbrMetallicRoughness"]["metallicRoughnessTexture"] = {"index": s_idx}
                    mat["pbrMetallicRoughness"]["metallicFactor"] = 1.0
            materials.append(mat)
        mat_idx = mat_name_to_idx[mat_key]

        prim = {
            "attributes": {
                "POSITION": pos_acc,
                "JOINTS_0": j_acc,
                "WEIGHTS_0": w_acc,
            },
            "indices": idx_acc,
            "material": mat_idx,
        }
        if norm_acc is not None:
            prim["attributes"]["NORMAL"] = norm_acc
        if uv_acc is not None:
            prim["attributes"]["TEXCOORD_0"] = uv_acc
        primitives.append(prim)

    # ------------------------------------------------------------------
    # Node hierarchy: bone nodes + armature root + skinned mesh
    # ------------------------------------------------------------------
    nodes: list[dict] = []
    children_of: list[list[int]] = [[] for _ in range(nbones)]
    root_bones: list[int] = []
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

    skin = {
        "joints": list(range(nbones)),
        "inverseBindMatrices": ibm_acc,
        "skeleton": armature_root,
    }

    gltf: dict = {
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
    if images:
        gltf["images"] = images
    if textures:
        gltf["textures"] = textures
    if samplers:
        gltf["samplers"] = samplers

    os.makedirs(os.path.dirname(os.path.abspath(output_path)) or ".", exist_ok=True)
    _write_glb(gltf, bytes(buf), output_path)

    n_tris = sum(len(g) for g in groups.values())
    print(f"{name}: {vc} verts, {n_tris} tris, {len(primitives)} submeshes, "
          f"{nbones} bones, {len(images)} textures -> {output_path} "
          f"({os.path.getsize(output_path)} bytes)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mesh")
    ap.add_argument("--skl", default=None, help="sibling .skl path (default: same name)")
    ap.add_argument("-o", "--output", default=None)
    ap.add_argument("--textures", default=None, help="directory with .d3dtx texture files")
    ap.add_argument("--hashdb", default="hashdb/BoneNames.HashDB")
    args = ap.parse_args()

    skl = args.skl or os.path.splitext(args.mesh)[0] + ".skl"
    if not os.path.exists(skl):
        sys.exit(f"no SKL companion found: {skl}")
    out = args.output or os.path.splitext(args.mesh)[0] + "_rigged.glb"

    export_rigged(
        mesh_path=args.mesh,
        skl_path=skl,
        output_path=out,
        texture_dir=args.textures,
        hashdb_path=args.hashdb,
    )


if __name__ == "__main__":
    main()
