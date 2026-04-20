"""Export a Telltale .skl skeleton to a glTF 2.0 .glb file.

Produces a valid glTF with:
- One node per bone (local TRS from .skl)
- A skin with joints[] and inverseBindMatrices
- A placeholder single-triangle mesh rigged to the root joint so viewers
  (Blender, Babylon.js Sandbox) display the armature.

Usage:
    python export_skeleton_glb.py <input.skl> [-o output.glb]
                                   [--hashdb hashdb/BoneNames.HashDB]
"""
from __future__ import annotations

import argparse
import json
import math
import os
import struct
import sys

from telltale.skeleton import parse_skeleton, load_hash_db


# ---------------------------------------------------------------------------
# 4x4 column-major matrix helpers (glTF stores matrices column-major)
# ---------------------------------------------------------------------------

def mat4_identity():
    return [1.0, 0.0, 0.0, 0.0,
            0.0, 1.0, 0.0, 0.0,
            0.0, 0.0, 1.0, 0.0,
            0.0, 0.0, 0.0, 1.0]


def quat_to_mat3(q):
    """Quaternion (x, y, z, w) → 3x3 row-major rotation matrix (9 floats)."""
    x, y, z, w = q
    xx, yy, zz = x * x, y * y, z * z
    xy, xz, yz = x * y, x * z, y * z
    wx, wy, wz = w * x, w * y, w * z
    return [
        1 - 2 * (yy + zz), 2 * (xy - wz),     2 * (xz + wy),
        2 * (xy + wz),     1 - 2 * (xx + zz), 2 * (yz - wx),
        2 * (xz - wy),     2 * (yz + wx),     1 - 2 * (xx + yy),
    ]


def trs_to_mat4(t, q):
    """Build a 4x4 column-major transform from translation + quaternion."""
    r = quat_to_mat3(q)
    tx, ty, tz = t
    return [
        r[0], r[3], r[6], 0.0,   # column 0
        r[1], r[4], r[7], 0.0,   # column 1
        r[2], r[5], r[8], 0.0,   # column 2
        tx,   ty,   tz,   1.0,   # column 3 (translation)
    ]


def mat4_mul(a, b):
    """Multiply two 4x4 column-major matrices: result = a * b."""
    out = [0.0] * 16
    for col in range(4):
        for row in range(4):
            s = 0.0
            for k in range(4):
                s += a[k * 4 + row] * b[col * 4 + k]
            out[col * 4 + row] = s
    return out


def mat4_invert_rigid(m):
    """Invert a rigid 4x4 (rotation + translation, no scale).

    For M = [R | t; 0 | 1],  M^-1 = [R^T | -R^T t; 0 | 1].
    """
    # Extract columns (column-major): R columns are m[0..2], m[4..6], m[8..10]
    r00, r10, r20 = m[0], m[1], m[2]
    r01, r11, r21 = m[4], m[5], m[6]
    r02, r12, r22 = m[8], m[9], m[10]
    tx, ty, tz    = m[12], m[13], m[14]

    # R^T (transpose)
    ix00, ix10, ix20 = r00, r01, r02
    ix01, ix11, ix21 = r10, r11, r12
    ix02, ix12, ix22 = r20, r21, r22

    # -R^T * t
    nx = -(ix00 * tx + ix01 * ty + ix02 * tz)
    ny = -(ix10 * tx + ix11 * ty + ix12 * tz)
    nz = -(ix20 * tx + ix21 * ty + ix22 * tz)

    return [
        ix00, ix10, ix20, 0.0,
        ix01, ix11, ix21, 0.0,
        ix02, ix12, ix22, 0.0,
        nx,   ny,   nz,   1.0,
    ]


# ---------------------------------------------------------------------------
# glTF .glb writer (same format as export_mesh_glb.py)
# ---------------------------------------------------------------------------

def _write_glb(json_dict, bin_data, path):
    json_raw = json.dumps(json_dict, separators=(",", ":")).encode("utf-8")
    r = len(json_raw) % 4
    json_bytes = json_raw + b" " * (4 - r) if r else json_raw
    r = len(bin_data) % 4
    bin_bytes = bin_data + b"\x00" * (4 - r) if r else bin_data

    total = 12 + 8 + len(json_bytes) + 8 + len(bin_bytes)
    with open(path, "wb") as f:
        f.write(b"glTF")
        f.write(struct.pack("<I", 2))
        f.write(struct.pack("<I", total))
        f.write(struct.pack("<I", len(json_bytes)))
        f.write(struct.pack("<I", 0x4E4F534A))  # "JSON"
        f.write(json_bytes)
        f.write(struct.pack("<I", len(bin_bytes)))
        f.write(struct.pack("<I", 0x004E4942))  # "BIN\0"
        f.write(bin_bytes)


# ---------------------------------------------------------------------------
# Skeleton → glTF
# ---------------------------------------------------------------------------

def _sanitize_name(name: str) -> str:
    # glTF allows any utf-8 string; just strip nulls.
    return name.replace("\x00", "")


def export_skeleton(skel, output_path, mesh_name="Armature"):
    bones = skel.bones
    n = len(bones)
    if n == 0:
        raise ValueError("skeleton has no bones")

    # ------------------------------------------------------------------
    # World-space bind matrices (for inverse bind matrices)
    # ------------------------------------------------------------------
    world = [mat4_identity() for _ in range(n)]
    for i, b in enumerate(bones):
        local = trs_to_mat4(b.local_position, b.local_rotation)
        if b.parent_index >= 0:
            world[i] = mat4_mul(world[b.parent_index], local)
        else:
            world[i] = local
    ibms = [mat4_invert_rigid(w) for w in world]

    # ------------------------------------------------------------------
    # Buffer layout: ibm_data | triangle positions | joints | weights
    # ------------------------------------------------------------------
    ibm_blob = bytearray()
    for m in ibms:
        ibm_blob += struct.pack("<16f", *m)

    # Placeholder triangle at world-origin (small) bound fully to root joint (index 0)
    pos_blob = struct.pack(
        "<9f",
        0.0, 0.0, 0.0,
        0.001, 0.0, 0.0,
        0.0, 0.001, 0.0,
    )
    # JOINTS_0 as UNSIGNED_SHORT VEC4
    joints_blob = struct.pack("<12H", 0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0)
    # WEIGHTS_0 as FLOAT VEC4
    weights_blob = struct.pack(
        "<12f",
        1.0, 0.0, 0.0, 0.0,
        1.0, 0.0, 0.0, 0.0,
        1.0, 0.0, 0.0, 0.0,
    )
    # Indices for the triangle
    idx_blob = struct.pack("<3H", 0, 1, 2)

    bin_data = bytearray()
    def add_view(blob, target=None):
        off = len(bin_data)
        bin_data.extend(blob)
        # pad to 4 bytes for subsequent views
        while len(bin_data) % 4:
            bin_data.append(0)
        bv = {"buffer": 0, "byteOffset": off, "byteLength": len(blob)}
        if target is not None:
            bv["target"] = target
        return bv

    buffer_views = []
    accessors = []

    bv_ibm = len(buffer_views); buffer_views.append(add_view(ibm_blob))
    acc_ibm = len(accessors)
    accessors.append({
        "bufferView": bv_ibm, "componentType": 5126,
        "count": n, "type": "MAT4",
    })

    bv_pos = len(buffer_views); buffer_views.append(add_view(pos_blob, target=34962))
    acc_pos = len(accessors)
    accessors.append({
        "bufferView": bv_pos, "componentType": 5126,
        "count": 3, "type": "VEC3",
        "min": [0.0, 0.0, 0.0], "max": [0.001, 0.001, 0.0],
    })

    bv_joints = len(buffer_views); buffer_views.append(add_view(joints_blob, target=34962))
    acc_joints = len(accessors)
    accessors.append({
        "bufferView": bv_joints, "componentType": 5123,  # UNSIGNED_SHORT
        "count": 3, "type": "VEC4",
    })

    bv_weights = len(buffer_views); buffer_views.append(add_view(weights_blob, target=34962))
    acc_weights = len(accessors)
    accessors.append({
        "bufferView": bv_weights, "componentType": 5126,
        "count": 3, "type": "VEC4",
    })

    bv_idx = len(buffer_views); buffer_views.append(add_view(idx_blob, target=34963))
    acc_idx = len(accessors)
    accessors.append({
        "bufferView": bv_idx, "componentType": 5123,
        "count": 3, "type": "SCALAR",
    })

    # ------------------------------------------------------------------
    # Nodes: one per bone (indices 0..n-1) + Armature root (n) + SkinMesh (n+1)
    # ------------------------------------------------------------------
    nodes = []
    # Bone nodes
    root_bone_indices = []
    children_of = [[] for _ in range(n)]
    for i, b in enumerate(bones):
        if b.parent_index >= 0:
            children_of[b.parent_index].append(i)
        else:
            root_bone_indices.append(i)

    for i, b in enumerate(bones):
        node = {
            "name": _sanitize_name(b.name),
            "translation": [float(v) for v in b.local_position],
            "rotation": [float(v) for v in b.local_rotation],
        }
        if children_of[i]:
            node["children"] = children_of[i]
        nodes.append(node)

    # Armature root (parent of all root bones)
    armature_root = n
    nodes.append({
        "name": mesh_name,
        "children": root_bone_indices,
    })

    # Skinned mesh node
    mesh_node = n + 1
    nodes.append({
        "name": "SkinPlaceholder",
        "mesh": 0,
        "skin": 0,
    })

    # ------------------------------------------------------------------
    # Skin
    # ------------------------------------------------------------------
    skin = {
        "joints": list(range(n)),
        "inverseBindMatrices": acc_ibm,
        "skeleton": armature_root,
    }

    # ------------------------------------------------------------------
    # Mesh
    # ------------------------------------------------------------------
    mesh = {
        "name": "SkinPlaceholder",
        "primitives": [{
            "attributes": {
                "POSITION": acc_pos,
                "JOINTS_0": acc_joints,
                "WEIGHTS_0": acc_weights,
            },
            "indices": acc_idx,
            "mode": 4,  # TRIANGLES
        }],
    }

    # ------------------------------------------------------------------
    # Final glTF
    # ------------------------------------------------------------------
    gltf = {
        "asset": {"version": "2.0", "generator": "telltale-explorer"},
        "scene": 0,
        "scenes": [{"nodes": [armature_root, mesh_node]}],
        "nodes": nodes,
        "skins": [skin],
        "meshes": [mesh],
        "accessors": accessors,
        "bufferViews": buffer_views,
        "buffers": [{"byteLength": len(bin_data)}],
    }

    _write_glb(gltf, bytes(bin_data), output_path)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input_skl")
    ap.add_argument("-o", "--output", default=None)
    ap.add_argument("--hashdb", default="hashdb/BoneNames.HashDB")
    ap.add_argument("--version", type=int, default=0)
    ap.add_argument("--early-game-fix", type=int, default=10)
    args = ap.parse_args()

    db = None
    if args.hashdb and os.path.exists(args.hashdb):
        db = load_hash_db(args.hashdb)

    with open(args.input_skl, "rb") as f:
        data = f.read()
    skel = parse_skeleton(
        data,
        version=args.version,
        early_game_fix=args.early_game_fix,
        hash_db=db or {},
    )

    out = args.output or os.path.splitext(args.input_skl)[0] + "_skeleton.glb"
    export_skeleton(skel, out, mesh_name=os.path.splitext(os.path.basename(args.input_skl))[0])
    print(f"wrote {out}  ({len(skel.bones)} bones)")


if __name__ == "__main__":
    main()
