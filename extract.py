#!/usr/bin/env python3
"""
Telltale Games Asset Extractor - CLI tool.

Extracts and converts assets from Telltale Games archives (.ttarch),
with focus on Tales of Monkey Island (D3DMESH V1, MTRE format).

Usage:
    python extract.py list <archive.ttarch> --game <game_id>
    python extract.py extract <archive.ttarch> --game <game_id> --output <dir>
    python extract.py mesh <file.d3dmesh> [--output <file.obj>]
    python extract.py skeleton <file.skl>
    python extract.py texture <file.d3dtx> [--output <file.dds>]
"""

import argparse
import os
import sys
import struct
import logging

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from telltale.ttarch import TtarchArchive, GAME_KEYS


def cmd_list(args):
    """List files in a TTARCH archive."""
    archive = TtarchArchive(args.archive, game_key=args.game)
    files = archive.list_files()

    # Count by extension
    exts = {}
    for f in files:
        ext = f.name.rsplit('.', 1)[-1] if '.' in f.name else '?'
        exts[ext] = exts.get(ext, 0) + 1

    print(f"Archive: {args.archive}")
    print(f"Total files: {len(files)}")
    print(f"\nBy extension:")
    for ext, count in sorted(exts.items(), key=lambda x: -x[1]):
        print(f"  .{ext}: {count}")

    if args.filter:
        filt = args.filter.lower()
        filtered = [f for f in files if filt in f.name.lower()]
        print(f"\nFiles matching '{args.filter}' ({len(filtered)}):")
        for f in filtered:
            print(f"  {f.name} ({f.size} bytes)")
    elif args.verbose:
        print(f"\nAll files:")
        for f in files:
            print(f"  {f.name} ({f.size} bytes)")


def cmd_extract(args):
    """Extract files from a TTARCH archive."""
    archive = TtarchArchive(args.archive, game_key=args.game)
    files = archive.list_files()

    if args.filter:
        filt = args.filter.lower()
        files = [f for f in files if filt in f.name.lower()]

    output_dir = args.output or "extracted"
    os.makedirs(output_dir, exist_ok=True)

    print(f"Extracting {len(files)} files to {output_dir}/")
    for i, entry in enumerate(files):
        out_path = os.path.join(output_dir, entry.name)
        os.makedirs(os.path.dirname(out_path), exist_ok=True) if os.path.dirname(out_path) else None
        archive.extract_file(entry, out_path)
        if (i + 1) % 100 == 0 or i == len(files) - 1:
            print(f"  [{i+1}/{len(files)}] {entry.name}")

    print(f"Done. Extracted {len(files)} files.")


def cmd_mesh(args):
    """Parse a D3DMESH file and optionally export to OBJ."""
    with open(args.file, 'rb') as f:
        data = f.read()

    from telltale.d3dmesh import parse_d3dmesh
    mesh = parse_d3dmesh(data, early_game_fix=args.game_fix)

    print(f"Mesh: {mesh.name}")
    print(f"Version: {mesh.version}")
    print(f"Bounding box: {mesh.bounding_box}")
    print(f"Submeshes: {len(mesh.submeshes)}")
    for i, sub in enumerate(mesh.submeshes):
        print(f"  [{i}] {sub.name or '(unnamed)'}: "
              f"{len(sub.vertices)} verts, {len(sub.faces)} faces, "
              f"material: {sub.material_name or '?'}")

    if args.output:
        from telltale.exporters.obj import export_obj
        export_obj(mesh, args.output)
        print(f"\nExported to {args.output}")


def cmd_skeleton(args):
    """Parse a SKL skeleton file."""
    with open(args.file, 'rb') as f:
        data = f.read()

    from telltale.skeleton import parse_skeleton
    skel = parse_skeleton(data, version=args.version, early_game_fix=args.game_fix)

    print(f"Bones: {len(skel.bones)}")
    for i, bone in enumerate(skel.bones):
        parent = f"-> {skel.bones[bone.parent_index].name}" if bone.parent_index >= 0 else "(root)"
        print(f"  [{i}] {bone.name} {parent}")
        print(f"      pos=({bone.local_position[0]:.3f}, {bone.local_position[1]:.3f}, {bone.local_position[2]:.3f})")


def cmd_texture(args):
    """Parse a D3DTX texture and convert to DDS."""
    with open(args.file, 'rb') as f:
        data = f.read()

    from telltale.d3dtx import parse_d3dtx, save_as_dds
    tex = parse_d3dtx(data)

    print(f"Texture: {tex.name}")
    print(f"Size: {tex.width}x{tex.height}")
    print(f"Format: {tex.d3d_format}")
    print(f"Mip levels: {tex.num_mip_levels}")

    if args.output:
        save_as_dds(tex, args.output)
        print(f"Saved as {args.output}")


def cmd_games(args):
    """List available game IDs."""
    print("Available game IDs:")
    for key, (name, _, is_new) in sorted(GAME_KEYS.items()):
        bf_type = "modified" if is_new else "standard"
        print(f"  {key:30s} {name} (BF: {bf_type})")


def main():
    parser = argparse.ArgumentParser(
        description="Telltale Games Asset Extractor"
    )
    parser.add_argument('-v', '--verbose', action='store_true')
    sub = parser.add_subparsers(dest='command')

    # list
    p_list = sub.add_parser('list', help='List archive contents')
    p_list.add_argument('archive')
    p_list.add_argument('--game', required=True, help='Game ID for decryption key')
    p_list.add_argument('--filter', help='Filter by name substring')
    p_list.add_argument('--verbose', '-V', action='store_true')

    # extract
    p_ext = sub.add_parser('extract', help='Extract files from archive')
    p_ext.add_argument('archive')
    p_ext.add_argument('--game', required=True)
    p_ext.add_argument('--output', '-o', help='Output directory')
    p_ext.add_argument('--filter', help='Filter by name substring')

    # mesh
    p_mesh = sub.add_parser('mesh', help='Parse D3DMESH file')
    p_mesh.add_argument('file')
    p_mesh.add_argument('--output', '-o', help='Export as OBJ')
    p_mesh.add_argument('--game-fix', type=int, default=10,
                        help='EarlyGameFix value (10=Monkey Island)')

    # skeleton
    p_skl = sub.add_parser('skeleton', help='Parse SKL file')
    p_skl.add_argument('file')
    p_skl.add_argument('--version', type=int, default=0)
    p_skl.add_argument('--game-fix', type=int, default=10)

    # texture
    p_tex = sub.add_parser('texture', help='Parse D3DTX texture')
    p_tex.add_argument('file')
    p_tex.add_argument('--output', '-o', help='Export as DDS')

    # games
    sub.add_parser('games', help='List available game IDs')

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)

    if args.command == 'list':
        cmd_list(args)
    elif args.command == 'extract':
        cmd_extract(args)
    elif args.command == 'mesh':
        cmd_mesh(args)
    elif args.command == 'skeleton':
        cmd_skeleton(args)
    elif args.command == 'texture':
        cmd_texture(args)
    elif args.command == 'games':
        cmd_games(args)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
