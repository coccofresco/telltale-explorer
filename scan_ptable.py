"""Scan ttarch archives for .ptable entries and extract them."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from telltale.ttarch import TtarchArchive

CANDIDATES = [
    ("ios_hd_mesh.ttarch", "monkeyisland101"),
    ("ps3_extracted/USRDIR_Pack_1_MonkeyIsland101_ps3_data.ttarch", "monkeyisland101"),
    ("ps3_extracted/USRDIR_Pack_0_0_eu.ttarch", "monkeyisland101"),
    ("wii_extracted/ttarch/1_MonkeyIsland101_wii_data.ttarch", "monkeyisland101"),
]

OUT = "extracted/ep1_ptable"
os.makedirs(OUT, exist_ok=True)

for path, key in CANDIDATES:
    if not os.path.exists(path):
        print(f"[SKIP missing] {path}"); continue
    try:
        arc = TtarchArchive(path, game_key=key)
    except Exception as e:
        print(f"[FAIL open] {path}: {e}"); continue
    entries = arc.list_files()
    ptables = [e for e in entries if e.name.lower().endswith(".ptable")]
    print(f"[{path}] v{arc.version}, {len(entries)} files, {len(ptables)} .ptable")
    for e in ptables[:3]:
        print(f"  - {e.name} ({e.size} B)")
    for e in ptables:
        dest = os.path.join(OUT, os.path.basename(e.name))
        if os.path.exists(dest): continue
        try:
            with open(dest, "wb") as f: f.write(arc.read_file(e))
        except Exception as ex:
            print(f"  [fail] {e.name}: {ex}")
    if ptables:
        print(f"  -> wrote to {OUT}")
        break
