# PTABLE — Phoneme Table Format

Per-character mapping from phoneme symbol to face animation. Combined
with `CompressedPhonemeKeys` in an ANM, this drives lip-sync.

Validated on 74 ep1 ptables (888 entries). 100% of phoneme keys match
`crc64_lower(base_phoneme_name)` where `base_phoneme_name` is one of
`aa`, `default`, `ee`, `fv`, `i`, `ll`, `mm`, `nn`, `o`, `sh`, `th`, `u`.

## Schema (from TelltaleToolLib `Types/PhonemeTable.h`)

```cpp
struct PhonemeTable {
    String mName;                                    // blocked
    // mContributionScaler is NOT serialized in TMI's version
    Map<Symbol, PhonemeEntry, Symbol::CompareCRC> mAnimations;   // blocked
};

struct PhonemeEntry {
    AnimOrChore mAnimation;                          // blocked
    float       mExtra;                              // not blocked (always 0 in TMI)
};

struct AnimOrChore {
    Handle<Animation> mhAnim;                        // blocked; String in MTRE
    Handle<Chore>     mhChore;                       // blocked; String in MTRE
};
```

## Wire format

```
MetaStream header                # ERTM, 4 class entries

# mName — a blocked String
u32  block_size                  # total = strlen + 8 (incl this field)
u32  strlen
char name[strlen]                # e.g. "sk03_elaine.ptable"

# mAnimations — blocked Map<Symbol, PhonemeEntry>
u32  block_size                  # covers the whole Map to EOF
u32  num_entries                 # 12 phonemes per variant (default + 11 vowels/consonants)
per entry:
    u64  phoneme_symbol          # crc64(phoneme_name)
    u32  0                       # Symbol debug-string trailer (MTRE v<5)
    # PhonemeEntry (members individually blocked):
    u32  mAnimation_block_size
        u32  mhAnim_block_size
        u32  strlen              # of anim handle path
        char anim_name[strlen]   # e.g. "elaine_phoneme_aa.anm"
        u32  mhChore_block_size  # always 8 in ep1
        u32  chore_strlen        # always 0 in ep1
    f32  mExtra                  # always 0.0
```

Block sizes include the 4-byte size-field itself: `block_end = start_of_size + block_size`.

## Reader

```python
from parse_ptable import parse_ptable, PhonemeTable, PhonemeEntry

pt = parse_ptable("extracted/ep1_ptable/sk03_elaine.ptable")
pt.name     # "sk03_elaine.ptable"
for e in pt.entries:
    e.phoneme_id    # u64 CRC64
    e.anim_name     # "elaine_phoneme_aa.anm"
    e.chore_name    # "" (always empty in ep1)
    e.extra         # 0.0
```

## Pipeline

A dialog ANM contains a `CompressedPhonemeKeys` value that emits samples
`(time, phoneme_id, fade_in, hold, fade_out, contribution)`. Tying it all
together:

1. Decode the phoneme key stream from the ANM (`parse_ctk.decode_phoneme_keys`).
2. Load the character's ptable (e.g. `sk03_elaine.ptable` or an emotion
   variant like `sk03_elaine_angry.ptable`).
3. For each phoneme sample, look up `pt.entries[i].anim_name` whose
   `phoneme_id` matches the sample — this is the face-morph anim to play.
4. Blend the face anim over the fade/hold envelope.
