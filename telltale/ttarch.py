"""
TTARCH archive parser and extractor for Telltale Games.

Handles the **original** TTARCH format (not TTARCH2) used by Telltale games
from Texas Hold'em (2005) through Poker Night 2 (2013).  TTARCH archives
contain game assets packed into a single file with an optional Blowfish-
encrypted and/or zlib-compressed file table and data region.

Supported archive versions
--------------------------
- **Version 0 (Legacy)**: Pre-versioned archives (oldest games).
- **Versions 1-2**: Simple header with optional Blowfish encryption.
- **Versions 3-6**: Adds zlib-compressed data blocks.
- **Version 7**: Modified Blowfish, compressed headers, configurable chunks.
- **Versions 8-9**: Extensions of v7 with extra fields.

Usage::

    from telltale.ttarch import TtarchArchive

    archive = TtarchArchive("path/to/archive.ttarch", game_key=b"\\x92\\xCA...")
    for entry in archive.list_files():
        print(entry.name, entry.size)
    archive.extract_all("output_dir")
"""

from __future__ import annotations

import io
import logging
import os
import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Dict, List, Optional, Tuple, Union

from telltale.blowfish import Blowfish

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Game key database
# ---------------------------------------------------------------------------

# Each Telltale game that uses TTARCH encryption has a unique 55-byte Blowfish
# key.  The keys below are taken from TelltaleToolLib (Lucas Saragosa) and
# ttarchext (Luigi Auriemma).
#
# The dictionary maps a short game identifier to a tuple of:
#   (display_name, key_bytes, is_new_encryption)
#
# ``is_new_encryption`` is True for games that use the modified Blowfish
# variant (swapped P-array entries during rounds and byte-swapped S[0][118]).

GAME_KEYS: Dict[str, Tuple[str, bytes, bool]] = {
    # -- No key needed (empty key) --
    "texasholdem": (
        "Telltale Texas Hold'em",
        b"",
        False,
    ),
    "csi3dimensions": (
        "CSI: 3 Dimensions of Murder",
        b"",
        False,
    ),

    # -- Standard Blowfish (pre-v7) keys --
    "boneville": (
        "Bone: Out from Boneville",
        b"\x82\xa3\x89\x88\x89\xd8\x9f\xb7\xd3\xd8\xda\xc0\x82\xd7\xc2\xc1"
        b"\xce\x8d\xa1\xea\x99\xb7\xa5\xdd\xca\x52\xe5\x87\x69\xc8\xa4\x6e"
        b"\xbb\x99\x97\xbb\xcd\xd7\x9a\xd8\xda\xd0\xc8\xde\xa6\x9c\xb7\xd2"
        b"\xb9\xd6\x82\x75\xdf\xe0\xa4",
        False,
    ),
    "cowrace": (
        "Bone: The Great Cow Race",
        b"\x81\xD8\x9B\x99\x56\xE2\x65\x73\xB4\xDB\xE3\xC9\x64\xDB\x85\x87"
        b"\xAB\x99\x9B\xDC\x6F\xEB\x68\x9F\xA7\x90\xDD\xBA\x6B\xE2\x93\x64"
        b"\xA1\xB4\xA0\xB4\x93\xD9\x6B\x9C\xB7\xE3\xE6\xD1\x69\xA8\x84\x9F"
        b"\x87\xD2\x94\x98\xA2\xE8\x71",
        False,
    ),
    "sammax101": (
        "Sam and Max: S1E1",
        b"\x92\xCA\x9A\x81\x85\xE4\x64\x73\xA3\xBF\xD6\xD1\x7F\xC6\xCB\x88"
        b"\x99\x5B\x80\xD8\xAA\xC2\x97\xE7\x96\x51\xA0\xA8\x9A\xD9\xAE\x95"
        b"\xD7\x76\x62\x80\xB4\xC4\xA6\xB9\xD6\xEC\xA9\x9C\x68\x85\xB3\xDC"
        b"\x92\xC4\x9E\x64\xA0\xA3\x92",
        False,
    ),
    "sammax102": (
        "Sam and Max: S1E2",
        b"\x92\xCA\x9A\x81\x85\xE4\x64\x73\xA4\xBF\xD6\xD1\x7F\xC6\xCB\x88"
        b"\x99\x01\x80\xD8\xAA\xC2\x97\xE7\x96\x51\xA1\xA8\x9A\xD9\xAE\x95"
        b"\xD7\x76\x62\x81\xB4\xC4\xA6\xB9\xD6\xEC\xA9\x9C\x69\x85\xB3\xDC"
        b"\x92\xC4\x9E\x64\xA0\xA4\x92",
        False,
    ),
    "sammax103": (
        "Sam and Max: S1E3",
        b"\x92\xca\x9a\x81\x85\xe4\x64\x73\xa5\xbf\xd6\xd1\x7f\xc6\xcb\x88"
        b"\x99\x5d\x80\xd8\xaa\xc2\x97\xe7\x96\x51\xa2\xa8\x9a\xd9\xae\x95"
        b"\xd7\x76\x62\x82\xb4\xc4\xa6\xb9\xd6\xec\xa9\x9c\x6a\x85\xb3\xdc"
        b"\x92\xc4\x9e\x64\xa0\xa5\x92",
        False,
    ),
    "sammax104": (
        "Sam and Max: S1E4",
        b"\x92\xCA\x9A\x81\x85\xE4\x64\x73\xA6\xBF\xD6\xD1\x7F\xC6\xCB\x88"
        b"\x99\x5E\x80\xD8\xAA\xC2\x97\xE7\x96\x51\xA3\xA8\x9A\xD9\xAE\x95"
        b"\xD7\x76\x62\x83\xB4\xC4\xA6\xB9\xD6\xEC\xA9\x9C\x6B\x85\xB3\xDC"
        b"\x92\xC4\x9E\x64\xA0\xA6\x92",
        False,
    ),
    "sammax105": (
        "Sam and Max: S1E5",
        b"\x92\xCA\x9A\x81\x85\xE4\x64\x73\xA7\xBF\xD6\xD1\x7F\xC6\xCB\x88"
        b"\x99\x5F\x80\xD8\xAA\xC2\x97\xE7\x96\x51\xA4\xA8\x9A\xD9\xAE\x95"
        b"\xD7\x76\x62\x84\xB4\xC4\xA6\xB9\xD6\xEC\xA9\x9C\x6C\x85\xB3\xDC"
        b"\x92\xC4\x9E\x64\xA0\xA7\x92",
        False,
    ),
    "sammax106": (
        "Sam and Max: S1E6",
        b"\x92\xCA\x9A\x81\x85\xE4\x64\x73\xA8\xBF\xD6\xD1\x7F\xC6\xCB\x88"
        b"\x99\x60\x80\xD8\xAA\xC2\x97\xE7\x96\x51\xA5\xA8\x9A\xD9\xAE\x95"
        b"\xD7\x76\x62\x85\xB4\xC4\xA6\xB9\xD6\xEC\xA9\x9C\x6D\x85\xB3\xDC"
        b"\x92\xC4\x9E\x64\xA0\xA8\x92",
        False,
    ),
    "csihard": (
        "CSI: Hard Evidence",
        b"\x82\xbc\x76\x68\x67\xbf\x7c\x77\xb5\xbf\xbe\x98\x75\xb8\x9c\x8b"
        b"\xac\x7d\x76\xab\x80\xc8\x7f\xa3\xa8\x74\xb8\x89\x7c\xbf\xaa\x68"
        b"\xa2\x98\x7b\x83\xa4\xb6\x82\xa0\xb8\xc7\xc1\xa0\x7a\x85\x9b\xa3"
        b"\x88\xb6\x6f\x67\xb3\xc5\x88",
        False,
    ),
    "sammax201": (
        "Sam and Max: S2E1",
        b"\x92\xca\x9a\x81\x85\xe4\x65\x73\xa3\xbf\xd6\xd1\x7f\xc6\xcb\x89"
        b"\x99\x5b\x80\xd8\xaa\xc2\x97\xe7\x97\x51\xa0\xa8\x9a\xd9\xae\x95"
        b"\xd7\x77\x62\x80\xb4\xc4\xa6\xb9\xd6\xec\xaa\x9c\x68\x85\xb3\xdc"
        b"\x92\xc4\x9e\x65\xa0\xa3\x92",
        False,
    ),
    "sammax202": (
        "Sam and Max: S2E2",
        b"\x92\xCA\x9A\x81\x85\xE4\x65\x73\xA4\xBF\xD6\xD1\x7F\xC6\xCB\x89"
        b"\x99\x01\x80\xD8\xAA\xC2\x97\xE7\x97\x51\xA1\xA8\x9A\xD9\xAE\x95"
        b"\xD7\x77\x62\x81\xB4\xC4\xA6\xB9\xD6\xEC\xAA\x9C\x69\x85\xB3\xDC"
        b"\x92\xC4\x9E\x65\xA0\xA4\x92",
        False,
    ),
    "sammax203": (
        "Sam and Max: S2E3",
        b"\x92\xCA\x9A\x81\x85\xE4\x65\x73\xA5\xBF\xD6\xD1\x7F\xC6\xCB\x89"
        b"\x99\x5D\x80\xD8\xAA\xC2\x97\xE7\x97\x51\xA2\xA8\x9A\xD9\xAE\x95"
        b"\xD7\x77\x62\x82\xB4\xC4\xA6\xB9\xD6\xEC\xAA\x9C\x6A\x85\xB3\xDC"
        b"\x92\xC4\x9E\x65\xA0\xA5\x92",
        False,
    ),
    "sammax204": (
        "Sam and Max: S2E4",
        b"\x92\xCA\x9A\x81\x85\xE4\x65\x73\xA6\xBF\xD6\xD1\x7F\xC6\xCB\x89"
        b"\x99\x5E\x80\xD8\xAA\xC2\x97\xE7\x97\x51\xA3\xA8\x9A\xD9\xAE\x95"
        b"\xD7\x77\x62\x83\xB4\xC4\xA6\xB9\xD6\xEC\xAA\x9C\x6B\x85\xB3\xDC"
        b"\x92\xC4\x9E\x65\xA0\xA6\x92",
        False,
    ),
    "sammax205": (
        "Sam and Max: S2E5",
        b"\x92\xca\x9a\x81\x85\xe4\x65\x73\xa7\xbf\xd6\xd1\x7f\xc6\xcb\x89"
        b"\x99\x5f\x80\xd8\xaa\xc2\x97\xe7\x97\x51\xa4\xa8\x9a\xd9\xae\x95"
        b"\xd7\x77\x62\x84\xb4\xc4\xa6\xb9\xd6\xec\xaa\x9c\x6c\x85\xb3\xdc"
        b"\x92\xc4\x9e\x65\xa0\xa7\x92",
        False,
    ),
    "sbcg4ap101": (
        "Strong Bad CG4AP S1E1",
        b"\x87\xD8\x9A\x99\x97\xE0\x94\xB5\xA3\x9C\xA6\xAC\xA1\xD2\xB8\xCA"
        b"\xDD\x8B\x9F\xA8\x6D\xA6\x7E\xDE\xD2\x86\xE2\xC9\x9A\xDE\x92\x64"
        b"\x90\x8D\xA1\xBC\xC6\xD6\xAD\xCD\xE7\xA5\xA8\x9D\x7F\xA1\xBF\xD4"
        b"\xB8\xD7\x87\xA5\xA1\xA2\x70",
        False,
    ),
    "sbcg4ap102": (
        "Strong Bad CG4AP S1E2",
        b"\x87\xd8\x9a\x99\x97\xe0\x94\xb5\xa3\x9c\xa7\xac\xa1\xd2\xb8\xca"
        b"\xdd\x8b\x9f\xa8\x6d\xa7\x7e\xde\xd2\x86\xe2\xc9\x9a\xde\x92\x64"
        b"\x91\x8d\xa1\xbc\xc6\xd6\xad\xcd\xe7\xa5\xa8\x9e\x7f\xa1\xbf\xd4"
        b"\xb8\xd7\x87\xa5\xa1\xa2\x71",
        False,
    ),
    "sbcg4ap103": (
        "Strong Bad CG4AP S1E3",
        b"\x87\xD8\x9A\x99\x97\xE0\x94\xB5\xA3\x9C\xA8\xAC\xA1\xD2\xB8\xCA"
        b"\xDD\x8B\x9F\xA8\x6D\xA8\x7E\xDE\xD2\x86\xE2\xC9\x9A\xDE\x92\x64"
        b"\x92\x8D\xA1\xBC\xC6\xD6\xAD\xCD\xE7\xA5\xA8\x9F\x7F\xA1\xBF\xD4"
        b"\xB8\xD7\x87\xA5\xA1\xA2\x72",
        False,
    ),
    "sbcg4ap104": (
        "Strong Bad CG4AP S1E4",
        b"\x87\xd8\x9a\x99\x97\xe0\x94\xb5\xa3\x9c\xa9\xac\xa1\xd2\xb8\xca"
        b"\xdd\x8b\x9f\xa8\x6d\xa9\x7e\xde\xd2\x86\xe2\xc9\x9a\xde\x92\x64"
        b"\x93\x8d\xa1\xbc\xc6\xd6\xad\xcd\xe7\xa5\xa8\xa0\x7f\xa1\xbf\xd4"
        b"\xb8\xd7\x87\xa5\xa1\xa2\x73",
        False,
    ),
    "sbcg4ap105": (
        "Strong Bad CG4AP S1E5",
        b"\x87\xd8\x9a\x99\x97\xe0\x94\xb5\xa3\x9c\xaa\xac\xa1\xd2\xb8\xca"
        b"\xdd\x8b\x9f\xa8\x6d\xaa\x7e\xde\xd2\x86\xe2\xc9\x9a\xde\x92\x64"
        b"\x94\x8d\xa1\xbc\xc6\xd6\xad\xcd\xe7\xa5\xa8\xa1\x7f\xa1\xbf\xd4"
        b"\xb8\xd7\x87\xa5\xa1\xa2\x74",
        False,
    ),
    "wag101": (
        "Wallace And Gromit: S1E1",
        b"\x96\xCA\x99\xA0\x85\xCF\x98\x8A\xE4\xDB\xE2\xCD\xA6\x96\x83\x88"
        b"\xC0\x8B\x99\xE3\x9E\xD8\x9B\xB6\xD7\x90\xDC\xBE\xAD\x9D\x91\x65"
        b"\xB6\xA6\x9E\xBB\xC2\xC6\x9E\xB3\xE7\xE3\xE5\xD5\xAB\x63\x82\xA0"
        b"\x9C\xC4\x92\x9F\xD1\xD5\xA4",
        False,
    ),
    "wag102": (
        "Wallace And Gromit: S1E2",
        b"\x96\xCA\x99\xA0\x85\xCF\x98\x8A\xE4\xDB\xE2\xCD\xA6\x96\x83\x89"
        b"\xC0\x8B\x99\xE3\x9E\xD8\x9B\xB6\xD7\x90\xDC\xBE\xAD\x9D\x91\x66"
        b"\xB6\xA6\x9E\xBB\xC2\xC6\x9E\xB3\xE7\xE3\xE5\xD5\xAB\x63\x82\xA1"
        b"\x9C\xC4\x92\x9F\xD1\xD5\xA4",
        False,
    ),
    "wag103": (
        "Wallace And Gromit: S1E3",
        b"\x96\xCA\x99\xA0\x85\xCF\x98\x8A\xE4\xDB\xE2\xCD\xA6\x96\x83\x8A"
        b"\xC0\x8B\x99\xE3\x9E\xD8\x9B\xB6\xD7\x90\xDC\xBE\xAD\x9D\x91\x67"
        b"\xB6\xA6\x9E\xBB\xC2\xC6\x9E\xB3\xE7\xE3\xE5\xD5\xAB\x63\x82\xA2"
        b"\x9C\xC4\x92\x9F\xD1\xD5\xA4",
        False,
    ),
    "wag104": (
        "Wallace And Gromit: S1E4",
        b"\x96\xCA\x99\xA0\x85\xCF\x98\x8A\xE4\xDB\xE2\xCD\xA6\x96\x83\x8B"
        b"\xC0\x8B\x99\xE3\x9E\xD8\x9B\xB6\xD7\x90\xDC\xBE\xAD\x9D\x91\x68"
        b"\xB6\xA6\x9E\xBB\xC2\xC6\x9E\xB3\xE7\xE3\xE5\xD5\xAB\x63\x82\xA3"
        b"\x9C\xC4\x92\x9F\xD1\xD5\xA4",
        False,
    ),

    # Tales of Monkey Island (game numbers 24-30 in ttarchext)
    "monkeyisland101": (
        "Tales of Monkey Island S1E1",
        b"\x8C\xD8\x9B\x9F\x89\xE5\x7C\xB6\xDE\xCD\xE3\xC8\x63\x95\x84\xA4"
        b"\xD8\x98\x98\xDC\xB6\xBE\xA9\xDB\xC6\x8F\xD3\x86\x69\x9D\xAE\xA3"
        b"\xCD\xB0\x97\xC8\xAA\xD6\xA5\xCD\xE3\xD8\xA9\x9C\x68\x7F\xC1\xDD"
        b"\xB0\xC8\x9F\x7C\xE3\xDE\xA0",
        True,
    ),
    "monkeyisland102": (
        "Tales of Monkey Island S1E2",
        b"\x8C\xD8\x9B\x9F\x89\xE5\x7C\xB6\xDE\xCD\xE3\xC8\x63\x95\x85\xA4"
        b"\xD8\x98\x98\xDC\xB6\xBE\xA9\xDB\xC6\x8F\xD3\x86\x69\x9E\xAE\xA3"
        b"\xCD\xB0\x97\xC8\xAA\xD6\xA5\xCD\xE3\xD8\xA9\x9C\x69\x7F\xC1\xDD"
        b"\xB0\xC8\x9F\x7C\xE3\xDE\xA0",
        True,
    ),
    "monkeyisland103": (
        "Tales of Monkey Island S1E3",
        b"\x8C\xD8\x9B\x9F\x89\xE5\x7C\xB6\xDE\xCD\xE3\xC8\x63\x95\x86\xA4"
        b"\xD8\x98\x98\xDC\xB6\xBE\xA9\xDB\xC6\x8F\xD3\x86\x69\x9F\xAE\xA3"
        b"\xCD\xB0\x97\xC8\xAA\xD6\xA5\xCD\xE3\xD8\xA9\x9C\x6A\x7F\xC1\xDD"
        b"\xB0\xC8\x9F\x7C\xE3\xDE\xA0",
        True,
    ),
    "monkeyisland104": (
        "Tales of Monkey Island S1E4",
        b"\x8c\xd8\x9b\x9f\x89\xe5\x7c\xb6\xde\xcd\xe3\xc8\x63\x95\x87\xa4"
        b"\xd8\x98\x98\xdc\xb6\xbe\xa9\xdb\xc6\x8f\xd3\x86\x69\xa0\xae\xa3"
        b"\xcd\xb0\x97\xc8\xaa\xd6\xa5\xcd\xe3\xd8\xa9\x9c\x6b\x7f\xc1\xdd"
        b"\xb0\xc8\x9f\x7c\xe3\xde\xa0",
        True,
    ),
    "monkeyisland105": (
        "Tales of Monkey Island S1E5",
        b"\x8c\xd8\x9b\x9f\x89\xe5\x7c\xb6\xde\xcd\xe3\xc8\x63\x95\x88\xa4"
        b"\xd8\x98\x98\xdc\xb6\xbe\xa9\xdb\xc6\x8f\xd3\x86\x69\xa1\xae\xa3"
        b"\xcd\xb0\x97\xc8\xaa\xd6\xa5\xcd\xe3\xd8\xa9\x9c\x6c\x7f\xc1\xdd"
        b"\xb0\xc8\x9f\x7c\xe3\xde\xa0",
        True,
    ),

    "csideadly": (
        "CSI: Deadly Intent",
        b"\x82\xBC\x76\x69\x54\x9C\x86\x90\xD7\xDA\xEA\xA7\x85\xAE\x88\x87"
        b"\x99\x7D\x7A\xDC\xAB\xEA\x79\xC2\xAE\x56\x9F\x85\x8C\xB9\xC6\xA2"
        b"\xD4\x88\x85\x98\x96\x93\x69\xBF\xC2\xD9\xE6\xE1\x7A\x85\x9B\xA4"
        b"\x75\x93\x79\x80\xD5\xE0\xB4",
        False,
    ),
    "hector101": (
        "Hector: Badge of Carnage E1",
        b"\x87\xCE\x90\xA8\x93\xDE\x64\x73\xA3\xB4\xDA\xC7\xA6\xD4\xC5\x88"
        b"\x99\x5B\x75\xDC\xA0\xE9\xA5\xE1\x96\x51\xA0\x9D\x9E\xCF\xD5\xA3"
        b"\xD1\x76\x62\x80\xA9\xC8\x9C\xE0\xE4\xE6\xA9\x9C\x68\x7A\xB7\xD2"
        b"\xB9\xD2\x98\x64\xA0\xA3\x87",
        False,
    ),
    "hector102": (
        "Hector: Badge of Carnage E2",
        b"\x87\xCE\x90\xA8\x93\xDE\x64\x73\xA4\xB4\xDA\xC7\xA6\xD4\xC5\x88"
        b"\x99\x01\x75\xDC\xA0\xE9\xA5\xE1\x96\x51\xA1\x9D\x9E\xCF\xD5\xA3"
        b"\xD1\x76\x62\x81\xA9\xC8\x9C\xE0\xE4\xE6\xA9\x9C\x69\x7A\xB7\xD2"
        b"\xB9\xD2\x98\x64\xA0\xA4\x87",
        False,
    ),
    "hector103": (
        "Hector: Badge of Carnage E3",
        b"\x87\xCE\x90\xA8\x93\xDE\x64\x73\xA5\xB4\xDA\xC7\xA6\xD4\xC5\x88"
        b"\x99\x5D\x75\xDC\xA0\xE9\xA5\xE1\x96\x51\xA2\x9D\x9E\xCF\xD5\xA3"
        b"\xD1\x76\x62\x82\xA9\xC8\x9C\xE0\xE4\xE6\xA9\x9C\x6A\x7A\xB7\xD2"
        b"\xB9\xD2\x98\x64\xA0\xA5\x87",
        False,
    ),
    "sammax301": (
        "Sam and Max: S3E1",
        b"\x92\xCA\x9A\x81\x85\xE4\x66\x73\xA3\xBF\xD6\xD1\x7F\xC6\xCB\x8A"
        b"\x99\x5B\x80\xD8\xAA\xC2\x97\xE7\x98\x51\xA0\xA8\x9A\xD9\xAE\x95"
        b"\xD7\x78\x62\x80\xB4\xC4\xA6\xB9\xD6\xEC\xAB\x9C\x68\x85\xB3\xDC"
        b"\x92\xC4\x9E\x66\xA0\xA3\x92",
        False,
    ),
    "sammax302": (
        "Sam and Max: S3E2",
        b"\x92\xCA\x9A\x81\x85\xE4\x66\x73\xA4\xBF\xD6\xD1\x7F\xC6\xCB\x8A"
        b"\x99\x01\x80\xD8\xAA\xC2\x97\xE7\x98\x51\xA1\xA8\x9A\xD9\xAE\x95"
        b"\xD7\x78\x62\x81\xB4\xC4\xA6\xB9\xD6\xEC\xAB\x9C\x69\x85\xB3\xDC"
        b"\x92\xC4\x9E\x66\xA0\xA4\x92",
        False,
    ),
    "sammax303": (
        "Sam and Max: S3E3",
        b"\x92\xCA\x9A\x81\x85\xE4\x66\x73\xA5\xBF\xD6\xD1\x7F\xC6\xCB\x8A"
        b"\x99\x5D\x80\xD8\xAA\xC2\x97\xE7\x98\x51\xA2\xA8\x9A\xD9\xAE\x95"
        b"\xD7\x78\x62\x82\xB4\xC4\xA6\xB9\xD6\xEC\xAB\x9C\x6A\x85\xB3\xDC"
        b"\x92\xC4\x9E\x66\xA0\xA5\x92",
        False,
    ),
    "sammax304": (
        "Sam and Max: S3E4",
        b"\x92\xCA\x9A\x81\x85\xE4\x66\x73\xA6\xBF\xD6\xD1\x7F\xC6\xCB\x8A"
        b"\x99\x5E\x80\xD8\xAA\xC2\x97\xE7\x98\x51\xA3\xA8\x9A\xD9\xAE\x95"
        b"\xD7\x78\x62\x83\xB4\xC4\xA6\xB9\xD6\xEC\xAB\x9C\x6B\x85\xB3\xDC"
        b"\x92\xC4\x9E\x66\xA0\xA6\x92",
        False,
    ),
    "sammax305": (
        "Sam and Max: S3E5",
        b"\x92\xCA\x9A\x81\x85\xE4\x66\x73\xA7\xBF\xD6\xD1\x7F\xC6\xCB\x8A"
        b"\x99\x5F\x80\xD8\xAA\xC2\x97\xE7\x98\x51\xA4\xA8\x9A\xD9\xAE\x95"
        b"\xD7\x78\x62\x84\xB4\xC4\xA6\xB9\xD6\xEC\xAB\x9C\x6C\x85\xB3\xDC"
        b"\x92\xC4\x9E\x66\xA0\xA7\x92",
        False,
    ),
    "grickle101": (
        "Puzzle Agent 1",
        b"\x86\xDB\x96\x97\x8F\xD8\x98\x74\xA2\x9D\xBC\xD6\x9B\xC8\xBE\xC3"
        b"\xCE\x5B\x5D\xA8\x84\xE7\x9F\xD2\xD0\x8D\xD4\x86\x69\x9D\xA8\xA6"
        b"\xC8\xA8\x9D\xBB\xC6\x94\x69\x9D\xBC\xE6\xE1\xCF\xA2\x9E\xB7\xA0"
        b"\x75\x94\x6D\xA5\xD9\xD5\xAA",
        False,
    ),
    "csifatal": (
        "CSI: Fatal Conspiracy",
        b"\x82\xBC\x76\x6A\x54\x9C\x76\x96\xBB\xA2\xA5\x94\x75\xB8\x9C\x8D"
        b"\x99\x5A\x70\xCA\x86\xAB\x66\x9F\xA8\x74\xB8\x8B\x69\x9C\xA4\x87"
        b"\xA8\x7B\x62\x7F\xA4\xB6\x82\xA2\xA5\xA4\xBB\xBF\x80\x68\x82\x9F"
        b"\x88\xB6\x6F\x69\xA0\xA2\x82",
        False,
    ),
    "celebritypoker": (
        "Poker Night 1",
        b"\x82\xCE\x99\x99\x86\xDE\x9C\xB7\xEB\xBC\xE4\xCF\x97\xD7\x96\xBC"
        b"\xD5\x8F\x8F\xE9\xA6\xE9\xAF\xBF\xD4\x8C\xD4\xC7\x7C\xD1\xCD\x99"
        b"\xC1\xB7\x9B\xC3\xDA\xB3\xA8\xD7\xDA\xE6\xBB\xD1\xA3\x97\xB4\xE1"
        b"\xAE\xD7\x9F\x83\xDF\xDD\xA4",
        False,
    ),
    "bttf101": (
        "Back to the Future S1E1",
        b"\x81\xCA\x90\x9F\x78\xDB\x87\xAB\xD7\xB2\xEA\xD8\xA7\xD7\xB8\x88"
        b"\x99\x5B\x6F\xD8\xA0\xE0\x8A\xDE\xB9\x89\xD4\x9B\xAE\xE0\xD6\xA6"
        b"\xC4\x76\x62\x80\xA3\xC4\x9C\xD7\xC9\xE3\xCC\xD4\x9C\x78\xC7\xE3"
        b"\xBA\xD5\x8B\x64\xA0\xA3\x81",
        False,
    ),
    "bttf102": (
        "Back to the Future S1E2",
        b"\x81\xca\x90\x9f\x78\xdb\x87\xab\xd7\xb2\xea\xd8\xa7\xd7\xb8\x88"
        b"\x99\x01\x6f\xd8\xa0\xe0\x8a\xde\xb9\x89\xd4\x9b\xae\xe0\xd6\xa6"
        b"\xc4\x76\x62\x81\xa3\xc4\x9c\xd7\xc9\xe3\xcc\xd4\x9c\x78\xc7\xe3"
        b"\xba\xd5\x8b\x64\xa0\xa4\x81",
        False,
    ),
    "bttf103": (
        "Back to the Future S1E3",
        b"\x81\xCA\x90\x9F\x78\xDB\x87\xAB\xD7\xB2\xEA\xD8\xA7\xD7\xB8\x88"
        b"\x99\x5D\x6F\xD8\xA0\xE0\x8A\xDE\xB9\x89\xD4\x9B\xAE\xE0\xD6\xA6"
        b"\xC4\x76\x62\x82\xA3\xC4\x9C\xD7\xC9\xE3\xCC\xD4\x9C\x78\xC7\xE3"
        b"\xBA\xD5\x8B\x64\xA0\xA5\x81",
        False,
    ),
    "bttf104": (
        "Back to the Future S1E4",
        b"\x81\xCA\x90\x9F\x78\xDB\x87\xAB\xD7\xB2\xEA\xD8\xA7\xD7\xB8\x88"
        b"\x99\x5E\x6F\xD8\xA0\xE0\x8A\xDE\xB9\x89\xD4\x9B\xAE\xE0\xD6\xA6"
        b"\xC4\x76\x62\x83\xA3\xC4\x9C\xD7\xC9\xE3\xCC\xD4\x9C\x78\xC7\xE3"
        b"\xBA\xD5\x8B\x64\xA0\xA6\x81",
        False,
    ),
    "bttf105": (
        "Back to the Future S1E5",
        b"\x81\xCA\x90\x9F\x78\xDB\x87\xAB\xD7\xB2\xEA\xD8\xA7\xD7\xB8\x88"
        b"\x99\x5F\x6F\xD8\xA0\xE0\x8A\xDE\xB9\x89\xD4\x9B\xAE\xE0\xD6\xA6"
        b"\xC4\x76\x62\x84\xA3\xC4\x9C\xD7\xC9\xE3\xCC\xD4\x9C\x78\xC7\xE3"
        b"\xBA\xD5\x8B\x64\xA0\xA7\x81",
        False,
    ),
    "grickle102": (
        "Puzzle Agent 2",
        b"\x86\xDB\x96\x97\x8F\xD8\x98\x74\xA2\x9E\xBC\xD6\x9B\xC8\xBE\xC3"
        b"\xCE\x5B\x5D\xA9\x84\xE7\x9F\xD2\xD0\x8D\xD4\x86\x69\x9E\xA8\xA6"
        b"\xC8\xA8\x9D\xBB\xC6\x94\x69\x9E\xBC\xE6\xE1\xCF\xA2\x9E\xB7\xA0"
        b"\x75\x95\x6D\xA5\xD9\xD5\xAA",
        False,
    ),
    "lawandorder": (
        "Law and Order",
        b"\x8B\xCA\xA4\x75\x92\xD0\x82\xB5\xD6\xD1\xE7\x95\x62\x95\x9F\xB8"
        b"\xE0\x6B\x9B\xDB\x8C\xE7\x9A\xD4\xD7\x52\x9F\x85\x85\xCD\xD8\x75"
        b"\xCD\xA9\x81\xC1\xC5\xC8\xAB\x9D\xA5\xA4\xC4\xCD\xAE\x73\xC0\xD3"
        b"\x94\xD5\x8A\x98\xE2\xA3\x6F",
        False,
    ),

    # -- Modified Blowfish (v7+) keys --
    "jurassicpark": (
        "Jurassic Park",
        b"\x89\xde\x9f\x95\x97\xdf\x9c\xa6\xc2\xcd\xe7\xcf\x63\x95\x83\xa1"
        b"\xde\x9c\x8e\xea\xb0\xde\x99\xbf\xc6\x93\xda\x86\x69\x9c\xab\xa9"
        b"\xd1\xa6\xa5\xc2\xca\xc6\x89\xcd\xe7\xdf\xa9\x9c\x67\x7c\xc7\xe1"
        b"\xa6\xd6\x99\x9c\xd3\xc2\xa0",
        True,
    ),
    "TWD1": (
        "The Walking Dead: Season 1",
        b"\x96\xca\x99\x9f\x8d\xda\x9a\x87\xd7\xcd\xd9\x95\x62\x95\xaa\xb8"
        b"\xd5\x95\x96\xe5\xa4\xb9\x9b\xd0\xc9\x52\x9f\x85\x90\xcd\xcd\x9f"
        b"\xc8\xb3\x99\x93\xc6\xc4\x9d\x9d\xa5\xa4\xcf\xcd\xa3\x9d\xbb\xdd"
        b"\xac\xa7\x8b\x94\xd4\xa3\x6f",
        False,
    ),
    "celebritypoker2": (
        "Poker Night 2",
        b"\x82\xCE\x99\x99\x86\xDE\x9C\xB7\xEB\xBC\xE4\xCF\x97\xD7\x85\x9A"
        b"\xCE\x96\x92\xD9\xAF\xDE\xAA\xE8\xB5\x90\xDA\xBA\xAB\x9E\xA4\x99"
        b"\xCB\xAA\x94\xC1\xCA\xD7\xB2\xBC\xE4\xDF\xDD\xDE\x69\x75\xB7\xDB"
        b"\xAA\xC5\x98\x9C\xE4\xEB\x8F",
        False,
    ),
    "Fables": (
        "The Wolf Among Us S1",
        b"\x85\xca\x8f\xa0\x89\xdf\x64\x73\xa2\xb2\xd6\xc6\x9e\xca\xc6\x88"
        b"\x99\x5a\x73\xd8\x9f\xe1\x9b\xe2\x96\x51\x9f\x9b\x9a\xce\xcd\x99"
        b"\xd2\x76\x62\x7f\xa7\xc4\x9b\xd8\xda\xe7\xa9\x9c\x67\x78\xb3\xd1"
        b"\xb1\xc8\x99\x64\xa0\xa2\x85",
        True,
    ),
    "WD2": (
        "The Walking Dead: Season 2",
        b"\x96\xCA\x99\x9F\x8D\xDA\x9A\x87\xD7\xCD\xD9\x96\x62\x95\xAA\xB8"
        b"\xD5\x95\x96\xE5\xA4\xB9\x9B\xD0\xC9\x53\x9F\x85\x90\xCD\xCD\x9F"
        b"\xC8\xB3\x99\x93\xC6\xC4\x9D\x9E\xA5\xA4\xCF\xCD\xA3\x9D\xBB\xDD"
        b"\xAC\xA7\x8B\x94\xD4\xA4\x6F",
        True,
    ),
    "Borderlands": (
        "Tales from the Borderlands",
        b"\x81\xD8\x9F\x98\x89\xDE\x9F\xA4\xE0\xD0\xE8\x95\x62\x95\x95\xC6"
        b"\xDB\x8E\x92\xE9\xA9\xD6\xA4\xD3\xD8\x52\x9F\x85\x7B\xDB\xD3\x98"
        b"\xC4\xB7\x9E\xB0\xCF\xC7\xAC\x9D\xA5\xA4\xBA\xDB\xA9\x96\xB7\xE1"
        b"\xB1\xC4\x94\x97\xE3\xA3\x6F",
        True,
    ),
    "GameOfThrones": (
        "Game of Thrones",
        b"\x86\xCA\x9A\x99\x73\xD2\x87\xAB\xE4\xDB\xE3\xC9\xA5\x96\x83\x87"
        b"\xB0\x8B\x9A\xDC\x8C\xDB\x8A\xD7\xD7\x90\xDD\xBA\xAC\x9D\x91\x64"
        b"\xA6\xA6\x9F\xB4\xB0\xC9\x8D\xD4\xE7\xE3\xE6\xD1\xAA\x63\x82\x9F"
        b"\x8C\xC4\x93\x98\xBF\xD8\x93",
        True,
    ),
    "MCSM": (
        "Minecraft Story Mode: Season 1",
        b"\x8c\xd2\x9b\x99\x87\xde\x94\xa9\xe6\x9d\xa5\x94\x7f\xce\xc1\xbc"
        b"\xcc\x9c\x8e\xdd\xb1\xa6\x66\x9f\xb2\x8a\xdd\xba\x9c\xde\xc2\x9a"
        b"\xd3\x76\x62\x7f\xae\xcc\xa7\xd1\xd8\xe6\xd9\xd2\xab\x63\x82\x9f"
        b"\x92\xcc\x94\x98\xd3\xe4\xa0",
        True,
    ),
    "WDM": (
        "The Walking Dead: Michonne",
        b"\x96\xca\x99\x9f\x8d\xda\x9a\x87\xd7\xcd\xd9\xb1\x63\x95\x83\xae"
        b"\xca\x96\x98\xe0\xab\xdc\x7a\xd4\xc6\x85\xbc\x86\x69\x9c\xb8\x95"
        b"\xcb\xb0\x9b\xbd\xc8\xa7\x9e\xcd\xd9\xc1\xa9\x9c\x67\x89\xb3\xdb"
        b"\xb0\xcc\x94\x9a\xb4\xd7\xa0",
        True,
    ),
    "BAT": (
        "Batman: Season 1",
        b"\x81\xca\xa1\xa1\x85\xda\x64\x73\xa2\xae\xd6\xd8\x9f\xc6\xc1\x88"
        b"\x99\x5a\x6f\xd8\xb1\xe2\x97\xdd\x96\x51\x9f\x97\x9a\xe0\xce\x95"
        b"\xcd\x76\x62\x7f\xa3\xc4\xad\xd9\xd6\xe2\xa9\x9c\x67\x74\xb3\xe3"
        b"\xb2\xc4\x94\x64\xa0\xa2\x81",
        True,
    ),
    "WD3": (
        "The Walking Dead: Season 3",
        b"\x96\xca\x99\x9f\x8d\xda\x9a\x87\xd7\xcd\xd9\x97\x62\x95\xaa\xb8"
        b"\xd5\x95\x96\xe5\xa4\xb9\x9b\xd0\xc9\x54\x9f\x85\x90\xcd\xcd\x9f"
        b"\xc8\xb3\x99\x93\xc6\xc4\x9d\x9f\xa5\xa4\xcf\xcd\xa3\x9d\xbb\xdd"
        b"\xac\xa7\x8b\x94\xd4\xa5\x6f",
        True,
    ),
    "GoG": (
        "Marvel's Guardians of the Galaxy",
        b"\x86\xDE\x8E\xA6\x88\xD5\x94\xB1\xE5\x9D\xA5\x94\x79\xDA\xB4\xC9"
        b"\xCD\x93\x8E\xE5\xB0\xA6\x66\x9F\xAC\x96\xD0\xC7\x9D\xD5\xC2\xA2"
        b"\xD2\x76\x62\x7F\xA8\xD8\x9A\xDE\xD9\xDD\xD9\xDA\xAA\x63\x82\x9F"
        b"\x8C\xD8\x87\xA5\xD4\xDB\xA0",
        True,
    ),
    "MC2": (
        "Minecraft Story Mode: Season 2",
        b"\x8c\xd2\x9b\x99\x87\xde\x94\xa9\xe6\x9e\xa5\x94\x7f\xce\xc1\xbc"
        b"\xcc\x9c\x8e\xdd\xb1\xa7\x66\x9f\xb2\x8a\xdd\xba\x9c\xde\xc2\x9a"
        b"\xd3\x77\x62\x7f\xae\xcc\xa7\xd1\xd8\xe6\xd9\xd2\xab\x64\x82\x9f"
        b"\x92\xcc\x94\x98\xd3\xe4\xa0",
        True,
    ),
    "BAT2": (
        "Batman: Season 2",
        b"\x81\xCA\xA1\xA1\x85\xDA\x65\x73\xA2\xAE\xD6\xD8\x9F\xC6\xC1\x89"
        b"\x99\x5A\x6F\xD8\xB1\xE2\x97\xDD\x97\x51\x9F\x97\x9A\xE0\xCE\x95"
        b"\xCD\x77\x62\x7F\xA3\xC4\xAD\xD9\xD6\xE2\xAA\x9C\x67\x74\xB3\xE3"
        b"\xB2\xC4\x94\x65\xA0\xA2\x81",
        True,
    ),
    "WD4": (
        "The Walking Dead: Season 4",
        b"\x96\xCA\x99\x9F\x8D\xDA\x9A\x87\xD7\xCD\xD9\x98\x62\x95\xAA\xB8"
        b"\xD5\x95\x96\xE5\xA4\xB9\x9B\xD0\xC9\x55\x9F\x85\x90\xCD\xCD\x9F"
        b"\xC8\xB3\x99\x93\xC6\xC4\x9D\xA0\xA5\xA4\xCF\xCD\xA3\x9D\xBB\xDD"
        b"\xAC\xA7\x8B\x94\xD4\xA6\x6F",
        True,
    ),
    "WDC": (
        "The Walking Dead: Definitive Series",
        b"\x96\xCA\x99\x9F\x8D\xDA\x9A\x87\xD7\xCD\xD9\xBB\x93\xD1\xBE\xC0"
        b"\xD7\x91\x71\xDC\x9E\xD9\x8D\xD0\xD1\x8C\xD8\xC3\xA0\xB0\xC6\x95"
        b"\xC3\x9C\x93\xBB\xCC\xCC\xA7\xD3\xB9\xD9\xD9\xD0\x8E\x93\xBE\xDA"
        b"\xAE\xD1\x8D\x77\xD5\xD3\xA3",
        True,
    ),
    "SM1": (
        "Sam and Max: Remastered",
        b"\x92\xCA\x9A\x81\x85\xE4\x64\x73\xA2\xBF\xD6\xD1\x7F\xC6\xCB\x88"
        b"\x99\x5A\x80\xD8\xAA\xC2\x97\xE7\x96\x51\x9F\xA8\x9A\xD9\xAE\x95"
        b"\xD7\x76\x62\x7F\xB4\xC4\xA6\xB9\xD6\xEC\xA9\x9C\x67\x85\xB3\xDC"
        b"\x92\xC4\x9E\x64\xA0\xA2\x92",
        True,
    ),
}


def get_game_key(game_id: str) -> Optional[bytes]:
    """Return the Blowfish key for the given game id, or None."""
    entry = GAME_KEYS.get(game_id)
    if entry is not None:
        return entry[1]
    return None


def is_new_encryption(game_id: str) -> bool:
    """Return True if the game uses modified (v7) Blowfish."""
    entry = GAME_KEYS.get(game_id)
    if entry is not None:
        return entry[2]
    return False


# ---------------------------------------------------------------------------
# Key extraction from game executable
# ---------------------------------------------------------------------------

# The Blowfish key in Telltale executables is located right after the constant
# 0x3AB551CE (985887462), which is part of the ORIG_S initialization array.
_KEY_MARKER = 0x3AB551CE


def find_key_in_executable(exe_path: str, key_length: int = 55) -> Optional[bytes]:
    """Search a game executable for the Blowfish key.

    The key is located by finding the marker constant ``0x3AB551CE``
    (a value from the Blowfish ORIG_S array) and reading the *key_length*
    bytes immediately following it.

    Parameters
    ----------
    exe_path : str
        Path to the game executable (e.g. ``GameApp.exe``).
    key_length : int
        Length of the key to extract (default 55).

    Returns
    -------
    bytes or None
        The extracted key, or ``None`` if the marker was not found.
    """
    marker_bytes = struct.pack("<I", _KEY_MARKER)
    with open(exe_path, "rb") as f:
        data = f.read()
    idx = data.find(marker_bytes)
    if idx < 0:
        return None
    key_start = idx + 4
    if key_start + key_length > len(data):
        return None
    return data[key_start : key_start + key_length]


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class TtarchEntry:
    """A single file entry inside a TTARCH archive."""

    name: str
    offset: int        # Offset relative to the data-region start (files_offset)
    size: int
    directory: str = ""  # Directory prefix (if any)

    @property
    def full_path(self) -> str:
        if self.directory:
            return f"{self.directory}/{self.name}"
        return self.name


@dataclass
class _ArchiveHeader:
    """Internal representation of the parsed TTARCH header metadata."""

    version: int = 0
    encryption: int = 0
    files_mode: int = 0         # 0=uncompressed, 2=compressed blocks
    compressed_block_sizes: List[int] = field(default_factory=list)
    file_data_size: int = 0
    chunk_size: int = 65536     # Default chunk size in bytes (64 * 1024)
    files_offset: int = 0       # Absolute offset in the archive where file data starts
    use_new_encryption: bool = False
    directories: List[str] = field(default_factory=list)
    entries: List[TtarchEntry] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Binary helpers
# ---------------------------------------------------------------------------

def _read_int32(f: BinaryIO) -> int:
    return struct.unpack("<i", f.read(4))[0]


def _read_uint32(f: BinaryIO) -> int:
    return struct.unpack("<I", f.read(4))[0]


def _read_bytes(f: BinaryIO, n: int) -> bytes:
    data = f.read(n)
    if len(data) < n:
        raise EOFError(f"Expected {n} bytes, got {len(data)}")
    return data


# ---------------------------------------------------------------------------
# Decryption / decompression helpers
# ---------------------------------------------------------------------------

def _decrypt_block(data: bytes, key: bytes, use_new: bool = False) -> bytes:
    """Decrypt *data* using Blowfish ECB in 8-byte blocks.

    Trailing bytes that do not fill a complete 8-byte block are left
    unchanged, matching Telltale's behaviour.
    """
    if not key:
        return data
    bf = Blowfish(key, modified=use_new)
    return bf.decrypt(data)


def _decompress(data: bytes) -> bytes:
    """Decompress *data* using zlib (try raw deflate if full zlib fails)."""
    # Try standard zlib first
    try:
        return zlib.decompress(data)
    except zlib.error:
        pass
    # Try raw deflate (wbits=-15)
    try:
        return zlib.decompress(data, -15)
    except zlib.error:
        pass
    # Try with auto-detect (wbits=47 covers zlib, gzip, and raw)
    try:
        return zlib.decompress(data, 47)
    except zlib.error as exc:
        raise ValueError(f"Failed to decompress {len(data)} bytes") from exc


# ---------------------------------------------------------------------------
# Header parsing
# ---------------------------------------------------------------------------

def _parse_file_table(data: bytes) -> Tuple[List[str], List[TtarchEntry]]:
    """Parse the file entry table from decrypted/decompressed header bytes.

    Returns (directories, entries).
    """
    buf = io.BytesIO(data)
    directories: List[str] = []
    entries: List[TtarchEntry] = []

    dir_count = _read_int32(buf)
    for _ in range(dir_count):
        name_len = _read_int32(buf)
        name = _read_bytes(buf, name_len).rstrip(b"\x00").decode("ascii", errors="replace")
        directories.append(name)

    file_count = _read_int32(buf)
    for _ in range(file_count):
        name_len = _read_int32(buf)
        name = _read_bytes(buf, name_len).rstrip(b"\x00").decode("ascii", errors="replace")
        _zero = _read_int32(buf)   # always 0 (folder assignment)
        file_offset = _read_uint32(buf)
        file_size = _read_int32(buf)
        entries.append(TtarchEntry(
            name=name,
            offset=file_offset,
            size=file_size,
        ))

    return directories, entries


def _parse_header(f: BinaryIO, key: bytes, use_new: bool) -> _ArchiveHeader:
    """Parse the TTARCH archive header from an open file handle.

    The file position should be at offset 0 when called.
    """
    hdr = _ArchiveHeader()
    hdr.use_new_encryption = use_new

    first_u32 = _read_uint32(f)

    # Determine the version.  If the value is 0 or > 9, it is a legacy
    # (version 0) archive where the first uint32 is the header size.
    if first_u32 == 0 or first_u32 > 9:
        hdr.version = 0
        return _parse_v0(f, hdr, first_u32, key)

    hdr.version = first_u32

    if hdr.version <= 2:
        return _parse_v1_v2(f, hdr, key)
    elif hdr.version <= 6:
        return _parse_v3_v6(f, hdr, key)
    elif hdr.version == 7:
        return _parse_v7(f, hdr, key)
    elif hdr.version <= 9:
        return _parse_v8_v9(f, hdr, key)
    else:
        raise ValueError(f"Unsupported TTARCH version {hdr.version}")


def _parse_v0(
    f: BinaryIO, hdr: _ArchiveHeader, header_size: int, key: bytes
) -> _ArchiveHeader:
    """Parse a legacy (version 0) archive."""
    hdr.version = 0
    if header_size > 128:
        # Encrypted header
        raw_header = _read_bytes(f, header_size)
        table_data = _decrypt_block(raw_header, key, hdr.use_new_encryption)
    else:
        # Unencrypted -- the header_size value we read is actually the start
        # of the file table.  Seek back and read the file table.
        f.seek(0)
        # Read everything up to the end; the file table is followed by
        # files_offset and files_size.
        # We need to parse the file table first to know how large it is.
        # For simplicity, read a generous amount and let the parser stop.
        rest = f.read()
        table_data = rest
        # After the table, there should be uint32 files_offset + uint32 files_size.
        # We will handle this below.

    hdr.files_offset = f.tell()
    dirs, entries = _parse_file_table(table_data)
    hdr.directories = dirs
    hdr.entries = entries
    return hdr


def _parse_v1_v2(f: BinaryIO, hdr: _ArchiveHeader, key: bytes) -> _ArchiveHeader:
    """Parse versions 1-2."""
    hdr.encryption = _read_int32(f)
    _unknown = _read_int32(f)
    header_size = _read_int32(f)

    raw_header = _read_bytes(f, header_size)
    if hdr.encryption == 1:
        raw_header = _decrypt_block(raw_header, key, hdr.use_new_encryption)

    hdr.files_offset = f.tell()
    dirs, entries = _parse_file_table(raw_header)
    hdr.directories = dirs
    hdr.entries = entries
    return hdr


def _parse_v3_v6(f: BinaryIO, hdr: _ArchiveHeader, key: bytes) -> _ArchiveHeader:
    """Parse versions 3-6."""
    hdr.encryption = _read_int32(f)
    _unknown = _read_int32(f)
    hdr.files_mode = _read_int32(f)

    chunk_count = _read_int32(f)
    hdr.compressed_block_sizes = [_read_int32(f) for _ in range(chunk_count)]
    hdr.file_data_size = _read_uint32(f)

    if hdr.version >= 4:
        _priority = _read_int32(f)
        _priority2 = _read_int32(f)

    header_size = _read_int32(f)
    raw_header = _read_bytes(f, header_size)
    if hdr.encryption == 1:
        raw_header = _decrypt_block(raw_header, key, hdr.use_new_encryption)

    hdr.files_offset = f.tell()
    dirs, entries = _parse_file_table(raw_header)
    hdr.directories = dirs
    hdr.entries = entries
    return hdr


def _parse_v7(f: BinaryIO, hdr: _ArchiveHeader, key: bytes) -> _ArchiveHeader:
    """Parse version 7."""
    hdr.encryption = _read_int32(f)
    _unknown = _read_int32(f)
    hdr.files_mode = _read_int32(f)

    chunk_count = _read_int32(f)
    hdr.compressed_block_sizes = [_read_int32(f) for _ in range(chunk_count)]
    hdr.file_data_size = _read_uint32(f)

    _priority = _read_int32(f)
    _priority2 = _read_int32(f)
    xmode1 = _read_int32(f)
    _xmode2 = _read_int32(f)
    chunk_size_kb = _read_int32(f)
    hdr.chunk_size = chunk_size_kb * 1024 if chunk_size_kb > 0 else 65536

    header_size = _read_int32(f)  # uncompressed header size
    if header_size == 0:
        # Workaround for some archives where headerSize is 0 and the
        # actual size follows.
        header_size = _read_int32(f)

    if hdr.files_mode >= 2:
        compressed_header_size = _read_int32(f)
        raw_header = _read_bytes(f, compressed_header_size)
        # For v7: decompress first, then decrypt (per TelltaleToolKit).
        raw_header = _decompress(raw_header)
    else:
        raw_header = _read_bytes(f, header_size)

    if hdr.encryption == 1:
        raw_header = _decrypt_block(raw_header, key, hdr.use_new_encryption)

    hdr.files_offset = f.tell()
    dirs, entries = _parse_file_table(raw_header)
    hdr.directories = dirs
    hdr.entries = entries
    return hdr


def _parse_v8_v9(f: BinaryIO, hdr: _ArchiveHeader, key: bytes) -> _ArchiveHeader:
    """Parse versions 8-9 (extensions of v7)."""
    hdr.encryption = _read_int32(f)
    _unknown = _read_int32(f)
    hdr.files_mode = _read_int32(f)

    chunk_count = _read_int32(f)
    hdr.compressed_block_sizes = [_read_int32(f) for _ in range(chunk_count)]
    hdr.file_data_size = _read_uint32(f)

    _priority = _read_int32(f)
    _priority2 = _read_int32(f)
    _xmode1 = _read_int32(f)
    _xmode2 = _read_int32(f)
    chunk_size_kb = _read_int32(f)
    hdr.chunk_size = chunk_size_kb * 1024 if chunk_size_kb > 0 else 65536

    # v8+ extra byte
    if hdr.version >= 8:
        _unknown_byte = f.read(1)

    # v9: CRC32
    if hdr.version >= 9 and hdr.files_mode >= 1:
        _crc32 = _read_uint32(f)

    header_size = _read_int32(f)
    if header_size == 0:
        header_size = _read_int32(f)

    if hdr.files_mode >= 2:
        compressed_header_size = _read_int32(f)
        raw_header = _read_bytes(f, compressed_header_size)
        raw_header = _decompress(raw_header)
    else:
        raw_header = _read_bytes(f, header_size)

    if hdr.encryption == 1:
        raw_header = _decrypt_block(raw_header, key, hdr.use_new_encryption)

    hdr.files_offset = f.tell()
    dirs, entries = _parse_file_table(raw_header)
    hdr.directories = dirs
    hdr.entries = entries
    return hdr


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class TtarchArchive:
    """Read-only accessor for TTARCH (v0-v9) archives.

    Parameters
    ----------
    filepath : str
        Path to the ``.ttarch`` archive file.
    game_key : bytes or str or None
        Blowfish key for decryption.  If a *str*, it is looked up in the
        built-in ``GAME_KEYS`` database.  If ``None``, no decryption is
        performed (works for unencrypted archives).
    """

    def __init__(
        self,
        filepath: str,
        game_key: Union[bytes, str, None] = None,
    ) -> None:
        self.filepath = filepath
        self._key: bytes = b""
        self._use_new: bool = False
        self._header: Optional[_ArchiveHeader] = None

        if isinstance(game_key, str):
            entry = GAME_KEYS.get(game_key)
            if entry is None:
                raise ValueError(
                    f"Unknown game key id {game_key!r}. "
                    f"Available: {', '.join(sorted(GAME_KEYS))}"
                )
            self._key = entry[1]
            self._use_new = entry[2]
        elif isinstance(game_key, bytes):
            self._key = game_key
        # else: no key

        self._parse()

    # -- internal -----------------------------------------------------------

    def _parse(self) -> None:
        with open(self.filepath, "rb") as f:
            self._header = _parse_header(f, self._key, self._use_new)
        log.info(
            "Parsed TTARCH v%d: %d files, files_offset=%d",
            self._header.version,
            len(self._header.entries),
            self._header.files_offset,
        )

    # -- public API ---------------------------------------------------------

    @property
    def version(self) -> int:
        """Archive format version (0-9)."""
        assert self._header is not None
        return self._header.version

    @property
    def directories(self) -> List[str]:
        """List of directory names declared in the archive."""
        assert self._header is not None
        return list(self._header.directories)

    def list_files(self) -> List[TtarchEntry]:
        """Return the list of file entries in the archive."""
        assert self._header is not None
        return list(self._header.entries)

    def extract_file(self, entry: TtarchEntry, output_path: str) -> None:
        """Extract a single file entry to *output_path*.

        Parameters
        ----------
        entry : TtarchEntry
            An entry obtained from :meth:`list_files`.
        output_path : str
            Destination file path.  Parent directories are created
            automatically.
        """
        assert self._header is not None
        hdr = self._header

        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

        with open(self.filepath, "rb") as f:
            data = self._read_entry_data(f, hdr, entry)

        with open(output_path, "wb") as out:
            out.write(data)

    def extract_all(self, output_dir: str) -> None:
        """Extract every file in the archive to *output_dir*.

        The directory structure from the archive is preserved.
        """
        assert self._header is not None
        hdr = self._header
        entries = hdr.entries

        with open(self.filepath, "rb") as f:
            for entry in entries:
                rel_path = entry.full_path
                dest = os.path.join(output_dir, rel_path)
                os.makedirs(os.path.dirname(os.path.abspath(dest)), exist_ok=True)
                data = self._read_entry_data(f, hdr, entry)
                with open(dest, "wb") as out:
                    out.write(data)
                log.debug("Extracted %s (%d bytes)", rel_path, len(data))

        log.info("Extracted %d files to %s", len(entries), output_dir)

    def read_file(self, entry: TtarchEntry) -> bytes:
        """Read a single file entry and return its contents as bytes.

        Parameters
        ----------
        entry : TtarchEntry
            An entry obtained from :meth:`list_files`.

        Returns
        -------
        bytes
            The raw file contents.
        """
        assert self._header is not None
        with open(self.filepath, "rb") as f:
            return self._read_entry_data(f, self._header, entry)

    # -- extraction helpers -------------------------------------------------

    def _read_entry_data(
        self, f: BinaryIO, hdr: _ArchiveHeader, entry: TtarchEntry
    ) -> bytes:
        """Read and return the raw data for a single entry."""
        if hdr.files_mode == 2 and hdr.compressed_block_sizes:
            return self._read_compressed(f, hdr, entry)
        else:
            return self._read_uncompressed(f, hdr, entry)

    def _read_uncompressed(
        self, f: BinaryIO, hdr: _ArchiveHeader, entry: TtarchEntry
    ) -> bytes:
        """Read an entry from an uncompressed archive."""
        abs_offset = hdr.files_offset + entry.offset
        f.seek(abs_offset)
        data = f.read(entry.size)
        if len(data) < entry.size:
            raise EOFError(
                f"Short read for {entry.name}: expected {entry.size}, "
                f"got {len(data)}"
            )
        return data

    def _read_compressed(
        self, f: BinaryIO, hdr: _ArchiveHeader, entry: TtarchEntry
    ) -> bytes:
        """Read an entry from a compressed (chunked) archive.

        Files may span across chunk boundaries.  We decompress the relevant
        chunks, concatenate, and extract the file's slice.
        """
        chunk_size = hdr.chunk_size
        block_sizes = hdr.compressed_block_sizes

        # Determine which decompressed chunks the file spans.
        block_start = entry.offset // chunk_size
        block_end = (entry.offset + entry.size - 1) // chunk_size if entry.size > 0 else block_start

        # Clamp to available blocks.
        block_end = min(block_end, len(block_sizes) - 1)
        if block_start >= len(block_sizes):
            raise ValueError(
                f"File {entry.name} starts at block {block_start} but "
                f"archive only has {len(block_sizes)} blocks"
            )

        # Compute the absolute offset of block_start in the compressed stream.
        compressed_offset = sum(block_sizes[:block_start])
        f.seek(hdr.files_offset + compressed_offset)

        decompressed = bytearray()
        for i in range(block_start, block_end + 1):
            comp_size = block_sizes[i]
            comp_data = f.read(comp_size)
            if len(comp_data) < comp_size:
                raise EOFError(
                    f"Short read for block {i}: expected {comp_size}, "
                    f"got {len(comp_data)}"
                )
            # Decrypt if needed.
            if hdr.encryption == 1:
                comp_data = _decrypt_block(comp_data, self._key, hdr.use_new_encryption)
            # Decompress.
            try:
                decompressed.extend(_decompress(comp_data))
            except ValueError:
                # If decompression fails, the block might not actually be
                # compressed (some archives mix modes).
                decompressed.extend(comp_data)

        # Slice out the file data from the decompressed buffer.
        local_offset = entry.offset - (chunk_size * block_start)
        return bytes(decompressed[local_offset : local_offset + entry.size])
