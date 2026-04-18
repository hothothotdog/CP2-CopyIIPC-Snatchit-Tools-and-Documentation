#!/usr/bin/env python3
"""
cp2_carve.py  —  File carver for SOFTWARE PIRATES .cp2 disk images

Scans the raw sector stream for known file-type signatures and extracts
them. Works entirely in-memory on the parsed CP2 sector dict — no .img
file is written.  FAT corruption is irrelevant; only the sector payload
bytes matter.

Usage:
    python cp2_carve.py disk.cp2
    python cp2_carve.py disk.cp2 --out ./recovered
    python cp2_carve.py disk.cp2 --window 65536    # bytes to pull per hit
    python cp2_carve.py disk.cp2 --min-size 64     # skip tiny hits
    python cp2_carve.py disk.cp2 --verbose
    python cp2_carve.py disk.cp2 --list-sigs        # show signature table

Requires cp2_to_img.py (load_cp2) in the same directory.
"""

import sys
import os
import struct
import argparse
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

# ── Pull load_cp2 from the sibling script ────────────────────────────────────

script_dir = Path(__file__).parent
sys.path.insert(0, str(script_dir))
try:
    from cp2_to_img import load_cp2          # standard name
except ModuleNotFoundError:
    from importlib.util import spec_from_file_location, module_from_spec
    _candidates = list(Path(script_dir).glob("*cp2_to_img*.py")) + \
                  list(Path(script_dir).glob("*cp2*.py"))
    _candidates = [p for p in _candidates if p.name != Path(__file__).name]
    if not _candidates:
        sys.exit("ERROR: Cannot find cp2_to_img.py — place it alongside this script.")
    _spec   = spec_from_file_location("cp2_to_img", _candidates[0])
    _module = module_from_spec(_spec)
    _spec.loader.exec_module(_module)
    load_cp2 = _module.load_cp2
    log.info("Imported load_cp2 from %s", _candidates[0].name)


# ── Signature table ───────────────────────────────────────────────────────────
# Each entry: (magic_bytes, offset_within_header, extension, description)
# offset_within_header: how far into a potential file the magic appears
# (almost always 0, but LHA stores its magic at offset 2)

SIGNATURES = [
    # ── Executables ──────────────────────────────────────────────────────────
    (b"MZ",                     0,  ".exe",  "DOS/Windows Executable"),
    (b"\xe9",                   0,  ".com",  "DOS COM (JMP rel16)"),   # common COM opening byte
    (b"\xeb",                   0,  ".com",  "DOS COM (JMP short)"),   # short-jump COM

    # ── Archives (very common on DOS era floppies) ────────────────────────────
    (b"PK\x03\x04",             0,  ".zip",  "ZIP archive"),
    (b"PK\x05\x06",             0,  ".zip",  "ZIP empty/end-of-central"),
    (b"\x60\xea",               0,  ".arj",  "ARJ archive"),
    (b"\x1a\x08",               0,  ".arc",  "ARC archive (type 8)"),
    (b"\x1a\x09",               0,  ".arc",  "ARC archive (type 9)"),
    (b"\x1a\x0a",               0,  ".arc",  "ARC archive (type 10)"),
    (b"Rar!",                   0,  ".rar",  "RAR archive"),
    (b"\x1f\x8b",               0,  ".gz",   "GZIP stream"),
    (b"BZh",                    0,  ".bz2",  "BZIP2 stream"),

    # LHA/LZH: magic is at byte offset 2 inside the header ("-lh0-" etc.)
    (b"-lh0-",                  2,  ".lzh",  "LHA/LZH level-0 (stored)"),
    (b"-lh1-",                  2,  ".lzh",  "LHA/LZH level-0 lh1"),
    (b"-lh4-",                  2,  ".lzh",  "LHA/LZH lh4"),
    (b"-lh5-",                  2,  ".lzh",  "LHA/LZH lh5"),
    (b"-lzs-",                  2,  ".lzh",  "LHA/LZH lzs"),
    (b"-lz4-",                  2,  ".lzh",  "LHA/LZH lz4"),

    # ── Images ───────────────────────────────────────────────────────────────
    (b"BM",                     0,  ".bmp",  "BMP bitmap"),
    (b"GIF87a",                 0,  ".gif",  "GIF 87a"),
    (b"GIF89a",                 0,  ".gif",  "GIF 89a"),
    (b"\xff\xd8\xff",           0,  ".jpg",  "JPEG image"),
    (b"\x89PNG\r\n\x1a\n",     0,  ".png",  "PNG image"),
    (b"RIFF",                   0,  ".wav",  "RIFF/WAV audio"),

    # ── Text / data ───────────────────────────────────────────────────────────
    # Plain text: we detect long ASCII runs separately (see scan_text)
    (b"\xff\xfe",               0,  ".txt",  "UTF-16 LE text (BOM)"),
    (b"\xfe\xff",               0,  ".txt",  "UTF-16 BE text (BOM)"),
    (b"\xef\xbb\xbf",          0,  ".txt",  "UTF-8 BOM text"),

    # ── DOS / PC specific ─────────────────────────────────────────────────────
    (b"\xeb\x3c\x90",           0,  ".img",  "FAT boot sector (EB 3C 90)"),
    (b"\xeb\x58\x90",           0,  ".img",  "FAT boot sector (EB 58 90)"),
    (b"MSDOS",                  3,  ".img",  "MS-DOS OEM ID in boot sector"),
]

# Minimum printable-ASCII run length to flag as a plain text file
TEXT_MIN_RUN = 64


# ── Disk linearisation ────────────────────────────────────────────────────────

def linearise(disk: dict, sectors_per_track: int = 9, num_heads: int = 2) -> bytes:
    """
    Flatten the (cyl, head) → {sec: bytes} dict into a single linear byte
    stream in CHS order (same ordering as build_img).  Geometry is auto-
    detected from the disk dict if possible, then snapped to standard values.
    """
    if not disk:
        raise ValueError("Empty disk dict")

    # Detect geometry from data
    detected_heads = max(h for _, h in disk) + 1
    detected_cyls  = max(c for c, _ in disk) + 1
    detected_spt   = max(
        (max(smap.keys()) for smap in disk.values() if smap),
        default=9
    )

    # Snap SPT to a known floppy format
    for std_spt in (8, 9, 15, 18, 36):
        if abs(detected_spt - std_spt) <= 1:
            detected_spt = std_spt
            break

    log.info("Linearising: %d cyls × %d heads × %d spt",
             detected_cyls, detected_heads, detected_spt)

    stream = bytearray()
    for cyl in range(detected_cyls):
        for head in range(detected_heads):
            smap = disk.get((cyl, head), {})
            for sec in range(1, detected_spt + 1):
                data = smap.get(sec, bytes(512))
                if len(data) < 512:
                    data = data.ljust(512, b"\x00")
                stream.extend(data[:512])

    return bytes(stream)


# ── EXE size heuristic ────────────────────────────────────────────────────────

def exe_size_hint(data: bytes) -> int | None:
    """
    Read the MZ header to estimate file size.
    Returns byte count or None if the header looks malformed.
    """
    if len(data) < 28 or data[:2] != b"MZ":
        return None
    e_cblp = struct.unpack_from("<H", data, 2)[0]   # bytes in last 512-byte page
    e_cp   = struct.unpack_from("<H", data, 4)[0]   # total 512-byte pages
    if e_cp == 0:
        return None
    size = (e_cp - 1) * 512 + (e_cblp if e_cblp else 512)
    # Sanity: must be at least a header and not absurdly large
    if size < 64 or size > 2 * 1024 * 1024:
        return None
    return size


# ── Plain-text detection ──────────────────────────────────────────────────────

def find_text_runs(stream: bytes, min_run: int = TEXT_MIN_RUN):
    """
    Yield (offset, length) for every run of printable ASCII + common
    whitespace that is at least min_run bytes long.
    """
    PRINTABLE = frozenset(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}
    i = 0
    n = len(stream)
    while i < n:
        if stream[i] in PRINTABLE:
            j = i + 1
            while j < n and stream[j] in PRINTABLE:
                j += 1
            run_len = j - i
            if run_len >= min_run:
                yield i, run_len
            i = j
        else:
            i += 1


# ── Main carver ───────────────────────────────────────────────────────────────

class Hit:
    __slots__ = ("offset", "ext", "desc", "data")

    def __init__(self, offset, ext, desc, data):
        self.offset = offset
        self.ext    = ext
        self.desc   = desc
        self.data   = data


def carve(stream: bytes, window: int, min_size: int) -> list:
    """
    Scan the linear byte stream for all known signatures.
    Returns a list of Hit objects.
    """
    hits    = []
    seen    = set()   # deduplicate overlapping hits at the same offset

    n = len(stream)

    # ── Signature scan ────────────────────────────────────────────────────────
    for magic, hdr_offset, ext, desc in SIGNATURES:
        mlen  = len(magic)
        start = 0
        while True:
            pos = stream.find(magic, start)
            if pos < 0:
                break
            start = pos + 1

            file_start = pos - hdr_offset
            if file_start < 0:
                continue
            if (file_start, ext) in seen:
                continue
            seen.add((file_start, ext))

            # For EXE files, try to use the MZ header to get the real size
            extract_len = window
            if ext == ".exe":
                hint = exe_size_hint(stream[file_start:file_start + 512])
                if hint:
                    extract_len = min(hint + 512, window)   # +512 for overlays

            raw = stream[file_start: file_start + extract_len]

            if len(raw) < min_size:
                log.debug("  skip %s @0x%X: too small (%d < %d)",
                          ext, file_start, len(raw), min_size)
                continue

            hits.append(Hit(file_start, ext, desc, raw))

    # ── Plain-text scan ───────────────────────────────────────────────────────
    for offset, length in find_text_runs(stream, TEXT_MIN_RUN):
        key = (offset, ".txt")
        if key in seen:
            continue
        seen.add(key)
        raw = stream[offset: offset + min(length, window)]
        if len(raw) >= min_size:
            hits.append(Hit(offset, ".txt", "Plain ASCII text run", raw))

    # Sort by file offset
    hits.sort(key=lambda h: h.offset)
    return hits


# ── Output ────────────────────────────────────────────────────────────────────

def save_hits(hits: list, out_dir: str) -> int:
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    saved = 0
    ext_counts = {}

    for hit in hits:
        n = ext_counts.get(hit.ext, 0)
        ext_counts[hit.ext] = n + 1
        sector = hit.offset // 512
        fname  = f"carved_{sector:05d}_hit{n:03d}{hit.ext}"
        fpath  = os.path.join(out_dir, fname)

        with open(fpath, "wb") as f:
            f.write(hit.data)

        log.info("  [0x%07X / sector %5d]  %-8s  %d bytes  ← %s",
                 hit.offset, sector, hit.ext, len(hit.data), hit.desc)
        saved += 1

    return saved


# ── CLI ───────────────────────────────────────────────────────────────────────

def list_signatures():
    print(f"\n{'Magic (hex)':<28} {'Offset':>6}  {'Ext':<8}  Description")
    print("-" * 70)
    for magic, hdr_off, ext, desc in SIGNATURES:
        hex_magic = magic.hex(" ") if len(magic) <= 8 else magic.hex(" ")[:23] + "…"
        print(f"  {hex_magic:<26} {hdr_off:>6}  {ext:<8}  {desc}")
    print(f"\n  + plain ASCII runs ≥ {TEXT_MIN_RUN} bytes → .txt")
    print()


def main():
    ap = argparse.ArgumentParser(
        description="Carve files from a SOFTWARE PIRATES .cp2 disk image"
    )
    ap.add_argument("source", nargs="?",
                    help=".cp2 file to carve")
    ap.add_argument("--out", "-o",
                    default="./carved",
                    help="Output directory for recovered files (default: ./carved)")
    ap.add_argument("--window", "-w",
                    type=int, default=65536,
                    help="Bytes to extract per hit (default: 65536 = 64 KB)")
    ap.add_argument("--min-size", "-m",
                    type=int, default=64,
                    help="Minimum file size in bytes to save (default: 64)")
    ap.add_argument("--list-sigs",
                    action="store_true",
                    help="Print the signature table and exit")
    ap.add_argument("--verbose", "-v",
                    action="store_true")
    args = ap.parse_args()

    if args.list_sigs:
        list_signatures()
        sys.exit(0)

    if not args.source:
        ap.error("source is required unless --list-sigs is used")

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # ── Load and linearise ────────────────────────────────────────────────────
    log.info("Reading  : %s", args.source)
    with open(args.source, "rb") as f:
        raw = f.read()

    disk   = load_cp2(raw)
    stream = linearise(disk)
    log.info("Stream   : %d bytes  (%d sectors)", len(stream), len(stream) // 512)

    # ── Carve ─────────────────────────────────────────────────────────────────
    log.info("Carving  : window=%d  min-size=%d", args.window, args.min_size)
    hits = carve(stream, args.window, args.min_size)

    if not hits:
        log.warning("No signatures found — disk may use an unsupported format")
        sys.exit(1)

    log.info("Found %d hit(s):", len(hits))

    # ── Save ──────────────────────────────────────────────────────────────────
    saved = save_hits(hits, args.out)
    log.info("Saved %d file(s) to: %s", saved, args.out)

    # ── Summary ───────────────────────────────────────────────────────────────
    by_type = {}
    for h in hits:
        by_type.setdefault(h.ext, []).append(h)
    print("\n── Summary ──────────────────────────────────────────────")
    for ext, group in sorted(by_type.items()):
        print(f"  {ext:<8} {len(group):>4}  hit(s)")
    print(f"  {'TOTAL':<8} {len(hits):>4}")
    print(f"\n  Output : {os.path.abspath(args.out)}")
    print()


if __name__ == "__main__":
    main()
