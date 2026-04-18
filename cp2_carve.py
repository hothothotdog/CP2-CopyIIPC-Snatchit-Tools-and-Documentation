#!/usr/bin/env python3
"""
cp2_carve.py  —  File carver for SOFTWARE PIRATES .cp2 disk images
Works directly on the parsed sector dict from cp2_to_img.py.
Does NOT require a healthy FAT — scans raw sector data for known file signatures.

Usage:
    python cp2_carve.py disk.cp2
    python cp2_carve.py disk.cp2 --out ./recovered
    python cp2_carve.py disk.cp2 --aggressive          # also carve .COM files (noisy)
    python cp2_carve.py disk.cp2 --min-size 64         # skip tiny hits (bytes)
    python cp2_carve.py disk.cp2 --max-size 512000     # cap carve size per file
    python cp2_carve.py disk.cp2 --probe               # show sector map + hits only

Requires cp2_to_img.py in the same directory (or on PYTHONPATH).
"""

import sys
import os
import argparse
import logging
import json
from pathlib import Path
from dataclasses import dataclass, field, asdict

try:
    from cp2_to_img import load_cp2
except ImportError:
    sys.exit("ERROR: cp2_to_img.py not found. Place it alongside this script.")

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)


# ── File signature table ──────────────────────────────────────────────────────
# (magic_bytes, extension, description)
# Ordered longest-magic-first so more-specific entries match before shorter ones.

SIGNATURES = [
    # ── Archives (very common on DOS software disks) ──────────────────────────
    (b'PK\x03\x04',            'zip',  'ZIP Archive'),
    (b'PK\x05\x06',            'zip',  'ZIP Archive (empty central dir)'),
    (b'Rar!\x1a\x07\x01\x00',  'rar',  'RAR v5+'),
    (b'Rar!\x1a\x07\x00',      'rar',  'RAR v1.5+'),
    (b'\x60\xea',              'arj',  'ARJ Archive'),
    (b'-lh0-',                 'lzh',  'LZH-0 (stored)'),
    (b'-lh5-',                 'lzh',  'LZH-5'),
    (b'-lh6-',                 'lzh',  'LZH-6'),
    (b'-lh7-',                 'lzh',  'LZH-7'),
    (b'LHA ',                  'lzh',  'LHA Archive'),
    (b'\x1f\xa0',              'lzh',  'LZH compressed'),
    (b'\x1f\x9d',              'lzh',  'LZH compressed (variant)'),
    (b'\x1a\x0b',              'arc',  'ARC Archive (v1)'),
    (b'\x1a\x08',              'arc',  'ARC Archive (v8)'),
    (b'\x1a\x09',              'arc',  'ARC Archive (v9)'),
    (b'\x1f\x8b',              'gz',   'GZIP'),
    (b'BZh',                   'bz2',  'BZIP2'),
    (b'\xfd7zXZ\x00',          'xz',   'XZ Stream'),
    # ── MS-compressed executables (common on install floppies) ────────────────
    (b'SZDD\x88\xf0\x27\x33',  'exe',  'MS-Compressed EXE (SZDD)'),
    (b'KWAJ\x88\xf0\x27\xd1',  'exe',  'MS-Compressed EXE (KWAJ)'),
    # ── DOS/Windows executables ───────────────────────────────────────────────
    (b'MZ',                    'exe',  'DOS/Windows Executable (MZ)'),
    (b'ZM',                    'exe',  'DOS Executable (ZM, reversed MZ)'),
    # ── Images ────────────────────────────────────────────────────────────────
    (b'\x89PNG\r\n\x1a\n',     'png',  'PNG Image'),
    (b'GIF89a',                'gif',  'GIF89a Image'),
    (b'GIF87a',                'gif',  'GIF87a Image'),
    (b'\xff\xd8\xff\xe0',      'jpg',  'JPEG/JFIF Image'),
    (b'\xff\xd8\xff\xe1',      'jpg',  'JPEG/Exif Image'),
    (b'\xff\xd8\xff\xdb',      'jpg',  'JPEG Image'),
    (b'BM',                    'bmp',  'Windows Bitmap'),
    (b'II*\x00',               'tif',  'TIFF (little-endian)'),
    (b'MM\x00*',               'tif',  'TIFF (big-endian)'),
    (b'\x0a\x05\x01',          'pcx',  'PCX Image (v5)'),
    (b'\x0a\x03\x01',          'pcx',  'PCX Image (v3)'),
    (b'\x0a\x02\x01',          'pcx',  'PCX Image (v2)'),
    # ── Audio ─────────────────────────────────────────────────────────────────
    (b'RIFF',                  'wav',  'RIFF container (WAV/AVI)'),
    (b'Creative Voice File',   'voc',  'Creative Labs VOC Audio'),
    (b'ID3',                   'mp3',  'MP3 with ID3 tag'),
    (b'\xff\xfb',              'mp3',  'MP3 frame (MPEG1 L3 CBR)'),
    (b'\xff\xf3',              'mp3',  'MP3 frame (MPEG2 L3)'),
    (b'OggS',                  'ogg',  'OGG container'),
    (b'FORM',                  'iff',  'IFF container (8SVX/AIFF)'),
    # ── Documents ─────────────────────────────────────────────────────────────
    (b'%PDF-',                 'pdf',  'PDF Document'),
    (b'{\\rtf',                'rtf',  'Rich Text Format'),
    (b'\xd0\xcf\x11\xe0',      'doc',  'MS Office OLE2 Document'),
    # ── DOS batch / script ────────────────────────────────────────────────────
    (b'@ECHO OFF',             'bat',  'DOS Batch File'),
    (b'@echo off',             'bat',  'DOS Batch File'),
    (b'@ECHO ON',              'bat',  'DOS Batch File'),
    # ── Boot sectors ─────────────────────────────────────────────────────────
    (b'\xeb\x3c\x90',          'boot', 'Boot sector (FAT16 BPB)'),
    (b'\xeb\x58\x90',          'boot', 'Boot sector (FAT32 BPB)'),
    (b'\xeb\x34\x90',          'boot', 'Boot sector (FAT12/16)'),
]

# Aggressive-mode COM heuristics — high false-positive rate, opt-in only
COM_SIGNATURES = [
    (b'\xe9',     'com', 'DOS COM (JMP near)'),
    (b'\xeb',     'com', 'DOS COM (JMP short)'),
    (b'\xb4',     'com', 'DOS COM (MOV AH,...)'),
    (b'\xcd\x21', 'com', 'DOS COM (INT 21h at byte 0)'),
]


def _build_index(sigs):
    """Build first-byte → [(magic, ext, desc), ...] lookup, longest-first."""
    idx = {}
    for magic, ext, desc in sigs:
        idx.setdefault(magic[0], []).append((magic, ext, desc))
    for b0 in idx:
        idx[b0].sort(key=lambda t: -len(t[0]))
    return idx

SIG_INDEX     = _build_index(SIGNATURES)
COM_SIG_INDEX = _build_index(COM_SIGNATURES)


# ── Geometry inference (mirrors build_img logic from cp2_to_img.py) ───────────

def infer_geometry(disk: dict) -> tuple:
    """Returns (max_cyl, num_heads, sectors_per_track) from the sector dict."""
    if not disk:
        raise ValueError("Empty disk dict — nothing parsed from CP2")

    num_heads = max(h for _, h in disk) + 1

    sec_counts = [max(smap.keys()) for smap in disk.values() if smap]
    spt        = max(set(sec_counts), key=sec_counts.count)

    all_cyls = sorted(set(c for c, _ in disk))
    true_max_cyl = 0
    for cyl in all_cyls:
        if all(len(disk.get((cyl, h), {})) >= spt for h in range(num_heads)):
            true_max_cyl = cyl
    max_cyl = true_max_cyl + 1

    for std in [40, 80]:
        if abs(max_cyl - std) <= 2 and max_cyl <= std:
            log.info("Snapping geometry to %d cylinders", std)
            max_cyl = std
            break

    return max_cyl, num_heads, spt


# ── Flat LBA view ─────────────────────────────────────────────────────────────

def build_lba_map(disk: dict, max_cyl: int, num_heads: int, spt: int) -> dict:
    """
    Build LBA → bytes mapping using standard CHS→LBA formula:
        lba = (cyl * num_heads + head) * spt + (sec - 1)

    Missing sectors map to None (distinguishable from stored zero sectors).
    """
    lba_map = {}
    for cyl in range(max_cyl):
        for head in range(num_heads):
            smap = disk.get((cyl, head), {})
            for sec in range(1, spt + 1):
                lba = (cyl * num_heads + head) * spt + (sec - 1)
                lba_map[lba] = smap.get(sec)
    return lba_map


# ── Carve result ──────────────────────────────────────────────────────────────

@dataclass
class CarvedFile:
    index:        int
    ext:          str
    description:  str
    start_lba:    int
    end_lba:      int
    sector_count: int
    byte_size:    int
    truncated:    bool   # hit --max-size cap
    zero_stopped: bool   # stopped on all-zero sector
    data:         bytes  = field(repr=False, default=b'')

    @property
    def filename(self) -> str:
        return f"carved_{self.index:04d}.{self.ext}"


# ── Core carver ───────────────────────────────────────────────────────────────

ZERO_SECTOR = bytes(512)

def scan_and_carve(
    lba_map:    dict,
    total_lbas: int,
    aggressive: bool = False,
    min_size:   int  = 16,
    max_size:   int  = 0,
) -> list:
    """
    Single forward pass over all LBAs.

    On a magic-byte hit: greedily collect contiguous sectors into one file.

    Stop conditions:
      1. Sector is missing (None) from parsed CP2 data
      2. Sector is all-zeros (unallocated gap)
      3. Sector starts a NEW signature hit (next file begins here)
      4. --max-size cap reached
      5. End of disk
    """
    sig_idx = dict(SIG_INDEX)
    if aggressive:
        for b0, entries in COM_SIG_INDEX.items():
            sig_idx.setdefault(b0, []).extend(entries)
        log.warning("Aggressive mode ON — COM heuristics active (expect false positives)")

    max_sectors = (max_size // 512) if max_size else 0
    claimed     = set()   # LBAs already consumed by a previous carve
    results     = []
    idx         = 0

    for lba in range(total_lbas):
        if lba in claimed:
            continue

        sector_data = lba_map.get(lba)
        if sector_data is None or sector_data == ZERO_SECTOR:
            continue

        # Pre-filter: check first byte against index
        candidates = sig_idx.get(sector_data[0])
        if not candidates:
            continue

        # Find best (longest) matching signature
        matched = None
        for magic, ext, desc in candidates:
            if sector_data[:len(magic)] == magic:
                matched = (magic, ext, desc)
                break
        if matched is None:
            continue

        _, match_ext, match_desc = matched

        # ── Greedy collection ─────────────────────────────────────────────────
        collected    = bytearray()
        cur          = lba
        truncated    = False
        zero_stopped = False

        while cur < total_lbas:
            chunk = lba_map.get(cur)

            # Stop: sector absent from CP2 parse
            if chunk is None:
                break

            # Stop: zero sector (treat as unallocated), but not the first sector
            if cur != lba and chunk == ZERO_SECTOR:
                zero_stopped = True
                break

            # Stop: new signature starts here (but not at the anchor LBA)
            if cur != lba:
                new_cands = sig_idx.get(chunk[0], [])
                if any(chunk[:len(m)] == m for m, _, _ in new_cands):
                    break

            collected.extend(chunk)
            claimed.add(cur)
            cur += 1

            # Stop: max-size cap
            if max_sectors and (cur - lba) >= max_sectors:
                truncated = True
                break

        data = bytes(collected)
        if len(data) < min_size:
            log.debug("LBA %d: hit below min_size (%d bytes) — skipping", lba, len(data))
            continue

        cf = CarvedFile(
            index        = idx,
            ext          = match_ext,
            description  = match_desc,
            start_lba    = lba,
            end_lba      = cur - 1,
            sector_count = cur - lba,
            byte_size    = len(data),
            truncated    = truncated,
            zero_stopped = zero_stopped,
            data         = data,
        )
        results.append(cf)
        flags = ("  [TRUNCATED]" if truncated else "") + ("  [ZERO-STOP]" if zero_stopped else "")
        log.info("  [%04d] LBA %-5d  %-6s  %7d bytes  %s%s",
                 idx, lba, match_ext, len(data), match_desc, flags)
        idx += 1

    return results


# ── Probe / sector map ────────────────────────────────────────────────────────

def probe_sectors(lba_map: dict, total_lbas: int, sig_idx: dict) -> None:
    """Print a compact visual sector map, collapsing empty runs."""
    print(f"\nSector map  ({total_lbas} LBAs × 512 bytes)\n")
    print(f"  {'LBA':<7} {'Type':<8} First 16 bytes (hex)")
    print(f"  {'─'*7} {'─'*8} {'─'*47}")

    empty_run = 0
    for lba in range(total_lbas):
        data = lba_map.get(lba)
        empty = data is None or data == ZERO_SECTOR
        if empty:
            empty_run += 1
            continue

        if empty_run:
            print(f"  ... {empty_run} empty/missing sector(s) ...")
            empty_run = 0

        label = "data"
        cands = sig_idx.get(data[0], [])
        for magic, ext, _ in cands:
            if data[:len(magic)] == magic:
                label = ext.upper()
                break

        print(f"  {lba:<7} {label:<8} {data[:16].hex(' ')}")

    if empty_run:
        print(f"  ... {empty_run} empty/missing sector(s) ...")
    print()


# ── Output ────────────────────────────────────────────────────────────────────

def write_results(results: list, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    manifest = []
    for cf in results:
        (out_dir / cf.filename).write_bytes(cf.data)
        entry = {k: v for k, v in asdict(cf).items() if k != 'data'}
        entry['filename'] = cf.filename
        manifest.append(entry)

    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    lines = [
        "cp2_carve — recovery summary",
        "─" * 65,
        f"Total files carved : {len(results)}",
        f"Output directory   : {out_dir.resolve()}",
        "─" * 65,
        f"{'#':<6} {'LBA':<7} {'Secs':<6} {'Bytes':<10} {'Ext':<7} Description",
        "─" * 65,
    ]
    for cf in results:
        flags = ""
        if cf.truncated:    flags += " [TRUNC]"
        if cf.zero_stopped: flags += " [ZERO-STOP]"
        lines.append(
            f"{cf.index:<6} {cf.start_lba:<7} {cf.sector_count:<6} "
            f"{cf.byte_size:<10} {cf.ext:<7} {cf.description}{flags}"
        )
    (out_dir / "summary.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    log.info("Wrote %d file(s) → %s", len(results), out_dir)
    log.info("Manifest : %s/manifest.json", out_dir)
    log.info("Summary  : %s/summary.txt",   out_dir)


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="Carve files from a SOFTWARE PIRATES .cp2 image (no FAT required)"
    )
    ap.add_argument("source",
                    help=".cp2 file to carve")
    ap.add_argument("--out",        default="./carved", metavar="DIR",
                    help="Output directory (default: ./carved)")
    ap.add_argument("--aggressive", action="store_true",
                    help="Also attempt .COM recovery (many false positives)")
    ap.add_argument("--min-size",   type=int, default=16, metavar="BYTES",
                    help="Discard hits smaller than N bytes (default: 16)")
    ap.add_argument("--max-size",   type=int, default=0,  metavar="BYTES",
                    help="Cap each carved file at N bytes, 0=unlimited (default: 0)")
    ap.add_argument("--probe",      action="store_true",
                    help="Print sector map and signature hits only — no files written")
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not os.path.isfile(args.source):
        log.error("Not a file: %r", args.source)
        sys.exit(1)

    log.info("Reading  : %s", args.source)
    with open(args.source, "rb") as f:
        raw = f.read()

    # Parse CP2
    try:
        disk = load_cp2(raw)
    except Exception as e:
        log.error("CP2 parse failed: %s", e)
        sys.exit(1)

    # Infer geometry
    try:
        max_cyl, num_heads, spt = infer_geometry(disk)
    except ValueError as e:
        log.error("Geometry inference failed: %s", e)
        sys.exit(1)

    total_lbas = max_cyl * num_heads * spt
    log.info("Geometry : %d cyl × %d head × %d sec/trk = %d LBAs  (%d KB)",
             max_cyl, num_heads, spt, total_lbas, total_lbas * 512 // 1024)

    # Build flat LBA map
    lba_map = build_lba_map(disk, max_cyl, num_heads, spt)
    present = sum(1 for v in lba_map.values() if v is not None and v != ZERO_SECTOR)
    log.info("Sectors  : %d with data, %d empty/missing",
             present, total_lbas - present)

    # Build combined signature index for probe/carve
    sig_idx = dict(SIG_INDEX)
    if args.aggressive:
        for b0, entries in COM_SIG_INDEX.items():
            sig_idx.setdefault(b0, []).extend(entries)

    if args.probe:
        probe_sectors(lba_map, total_lbas, sig_idx)
        return

    # Carve
    log.info("Carving ...")
    results = scan_and_carve(
        lba_map    = lba_map,
        total_lbas = total_lbas,
        aggressive = args.aggressive,
        min_size   = args.min_size,
        max_size   = args.max_size,
    )

    if not results:
        log.warning("No files found. Try --aggressive or inspect with --probe.")
        sys.exit(0)

    log.info("Found %d candidate file(s)", len(results))
    write_results(results, Path(args.out))
    log.info("Done.")


if __name__ == "__main__":
    main()
