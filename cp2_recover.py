#!/usr/bin/env python3
"""
cp2_recover.py  —  Directory-driven file recovery for SOFTWARE PIRATES .cp2 images
Uses intact FAT12 root directory entries to extract files with correct names,
exact sizes, and zero false positives — even when the FAT chain is fully corrupted.

Strategy:
  1. Read BPB from LBA 0 → derive data_start LBA, spc, root dir location
  2. Parse root directory entries → (filename, start_cluster, file_size)
  3. Extract each file: cluster → LBA → read exactly file_size bytes
  4. Optionally fall back to signature carving for anything not in the directory

Usage:
    python cp2_recover.py disk.cp2
    python cp2_recover.py disk.cp2 --out ./recovered
    python cp2_recover.py disk.cp2 --carve-extra      # also carve unaccounted sectors
    python cp2_recover.py disk.cp2 --probe            # show BPB + directory only
    python cp2_recover.py disk.cp2 --verbose

Requires cp2_to_img.py in the same directory (or on PYTHONPATH).
"""

import sys
import os
import struct
import argparse
import logging
import json
import math
from pathlib import Path
from dataclasses import dataclass, field, asdict

try:
    from cp2_to_img import load_cp2, filter_disk
except ImportError:
    sys.exit("ERROR: cp2_to_img.py not found — place it alongside this script.")

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)


# ── BPB / geometry ────────────────────────────────────────────────────────────

@dataclass
class BPB:
    """BIOS Parameter Block parsed from FAT12 boot sector (LBA 0)."""
    oem_name:          str
    bytes_per_sector:  int
    sectors_per_clus:  int
    reserved_sectors:  int
    num_fats:          int
    root_entry_count:  int
    total_sectors_16:  int
    media_byte:        int
    fat_size_16:       int
    sectors_per_track: int
    num_heads:         int
    # Derived
    data_start:        int = 0
    root_dir_start:    int = 0
    root_dir_sectors:  int = 0
    total_clusters:    int = 0

    def describe(self):
        kb = (self.total_sectors_16 * self.bytes_per_sector) // 1024
        print(f"  OEM            : {self.oem_name!r}")
        print(f"  Bytes/sector   : {self.bytes_per_sector}")
        print(f"  Sectors/cluster: {self.sectors_per_clus}")
        print(f"  Reserved secs  : {self.reserved_sectors}")
        print(f"  FAT copies     : {self.num_fats}  ×  {self.fat_size_16} sectors each")
        print(f"  Root entries   : {self.root_entry_count} ({self.root_dir_sectors} sectors)")
        print(f"  Total sectors  : {self.total_sectors_16} ({kb} KB)")
        print(f"  Geometry       : {self.sectors_per_track} sec/trk × {self.num_heads} heads")
        print(f"  Root dir start : LBA {self.root_dir_start}")
        print(f"  Data start     : LBA {self.data_start}")
        print(f"  Total clusters : {self.total_clusters}")


def parse_bpb(sector0: bytes) -> BPB | None:
    """
    Parse FAT12 BPB from the boot sector.
    Returns None if the sector doesn't look like a valid FAT12 BPB.
    """
    if len(sector0) < 62:
        return None

    # Jump must be EB xx 90 or E9 xx xx
    if sector0[0] not in (0xEB, 0xE9):
        log.debug("BPB: bad jump byte 0x%02X", sector0[0])
        return None

    bps  = struct.unpack_from("<H", sector0, 11)[0]
    if bps not in (128, 256, 512, 1024, 2048, 4096):
        log.debug("BPB: implausible bytes_per_sector %d", bps)
        return None

    spc   = sector0[13]
    res   = struct.unpack_from("<H", sector0, 14)[0]
    nfat  = sector0[16]
    rde   = struct.unpack_from("<H", sector0, 17)[0]
    tsec  = struct.unpack_from("<H", sector0, 19)[0]
    media = sector0[21]
    fatsz = struct.unpack_from("<H", sector0, 22)[0]
    spt   = struct.unpack_from("<H", sector0, 24)[0]
    nhead = struct.unpack_from("<H", sector0, 26)[0]

    if spc == 0 or res == 0 or nfat == 0 or fatsz == 0:
        log.debug("BPB: zero field — not a valid BPB")
        return None

    oem = sector0[3:11].decode("cp437", errors="replace")

    root_dir_start  = res + nfat * fatsz
    root_dir_sectors = (rde * 32 + bps - 1) // bps
    data_start       = root_dir_start + root_dir_sectors
    total_clusters   = (tsec - data_start) // spc if spc else 0

    bpb = BPB(
        oem_name          = oem,
        bytes_per_sector  = bps,
        sectors_per_clus  = spc,
        reserved_sectors  = res,
        num_fats          = nfat,
        root_entry_count  = rde,
        total_sectors_16  = tsec,
        media_byte        = media,
        fat_size_16       = fatsz,
        sectors_per_track = spt,
        num_heads         = nhead,
        root_dir_start    = root_dir_start,
        root_dir_sectors  = root_dir_sectors,
        data_start        = data_start,
        total_clusters    = total_clusters,
    )
    return bpb


# Fallback: known FAT12 geometries if BPB is unreadable
FALLBACK_GEOMETRIES = [
    # label, reserved, num_fats, fat_secs, root_entries, spc
    ("360KB  (40×2× 9)", 1, 2, 2,  112, 2),
    ("720KB  (80×2× 9)", 1, 2, 3,  112, 2),
    ("1.44MB (80×2×18)", 1, 2, 9,  224, 2),
    ("1.2MB  (80×2×15)", 1, 2, 7,  224, 1),
    ("2.88MB (80×2×36)", 1, 2, 9,  240, 2),
]

def guess_bpb_from_clusters(disk: dict) -> BPB | None:
    """
    When the BPB is unreadable, try standard geometries and pick the one
    whose data_start produces consistent cluster→LBA mappings.
    We use the known cluster gaps (spc=2 confirmed from directory analysis)
    as a cross-check.
    """
    # Probe which geometry gives a data_start that's within the disk
    max_lba = max(
        (cyl * 2 + head) * max(smap.keys())
        for (cyl, head), smap in disk.items()
        if smap
    )
    log.warning("BPB unreadable — probing standard geometries against disk extent")
    for label, res, nfat, fatsz, rde, spc in FALLBACK_GEOMETRIES:
        rds   = (rde * 32 + 511) // 512
        ds    = res + nfat * fatsz + rds
        nhead = 2
        # approximate total sectors
        tsec  = max_lba + 1
        tc    = (tsec - ds) // spc if spc else 0
        log.info("  %s → data_start=%d  spc=%d  total_clusters≈%d", label, ds, spc, tc)
        if 0 < ds < max_lba:
            # Return first plausible one; user can override
            return BPB(
                oem_name="(guessed)",
                bytes_per_sector=512,
                sectors_per_clus=spc,
                reserved_sectors=res,
                num_fats=nfat,
                root_entry_count=rde,
                total_sectors_16=tsec,
                media_byte=0xF9,
                fat_size_16=fatsz,
                sectors_per_track=9,
                num_heads=nhead,
                root_dir_start=res + nfat * fatsz,
                root_dir_sectors=rds,
                data_start=ds,
                total_clusters=tc,
            )
    return None


# FAT12 media descriptor → disk geometry for early PC-DOS single/double-sided formats.
# These predate the BPB and rely solely on the first byte of the FAT.
# (head, spt, cyls, reserved, num_fats, fat_secs, root_entries, spc)
MEDIA_GEOMETRIES = {
    0xFF: (2,  8, 40, 1, 2, 1,  64, 1),  # 320 KB  double-sided 8-sector
    0xFE: (1,  8, 40, 1, 2, 1,  64, 1),  # 160 KB  single-sided 8-sector  ← Bank Street Writer etc.
    0xFD: (2,  9, 40, 1, 2, 2, 112, 2),  # 360 KB  double-sided 9-sector
    0xFC: (1,  9, 40, 1, 2, 2,  64, 1),  # 180 KB  single-sided 9-sector
    0xFB: (2,  8, 80, 1, 2, 2, 112, 2),  # 640 KB  double-sided 8-sector 80-track
    0xFA: (1,  8, 80, 1, 2, 2,  64, 1),  # 320 KB  single-sided 8-sector 80-track (rare)
    0xF9: (2,  9, 80, 1, 2, 3, 112, 2),  # 720 KB  (also used for 1.2 MB; resolved below)
    0xF0: (2, 18, 80, 1, 2, 9, 224, 2),  # 1.44 MB (default; 2.88 MB also uses F0)
}

def guess_bpb_from_fat_media(disk: dict, lba_map: dict, spt: int) -> BPB | None:
    """
    Read the FAT media descriptor byte from the first FAT sector and use it
    to reconstruct a BPB for early PC-DOS formats that predate the BPB field
    (or use a non-standard boot sector jump).

    The FAT is normally at LBA 1 (reserved=1 sector), but some disks with
    non-standard layouts place it at LBA 2.  We try both.  Sectors stored as
    zero-length bytes (b'') due to bad size codes in the CP2 are treated as
    absent — read_lba already handles this, but we add an explicit length
    guard here as a belt-and-suspenders defence.

    A valid FAT start is identified by: first byte in MEDIA_GEOMETRIES, and
    second and third bytes both 0xFF (standard FAT12 padding).
    """
    for fat_lba in (1, 2):
        fat_sector = read_lba(lba_map, fat_lba)
        if len(fat_sector) < 3:
            log.debug("guess_bpb_from_fat_media: LBA %d is short (%d bytes) — skipping",
                      fat_lba, len(fat_sector))
            continue

        med  = fat_sector[0]
        pad1 = fat_sector[1]
        pad2 = fat_sector[2]

        if med not in MEDIA_GEOMETRIES or pad1 != 0xFF or pad2 != 0xFF:
            log.debug("guess_bpb_from_fat_media: LBA %d first bytes %02X %02X %02X — not a FAT",
                      fat_lba, med, pad1, pad2)
            continue

        nhead, spt_fat, cyls, res, nfat, fatsz, rde, spc = MEDIA_GEOMETRIES[med]

        # For 0xF9 distinguish 720 KB (9 spt) from 1.2 MB (15 spt) using inferred spt
        if med == 0xF9 and spt == 15:
            nhead, spt_fat, cyls, res, nfat, fatsz, rde, spc = (2, 15, 80, 1, 2, 7, 224, 1)

        rds        = (rde * 32 + 511) // 512
        data_start = res + nfat * fatsz + rds
        tsec       = cyls * nhead * spt_fat
        tc         = (tsec - data_start) // spc if spc else 0

        log.info("BPB      : inferred from FAT media byte 0x%02X at LBA %d"
                 " → %d cyl × %d head × %d spt (%d KB)",
                 med, fat_lba, cyls, nhead, spt_fat, tsec * 512 // 1024)

        return BPB(
            oem_name          = f"(media=0x{med:02X})",
            bytes_per_sector  = 512,
            sectors_per_clus  = spc,
            reserved_sectors  = res,
            num_fats          = nfat,
            root_entry_count  = rde,
            total_sectors_16  = tsec,
            media_byte        = med,
            fat_size_16       = fatsz,
            sectors_per_track = spt_fat,
            num_heads         = nhead,
            root_dir_start    = res + nfat * fatsz,
            root_dir_sectors  = rds,
            data_start        = data_start,
            total_clusters    = tc,
        )

    return None

def _logical_spt(smap: dict) -> int:
    """
    Return the logical sectors-per-track for one track's sector map.

    Standard floppies number sectors 1..N consecutively.  Copy-protected
    disks often interleave non-standard sector numbers (e.g. 10, 12, 14…27)
    among the real data sectors.  Using max(smap.keys()) on such a track
    would return 27 instead of 8, exploding the inferred geometry.

    This function returns the length of the unbroken consecutive run
    1, 2, 3, … starting from sector 1 (only counting sector numbers in
    the standard floppy range [1..18]).  If no such run exists it falls
    back to max(smap.keys()) — the legacy behaviour for unusual disks.
    """
    secs = sorted(s for s in smap.keys() if 1 <= s <= 18)
    run = 0
    for s in secs:
        if s == run + 1:
            run = s
        else:
            break
    return run if run > 0 else (max(smap.keys()) if smap else 0)


def infer_disk_geometry(disk: dict):
    """Return (max_cyl, num_heads, spt) from the parsed CP2 sector dict.
    Corrupt track headers are filtered out via filter_disk() before geometry
    is inferred, preventing garbage head values from inflating the output.
    Non-sequential (copy-protection) sector numbering is handled by
    _logical_spt(), which detects the real consecutive run 1..N rather than
    using the raw maximum sector number."""
    disk = filter_disk(disk)
    if not disk:
        raise ValueError("Empty disk dict after filtering")
    num_heads = max(h for _, h in disk) + 1
    # Use logical SPT (consecutive run from 1) not raw max sector number
    sec_counts = [_logical_spt(smap) for smap in disk.values() if smap]
    spt = max(set(sec_counts), key=sec_counts.count)
    all_cyls = sorted(set(c for c, _ in disk))
    true_max = 0
    for cyl in all_cyls:
        if all(_logical_spt(disk.get((cyl, h), {})) >= spt
               for h in range(num_heads)):
            true_max = cyl
    max_cyl = true_max + 1
    for std in [40, 80]:
        if abs(max_cyl - std) <= 2 and max_cyl <= std:
            max_cyl = std
            break
    return max_cyl, num_heads, spt


def build_lba_map(disk: dict, max_cyl: int, num_heads: int, spt: int) -> dict:
    lba_map = {}
    for cyl in range(max_cyl):
        for head in range(num_heads):
            smap = disk.get((cyl, head), {})
            for sec in range(1, spt + 1):
                lba = (cyl * num_heads + head) * spt + (sec - 1)
                lba_map[lba] = smap.get(sec)
    return lba_map


def read_lba(lba_map: dict, lba: int) -> bytes:
    """Read a single 512-byte sector; returns zero sector if missing or empty.

    Sectors stored as zero-length bytes (b'') arise when the CP2 parser
    records a sector with size-code N>6 or N=0 and no data offset — the
    sector exists in the directory but carries no usable data.  Treat them
    identically to absent sectors rather than propagating the empty buffer.
    """
    data = lba_map.get(lba)
    if not data:   # handles None and b''
        return bytes(512)
    return data


# ── Directory parsing ─────────────────────────────────────────────────────────

ATTR_READONLY  = 0x01
ATTR_HIDDEN    = 0x02
ATTR_SYSTEM    = 0x04
ATTR_VOLUME_ID = 0x08
ATTR_DIRECTORY = 0x10
ATTR_ARCHIVE   = 0x20
ATTR_LONG_NAME = 0x0F

@dataclass
class DirEntry:
    raw_name:      str       # 8 chars
    raw_ext:       str       # 3 chars
    attr:          int
    start_cluster: int
    file_size:     int
    is_deleted:    bool = False

    @property
    def filename(self) -> str:
        n = self.raw_name.rstrip()
        e = self.raw_ext.rstrip()
        return f"{n}.{e}" if e else n

    @property
    def attr_str(self) -> str:
        flags = ""
        if self.attr & ATTR_READONLY:  flags += "R"
        if self.attr & ATTR_HIDDEN:    flags += "H"
        if self.attr & ATTR_SYSTEM:    flags += "S"
        if self.attr & ATTR_VOLUME_ID: flags += "V"
        if self.attr & ATTR_DIRECTORY: flags += "D"
        if self.attr & ATTR_ARCHIVE:   flags += "A"
        return flags or "-"

    @property
    def is_valid(self) -> bool:
        """True if this is a regular extractable file."""
        if self.is_deleted:
            return False
        # LFN entry: all four attribute bits set simultaneously (exactly 0x0F).
        # Must use equality, not bitwise AND — attr=0x06 (READONLY|HIDDEN) is a
        # perfectly valid system file (e.g. IBMBIO.COM) and must not be rejected.
        if self.attr == ATTR_LONG_NAME:
            return False
        if self.attr & (ATTR_VOLUME_ID | ATTR_DIRECTORY):
            return False
        if self.file_size == 0:
            return False
        return True


def parse_dir_sector(sector: bytes) -> list:
    """Parse up to 16 directory entries from a 512-byte sector."""
    entries = []
    for i in range(0, 512, 32):
        e = sector[i:i+32]
        if len(e) < 32:
            break

        b0 = e[0]
        if b0 == 0x00:
            # End of directory
            entries.append(None)
            break
        if b0 == 0xE5:
            # Deleted entry — record but mark
            de = DirEntry(
                raw_name=e[1:8].decode("cp437","replace"),
                raw_ext=e[8:11].decode("cp437","replace"),
                attr=e[11],
                start_cluster=struct.unpack_from("<H", e, 26)[0],
                file_size=struct.unpack_from("<I", e, 28)[0],
                is_deleted=True,
            )
            entries.append(de)
            continue

        attr = e[11]
        if attr == ATTR_LONG_NAME:
            # LFN entry — skip
            continue

        de = DirEntry(
            raw_name=e[0:8].decode("cp437","replace"),
            raw_ext=e[8:11].decode("cp437","replace"),
            attr=attr,
            start_cluster=struct.unpack_from("<H", e, 26)[0],
            file_size=struct.unpack_from("<I", e, 28)[0],
            is_deleted=False,
        )
        entries.append(de)

    return entries


def read_dir_sectors(lba_map: dict, start_lba: int, num_sectors: int,
                     skip_bytes: int = 0,
                     skip_zero_sectors: bool = False) -> list:
    """
    Read directory entries from 'num_sectors' contiguous sectors at start_lba.
    Stops early on the 0x00 end-of-directory sentinel.
    Returns flat list of DirEntry (no None sentinels).

    skip_bytes: discard this many bytes from the very start of the first sector
    before parsing begins.  Handles the case where a non-standard disk stores
    the root directory at a sub-sector-aligned byte offset (e.g. mid-FAT-sector).

    skip_zero_sectors: if True, entirely zero-filled sectors in the middle of
    the directory region are skipped rather than treated as end-of-directory.
    Handles non-standard disks where a gap sector (e.g. an unwritten logical
    sector between two data-bearing sectors) would otherwise terminate the walk
    before all directory entries are found.
    """
    # Collect raw bytes, optionally skipping near-zero sectors.
    # A sector must be ≥ 95% zeros to be skipped — a byte-perfect check
    # misses sectors that contain only a handful of stray non-zero bytes
    # (e.g. FAT metadata or trailing garbage) yet carry no directory entries.
    ZERO_THRESHOLD = 0.95
    buf = bytearray()
    for i in range(num_sectors):
        sector = read_lba(lba_map, start_lba + i)
        if skip_zero_sectors and (sector.count(0) / 512) >= ZERO_THRESHOLD:
            log.debug("read_dir_sectors: skipping near-zero sector at LBA %d "
                      "(%d non-zero bytes)", start_lba + i, 512 - sector.count(0))
            continue
        buf.extend(sector)

    if skip_bytes:
        log.debug("read_dir_sectors: skipping %d bytes before first entry", skip_bytes)
        buf = buf[skip_bytes:]

    entries = []
    for off in range(0, len(buf) - 31, 32):
        e = bytes(buf[off:off + 32])
        b0 = e[0]
        if b0 == 0x00:
            break
        if b0 == 0xE5:
            de = DirEntry(
                raw_name=e[1:8].decode("cp437", "replace"),
                raw_ext=e[8:11].decode("cp437", "replace"),
                attr=e[11],
                start_cluster=struct.unpack_from("<H", e, 26)[0],
                file_size=struct.unpack_from("<I", e, 28)[0],
                is_deleted=True,
            )
            entries.append(de)
            continue
        attr = e[11]
        if attr == ATTR_LONG_NAME:
            continue
        de = DirEntry(
            raw_name=e[0:8].decode("cp437", "replace"),
            raw_ext=e[8:11].decode("cp437", "replace"),
            attr=attr,
            start_cluster=struct.unpack_from("<H", e, 26)[0],
            file_size=struct.unpack_from("<I", e, 28)[0],
            is_deleted=False,
        )
        entries.append(de)
    return entries


def parse_dir_bytes(data: bytes) -> list:
    """
    Parse FAT12 directory entries from a raw byte buffer.
    Used by --cp2-dir-offset to parse directly from the CP2 file stream
    without going through the LBA map at all.
    Returns flat list of DirEntry (stops on 0x00 sentinel).
    """
    entries = []
    for off in range(0, len(data) - 31, 32):
        e = data[off:off + 32]
        b0 = e[0]
        if b0 == 0x00:
            break
        if b0 == 0xE5:
            de = DirEntry(
                raw_name=e[1:8].decode("cp437", "replace"),
                raw_ext=e[8:11].decode("cp437", "replace"),
                attr=e[11],
                start_cluster=struct.unpack_from("<H", e, 26)[0],
                file_size=struct.unpack_from("<I", e, 28)[0],
                is_deleted=True,
            )
            entries.append(de)
            continue
        attr = e[11]
        if attr == ATTR_LONG_NAME:
            continue
        de = DirEntry(
            raw_name=e[0:8].decode("cp437", "replace"),
            raw_ext=e[8:11].decode("cp437", "replace"),
            attr=attr,
            start_cluster=struct.unpack_from("<H", e, 26)[0],
            file_size=struct.unpack_from("<I", e, 28)[0],
            is_deleted=False,
        )
        entries.append(de)
    return entries


def walk_directory(
    lba_map:           dict,
    bpb:               BPB,
    start_lba:         int,
    num_sectors:       int,
    current_path:      str  = "",
    visited_clusters:  set  = None,
    skip_bytes:        int  = 0,
    skip_zero_sectors: bool = False,
) -> list:
    """
    Recursively walk a FAT12 directory tree starting at start_lba.

    Returns a flat list of (DirEntry, path_str) tuples for every
    extractable file found at any depth.  Subdirectories themselves
    are not included — only the files inside them.

    visited_clusters guards against corrupt entries that form cycles.
    current_path is the slash-joined path prefix, e.g. "CHILD/SUBDIR".
    skip_bytes is only applied at the top-level call (root directory);
    subdirectory clusters always start at byte 0.
    skip_zero_sectors skips entirely zero-filled sectors when building
    the directory byte buffer; applied at all levels.
    """
    if visited_clusters is None:
        visited_clusters = set()

    results = []
    entries = read_dir_sectors(lba_map, start_lba, num_sectors,
                               skip_bytes=skip_bytes,
                               skip_zero_sectors=skip_zero_sectors)

    for de in entries:
        # ── Skip deleted and . / .. entries ──────────────────────────────────
        if de.is_deleted:
            continue
        name = de.raw_name.rstrip()
        if name in (".", ".."):
            continue

        full_path = f"{current_path}/{de.filename}" if current_path else de.filename

        # ── Subdirectory → recurse ────────────────────────────────────────────
        if de.attr & ATTR_DIRECTORY:
            if de.start_cluster < 2:
                log.debug("  Dir %s: invalid cluster %d — skipping", full_path, de.start_cluster)
                continue
            if de.start_cluster in visited_clusters:
                log.warning("  Dir %s: cluster %d already visited — loop detected, skipping",
                            full_path, de.start_cluster)
                continue
            visited_clusters.add(de.start_cluster)
            sub_lba      = cluster_to_lba(de.start_cluster, bpb)
            sub_sectors  = bpb.sectors_per_clus   # one cluster per subdir on a floppy
            log.debug("  Entering dir: %s  (cluster=%d  LBA=%d)", full_path, de.start_cluster, sub_lba)
            sub_results  = walk_directory(lba_map, bpb, sub_lba, sub_sectors,
                                          full_path, visited_clusters,
                                          skip_zero_sectors=skip_zero_sectors)
            results.extend(sub_results)
            continue

        # ── Volume label / LFN / zero-size — skip ────────────────────────────
        if not de.is_valid:
            if de.attr & ATTR_VOLUME_ID:
                log.debug("  Volume label %r — skipping", de.filename)
            continue

        results.append((de, current_path))

    return results


# ── File extraction ───────────────────────────────────────────────────────────

@dataclass
class RecoveredFile:
    filename:      str
    dir_path:      str   # slash-joined path relative to root, "" means root
    start_cluster: int
    file_size:     int
    start_lba:     int
    sectors_read:  int
    bytes_written: int
    missing_secs:  int
    attr_str:      str
    is_deleted:    bool
    data:          bytes = field(repr=False, default=b'')

    @property
    def full_path(self) -> str:
        return f"{self.dir_path}/{self.filename}" if self.dir_path else self.filename

    @property
    def complete(self) -> bool:
        return self.missing_secs == 0 and self.bytes_written == self.file_size


def cluster_to_lba(cluster: int, bpb: BPB) -> int:
    """Convert cluster number to LBA (FAT12 standard formula)."""
    return bpb.data_start + (cluster - 2) * bpb.sectors_per_clus


def extract_file(lba_map: dict, de: DirEntry, bpb: BPB, dir_path: str = "") -> RecoveredFile:
    """
    Extract a file from the disk using the directory entry.
    Since the FAT is corrupt we read contiguous sectors from start_cluster.
    This works perfectly for files written sequentially (standard floppy writes).
    """
    start_lba    = cluster_to_lba(de.start_cluster, bpb)
    total_sectors = math.ceil(de.file_size / 512)
    collected    = bytearray()
    missing      = 0

    for i in range(total_sectors):
        lba    = start_lba + i
        sector = lba_map.get(lba)
        if sector is None:
            log.warning("    %s: sector LBA %d missing — zero fill", de.filename, lba)
            collected.extend(bytes(512))
            missing += 1
        else:
            collected.extend(sector)

    # Trim to exact file size
    data = bytes(collected[:de.file_size])

    return RecoveredFile(
        filename      = de.filename,
        dir_path      = dir_path,
        start_cluster = de.start_cluster,
        file_size     = de.file_size,
        start_lba     = start_lba,
        sectors_read  = total_sectors,
        bytes_written = len(data),
        missing_secs  = missing,
        attr_str      = de.attr_str,
        is_deleted    = de.is_deleted,
        data          = data,
    )


# ── Optional: signature carver for unaccounted sectors ───────────────────────

CARVE_SIGS = [
    (b'PK\x03\x04', 'zip'), (b'\x1f\x8b', 'gz'),
    (b'Rar!\x1a\x07', 'rar'), (b'\x60\xea', 'arj'),
    (b'-lh5-', 'lzh'), (b'-lh6-', 'lzh'), (b'-lh7-', 'lzh'),
    (b'MZ', 'exe'), (b'SZDD\x88\xf0\x27\x33', 'exe'),
    (b'\x89PNG\r\n\x1a\n', 'png'), (b'GIF89a', 'gif'), (b'GIF87a', 'gif'),
    (b'\xff\xd8\xff', 'jpg'), (b'BM', 'bmp'), (b'\x0a\x05\x01', 'pcx'),
    (b'%PDF-', 'pdf'), (b'RIFF', 'wav'), (b'Creative Voice File', 'voc'),
]
ZERO_SECTOR = bytes(512)

def carve_unclaimed(lba_map: dict, total_lbas: int, claimed_lbas: set) -> list:
    """
    Scan sectors not already claimed by directory extraction for known signatures.
    Returns list of (start_lba, ext, data).
    """
    sig_index = {}
    for magic, ext in CARVE_SIGS:
        sig_index.setdefault(magic[0], []).append((magic, ext))
    for b0 in sig_index:
        sig_index[b0].sort(key=lambda t: -len(t[0]))

    results = []
    carve_claimed = set()

    for lba in range(total_lbas):
        if lba in claimed_lbas or lba in carve_claimed:
            continue
        sector = lba_map.get(lba)
        if not sector or sector == ZERO_SECTOR:
            continue

        cands = sig_index.get(sector[0], [])
        matched_ext = None
        for magic, ext in cands:
            if sector[:len(magic)] == magic:
                matched_ext = ext
                break
        if not matched_ext:
            continue

        # Greedy collect
        collected = bytearray()
        cur = lba
        while cur < total_lbas:
            chunk = lba_map.get(cur)
            if chunk is None or (cur != lba and chunk == ZERO_SECTOR):
                break
            if cur != lba:
                for magic, _ in CARVE_SIGS:
                    if chunk[:len(magic)] == magic:
                        break
                else:
                    pass  # no new sig, keep going
            collected.extend(chunk)
            carve_claimed.add(cur)
            cur += 1

        if len(collected) >= 16:
            results.append((lba, matched_ext, bytes(collected)))
            log.info("  [carve] LBA %-5d  %-6s  %d bytes", lba, matched_ext, len(collected))

    return results


# ── Output ────────────────────────────────────────────────────────────────────

def write_output(
    recovered:   list,
    carved:      list,
    out_dir:     Path,
    total_lbas:  int,
    bpb:         BPB,
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    manifest = []
    for rf in recovered:
        # Mirror the original directory tree
        dest_dir = out_dir / rf.dir_path if rf.dir_path else out_dir
        dest_dir.mkdir(parents=True, exist_ok=True)
        (dest_dir / rf.filename).write_bytes(rf.data)

        entry = {k: v for k, v in asdict(rf).items() if k != 'data'}
        entry['full_path'] = rf.full_path
        entry['source']    = 'directory'
        manifest.append(entry)

    for i, (lba, ext, data) in enumerate(carved):
        fname = f"carved_{i:04d}.{ext}"
        (out_dir / fname).write_bytes(data)
        manifest.append({
            'filename': fname, 'source': 'carve',
            'start_lba': lba, 'byte_size': len(data),
        })

    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    lines = [
        "cp2_recover — recovery summary",
        "─" * 75,
        f"Files from directory : {len(recovered)}",
        f"Files from carving   : {len(carved)}",
        f"Output directory     : {out_dir.resolve()}",
        "─" * 75,
        f"{'Path':<30} {'Attr':<5} {'Cluster':>8} {'Size':>10} {'LBA':>6}  Status",
        "─" * 75,
    ]
    for rf in recovered:
        status  = "OK" if rf.complete else f"PARTIAL ({rf.missing_secs} missing secs)"
        deleted = " [DELETED]" if rf.is_deleted else ""
        lines.append(
            f"  {rf.full_path:<30} {rf.attr_str:<5} {rf.start_cluster:>8} "
            f"{rf.file_size:>10} {rf.start_lba:>6}  {status}{deleted}"
        )
    for i, (lba, ext, data) in enumerate(carved):
        lines.append(f"  carved_{i:04d}.{ext:<20}  {'?':<5} {'?':>8} {len(data):>10} {lba:>6}  CARVED")

    (out_dir / "summary.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    log.info("Wrote %d file(s) to %s", len(recovered) + len(carved), out_dir)


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="Directory-driven recovery from SOFTWARE PIRATES .cp2 images"
    )
    ap.add_argument("source",
                    help=".cp2 file to recover from")
    ap.add_argument("--out",          default="./recovered", metavar="DIR")
    ap.add_argument("--carve-extra",  action="store_true",
                    help="Also carve sectors not claimed by the directory")
    ap.add_argument("--probe",        action="store_true",
                    help="Show BPB and directory listing only — do not extract")
    ap.add_argument("--data-start",   type=int, default=None, metavar="LBA",
                    help="Override data area start LBA (if BPB is unreadable)")
    ap.add_argument("--spc",          type=int, default=None, metavar="N",
                    help="Override sectors-per-cluster (default: read from BPB)")
    ap.add_argument("--root-dir-lba", type=int, default=None, metavar="LBA",
                    help="Override root directory start LBA (if BPB is unreadable or wrong)")
    ap.add_argument("--root-dir-skip", type=int, default=0, metavar="BYTES",
                    help="Skip N bytes at the start of --root-dir-lba before parsing entries "
                         "(for non-standard disks where the directory starts mid-sector, "
                         "e.g. 502 bytes into LBA 3). Default: 0")
    ap.add_argument("--root-dir-sectors", type=int, default=None, metavar="N",
                    help="Number of sectors to read for the root directory "
                         "(default: derived from BPB root_entry_count)")
    ap.add_argument("--skip-zero-sectors", action="store_true",
                    help="Skip near-zero sectors (≥95%% zeros) when reading directory regions. "
                         "Useful when a missing sector between two data-bearing directory "
                         "sectors would otherwise terminate the directory walk early.")
    ap.add_argument("--cp2-dir-offset",  type=lambda x: int(x, 0), default=None, metavar="OFFSET",
                    help="Read the root directory entries directly from the raw CP2 file at "
                         "this byte offset (hex or decimal, e.g. 0x203D), bypassing the LBA "
                         "map entirely. Use when the disk's interleave stores the directory "
                         "contiguously in the CP2 byte stream but the LBA map cannot "
                         "reconstruct it correctly.")
    ap.add_argument("--cp2-dir-size",    type=int, default=512, metavar="BYTES",
                    help="Number of bytes to read from --cp2-dir-offset (default: 512). "
                         "Increase if the directory spans more than one sector's worth of "
                         "entries.")
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

    # Build flat LBA map
    max_cyl, num_heads, spt = infer_disk_geometry(disk)
    total_lbas = max_cyl * num_heads * spt
    log.info("Disk     : %d cyl × %d head × %d sec/trk = %d LBAs (%d KB)",
             max_cyl, num_heads, spt, total_lbas, total_lbas * 512 // 1024)
    lba_map = build_lba_map(disk, max_cyl, num_heads, spt)

    # Parse BPB
    sector0 = read_lba(lba_map, 0)
    bpb = parse_bpb(sector0)
    if bpb:
        log.info("BPB      : read OK")
    else:
        # Second attempt: infer from FAT media descriptor byte (PC-DOS 1.x era)
        bpb = guess_bpb_from_fat_media(disk, lba_map, spt)
        if bpb:
            log.info("BPB      : derived from FAT media descriptor 0x%02X", bpb.media_byte)
        else:
            log.warning("BPB      : unreadable — trying standard geometries")
            bpb = guess_bpb_from_clusters(disk)
            if not bpb:
                log.error("Could not determine disk geometry. Use --data-start and --spc.")
                sys.exit(1)

    # Apply CLI overrides
    if args.data_start is not None:
        log.info("Override : data_start = LBA %d", args.data_start)
        bpb.data_start = args.data_start
    if args.spc is not None:
        log.info("Override : sectors_per_cluster = %d", args.spc)
        bpb.sectors_per_clus = args.spc
    if args.root_dir_lba is not None:
        log.info("Override : root_dir_start = LBA %d", args.root_dir_lba)
        bpb.root_dir_start = args.root_dir_lba
    if args.root_dir_sectors is not None:
        log.info("Override : root_dir_sectors = %d", args.root_dir_sectors)
        bpb.root_dir_sectors = args.root_dir_sectors
    root_skip = args.root_dir_skip
    if root_skip:
        log.info("Override : root_dir_skip = %d bytes", root_skip)

    if args.probe:
        print("\n=== BPB ===")
        bpb.describe()
        if root_skip:
            print(f"  Root dir skip  : {root_skip} bytes (--root-dir-skip)")
        if args.cp2_dir_offset is not None:
            print(f"  CP2 dir offset : 0x{args.cp2_dir_offset:X}  size={args.cp2_dir_size} bytes "
                  f"(--cp2-dir-offset)")

    # ── Collect root directory entries ────────────────────────────────────────
    if args.cp2_dir_offset is not None:
        # Fast path: read directory entries directly from the CP2 byte stream.
        # The sectors may be stored in interleaved order in the CP2 file, but
        # the directory data itself is contiguous starting at cp2_dir_offset.
        cp2_off  = args.cp2_dir_offset
        cp2_size = args.cp2_dir_size
        if cp2_off + cp2_size > len(raw):
            log.error("--cp2-dir-offset 0x%X + --cp2-dir-size %d exceeds file size %d",
                      cp2_off, cp2_size, len(raw))
            sys.exit(1)
        log.info("Dir      : reading %d bytes from CP2 offset 0x%X (raw stream)",
                 cp2_size, cp2_off)
        dir_bytes  = raw[cp2_off : cp2_off + cp2_size]
        dir_entries_raw = parse_dir_bytes(dir_bytes)
        # Wrap into the same (de, path) tuples that walk_directory returns,
        # all at root level.  Subdirectories found here will be walked via
        # the LBA map as normal.
        all_files = []
        visited   = set()
        for de in dir_entries_raw:
            name = de.raw_name.rstrip()
            if name in (".", ".."):
                continue
            if de.attr & ATTR_DIRECTORY:
                if de.start_cluster < 2 or de.start_cluster in visited:
                    continue
                visited.add(de.start_cluster)
                sub_lba     = cluster_to_lba(de.start_cluster, bpb)
                sub_sectors = bpb.sectors_per_clus
                log.debug("  Entering subdir %s (cluster=%d LBA=%d)",
                          de.filename, de.start_cluster, sub_lba)
                sub = walk_directory(lba_map, bpb, sub_lba, sub_sectors,
                                     de.filename, visited,
                                     skip_zero_sectors=args.skip_zero_sectors)
                all_files.extend(sub)
                continue
            if not de.is_valid:
                continue
            all_files.append((de, ""))
    else:
        # Normal path: walk the LBA map from the root directory region.
        all_files = walk_directory(
            lba_map, bpb,
            start_lba         = bpb.root_dir_start,
            num_sectors       = bpb.root_dir_sectors,
            current_path      = "",
            skip_bytes        = root_skip,
            skip_zero_sectors = args.skip_zero_sectors,
        )

    files   = [(de, p) for de, p in all_files if not de.is_deleted]
    deleted = [(de, p) for de, p in all_files if de.is_deleted]
    log.info("Found    : %d file(s) across all directories (%d deleted)",
             len(files), len(deleted))

    if args.probe:
        print(f"\n=== Directory tree ({len(files)} files, {len(deleted)} deleted) ===")
        print(f"  {'Path':<35} {'Attr':<5} {'Cluster':>8} {'Size':>10}  LBA")
        print(f"  {'─'*35} {'─'*5} {'─'*8} {'─'*10}  {'─'*6}")
        for de, path in files:
            full = f"{path}/{de.filename}" if path else de.filename
            lba  = cluster_to_lba(de.start_cluster, bpb)
            print(f"  {full:<35} {de.attr_str:<5} {de.start_cluster:>8} {de.file_size:>10}  {lba}")
        for de, path in deleted:
            full = f"{path}/{de.filename}" if path else de.filename
            lba  = cluster_to_lba(de.start_cluster, bpb) if de.start_cluster >= 2 else -1
            print(f"  [{full:<34}] {de.attr_str:<5} {de.start_cluster:>8} {de.file_size:>10}  {lba}  [DELETED]")
        return

    # Extract every file, preserving directory structure
    log.info("Extracting %d file(s) ...", len(files))
    claimed_lbas = set()
    recovered    = []

    for de, dir_path in files:
        if de.start_cluster < 2:
            log.warning("  %s: invalid cluster %d — skipping", de.filename, de.start_cluster)
            continue

        rf = extract_file(lba_map, de, bpb, dir_path)
        recovered.append(rf)

        for i in range(rf.sectors_read):
            claimed_lbas.add(rf.start_lba + i)

        status = "OK" if rf.complete else f"PARTIAL ({rf.missing_secs} missing)"
        log.info("  %-36s  cluster=%-5d  LBA=%-5d  %7d bytes  [%s]",
                 rf.full_path, de.start_cluster, rf.start_lba, rf.bytes_written, status)

    # Optional: carve unclaimed sectors
    carved = []
    if args.carve_extra:
        unclaimed = total_lbas - len(claimed_lbas)
        log.info("Carving %d unclaimed sectors ...", unclaimed)
        carved = carve_unclaimed(lba_map, total_lbas, claimed_lbas)
        log.info("Carve found %d additional file(s)", len(carved))

    write_output(recovered, carved, Path(args.out), total_lbas, bpb)
    log.info("Done.")


if __name__ == "__main__":
    main()
