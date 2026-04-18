#!/usr/bin/env python3
"""
cp2_to_img.py  —  SOFTWARE PIRATES .cp2 → raw .img converter
Translated from PCE psi-img-cp2.c by Hampa Hug (GPL2)

Usage:
    python cp2_to_img.py disk.cp2
    python cp2_to_img.py disk.cp2 output.img
    python cp2_to_img.py /folder/of/cp2s
    python cp2_to_img.py /folder/of/cp2s --output-dir /target
    python cp2_to_img.py disk.cp2 --probe    # dump structure, no output file
    python cp2_to_img.py disk.cp2 --probe --verbose
"""

import sys
import os
import struct
import argparse
import logging

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

# ── Format constants (from C source) ─────────────────────────────────────────

MAGIC          = b"SOFTWARE PIRATES"   # 16 bytes at offset 0
HEADER_SIZE    = 30                    # magic (16) + version string (14)
TRACK_HDR_SIZE = 3 + 16 * 24          # 387 bytes: [cyl,head,scount] + 24×16-byte sector headers
SDATA_BIAS     = 0x16AD               # subtracted from raw sector offset field to get relative offset
MAX_SECTORS    = 24                    # max sectors per track

# Known version strings (14 chars each, from C source)
# We also accept unknown versions with a warning rather than failing.
KNOWN_VERSIONS = {
    "Release 3.02$0",
    "Release 3.07$0",
    "Release 3.09$0",
    "Release 4.00$0",
    "Release 4.01$0",
    "Release 4.02$0",
    "Release 5.01$0",
    "Release 6.0\x0a$0",
}


# ── Sector / track data structures ───────────────────────────────────────────

class Sector:
    __slots__ = ("cyl", "head", "sec", "size_code", "size",
                 "data_offset", "data",
                 "flag_crc_id", "flag_crc_data", "flag_no_dam", "flag_del_dam")

    def __init__(self):
        self.cyl = self.head = self.sec = self.size_code = self.size = 0
        self.data_offset = None
        self.data = None
        self.flag_crc_id = self.flag_crc_data = self.flag_no_dam = self.flag_del_dam = False


class Track:
    __slots__ = ("cyl", "head", "sectors")

    def __init__(self, cyl, head):
        self.cyl     = cyl
        self.head    = head
        self.sectors = []   # list of Sector, in the order stored


# ── Parsing ───────────────────────────────────────────────────────────────────

def parse_header(raw: bytes) -> str:
    """Validate magic, return version string. Raises ValueError on bad magic."""
    if len(raw) < HEADER_SIZE:
        raise ValueError(f"File too short ({len(raw)} bytes)")

    if raw[:16] != MAGIC:
        raise ValueError(f"Bad magic: {raw[:16]!r}")

    version_raw = raw[16:30]
    version     = version_raw.decode("cp437", errors="replace")

    if version not in KNOWN_VERSIONS:
        log.warning("Unrecognised version string %r — attempting anyway", version)
    else:
        log.info("Version : %s", version.rstrip('\x00').rstrip('$0').strip())

    return version


def parse_sector_header(sh: bytes) -> Sector:
    """
    Parse a 16-byte sector header.
    Layout (from C comments):
      sh[0]      read result
      sh[1]      ST0
      sh[2]      ST1 (bit5=CRC error, bit2=unknown)
      sh[3]      ST2 (bit0=no DAM, bit5=CRC data, bit6=deleted DAM)
      sh[4]      C (cylinder id)
      sh[5]      H (head id)
      sh[6]      R (sector number)
      sh[7]      N (size code: sector size = 128 << N)
      sh[8..9]   uint16 LE: raw sector data offset
      sh[10..15] flags / unknown
    """
    s = Sector()
    s.cyl       = sh[4]
    s.head      = sh[5]
    s.sec       = sh[6]
    s.size_code = sh[7]
    s.size      = (128 << sh[7]) if sh[7] <= 6 else 0

    raw_ofs     = sh[8] | (sh[9] << 8)      # uint16 LE
    s.data_offset = raw_ofs                   # kept raw; subtract SDATA_BIAS later

    st1 = sh[2]
    st2 = sh[3]

    # CRC flags
    if st1 & 0x20:
        if st2 & 0x20:
            s.flag_crc_data = True
        else:
            s.flag_crc_id   = True

    # DAM flags
    s.flag_no_dam  = bool(st2 & 0x01)
    s.flag_del_dam = bool(st2 & 0x40)

    # Fill conditions (data not stored for these sectors)
    skip = (
        (st1  & 0x96)               or   # unknown ST1 bits
        sh[10] or sh[11]            or   # unknown header fields
        (sh[14] & 0x7F)             or   # unknown flags
        sh[15]                      or   # unknown flags
        sh[7] > 6                   or   # oversized sector
        s.flag_no_dam               or   # missing data address mark
        (sh[14] & 0x32)             or   # more unknown flags
        s.size < 256                or   # tiny sectors not stored
        s.size > 4096               or   # huge sectors not stored
        raw_ofs < SDATA_BIAS             # bad / no data offset
    )

    if skip:
        s.data_offset = None   # signal: fill with zeros

    return s


def parse_track_header(buf: bytes) -> Track:
    """Parse a 387-byte track header block."""
    cyl   = buf[0]
    head  = buf[1]
    n_sec = buf[2]

    trk   = Track(cyl, head)

    n_sec = min(n_sec, MAX_SECTORS)
    for i in range(n_sec):
        off = 3 + i * 16
        sh  = buf[off: off + 16]
        trk.sectors.append(parse_sector_header(sh))

    return trk


def parse_segment(raw: bytes, file_offset: int) -> tuple:
    """
    Parse one segment at file_offset.
    Returns (list[Track], next_file_offset).
    Returns (None, file_offset) when size1 == 0 (end marker).
    """
    if file_offset + 2 > len(raw):
        return None, file_offset

    size1 = struct.unpack_from("<H", raw, file_offset)[0]

    if size1 == 0:
        log.debug("End-of-segments marker at 0x%X", file_offset)
        return None, file_offset

    log.debug("Segment at 0x%X: size1=%d", file_offset, size1)

    # size2 is at file_offset + 2 + size1
    size2_offset = file_offset + 2 + size1
    if size2_offset + 2 > len(raw):
        raise ValueError(f"Truncated segment at 0x{file_offset:X}: size1={size1} runs past EOF")

    size2 = struct.unpack_from("<H", raw, size2_offset)[0]
    log.debug("Segment at 0x%X: size2=%d", file_offset, size2)

    # Track headers occupy bytes [file_offset+2 .. file_offset+2+size1)
    track_data_start = file_offset + 2
    # Sector data block starts after size2 field
    sector_data_start = size2_offset + 2

    # Parse track headers
    tracks = []
    ofs1   = 0
    while (ofs1 + TRACK_HDR_SIZE) <= size1:
        buf_start = track_data_start + ofs1
        buf       = raw[buf_start: buf_start + TRACK_HDR_SIZE]
        trk       = parse_track_header(buf)

        if trk.cyl == 0 and trk.head == 0 and len(trk.sectors) == 0:
            log.debug("  Empty track header at ofs1=%d, skipping", ofs1)
            ofs1 += TRACK_HDR_SIZE
            continue

        log.debug("  Track c=%d h=%d sectors=%d", trk.cyl, trk.head, len(trk.sectors))

        # Resolve sector data for each sector
        for sec in trk.sectors:
            if sec.data_offset is None or sec.size == 0:
                sec.data = bytes(sec.size) if sec.size else b''
                continue

            rel_ofs = sec.data_offset - SDATA_BIAS
            abs_ofs = sector_data_start + rel_ofs

            if rel_ofs < 0 or abs_ofs + sec.size > len(raw):
                log.warning(
                    "    c=%d h=%d r=%d: data offset 0x%X out of range — zero fill",
                    sec.cyl, sec.head, sec.sec, sec.data_offset
                )
                sec.data = bytes(sec.size)
            else:
                sec.data = raw[abs_ofs: abs_ofs + sec.size]
                if len(sec.data) < sec.size:
                    log.warning(
                        "    c=%d h=%d r=%d: short read (%d/%d) — padding",
                        sec.cyl, sec.head, sec.sec, len(sec.data), sec.size
                    )
                    sec.data = sec.data.ljust(sec.size, b'\x00')

        tracks.append(trk)
        ofs1 += TRACK_HDR_SIZE

    next_offset = file_offset + 2 + size1 + 2 + size2
    return tracks, next_offset


# ── Image assembly ────────────────────────────────────────────────────────────

def load_cp2(raw: bytes) -> dict:
    """
    Parse entire CP2 file.
    Returns dict: (cyl, head) → {sector_num: bytes}
    """
    parse_header(raw)   # validates magic + version

    disk = {}           # (cyl, head) → {sector_num → data bytes}
    offset = HEADER_SIZE

    seg_count = 0
    while True:
        tracks, new_offset = parse_segment(raw, offset)
        if tracks is None:
            break

        for trk in tracks:
            key    = (trk.cyl, trk.head)
            secmap = disk.setdefault(key, {})
            for sec in trk.sectors:
                secmap[sec.sec] = sec.data if sec.data is not None else bytes(512)

        seg_count   += 1
        offset       = new_offset

        if offset >= len(raw):
            break

    log.info("Loaded %d segment(s), %d track-sides", seg_count, len(disk))
    return disk


def filter_disk(disk: dict) -> dict:
    """
    Remove (cyl, head) entries whose head value is a corruption artefact.

    Legitimate heads appear on multiple cylinders and carry sectors whose
    numbers fall in the standard floppy range [1–18].  Corrupt track headers
    (e.g. from garbage segments with size2=0) produce head values that occur
    on only one cylinder, or carry only out-of-range sector numbers.

    A head value is trusted when at least two distinct cylinders have four or
    more sectors numbered 1–18 with 512 bytes of data.  If no head survives
    that test the original dict is returned unchanged so the caller can still
    emit a best-effort image.
    """
    from collections import Counter
    head_qual: Counter = Counter()
    for (c, h), smap in disk.items():
        good = sum(1 for s, d in smap.items() if 1 <= s <= 18 and len(d) >= 512)
        if good >= 4:
            head_qual[h] += 1

    trusted = {h for h, n in head_qual.items() if n >= 2}
    if not trusted:
        log.debug("filter_disk: no heads passed the quorum test — returning unfiltered dict")
        return disk

    dropped = {h for h in set(h for _, h in disk) if h not in trusted}
    if dropped:
        log.warning("filter_disk: dropping head value(s) %s — likely corrupt track headers",
                    sorted(dropped))

    return {k: v for k, v in disk.items() if k[1] in trusted}


def build_img(disk: dict) -> bytes:
    """
    Assemble a standard raw IMG from the disk map.
    Geometry is inferred from the track/sector data present.
    Output order: track0-side0-sec1, track0-side0-sec2, ..., track0-side1-sec1, ...
    (Standard DOS CHS interleave for .img files)

    Ghost tracks: the last segment often contains partial/padding track records
    with only 1 sector. We detect the true max cylinder as the highest one where
    ALL heads have a full sector complement.
    """
    if not disk:
        raise ValueError("No track data found")

    disk = filter_disk(disk)

    max_head = max(h for c, h in disk) + 1

    # Expected sector count = most common max-sector value across all tracks
    sec_counts = [max(smap.keys()) for smap in disk.values() if smap]
    max_sec    = max(set(sec_counts), key=sec_counts.count)

    # Find the highest cylinder where every head has a full sector map
    all_cyls = sorted(set(c for c, h in disk))
    true_max_cyl = 0
    for cyl in all_cyls:
        heads_ok = all(
            len(disk.get((cyl, h), {})) >= max_sec
            for h in range(max_head)
        )
        if heads_ok:
            true_max_cyl = cyl

    max_cyl = true_max_cyl + 1

    # Snap to nearest standard floppy geometry if close (within 2 cylinders)
    standard_cyls = {40: "360K", 80: "720K/1.44M/2.88M"}
    for std_cyl in sorted(standard_cyls):
        if abs(max_cyl - std_cyl) <= 2 and max_cyl <= std_cyl:
            log.info("Snapping geometry from %d to %d cylinders (%s)",
                     max_cyl, std_cyl, standard_cyls[std_cyl])
            max_cyl = std_cyl
            break

    log.info("Geometry: %d cylinders × %d heads × %d sectors = %d KB",
             max_cyl, max_head, max_sec,
             max_cyl * max_head * max_sec * 512 // 1024)

    img = bytearray()
    missing = 0

    for cyl in range(max_cyl):
        for head in range(max_head):
            smap = disk.get((cyl, head), {})
            for sec in range(1, max_sec + 1):
                data = smap.get(sec)
                if data is None:
                    log.debug("  Missing: c=%d h=%d s=%d — zero fill", cyl, head, sec)
                    img.extend(bytes(512))
                    missing += 1
                elif len(data) < 512:
                    img.extend(data.ljust(512, b'\x00'))
                elif len(data) > 512:
                    img.extend(data[:512])
                else:
                    img.extend(data)

    if missing:
        log.warning("%d sector(s) were missing and zero-filled", missing)

    return bytes(img)


# ── Probe mode ────────────────────────────────────────────────────────────────

def probe(raw: bytes) -> None:
    parse_header(raw)

    offset    = HEADER_SIZE
    seg_idx   = 0
    all_sizes = []

    while offset < len(raw):
        if offset + 2 > len(raw):
            break

        size1 = struct.unpack_from("<H", raw, offset)[0]
        if size1 == 0:
            print(f"\nSeg {seg_idx}: end-of-file marker at 0x{offset:X}")
            break

        size2_ofs = offset + 2 + size1
        if size2_ofs + 2 > len(raw):
            print(f"\nSeg {seg_idx}: truncated at 0x{offset:X}")
            break

        size2 = struct.unpack_from("<H", raw, size2_ofs)[0]
        n_tracks = size1 // TRACK_HDR_SIZE

        print(f"\nSeg {seg_idx}  offset=0x{offset:06X}  "
              f"size1={size1} ({n_tracks} tracks)  size2={size2}")

        # Show first few tracks
        shown = 0
        ofs1  = 0
        while (ofs1 + TRACK_HDR_SIZE) <= size1 and shown < 3:
            buf = raw[offset + 2 + ofs1: offset + 2 + ofs1 + TRACK_HDR_SIZE]
            trk = parse_track_header(buf)
            if trk.cyl or trk.head or trk.sectors:
                print(f"  Track c={trk.cyl:2d} h={trk.head}  {len(trk.sectors)} sectors", end="")
                for s in trk.sectors[:4]:
                    flag = ""
                    if s.data_offset is None: flag = "[NO_DATA]"
                    print(f"  s{s.sec}@0x{s.data_offset or 0:04X}{flag}", end="")
                print()
                shown += 1
            ofs1 += TRACK_HDR_SIZE

        all_sizes.append((size1, size2))
        offset += 2 + size1 + 2 + size2
        seg_idx += 1

    print(f"\nTotal segments: {seg_idx}")
    print(f"File size: {len(raw)}  Bytes parsed: {offset}")
    print(f"Unread: {len(raw) - offset}")


# ── Convert single file ───────────────────────────────────────────────────────

def convert(src: str, dst: str, probe_only: bool = False) -> bool:
    log.info("Reading : %s", src)
    with open(src, "rb") as f:
        raw = f.read()

    if probe_only:
        probe(raw)
        return True

    try:
        disk = load_cp2(raw)
    except Exception as e:
        log.error("Load failed: %s", e)
        return False

    try:
        img = build_img(disk)
    except Exception as e:
        log.error("Image build failed: %s", e)
        return False

    os.makedirs(os.path.dirname(os.path.abspath(dst)), exist_ok=True)
    with open(dst, "wb") as f:
        f.write(img)

    log.info("Written : %s (%d bytes)", dst, len(img))
    return True


# ── CLI ───────────────────────────────────────────────────────────────────────

def build_dst(src: str, out_dir: str | None) -> str:
    base = os.path.splitext(os.path.basename(src))[0] + ".img"
    return os.path.join(out_dir or os.path.dirname(os.path.abspath(src)), base)


def main():
    ap = argparse.ArgumentParser(description="Convert SOFTWARE PIRATES .cp2 → .img")
    ap.add_argument("source", help=".cp2 file or directory")
    ap.add_argument("output", nargs="?", help="Output .img (single file mode)")
    ap.add_argument("--output-dir", metavar="DIR")
    ap.add_argument("--probe", action="store_true",
                    help="Dump segment/track structure without converting")
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    src = args.source

    if os.path.isfile(src):
        dst = args.output or build_dst(src, args.output_dir)
        sys.exit(0 if convert(src, dst, args.probe) else 1)

    if os.path.isdir(src):
        files = sorted(
            os.path.join(src, f)
            for f in os.listdir(src)
            if f.lower().endswith(".cp2")
        )
        if not files:
            log.error("No .cp2 files in %s", src)
            sys.exit(1)

        log.info("Found %d file(s)", len(files))
        ok = fail = 0
        for path in files:
            dst = build_dst(path, args.output_dir)
            if convert(path, dst, args.probe):
                ok += 1
            else:
                fail += 1

        log.info("Done: %d ok, %d failed", ok, fail)
        sys.exit(0 if fail == 0 else 1)

    log.error("Not a file or directory: %r", src)
    sys.exit(1)


if __name__ == "__main__":
    main()
