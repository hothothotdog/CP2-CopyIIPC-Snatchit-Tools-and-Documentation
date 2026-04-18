#!/usr/bin/env python3
"""
cp2_check.py  —  Batch integrity checker for SOFTWARE PIRATES .cp2 disk images

Scans a folder (or a single file) for .cp2 files, runs a suite of validation
checks on each, and moves any file that has at least one ERROR or FATAL issue
into a "_Errors" subfolder alongside a companion .txt report.

Files with only WARNings (e.g. an unrecognised but otherwise healthy version
string) are left in place — they will convert normally.

Usage:
    python cp2_check.py /path/to/cp2s
    python cp2_check.py /path/to/cp2s --errors-dir /some/other/folder
    python cp2_check.py disk.cp2              # single-file mode
    python cp2_check.py /path/to/cp2s --dry-run   # report only, no moves
    python cp2_check.py /path/to/cp2s --verbose

Requires cp2_to_img.py and cp2_recover.py in the same directory (or PYTHONPATH).
"""

import sys
import os
import struct
import shutil
import argparse
import logging
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime

# ── Companion script imports ───────────────────────────────────────────────────

try:
    from cp2_to_img import (
        load_cp2, filter_disk, parse_header,
        MAGIC, KNOWN_VERSIONS, HEADER_SIZE,
    )
except ImportError:
    sys.exit("ERROR: cp2_to_img.py not found — place it alongside this script.")

try:
    from cp2_recover import (
        parse_bpb, guess_bpb_from_clusters,
        infer_disk_geometry, build_lba_map, read_lba,
    )
except ImportError:
    sys.exit("ERROR: cp2_recover.py not found — place it alongside this script.")

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

# Silence the imported modules while we run our own checks
_null_handler = logging.NullHandler()


# ── Issue severity ─────────────────────────────────────────────────────────────
#
#   FATAL  — file cannot be parsed at all; no recovery possible without raw repair
#   ERROR  — significant structural problem; recovery needs manual arguments
#   WARN   — minor anomaly; conversion will likely succeed but with caveats
#   INFO   — purely informational finding

SEVERITIES = ["FATAL", "ERROR", "WARN", "INFO"]

MOVES_TO_ERRORS = {"FATAL", "ERROR"}   # these trigger quarantine


@dataclass
class Issue:
    severity: str    # FATAL / ERROR / WARN / INFO
    code:     str    # short machine-readable tag
    message:  str    # human-readable description


@dataclass
class CheckResult:
    path:          Path
    issues:        list = field(default_factory=list)
    hints:         dict = field(default_factory=dict)   # arg → value for suggested command
    disk_summary:  dict = field(default_factory=dict)   # geometry / file count etc.

    @property
    def worst(self) -> str:
        """Highest severity code seen, or 'OK' if no issues."""
        for sev in SEVERITIES:
            if any(i.severity == sev for i in self.issues):
                return sev
        return "OK"

    @property
    def needs_quarantine(self) -> bool:
        return self.worst in MOVES_TO_ERRORS


# ── Individual checks ──────────────────────────────────────────────────────────

def _check_magic(raw: bytes, result: CheckResult) -> bool:
    """Return False (stop checking) if magic is wrong."""
    if raw[:16] != MAGIC:
        result.issues.append(Issue("FATAL", "BAD_MAGIC",
            f"File does not start with 'SOFTWARE PIRATES' magic bytes. "
            f"Got: {raw[:16]!r}. This is not a valid CP2 file."))
        return False
    return True


def _check_version(raw: bytes, result: CheckResult):
    version = raw[16:30].decode("cp437", errors="replace")
    if version not in KNOWN_VERSIONS:
        result.issues.append(Issue("WARN", "UNKNOWN_VERSION",
            f"Version string {version!r} is not in the known-good list. "
            f"Conversion will be attempted anyway but may produce incorrect output."))
    result.disk_summary["version"] = version.rstrip("\x00").rstrip("$0").rstrip()


def _check_segments(raw: bytes, result: CheckResult) -> dict | None:
    """Parse segments; return disk dict or None on failure."""
    # Suppress noisy log output from load_cp2 during our scan
    root_log = logging.getLogger()
    prev_level = root_log.level
    root_log.setLevel(logging.CRITICAL)
    try:
        disk = load_cp2(raw)
    except Exception as e:
        result.issues.append(Issue("FATAL", "PARSE_FAILED",
            f"Segment parsing raised an exception: {e}"))
        return None
    finally:
        root_log.setLevel(prev_level)

    if not disk:
        result.issues.append(Issue("FATAL", "NO_DATA",
            "No sector data was found in any segment."))
        return None

    # Count segments from the raw file
    seg_count = 0
    offset = HEADER_SIZE
    while offset < len(raw) - 1:
        size1 = struct.unpack_from("<H", raw, offset)[0]
        if size1 == 0:
            break
        size2_ofs = offset + 2 + size1
        if size2_ofs + 2 > len(raw):
            break
        size2 = struct.unpack_from("<H", raw, size2_ofs)[0]
        seg_count += 1
        offset += 2 + size1 + 2 + size2
        if offset >= len(raw):
            break

    result.disk_summary["segments"] = seg_count

    # Detect segments with size2=0 (track headers present but no sector data)
    phantom_segs = 0
    offset = HEADER_SIZE
    while offset < len(raw) - 1:
        size1 = struct.unpack_from("<H", raw, offset)[0]
        if size1 == 0:
            break
        size2_ofs = offset + 2 + size1
        if size2_ofs + 2 > len(raw):
            break
        size2 = struct.unpack_from("<H", raw, size2_ofs)[0]
        if size2 == 0 and size1 > 0:
            phantom_segs += 1
        offset += 2 + size1 + 2 + size2
        if offset >= len(raw):
            break

    if phantom_segs:
        result.issues.append(Issue("WARN", "PHANTOM_SEGMENTS",
            f"{phantom_segs} segment(s) contain track headers but zero sector data "
            f"(size2=0). These tracks will be zero-filled in the output image."))

    return disk


def _check_geometry(disk: dict, result: CheckResult) -> dict | None:
    """Filter geometry, report contamination, return filtered disk or None."""
    raw_heads = set(h for _, h in disk)

    root_log = logging.getLogger()
    prev_level = root_log.level
    root_log.setLevel(logging.CRITICAL)
    filtered = filter_disk(disk)
    root_log.setLevel(prev_level)

    dropped = raw_heads - set(h for _, h in filtered)

    if dropped:
        result.issues.append(Issue("ERROR", "BAD_GEOMETRY",
            f"Corrupt track headers detected: {len(dropped)} garbage head value(s) "
            f"found ({sorted(dropped)[:10]}{'…' if len(dropped)>10 else ''}). "
            f"These are caused by uninitialised memory in segment 1 (size2=0 segments). "
            f"filter_disk() will remove them automatically during conversion."))

    if not filtered:
        result.issues.append(Issue("FATAL", "NO_VALID_TRACKS",
            "No valid track data remains after geometry filtering. "
            "The file may be entirely corrupt."))
        return None

    return filtered


def _check_disk_extent(disk: dict, result: CheckResult) -> tuple:
    """Infer geometry, check for partial captures. Returns (max_cyl, num_heads, spt)."""
    num_heads = max(h for _, h in disk) + 1
    sec_counts = [max(smap.keys()) for smap in disk.values() if smap]
    spt = max(set(sec_counts), key=sec_counts.count)

    all_cyls = sorted(set(c for c, _ in disk))
    true_max = 0
    for cyl in all_cyls:
        if all(len(disk.get((cyl, h), {})) >= spt for h in range(num_heads)):
            true_max = cyl
    max_cyl = true_max + 1

    for std in [40, 80]:
        if abs(max_cyl - std) <= 2 and max_cyl <= std:
            max_cyl = std
            break

    expected = 40 if max_cyl <= 40 else 80
    pct = max_cyl / expected * 100

    result.disk_summary.update({
        "cylinders":  max_cyl,
        "heads":      num_heads,
        "sectors_per_track": spt,
        "total_lbas": max_cyl * num_heads * spt,
        "disk_kb":    max_cyl * num_heads * spt * 512 // 1024,
    })

    if max_cyl < 4:
        result.issues.append(Issue("ERROR", "PARTIAL_DISK",
            f"Only {max_cyl} cylinder(s) recovered out of an expected {expected} "
            f"({pct:.0f}%). The majority of file content will be zero-filled. "
            f"The source floppy was likely damaged when imaged."))
    elif max_cyl < expected * 0.9:
        result.issues.append(Issue("WARN", "PARTIAL_DISK",
            f"{max_cyl}/{expected} cylinders recovered ({pct:.0f}%). "
            f"Files in the latter portion of the disk will be incomplete."))

    return max_cyl, num_heads, spt


def _check_sectors(disk: dict, max_cyl: int, num_heads: int, spt: int,
                   result: CheckResult) -> dict:
    """Build LBA map, report missing sectors."""
    lba_map = build_lba_map(disk, max_cyl, num_heads, spt)
    total   = max_cyl * num_heads * spt
    missing = sum(1 for v in lba_map.values() if v is None)

    result.disk_summary["missing_sectors"] = missing
    result.disk_summary["total_sectors"]   = total

    if missing:
        pct = missing / total * 100
        sev = "ERROR" if pct > 25 else "WARN"
        result.issues.append(Issue(sev, "MISSING_SECTORS",
            f"{missing} of {total} sectors are absent ({pct:.1f}%). "
            f"Missing sectors are zero-filled in the output image and in extracted files."))

    return lba_map


def _check_bpb(lba_map: dict, disk: dict, result: CheckResult) -> tuple:
    """
    Try to read the BPB. Return (bpb, bpb_readable).
    Populates hints with data_start and spc regardless of source.
    """
    root_log = logging.getLogger()
    prev_level = root_log.level
    root_log.setLevel(logging.CRITICAL)

    sector0 = read_lba(lba_map, 0)
    bpb = parse_bpb(sector0)
    bpb_readable = bpb is not None

    if not bpb_readable:
        result.issues.append(Issue("WARN", "BPB_UNREADABLE",
            f"The boot sector does not contain a recognisable FAT12 BPB "
            f"(jump byte 0x{sector0[0]:02X} is not 0xEB or 0xE9, or other fields are zero). "
            f"cp2_recover.py will use a geometry fallback, but manual override flags "
            f"may be needed for correct extraction."))
        bpb = guess_bpb_from_clusters(disk)

    root_log.setLevel(prev_level)

    if bpb:
        result.hints["data_start"] = bpb.data_start
        result.hints["spc"]        = bpb.sectors_per_clus
        result.disk_summary["data_start_lba"] = bpb.data_start
        result.disk_summary["sectors_per_cluster"] = bpb.sectors_per_clus
        result.disk_summary["bpb_readable"] = bpb_readable

    return bpb, bpb_readable


def _check_directory(raw: bytes, lba_map: dict, bpb, bpb_readable: bool,
                     result: CheckResult):
    """
    Try to find and parse the root directory.
    When the BPB is readable, use the LBA map first.
    When unreadable, or when the LBA path yields garbage, fall back to
    scanning the raw CP2 byte stream directly.
    """
    files_from_bpb = []

    if bpb and bpb_readable:
        # Only attempt BPB-guided read when BPB is genuinely readable —
        # a guessed BPB may point root_dir_start at FAT/data sectors.
        from cp2_recover import read_dir_sectors, ATTR_VOLUME_ID, ATTR_DIRECTORY
        try:
            entries = read_dir_sectors(lba_map, bpb.root_dir_start,
                                       bpb.root_dir_sectors, skip_zero_sectors=True)
            for de in entries:
                if de.attr & (ATTR_VOLUME_ID | ATTR_DIRECTORY):
                    continue
                if de.file_size == 0 and de.start_cluster == 0:
                    continue
                # Sanity-check: filenames must be printable ASCII
                name_ok = all(0x20 <= ord(c) < 0x7F for c in de.raw_name
                              if c not in (' ', '\x00'))
                if not name_ok:
                    continue
                if de.file_size > 0x200000:   # >2MB on a floppy is garbage
                    continue
                files_from_bpb.append((de.filename, de.start_cluster, de.file_size))
        except Exception:
            pass

    # Always scan the raw CP2 byte stream — it's the ground truth for
    # non-standard disks where sectors are stored in interleaved order.
    dir_offset_raw = _scan_for_directory(raw)
    files_from_raw = []
    if dir_offset_raw is not None:
        from cp2_recover import parse_dir_bytes, ATTR_VOLUME_ID, ATTR_DIRECTORY
        dir_bytes = raw[dir_offset_raw:dir_offset_raw + 512]
        entries   = parse_dir_bytes(dir_bytes)
        for de in entries:
            if de.attr & (ATTR_VOLUME_ID | ATTR_DIRECTORY):
                continue
            if de.file_size == 0 and de.start_cluster == 0:
                continue
            name_ok = all(0x20 <= ord(c) < 0x7F for c in de.raw_name
                          if c not in (' ', '\x00'))
            if not name_ok:
                continue
            files_from_raw.append((de.filename, de.start_cluster, de.file_size))

    # Choose the best source: BPB path when it found clean entries,
    # raw stream otherwise (handles non-standard BPBs like FLASH604).
    if files_from_bpb:
        result.disk_summary["files_found"]   = len(files_from_bpb)
        result.disk_summary["dir_source"]    = "BPB (LBA map)"
        result.disk_summary["file_listing"]  = files_from_bpb
        # If the raw scan ALSO found entries at a different offset, note it
        if files_from_raw and dir_offset_raw is not None:
            result.hints["cp2_dir_offset_alt"] = f"0x{dir_offset_raw:X}"
    elif files_from_raw:
        result.disk_summary["files_found"]   = len(files_from_raw)
        result.disk_summary["dir_source"]    = f"raw CP2 offset 0x{dir_offset_raw:X}"
        result.disk_summary["file_listing"]  = files_from_raw
        result.hints["cp2_dir_offset"]       = f"0x{dir_offset_raw:X}"
        result.issues.append(Issue("INFO", "DIR_FOUND_IN_RAW_STREAM",
            f"Directory entries found at CP2 file offset 0x{dir_offset_raw:X} "
            f"({len(files_from_raw)} file(s)) by scanning the raw byte stream. "
            f"The BPB-guided LBA path could not locate them — use "
            f"--cp2-dir-offset 0x{dir_offset_raw:X} with cp2_recover.py."))
    else:
        result.issues.append(Issue("ERROR", "NO_DIRECTORY",
            "Could not locate any readable FAT12 root directory entries, "
            "either via the BPB or by scanning the raw CP2 byte stream. "
            "The filesystem metadata may be fully corrupted. "
            "Try cp2_carve.py with --aggressive for signature-based recovery."))


def _scan_for_directory(raw: bytes) -> int | None:
    """
    Scan the raw CP2 byte stream for a run of ≥4 contiguous valid-looking
    32-byte FAT12 directory entries.  Returns the byte offset of the first
    entry, or None if nothing plausible is found.
    """
    VALID_ATTRS = {0x00, 0x01, 0x20, 0x21, 0x10, 0x16, 0x30, 0x22, 0x06}
    for off in range(HEADER_SIZE, len(raw) - 128, 1):
        e = raw[off:off + 32]
        b0 = e[0]
        # First byte must be a printable ASCII char (valid DOS filename)
        if not (0x21 <= b0 <= 0x7E):
            continue
        attr = e[11]
        if attr not in VALID_ATTRS:
            continue
        sz = struct.unpack_from("<I", e, 28)[0]
        if sz > 0x400000:   # >4MB on a floppy = nonsense
            continue
        clus = struct.unpack_from("<H", e, 26)[0]
        if sz > 0 and clus == 0:
            continue

        # Require at least 3 more consecutive valid entries
        valid_run = 0
        for i in range(1, 5):
            e2 = raw[off + i*32 : off + i*32 + 32]
            if len(e2) < 32:
                break
            b2 = e2[0]
            if (0x21 <= b2 <= 0x7E or b2 == 0xE5) and e2[11] in VALID_ATTRS:
                sz2 = struct.unpack_from("<I", e2, 28)[0]
                if sz2 <= 0x400000:
                    valid_run += 1
        if valid_run >= 3:
            return off
    return None


# ── Main checker entry point ───────────────────────────────────────────────────

def check_cp2(path: Path) -> CheckResult:
    """Run all checks on a single CP2 file. Returns a populated CheckResult."""
    result = CheckResult(path=path)

    try:
        raw = path.read_bytes()
    except OSError as e:
        result.issues.append(Issue("FATAL", "READ_ERROR", f"Cannot read file: {e}"))
        return result

    result.disk_summary["file_size_bytes"] = len(raw)

    # Run checks in dependency order; abort early on fatal issues
    if not _check_magic(raw, result):
        return result

    _check_version(raw, result)

    disk = _check_segments(raw, result)
    if disk is None:
        return result

    disk = _check_geometry(disk, result)
    if disk is None:
        return result

    max_cyl, num_heads, spt = _check_disk_extent(disk, result)
    lba_map  = _check_sectors(disk, max_cyl, num_heads, spt, result)
    bpb, bpb_readable = _check_bpb(lba_map, disk, result)
    _check_directory(raw, lba_map, bpb, bpb_readable, result)

    return result


# ── Report generation ──────────────────────────────────────────────────────────

def _build_suggested_command(result: CheckResult) -> str:
    """
    Construct a suggested cp2_recover.py command line with actual values
    derived from the checks.
    """
    h     = result.hints
    fname = result.path.name
    stem  = result.path.stem
    parts = [f"python cp2_recover.py {fname}"]

    if "cp2_dir_offset" in h:
        parts.append(f"  --cp2-dir-offset {h['cp2_dir_offset']}")
        if result.disk_summary.get("sectors_per_cluster", 2) != 2:
            # non-default size — include
            parts.append(f"  --cp2-dir-size 512")

    if "data_start" in h:
        parts.append(f"  --data-start {h['data_start']}")

    if "spc" in h:
        parts.append(f"  --spc {h['spc']}")

    # If BPB was not readable, also suggest the fallback flags
    if not result.disk_summary.get("bpb_readable", True):
        parts.append(f"  --skip-zero-sectors")

    parts.append(f"  --out ./recovered_{stem}")

    return " \\\n".join(parts)


def _build_carve_command(result: CheckResult) -> str:
    fname = result.path.name
    stem  = result.path.stem
    return f"python cp2_carve.py {fname} --out ./carved_{stem}"


def generate_report(result: CheckResult) -> str:
    """Build the full text report for a quarantined file."""
    now   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    fname = result.path.name
    worst = result.worst
    ds    = result.disk_summary

    lines = []
    lines.append("=" * 70)
    lines.append(f"  cp2_check  —  integrity report")
    lines.append(f"  File    : {fname}")
    lines.append(f"  Checked : {now}")
    lines.append(f"  Status  : {worst}")
    lines.append("=" * 70)

    # Disk summary
    lines.append("")
    lines.append("── Disk summary ─────────────────────────────────────────────────────")
    if "version" in ds:
        lines.append(f"  Version          : {ds['version']}")
    if "segments" in ds:
        lines.append(f"  Segments         : {ds['segments']}")
    if "cylinders" in ds:
        lines.append(
            f"  Geometry         : {ds['cylinders']} cyl × {ds['heads']} head × "
            f"{ds['sectors_per_track']} sec/trk = {ds['disk_kb']} KB"
        )
    if "missing_sectors" in ds:
        lines.append(
            f"  Missing sectors  : {ds['missing_sectors']} / {ds['total_sectors']} "
            f"({ds['missing_sectors']/ds['total_sectors']*100:.1f}%)"
        )
    if "data_start_lba" in ds:
        lines.append(f"  Data start LBA   : {ds['data_start_lba']}")
    if "sectors_per_cluster" in ds:
        lines.append(f"  Sectors/cluster  : {ds['sectors_per_cluster']}")
    if "bpb_readable" in ds:
        lines.append(f"  BPB readable     : {'yes' if ds['bpb_readable'] else 'NO'}")
    if "dir_source" in ds:
        lines.append(f"  Directory source : {ds['dir_source']}")
    if "files_found" in ds:
        lines.append(f"  Files in dir     : {ds['files_found']}")

    # File listing
    if "file_listing" in ds and ds["file_listing"]:
        lines.append("")
        lines.append("── Files found in directory ──────────────────────────────────────────")
        lines.append(f"  {'Filename':<16}  {'Cluster':>8}  {'Size':>10}")
        lines.append(f"  {'─'*16}  {'─'*8}  {'─'*10}")
        for fname_e, clus, sz in ds["file_listing"]:
            lines.append(f"  {fname_e:<16}  {clus:>8}  {sz:>10}")

    # Issues
    lines.append("")
    lines.append("── Issues ────────────────────────────────────────────────────────────")
    if not result.issues:
        lines.append("  None.")
    else:
        for issue in result.issues:
            lines.append(f"")
            lines.append(f"  [{issue.severity}] {issue.code}")
            # Word-wrap the message at 66 chars
            words = issue.message.split()
            line  = "    "
            for word in words:
                if len(line) + len(word) + 1 > 70:
                    lines.append(line.rstrip())
                    line = "    " + word + " "
                else:
                    line += word + " "
            if line.strip():
                lines.append(line.rstrip())

    # Suggested recovery commands
    lines.append("")
    lines.append("── Suggested recovery commands ───────────────────────────────────────")
    lines.append("")
    lines.append("  Directory-driven extraction (cp2_recover.py):")
    lines.append("")
    for part in _build_suggested_command(result).splitlines():
        lines.append(f"    {part}")
    lines.append("")
    lines.append("  Signature carving fallback (cp2_carve.py):")
    lines.append("")
    lines.append(f"    {_build_carve_command(result)}")
    lines.append("")
    lines.append("── Notes ─────────────────────────────────────────────────────────────")
    lines.append("")

    # Tailored notes based on issues present
    codes = {i.code for i in result.issues}
    if "BAD_GEOMETRY" in codes:
        lines.append("  The geometry contamination is handled automatically — no extra")
        lines.append("  flags are needed for cp2_to_img.py or cp2_recover.py.")
    if "PARTIAL_DISK" in codes:
        lines.append("  Files whose cluster chains extend beyond the recovered cylinders")
        lines.append("  will be zero-padded in the output. Only the first few files on")
        lines.append("  the disk will be fully intact.")
    if "BPB_UNREADABLE" in codes:
        lines.append("  Because the BPB is corrupt, --data-start and --spc must be")
        lines.append("  supplied manually. The values shown above are derived from the")
        lines.append("  cluster gap analysis of the directory entries.")
    if "DIR_FOUND_IN_RAW_STREAM" in codes:
        lines.append("  --cp2-dir-offset bypasses the LBA map and reads directory entries")
        lines.append("  directly from the CP2 file's byte stream at the given offset.")
        lines.append("  This is needed when the sector interleave prevents normal assembly.")
    if "MISSING_SECTORS" in codes:
        lines.append("  Missing sectors are inherent to the source image — they cannot be")
        lines.append("  recovered from this CP2 file. The companion disk (if it exists)")
        lines.append("  may contain the data on the missing cylinders.")
    if not codes:
        lines.append("  No issues found. This line should not appear in an error report.")

    lines.append("")
    lines.append("=" * 70)
    return "\n".join(lines)


# ── Quarantine logic ───────────────────────────────────────────────────────────

def quarantine(result: CheckResult, errors_dir: Path, dry_run: bool) -> Path:
    """
    Move the CP2 file and its report into errors_dir.
    Returns the destination path.
    """
    errors_dir.mkdir(parents=True, exist_ok=True)

    dest_cp2  = errors_dir / result.path.name
    dest_txt  = errors_dir / (result.path.stem + "_report.txt")
    report    = generate_report(result)

    if dry_run:
        log.info("  [DRY-RUN] Would move to: %s", dest_cp2)
        log.info("  [DRY-RUN] Would write report: %s", dest_txt)
    else:
        shutil.move(str(result.path), dest_cp2)
        dest_txt.write_text(report, encoding="utf-8")
        log.info("  Moved   → %s", dest_cp2)
        log.info("  Report  → %s", dest_txt)

    return dest_cp2


# ── Console summary table ──────────────────────────────────────────────────────

def print_summary(results: list[CheckResult]) -> None:
    ok      = [r for r in results if r.worst == "OK"]
    warn    = [r for r in results if r.worst == "WARN"]
    errored = [r for r in results if r.needs_quarantine]

    print()
    print("┌─────────────────────────────────────────────────────────────────┐")
    print("│  cp2_check — summary                                            │")
    print("├────────────┬──────────────────────────────────────────────────┤")
    print(f"│  OK        │  {len(ok):<3}  {', '.join(r.path.name for r in ok[:5]):<44}│")
    print(f"│  WARN only │  {len(warn):<3}  {', '.join(r.path.name for r in warn[:5]):<44}│")
    print(f"│  Errors    │  {len(errored):<3}  {', '.join(r.path.name for r in errored[:5]):<44}│")
    print("└────────────┴──────────────────────────────────────────────────┘")

    if errored:
        print()
        print("  Files moved to _Errors:")
        for r in errored:
            worst_issue = next(i for i in r.issues if i.severity == r.worst)
            print(f"    {r.path.name:<30}  [{r.worst}] {worst_issue.code}")

    print()


# ── CLI ────────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="Batch integrity checker for SOFTWARE PIRATES .cp2 disk images"
    )
    ap.add_argument("source",
                    help="Directory containing .cp2 files, or a single .cp2 file")
    ap.add_argument("--errors-dir", metavar="DIR", default=None,
                    help="Where to move errored files (default: <source>/_Errors)")
    ap.add_argument("--dry-run", action="store_true",
                    help="Report issues without moving any files")
    ap.add_argument("--warn-moves", action="store_true",
                    help="Also quarantine files that have WARN-level issues "
                         "(default: only ERROR and FATAL trigger a move)")
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    src = Path(args.source)

    # Collect files to check
    if src.is_file():
        if src.suffix.lower() != ".cp2":
            log.warning("File %s does not have a .cp2 extension — checking anyway", src.name)
        files = [src]
        default_errors_dir = src.parent / "_Errors"
    elif src.is_dir():
        files = sorted(src.glob("*.cp2")) + sorted(src.glob("*.CP2"))
        # Deduplicate (case-insensitive filesystems)
        seen = set()
        files = [f for f in files if f.name.lower() not in seen and not seen.add(f.name.lower())]
        if not files:
            log.error("No .cp2 files found in %s", src)
            sys.exit(1)
        default_errors_dir = src / "_Errors"
    else:
        log.error("Not a file or directory: %s", src)
        sys.exit(1)

    errors_dir = Path(args.errors_dir) if args.errors_dir else default_errors_dir

    if args.warn_moves:
        global MOVES_TO_ERRORS
        MOVES_TO_ERRORS = {"FATAL", "ERROR", "WARN"}

    log.info("Checking %d file(s) ...", len(files))
    results = []

    for cp2_path in files:
        # Skip files already inside the _Errors folder
        if errors_dir in cp2_path.parents:
            continue

        log.info("  %s", cp2_path.name)
        result = check_cp2(cp2_path)
        results.append(result)

        # Log each issue at appropriate level
        for issue in result.issues:
            level = {
                "FATAL": logging.ERROR,
                "ERROR": logging.ERROR,
                "WARN":  logging.WARNING,
                "INFO":  logging.INFO,
            }.get(issue.severity, logging.INFO)
            log.log(level, "    [%s] %s: %s", issue.severity, issue.code,
                    issue.message[:100] + ("…" if len(issue.message) > 100 else ""))

        if result.needs_quarantine:
            quarantine(result, errors_dir, args.dry_run)
        else:
            log.info("    → %s (no quarantine needed)", result.worst)

    print_summary(results)

    # Exit code: 0 = all clean, 1 = some errors found
    sys.exit(0 if not any(r.needs_quarantine for r in results) else 1)


if __name__ == "__main__":
    main()
