# cp2_check.py

Batch integrity checker for SOFTWARE PIRATES `.cp2` disk images.
Scans a folder (or a single file), runs a suite of structural checks on
each image, and moves any file with an ERROR or FATAL issue into a
`_Errors` subfolder alongside a plain-text report.

Files with only WARN-level findings are left in place — they will
convert normally. Files that pass all checks are left in place silently.

Requires `cp2_to_img.py` and `cp2_recover.py` in the same directory.

---

## Usage

```
python cp2_check.py /path/to/collection
python cp2_check.py disk.cp2
python cp2_check.py /path/to/collection --dry-run
python cp2_check.py /path/to/collection --errors-dir /other/folder
python cp2_check.py /path/to/collection --warn-moves
```

---

## Options

| Flag | Description |
|---|---|
| `--errors-dir DIR` | Where to move errored files (default: `<source>/_Errors`) |
| `--dry-run` | Report and print without moving any files |
| `--warn-moves` | Also quarantine WARN-level files (default: ERROR and FATAL only) |
| `--verbose` / `-v` | Enable debug logging |

---

## Checks performed

| Code | Severity | What it detects |
|---|---|---|
| `BAD_MAGIC` | FATAL | File does not start with `SOFTWARE PIRATES` |
| `UNKNOWN_VERSION` | WARN | Version string not in the known-good list |
| `PARSE_FAILED` | FATAL | Segment parsing raises an exception |
| `PHANTOM_SEGMENTS` | WARN | Segments with `size2=0` (track headers, no data) |
| `BAD_GEOMETRY` | ERROR | Garbage head values from corrupt track headers |
| `PARTIAL_DISK` | ERROR/WARN | Fewer cylinders than expected for the disk format |
| `MISSING_SECTORS` | ERROR/WARN | Gaps in the captured sector data |
| `BPB_UNREADABLE` | WARN | Boot sector lacks a valid FAT12 BPB |
| `NO_DIRECTORY` | ERROR | No FAT12 directory entries found by any method |
| `DIR_FOUND_IN_RAW_STREAM` | INFO | Directory located by raw byte scan; LBA map path failed |

`PARTIAL_DISK` is ERROR when fewer than 4 cylinders are recovered, WARN
when coverage is between 4 and 90% of the expected geometry.
`MISSING_SECTORS` is ERROR above 25% missing, WARN otherwise.

---

## Report file

Each quarantined file gets a companion `<stem>_report.txt` containing:

- **Disk summary** — version, segment count, geometry, missing sector
  percentage, BPB status, directory source, and a file listing
- **Issues** — every finding with full description
- **Suggested recovery commands** — ready-to-paste `cp2_recover.py` and
  `cp2_carve.py` command lines with actual values filled in, for example:

```
python cp2_recover.py 500-FLASH604.CP2 \
  --cp2-dir-offset 0x203D \
  --data-start 12 \
  --spc 2 \
  --skip-zero-sectors \
  --out ./recovered_500-FLASH604
```

The `--cp2-dir-offset` value is discovered automatically by scanning the
raw CP2 byte stream for a plausible run of directory entries.

- **Notes** — plain-English explanation of each issue and its
  implications for recovery

---

## Console output

After processing all files a summary table is printed:

```
┌─────────────────────────────────────────────────────────────────┐
│  cp2_check — summary                                            │
├────────────┬──────────────────────────────────────────────────┤
│  OK        │  12   GAME1.CP2, GAME2.CP2, ...                  │
│  WARN only │  3    UTIL1.CP2, UTIL2.CP2, UTIL3.CP2            │
│  Errors    │  2    BROKEN1.CP2, BROKEN2.CP2                   │
└────────────┴──────────────────────────────────────────────────┘

  Files moved to _Errors:
    BROKEN1.CP2                    [ERROR] BAD_GEOMETRY
    BROKEN2.CP2                    [FATAL] PARSE_FAILED
```

Exit code is `0` if all files pass, `1` if any were quarantined.

---

## Recommended workflow

```bash
# 1. Check everything first
python cp2_check.py /collection --dry-run

# 2. Quarantine and report
python cp2_check.py /collection

# 3. Convert the healthy files in bulk
for f in /collection/*.cp2; do
    python cp2_to_img.py "$f" --output-dir ./images
done

# 4. Work through _Errors manually using each report's suggested command
```
