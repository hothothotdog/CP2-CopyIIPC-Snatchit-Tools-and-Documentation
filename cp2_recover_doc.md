# cp2_recover.py

Extracts files from a SOFTWARE PIRATES `.cp2` image using the FAT12
directory entries to determine filenames, cluster positions, and exact
sizes. Works even when the FAT chain is fully corrupt, because DOS
floppies are written sequentially and files can be read as contiguous
runs of clusters from their starting cluster.

Subdirectories are walked recursively and the original folder structure
is preserved in the output.

Requires `cp2_to_img.py` in the same directory.

---

## Usage

```
python cp2_recover.py disk.cp2
python cp2_recover.py disk.cp2 --out ./recovered
python cp2_recover.py disk.cp2 --probe
python cp2_recover.py disk.cp2 --cp2-dir-offset 0x203D --data-start 12 --spc 2
```

---

## Options

| Flag | Description |
|---|---|
| `--out DIR` | Output directory (default: `./recovered`) |
| `--probe` | Show BPB and directory tree only; do not extract |
| `--carve-extra` | Also carve unclaimed sectors after directory extraction |
| `--verbose` / `-v` | Enable debug logging |

### Geometry overrides

Used when the BPB is unreadable or incorrect. Values can be determined
from `cp2_check.py` output or from manual inspection.

| Flag | Description |
|---|---|
| `--data-start LBA` | Override data area start LBA |
| `--spc N` | Override sectors per cluster |
| `--root-dir-lba LBA` | Override root directory start LBA |
| `--root-dir-sectors N` | Override number of root directory sectors |
| `--root-dir-skip BYTES` | Skip N bytes at the start of the root directory sector |
| `--skip-zero-sectors` | Skip near-zero sectors (≥95% zeros) when reading directory regions |

### Non-standard directory location

| Flag | Description |
|---|---|
| `--cp2-dir-offset OFFSET` | Read directory entries directly from the raw CP2 byte stream at this offset (hex or decimal) |
| `--cp2-dir-size BYTES` | Bytes to read from `--cp2-dir-offset` (default: 512) |

`--cp2-dir-offset` bypasses the LBA map entirely. It is needed when
the sector interleave stores directory sectors non-contiguously in the
assembled image even though they appear contiguous in the CP2 file.
`cp2_check.py` detects this automatically and suggests the correct value.

---

## Output

Each recovered file is written at its original path relative to the
output directory, preserving subdirectory structure:

```
recovered/
  COMMAND.COM
  AUTOEXEC.BAT
  UTILS/
    FORMAT.COM
    CHKDSK.COM
```

Two summary files are always written:

- **`summary.txt`** — table of all recovered files with cluster, LBA,
  size, and status (OK or PARTIAL with missing sector count)
- **`manifest.json`** — machine-readable version of the same information

---

## Recovery strategy

1. Parse the CP2 file and build a flat LBA map.
2. Read the BPB from LBA 0. If unreadable, fall back to standard
   floppy geometry constants.
3. Apply any CLI geometry overrides.
4. Walk the root directory recursively, descending into subdirectories.
5. For each file: locate its starting LBA from `cluster_to_lba()`,
   read `ceil(size / 512)` contiguous sectors, trim to exact byte size.
6. Missing sectors are zero-filled and counted in the manifest.

The contiguous cluster assumption holds for standard floppy writes.
Heavily fragmented disks (uncommon on floppies) may produce incorrect
output for files whose clusters are not contiguous; FAT chain walking
would be required in that case.

---

## When to use which recovery tool

| Situation | Tool |
|---|---|
| Filesystem intact | `cp2_recover.py` (default) |
| FAT corrupt, directory readable | `cp2_recover.py` (still works) |
| BPB unreadable | `cp2_recover.py --data-start --spc` |
| Directory not at BPB location | `cp2_recover.py --cp2-dir-offset` |
| Directory missing or corrupt | `cp2_carve.py` |
