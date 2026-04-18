# cp2_to_img.py

Converts a SOFTWARE PIRATES `.cp2` floppy disk image to a standard raw
`.img` file suitable for use with emulators, `dd`, or filesystem tools.

This is the base script. `cp2_recover.py`, `cp2_carve.py`, and
`cp2_check.py` all import from it.

---

## Usage

```
python cp2_to_img.py disk.cp2
python cp2_to_img.py disk.cp2 output.img
python cp2_to_img.py /folder/of/cp2s
python cp2_to_img.py /folder/of/cp2s --output-dir /target
python cp2_to_img.py disk.cp2 --probe
python cp2_to_img.py disk.cp2 --probe --verbose
```

With no output argument, the `.img` is written alongside the source file
with the same stem. In directory mode, all `.cp2` files are processed in
order; failures are reported and counted but do not stop the batch.

---

## Options

| Flag | Description |
|---|---|
| `output` | Output `.img` path (single-file mode only) |
| `--output-dir DIR` | Directory for output files (batch mode) |
| `--probe` | Print segment and track structure; do not write output |
| `--verbose` / `-v` | Enable debug-level logging |

---

## Output

The output is a flat raw sector image in standard CHS order:

```
cylinder 0, head 0, sector 1
cylinder 0, head 0, sector 2
...
cylinder 0, head 1, sector 1
...
cylinder N, head M, sector SPT
```

Each sector is exactly 512 bytes. Missing sectors are zero-filled.
Geometry is snapped to the nearest standard floppy size (40 or 80
cylinders) if within two cylinders.

---

## Geometry filtering

Before inferring geometry, `filter_disk()` removes `(cylinder, head)`
entries whose head value appears on fewer than two cylinders with four
or more sectors numbered 1–18. This eliminates the garbage head values
(32, 68, 139, 173, 255, etc.) that appear in phantom segments (`size2=0`)
due to uninitialised memory in the imaging software.

Without this filter, a single corrupt segment can cause the inferred
geometry to expand to 256 heads × 255 sectors, producing a ~32 MB output
image that is almost entirely zeros.

The filter is a no-op on healthy files.

---

## Probe mode

`--probe` prints a summary of every segment, its track count and sector
data size, and the first few tracks of each. Useful for understanding a
file's structure before attempting conversion:

```
Seg 0  offset=0x00001E  size1=4645 (12 tracks)  size2=11828
  Track c= 0 h=0  9 sectors  s1@0x16AD  s2@0x20AD ...
  Track c= 0 h=1  9 sectors  s1@0x28AD ...

Seg 1  offset=0x00407B  size1=50263 (129 tracks)  size2=0
  Track c=62 h=34  0 sectors    ← phantom segment
```

A `size2=0` segment with garbage CHS values is the signature of
the phantom segment geometry problem described above.

---

## Importable API

```python
from cp2_to_img import load_cp2, filter_disk

raw  = open("disk.cp2", "rb").read()
disk = load_cp2(raw)       # {(cyl, head): {sector_num: bytes}}
disk = filter_disk(disk)   # remove corrupt geometry entries
```

`load_cp2` returns a dict mapping `(cylinder, head)` tuples to dicts of
`{sector_number: bytes}`. `filter_disk` returns a filtered copy of that
dict. Both are used by the other three scripts.
