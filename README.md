# cp2-tools

A Python toolkit for converting, recovering, and validating floppy disk
images in the **SOFTWARE PIRATES `.cp2`** format.

The CP2 format was produced by the SOFTWARE PIRATES disk imaging utility
for DOS (versions 3.02 – 6.0). It stores raw FDC read results track by
track, including sector status flags and an interleaved sector data block.
See [`CP2_FORMAT.md`](CP2_FORMAT.md) for the full format specification.

---

## Scripts

| Script | Purpose |
|---|---|
| [`cp2_to_img.py`](cp2_to_img.py) | Convert `.cp2` → raw `.img` |
| [`cp2_recover.py`](cp2_recover.py) | Extract files by name using directory entries |
| [`cp2_carve.py`](cp2_carve.py) | Recover files by magic-byte signature scanning |
| [`cp2_check.py`](cp2_check.py) | Batch integrity checker; quarantines broken files |

`cp2_recover.py` and `cp2_carve.py` import from `cp2_to_img.py`.
`cp2_check.py` imports from both. Keep all four scripts in the same
directory.

---

## Quick start

```bash
# Convert a disk image
python cp2_to_img.py disk.cp2

# Check a folder of CP2 files for problems
python cp2_check.py /path/to/collection

# Extract files from a healthy disk
python cp2_recover.py disk.cp2 --out ./recovered

# Recover files when the FAT is corrupt
python cp2_carve.py disk.cp2 --out ./carved
```

---

## Requirements

Python 3.10 or later. No third-party packages.

---

## Handling corrupt images

Run `cp2_check.py` first. It detects common problems and writes a
companion report with suggested arguments for `cp2_recover.py` — including
`--cp2-dir-offset`, `--data-start`, and `--spc` values derived from the
file itself.

Recovery strategy by problem type:

| Problem | Tool | Notes |
|---|---|---|
| Healthy FAT | `cp2_recover.py` | Files extracted with correct names and sizes |
| Corrupt FAT, intact directory | `cp2_recover.py` | Contiguous cluster extraction; no FAT chain needed |
| Non-standard BPB | `cp2_recover.py --cp2-dir-offset` | Directory read from raw CP2 byte stream |
| Corrupt or missing directory | `cp2_carve.py` | Signature scanning; no filesystem metadata needed |
| Partial disk capture | `cp2_recover.py` | Files extracted; missing sectors zero-filled |

---

## Format notes

Two structural issues are handled automatically:

**Phantom segment geometry contamination.** Segments with `size2=0`
(track headers present, no sector data) frequently contain uninitialised
memory in their track header fields, producing garbage head values that
inflate the inferred disk geometry. `cp2_to_img.py` filters these out
via a quorum test before geometry is calculated.

**Interleaved sector storage.** Sectors within the data block are stored
in FDC read order, not logical order. This means sector data for
logically adjacent sectors may appear non-contiguously in the LBA map.
`cp2_recover.py --cp2-dir-offset` addresses cases where this prevents
normal directory location.

Full details of these and other failure modes are in the format
specification.

---

## Acknowledgements

The CP2 format was originally reverse-engineered from
[`psi-img-cp2.c`](http://www.hampa.ch/pce/) by Hampa Hug (PCE project,
GPL2), which provided the ground truth for the core format layout,
`SDATA_BIAS`, and sector skip conditions. The corruption analysis and
recovery strategies were developed independently through examination of
real-world damaged images.

---

## Contributing

Additional CP2 samples — particularly from imager versions not yet in
the known-version list, or with unusual failure modes — are welcome.
The format specification will be updated as new variants are observed.
