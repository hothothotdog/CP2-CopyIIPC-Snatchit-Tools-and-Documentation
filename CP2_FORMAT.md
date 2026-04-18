# SOFTWARE PIRATES CP2 Disk Image Format

A reverse-engineered specification of the `.cp2` floppy disk image format
CP2 is the native image format of the CopyII PC / Snatchit disk imaging
utilities by Central Point Software produced by the **SOFTWARE PIRATES**
disk imaging utility for DOS.

This document was produced by analysing real CP2 files — including several
with structural corruption — alongside the C source of Hampa Hug's
[PCE emulator](http://www.hampa.ch/pce/) (`psi-img-cp2.c`, GPL2), which
provided the ground truth for the format's core layout. The corruption
analysis sections describe behaviour discovered empirically that is not
present in the original C source.

---

## Contents

1. [Overview](#1-overview)
2. [File Structure](#2-file-structure)
3. [File Header](#3-file-header)
4. [Segment Structure](#4-segment-structure)
5. [Track Header Block](#5-track-header-block)
6. [Sector Header](#6-sector-header)
7. [Sector Data Block](#7-sector-data-block)
8. [Resolving a Sector's Data](#8-resolving-a-sectors-data)
9. [End-of-File Marker](#9-end-of-file-marker)
10. [Sector Storage Order and Interleaving](#10-sector-storage-order-and-interleaving)
11. [Building a Raw Disk Image](#11-building-a-raw-disk-image)
12. [Known Corruption Patterns](#12-known-corruption-patterns)
13. [Worked Example](#13-worked-example)
14. [Constants Reference](#14-constants-reference)

---

## 1. Overview

CP2 is a track-by-track floppy disk image format. The file records the
raw FDC (Floppy Disk Controller) read results for each sector on each
track, including status flags (CRC errors, deleted data address marks,
missing address marks), and stores the sector data in a separate
contiguous block within each *segment*.

The format groups tracks into one or more **segments**. Each segment
contains a *track header block* (describing geometry and sector metadata)
followed by a *sector data block* (the raw sector bytes). Sectors within
the data block are not stored in logical order; they are stored in the
physical read order from the FDC and referenced by offset from within
that block.

A typical 360 KB floppy produces two segments: one covering the first
six or so cylinders, and one covering the remainder, though this varies
by imager version and disk size.

---

## 2. File Structure

```
┌──────────────────────────────────────────────┐
│  File Header (30 bytes)                      │
│    Magic: "SOFTWARE PIRATES" (16 bytes)      │
│    Version string (14 bytes)                 │
├──────────────────────────────────────────────┤
│  Segment 0                                   │
│  ┌────────────────────────────────────────┐  │
│  │  size1        uint16 LE                │  │
│  │  Track header block  (size1 bytes)     │  │
│  │  size2        uint16 LE                │  │
│  │  Sector data block   (size2 bytes)     │  │
│  └────────────────────────────────────────┘  │
│  Segment 1 …                                 │
│  Segment N …                                 │
├──────────────────────────────────────────────┤
│  End-of-segments marker: 0x0000 (uint16 LE)  │
└──────────────────────────────────────────────┘
```

All multi-byte integer fields are **little-endian**.

---

## 3. File Header

| Offset | Size | Field          | Notes                                      |
|--------|------|----------------|--------------------------------------------|
| 0      | 16   | Magic          | ASCII `SOFTWARE PIRATES` (no terminator)   |
| 16     | 14   | Version string | CP437, fixed 14 bytes, `$0`-terminated     |

**Total header size: 30 bytes.**

### Version strings

The version field is exactly 14 bytes. Known values (from PCE source):

| Version string (14 bytes, hex escaped)  | Imager version |
|-----------------------------------------|----------------|
| `Release 3.02$0`                        | 3.02           |
| `Release 3.07$0`                        | 3.07           |
| `Release 3.09$0`                        | 3.09           |
| `Release 4.00$0`                        | 4.00           |
| `Release 4.01$0`                        | 4.01           |
| `Release 4.02$0`                        | 4.02           |
| `Release 5.01$0`                        | 5.01           |
| `Release 6.0\x0a$0`                     | 6.0            |

Versions not in this list (e.g. `Release 4.05$0`, `Release 5.00$0`) have
been observed in the wild. Parsers should warn but continue rather than
reject the file.

---

## 4. Segment Structure

Immediately following the file header (and following each subsequent
segment), a segment begins with a 16-bit `size1` field:

```
Offset (from segment start)
  0        uint16 LE   size1  — byte length of the track header block
  2        [size1 bytes]      — track header block
  2+size1  uint16 LE   size2  — byte length of the sector data block
  4+size1  [size2 bytes]      — sector data block

Next segment starts at: offset + 2 + size1 + 2 + size2
```

- `size1` is always a multiple of 387 (the track header block size).
  `size1 / 387` gives the number of track records in this segment.
- `size2` is the total number of raw sector data bytes in this segment.
- If `size1 == 0`, this is the **end-of-segments marker** (see §9).

### Phantom segments

If `size2 == 0` while `size1 > 0`, the segment contains track header
records but **no sector data**. All sectors in such a segment must be
treated as absent (zero-filled in output). This occurs when the imager
encountered unreadable tracks and recorded the FDC geometry response but
could not retrieve data. The track header fields in phantom segments are
often filled with garbage values from uninitialised memory (see §12).

---

## 5. Track Header Block

The track header block is a sequence of **387-byte track records**,
one per track. The number of records is `size1 / 387`.

```
Track record layout (387 bytes):
  Offset  Size  Field
  0       1     Cylinder number (C)
  1       1     Head number (H)
  2       1     Sector count (number of valid sector headers, max 24)
  3       384   Sector headers: up to 24 × 16-byte sector header entries
```

The sector count at offset 2 is clamped to 24. If it is 0, the track
contains no readable sectors. Empty track records (all three header bytes
zero, no sectors) may appear as padding and should be skipped.

---

## 6. Sector Header

Each of the up to 24 sector header entries within a track record is
exactly **16 bytes**:

```
Byte  Field             Notes
 0    Read result       Raw FDC read result byte
 1    ST0               FDC status register 0
 2    ST1               FDC status register 1
                          bit 5 (0x20): CRC error flag
 3    ST2               FDC status register 2
                          bit 0 (0x01): no DAM (missing data address mark)
                          bit 5 (0x20): CRC error in data field
                          bit 6 (0x40): deleted data address mark
 4    C                 Cylinder ID as read from sector ID field
 5    H                 Head ID as read from sector ID field
 6    R                 Sector number as read from sector ID field
 7    N                 Size code: sector size = 128 << N
                          N=0 → 128 B,  N=1 → 256 B,  N=2 → 512 B
                          N=3 → 1024 B, N=4 → 2048 B, N=5 → 4096 B
                          N=6 → 8192 B (max stored), N>6 → not stored
 8-9  Data offset       uint16 LE — raw sector data offset (see §8)
10-15 Flags/unknown     Reserved; must be zero for data to be present
```

### CRC flags

If ST1 bit 5 is set:
- If ST2 bit 5 is also set → `flag_crc_data` (CRC error in data field)
- Otherwise → `flag_crc_id` (CRC error in ID field only)

### Skip conditions

A sector's data is **not stored** in the sector data block if any of
the following apply. In these cases the data offset field at bytes 8–9
is meaningless and the sector should be zero-filled:

- ST1 & `0x96` is non-zero (unexpected status bits)
- Bytes 10 or 11 are non-zero
- Byte 14 & `0x7F` is non-zero
- Byte 14 & `0x32` is non-zero
- Byte 15 is non-zero
- N > 6 (size code out of range)
- `flag_no_dam` is set (no data address mark)
- Sector size < 256 bytes (N < 1)
- Sector size > 4096 bytes (N > 5, after the N≤6 check above)
- Raw data offset < `SDATA_BIAS` (0x16AD) — indicates no data pointer

---

## 7. Sector Data Block

The sector data block immediately follows the `size2` field. It is a
flat array of raw sector bytes with **no internal structure or
separators**. Sectors are not stored in logical (CHS) order; they are
stored in the physical order they were read from the drive, which varies
by track and imager version.

Each sector's position within this block is given by its **data offset**
field (bytes 8–9 of the sector header), adjusted by `SDATA_BIAS`.

---

## 8. Resolving a Sector's Data

Given a valid sector header with data offset `raw_ofs` (bytes 8–9,
uint16 LE):

```
relative_offset = raw_ofs - SDATA_BIAS          # (SDATA_BIAS = 0x16AD = 5805)
absolute_offset = sector_data_block_start + relative_offset
sector_data     = file_bytes[absolute_offset : absolute_offset + sector_size]
```

where `sector_data_block_start` is the file offset of the first byte of
the sector data block for the *current segment*:

```
sector_data_block_start = segment_offset + 2 + size1 + 2
```

### SDATA_BIAS

The constant `0x16AD` (5805 decimal) is subtracted from the raw offset
field to yield a zero-based offset into the sector data block. Its value
corresponds to the minimum possible raw offset value that can appear in a
valid data pointer — offsets below this threshold indicate a missing or
invalid data reference. The constant originates from the DOS imaging
software's internal memory layout and is fixed across all known versions.

### Offset validity check

Before using a data offset, verify:

```python
if raw_ofs < SDATA_BIAS:
    # No data for this sector — zero-fill
    ...
if relative_offset < 0 or absolute_offset + sector_size > len(file):
    # Out-of-range — zero-fill and warn
    ...
```

---

## 9. End-of-File Marker

After the last segment, a two-byte end-of-segments marker is written:

```
uint16 LE value 0x0000
```

Any bytes following this marker are not part of the CP2 format and
should be ignored. In practice, some files contain appended binary data
(e.g. the executable code of the imaging software itself) after this
marker. This is benign and does not indicate corruption.

---

## 10. Sector Storage Order and Interleaving

Within the sector data block, sectors are stored in **FDC read order**,
not logical order. On a standard 9-sector-per-track floppy, the
interleave pattern within segment 0 of a 360 KB disk is:

```
Logical sector order:  S1  S2  S3  S4  S5  S6  S7  S8  S9
CP2 storage order:     S1  S3  S5  S7  S9  S2  S4  S6  S8
```

This means that the byte range `[sector_data_block_start, +size2)` does
**not** correspond to a simple sequential layout of the disk tracks.
Sector N's data can only be located by following its individual offset
pointer from the sector header.

**Practical consequence:** when extracting files by reading the raw CP2
byte stream at a known offset (e.g. `--cp2-dir-offset`), a run of
logically contiguous sectors may happen to be physically contiguous in
the CP2 file, but this is coincidental and depends on the specific track
geometry and imager behaviour. Always use the offset pointers from the
sector headers for reliable data location.

---

## 11. Building a Raw Disk Image

To produce a standard raw `.img` file (as used by emulators and `dd`):

1. Parse all segments and build a `(cylinder, head) → {sector_num: bytes}` map.
2. Determine geometry:
   - `max_head + 1` = number of heads
   - Most common `max(sector_num)` across all tracks = sectors per track (SPT)
   - Highest cylinder where **all** heads have a full sector complement = `max_cyl`
3. Snap `max_cyl` to the nearest standard floppy geometry if within 2:
   - 40 cylinders → 360 KB (40×2×9)
   - 80 cylinders → 720 KB / 1.44 MB / 2.88 MB (80×2×9/18/36)
4. Write sectors in standard CHS order:
   ```
   for cyl in 0..max_cyl:
     for head in 0..num_heads:
       for sec in 1..SPT:
         write sector_data[(cyl, head)][sec]  # zero-fill if absent
   ```

The CHS → LBA formula for the resulting image:

```
LBA = (cylinder × num_heads + head) × SPT + (sector - 1)
```

---

## 12. Known Corruption Patterns

These failure modes were identified by analysing real-world CP2 files
and are not described in the original C source.

### 12.1 Phantom segment geometry contamination

**Symptom:** Geometry inference produces absurd results (e.g. 1 cylinder
× 256 heads × 255 sectors) resulting in a ~32 MB output image.

**Cause:** When a segment has `size2 = 0`, its track header block was
written by the imaging software but the sector data block is empty. The
track header entries in these segments frequently contain uninitialised
memory from the imaging software's data segment rather than valid CHS
values. This produces head values of 32, 68, 139, 173, 227, 255, etc.
alongside the legitimate H=0 and H=1 entries. The maximum head value
across all parsed entries then inflates `num_heads` catastrophically.

**Detection:** After parsing, count how many distinct cylinder values
each head value appears on, weighted by having ≥ 4 sectors with numbers
in [1, 18] and 512 bytes of data. Head values appearing on fewer than 2
qualifying cylinders are garbage.

**Remedy:** Discard `(cylinder, head)` entries whose head value does not
pass the above quorum test before inferring geometry.

### 12.2 Non-standard boot sector

**Symptom:** The BPB parser rejects the boot sector; geometry must be
inferred from cluster gap analysis of directory entries.

**Cause:** Some imaged disks carry boot sectors that do not begin with
the standard FAT12 `0xEB xx 0x90` or `0xE9 xx xx` jump instruction
(e.g. jump byte `0x30` has been observed). These are valid DOS disks that
happen to use a custom or non-OEM bootstrap loader.

**Remedy:** Fall back to standard floppy geometry constants and/or
cluster gap analysis. For a disk with `spc=2`, the cluster gap between
consecutive files (derived from directory entries) confirms the
sectors-per-cluster value independently of the BPB.

### 12.3 Sub-sector-aligned directory

**Symptom:** The root directory cannot be found at the LBA derived from
the BPB (or the fallback geometry).

**Cause:** CP2's sector interleaving means that the sectors comprising
the root directory may be physically non-contiguous within the LBA map
even though they are contiguous in the CP2 byte stream. In the observed
case, the directory began 502 bytes into LBA 3 (in the middle of what
appears to be a FAT sector in the assembled image), because sector S=4
and sector S=6 of track 0 are stored adjacently in the CP2 file even
though they map to non-contiguous LBAs.

**Remedy:** Scan the raw CP2 byte stream for a run of ≥ 4 valid-looking
32-byte FAT12 directory entries (printable first byte, valid attribute
byte, plausible file size). The directory can be read directly from the
raw stream at the discovered offset.

### 12.4 Trailing data after EOF marker

**Symptom:** File contains hundreds of kilobytes of data after the
`0x0000` end-of-segments marker.

**Cause:** Observed in at least one file where the imaging software's
own executable code was appended to the image file, possibly as a
self-contained distribution format.

**Remedy:** Stop parsing at the `0x0000` marker. The trailing data is
not CP2 format and should be ignored.

### 12.5 Partial disk capture

**Symptom:** Only a small number of cylinders (e.g. 3 of 40) are
present; most files in the directory are zero-filled beyond their first
few sectors.

**Cause:** The source floppy was damaged when imaged. The imaging
software recorded the tracks it could read and stopped (or was
interrupted) before completing the disk. The directory and boot track
may be intact while the bulk of the data area is absent.

**Remedy:** Extract files using directory entries for names and sizes.
Mark extracted files as partial where sectors are missing.

---

## 13. Worked Example

### File header (offset 0x000)

```
Offset  Hex                              Field
000000  53 4F 46 54 57 41 52 45 20 50    Magic: "SOFTWARE PI"
000008  49 52 41 54 45 53              → Magic: "RATES"
000010  52 65 6C 65 61 73 65 20 35 2E    Version: "Release 5."
000018  30 30 24 30                    → Version: "00$0"  (= "Release 5.00$0")
```

### First segment (offset 0x01E = 30)

```
00001E  21 12        size1 = 0x1221 = 4645  (4645 / 387 = 12 track records)
000020  [4645 bytes of track header block]
00131B  24 2E        size2 = 0x2E24 = 11812
00131D  [11812 bytes of sector data block]
```

### First track record (offset 0x0020)

```
000020  00           Cylinder = 0
000021  00           Head = 0
000022  09           Sector count = 9
000023  [9 × 16-byte sector headers follow]
```

### First sector header (offset 0x0023)

```
000023  00           Read result
000024  00           ST0
000025  00           ST1
000026  00           ST2
000027  00           C = 0 (cylinder)
000028  00           H = 0 (head)
000029  01           R = 1 (sector number)
00002A  02           N = 2 → sector size = 128 << 2 = 512 bytes
00002B  AD 16        raw_ofs = 0x16AD
00002D  00 00 90 02 00 00   flags (all zero = data present)
```

Resolving sector data:
```
relative_offset = 0x16AD - 0x16AD = 0x0000
absolute_offset = 0x131D + 0x0000 = 0x131D
sector_data     = file[0x131D : 0x151D]   (512 bytes)
```

This is the first physical sector of the disk (C=0, H=0, S=1), which
on a standard FAT12 floppy is the boot sector.

---

## 14. Constants Reference

| Constant        | Value    | Description                                        |
|-----------------|----------|----------------------------------------------------|
| `MAGIC`         | `SOFTWARE PIRATES` | File identification string (16 bytes)  |
| `HEADER_SIZE`   | 30       | Bytes before first segment                         |
| `TRACK_HDR_SIZE`| 387      | Bytes per track record (3 + 24×16)                 |
| `MAX_SECTORS`   | 24       | Maximum sectors per track record                   |
| `SDATA_BIAS`    | 0x16AD   | Subtracted from raw sector offset to get relative position in sector data block |

---

## References

- Hampa Hug, **PCE — PC emulator and utilities**, `psi-img-cp2.c`  
  http://www.hampa.ch/pce/  
  The canonical C implementation; source of the track/sector header
  layouts, `SDATA_BIAS`, and skip conditions documented here.

- **SOFTWARE PIRATES** disk imaging utility for DOS (various versions
  3.02 – 6.0). Closed-source; the format was inferred from its output.

---

*This document was produced through analysis of real CP2 files and the
PCE source code. Corrections and additional version string observations
are welcome.*
