# cp2_carve.py

Recovers files from a SOFTWARE PIRATES `.cp2` image by scanning raw
sector data for known file signatures (magic bytes), with no dependency
on the FAT, BPB, or directory entries. Use this when the filesystem
metadata is too corrupt for `cp2_recover.py` to work.

Requires `cp2_to_img.py` in the same directory.

---

## Usage

```
python cp2_carve.py disk.cp2
python cp2_carve.py disk.cp2 --out ./carved
python cp2_carve.py disk.cp2 --probe
python cp2_carve.py disk.cp2 --aggressive
python cp2_carve.py disk.cp2 --min-size 128 --max-size 200000
```

---

## Options

| Flag | Description |
|---|---|
| `--out DIR` | Output directory (default: `./carved`) |
| `--probe` | Print sector map with signature hits; do not write files |
| `--aggressive` | Also attempt `.COM` file recovery (many false positives) |
| `--min-size BYTES` | Discard hits smaller than N bytes (default: 16) |
| `--max-size BYTES` | Cap each carved file at N bytes; 0 = unlimited (default: 0) |
| `--verbose` / `-v` | Enable debug logging |

---

## How it works

The CP2 is parsed and filtered using `cp2_to_img.load_cp2()` and
`filter_disk()`. The sector dict is then converted to a flat LBA map
using standard CHS→LBA formula.

A single forward pass scans every LBA for known file signatures. On a
hit, sectors are greedily collected forward until one of four stop
conditions:

1. A sector is absent from the parsed CP2 data
2. A sector is all zeros (treated as unallocated gap)
3. A new file signature starts (next file begins here)
4. `--max-size` cap is reached

Collected bytes are trimmed and written as individual files. Previously
claimed LBAs are skipped so sectors are not double-attributed.

---

## Recognised signatures

Archives: ZIP, RAR, ARJ, LZH/LHA, ARC, GZ, BZ2, XZ  
Executables: MZ (DOS/Windows), SZDD/KWAJ (MS-compressed)  
Images: PNG, GIF, JPEG, BMP, TIFF, PCX  
Audio: WAV/RIFF, VOC, MP3, OGG, IFF  
Documents: PDF, RTF, MS Office OLE2  
DOS: batch files (ECHO OFF/ON), boot sectors  

`.COM` files have no magic bytes and are only attempted in `--aggressive`
mode, using heuristics based on common first-byte patterns (`JMP near`,
`JMP short`, `MOV AH`, `INT 21h`). This produces many false positives
and is best used when other methods have failed.

---

## Output

Recovered files are named `carved_0000.ext`, `carved_0001.ext`, etc.
Two summary files are always written:

- **`summary.txt`** — table of all carved files with start LBA, sector
  count, byte size, and signature description
- **`manifest.json`** — machine-readable version of the same information

---

## Probe mode

`--probe` prints a compact sector map showing which LBAs contain data
and which contain recognised file signatures, without writing any files:

```
Sector map  (720 total LBAs, 512 bytes each)

  LBA     Type     First 16 bytes (hex)
  ──────  ────────  ───────────────────────────────────────────────
  0       BOOT      eb 34 90 4d 53 44 4f 53 ...
  1       data      f9 ff ff 00 00 00 00 00 ...
  ...
  12      EXE       4d 5a 90 00 03 00 00 00 ...
  ... 14 empty/missing sector(s) ...
  27      EXE       4d 5a 50 00 02 00 00 00 ...
```

---

## Limitations

- Carved files are named generically; original filenames are not
  recoverable without directory metadata.
- Files whose first sector does not begin with a recognised signature
  will not be found. Most DOS program types are covered, but custom or
  compressed formats may be missed.
- The stop conditions may terminate a file early if it contains an
  all-zero sector or a coincidental magic byte sequence mid-file.
  `--max-size 0` (unlimited) and `--min-size 16` are conservative
  defaults that work well for typical floppy content.
