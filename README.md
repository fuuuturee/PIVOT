# PIVOT — Forensic Artifact Pivot Engine

**PIVOT** turns scattered Windows artifacts into one connected evidence graph.

It parses Prefetch, Shell Link and PE files, extracts a common layer of
*identifiers* (paths, prefetch hashes, volume serials, MD5/imphash/Rich values)
and lets you pivot from any single one of them to everything else that belongs
to the same object — plus a chronological timeline and a list of hashes that
could **not** be resolved.

```
   LNK  ──path:discord.exe────────────────┐
   PE   ──md5: / imphash: / richkey:─────┼──▶  PIVOT index  ──▶  show / resolve
   PF   ──pfhash:7438817f────────────────┘         │            timeline
   path:<candidate> ──▶ prefetch hash resolution ───┘            unresolved
```

* Single self-contained C++20 binary, no runtime dependencies, no third-party libraries.
* Reads only — PIVOT never modifies the evidence.
* Every parser validates what it finds; implausible values become `warning:`
  fields instead of silently wrong output.

---

## Table of contents

- [Quick start](#quick-start)
- [Why "pivot"?](#why-pivot)
- [Command reference](#command-reference)
- [Identifier scheme](#identifier-scheme)
- [Prefetch hash resolution](#prefetch-hash-resolution)
- [Supported artifacts](#supported-artifacts)
- [Data model](#data-model)
- [Project layout](#project-layout)
- [Testing](#testing)
- [Limitations](#limitations)
- [Roadmap](#roadmap)
- [License](#license)

---

## Quick start

### Build

Requires Windows + MSVC (Visual Studio 2022 or newer, C++ workload).
`build.bat` locates the toolchain itself.

```cmd
build.bat release      :: -> bin\release\pivot.exe
build.bat debug
```

<details>
<summary>Manual build</summary>

```cmd
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
cl /nologo /std:c++20 /EHsc /W3 /D_CRT_SECURE_NO_WARNINGS /O2 /I src ^
   src\main.cpp src\record.cpp src\util.cpp src\index.cpp ^
   src\parsers\prefetch.cpp src\parsers\lnk.cpp src\parsers\pe.cpp ^
   /Fe:pivot.exe
```

</details>

### 60-second tour

```cmd
:: 1. ingest artifacts (files and/or directories, -r for recursion)
pivot ingest C:\Evidence\Prefetch C:\Evidence\StartMenu ^
        --store case.store --json case.json

:: 2. what identifiers do we have, and how often?
pivot ids --store case.store --limit 20

:: 3. everything that belongs to one object
pivot show "path:c:\users\rrifa\appdata\local\discord\discord.exe" --store case.store -v

:: 4. turn a prefetch hash back into a path
pivot resolve pfhash:7438817f --store case.store --candidates candidates.txt

:: 5. which prefetch hashes could not be resolved at all?
pivot unresolved --store case.store --candidates candidates.txt

:: 6. put all of it in chronological order
pivot timeline --store case.store --from 2026-01-01 --to 2026-02-01
```

Real output from the shipped test fixtures:

```text
> pivot ids --store case.store --limit 8
3          path:\ntdll.dll
3          path:ntdll.dll
3          pref:testapp.exe
2          device:c:\
2          vserial:1234abcd
1          path:\config.dll
1          path:explorer.exe
1          path:kernel32.dll
... (20 identifiers total)

> pivot resolve pfhash:7438817f --store case.store --candidates candidates.txt
hash 7438817f -> 1 candidate path(s) [18 candidates tested]
  ror13-add C:\PROGRAM FILES\TESTAPP\TESTAPP.EXE C:\Program Files\TestApp\TestApp.exe

> pivot stats --store case.store
records    : 8
identifiers: 28
candidates : 12
  prefetch     3
  prefetch.ref 5
time range : 2025-12-31T22:00:00Z .. 2026-01-01T00:00:00Z
```

---

## Why "pivot"?

In an investigation you rarely start with the question *"show me all Prefetch
files"*. You start with one handle on the object — a path, a hash, a volume
serial — and want to know everything else that touches it.

PIVOT models that directly:

1. Every parser emits **Records** — a normalized unit (`kind`, `source`,
   `fields`, `times`) that carries **identifiers**.
2. The **index** maps every identifier to the records that carry it.
3. A question like *"what else refers to `discord.exe`?"* becomes a single
   identifier lookup, regardless of which artifact type the answer comes from.

A Prefetch file only ever stores the **file name** of the images it references,
never the full path — so a prefetch hash cannot be resolved by reading the
Prefetch file alone. PIVOT therefore keeps a candidate-path pool (from every
ingested `path:` identifier plus an optional `--candidates` file) and hashes
every candidate in every known Windows variant. Hashes that match nothing stay
visible in `unresolved` — an open lead, not a silent drop.

---

## Command reference

| Command | Purpose |
|---|---|
| `pivot ingest <paths...>` | Parse artifacts into the store. `--store F`, `--json F`, `--candidates F`, `-r` recursive. |
| `pivot ids` | List identifiers with usage counts. `--kind TYPE` (record kind, e.g. `pe`), `--limit N`. |
| `pivot show <identifier>` | All records carrying that identifier. Exact match, otherwise substring search. `-v` for all fields. |
| `pivot resolve <hash>` | Resolve a prefetch hash to candidate paths. `--candidates F`. |
| `pivot unresolved` | Prefetch hashes that matched no candidate path. `--candidates F`. |
| `pivot timeline` | Records in chronological order. `--kind K`, `--from ISO`, `--to ISO`. |
| `pivot records` | Raw record dump. `--kind K`, `--json F`. |
| `pivot stats` | Record/identifier counts and the overall time range. |
| `pivot --version` / `--help` | Version / usage. |

Common flags: `--store F` (default `pivot.store`) selects the binary index.

---

## Identifier scheme

Identifiers are lower-case, prefixed by type. They are the pivoting surface.

| Prefix | Example | Source |
|---|---|---|
| `path:` | `path:c:\users\rrifa\appdata\local\discord\discord.exe` | LNK target, PE file path, prefetch file name |
| `pfhash:` | `pfhash:7438817f` | Prefetch (file header **and** file name) |
| `vserial:` | `vserial:1234abcd` | Prefetch volume, LNK volume |
| `device:` | `device:c:\` | Prefetch volume device path |
| `pref:` | `pref:testapp.exe` | binds a reference entry to the image that triggered it |
| `md5:` | `md5:e4c383425af9cf226384308a47cad3a9` | MD5 of the file |
| `imphash:` | `imphash:8c057fce77b6ad4e03dd32d47003991f` | import hash (module + function, no folders) |
| `richkey:` | `richkey:37c27851` | Rich header XOR key |
| `richhash:` | `richhash:39b3f85b385394ff1b9b8563c135f97e` | MD5 over the Rich header |
| `linktime:` | `linktime:6a60755d` | PE `TimeDateStamp` |

Because identifiers are typed, `show` can be pointed at any of them directly:

```cmd
pivot show md5:e4c383425af9cf226384308a47cad3a9 --store case.store
pivot show vserial:1234abcd --store case.store
```

---

## Prefetch hash resolution

Windows hashes the path of the executed image in **upper case**. The exact
algorithm differs between builds, so PIVOT tries the full cross product:

| Parameter | Values |
|---|---|
| Rotation | `ROL13`, `ROR13` |
| Accumulation | `+ char`, `- char` |
| Length term | with / without `+ len(path)` |

→ **8 hash variants**.

Each candidate path is additionally expanded into several shapes: as given,
lower case, upper case, with and without a leading `\`, and the bare file
name. The winning combination is reported with the match, so the analyst can
see *why* a hash resolved:

```text
hash 7438817f -> 1 candidate path(s) [18 candidates tested]
  ror13-add C:\PROGRAM FILES\TESTAPP\TESTAPP.EXE C:\Program Files\TestApp\TestApp.exe
```

Unresolved hashes — the interesting ones, because they point at paths that
exist on the system but are not in your evidence yet:

```text
3 unresolved prefetch hash(es)

  08bcceea  explorer.exe   ...\EXPLORER.EXE-08BCCEEA.pf
  d0b0d52d  notepad.exe    ...\NOTEPAD.EXE-D0B0D52D.pf
  7438817f  TestApp.exe    ...\TESTAPP.EXE-7438817F.pf
```

---

## Supported artifacts

### Windows Prefetch (SCCA/MAM) — `src/parsers/prefetch.cpp`

| Version | OS | Status |
|---|---|---|
| 17 | Vista / 2008 | header, single run time, inline file names |
| 23 | Windows 7 | header, 60-byte metric entries, relative name offsets |
| 26 | Windows 8 / 8.1 | 36-byte metric entries |
| 30 | Windows 10 | 32-byte metric entries, absolute name offsets |
| 31–34 | Windows 11 | 32-byte metric entries |

Extracted: executable name and hash, run count, last run time, the last eight
run times, every referenced file (name, size, flags), and volume information
(device path, volume serial).

Parsing details that matter in practice:

* the file-metrics entry size is version dependent — guessing it wrong yields
  garbage names;
* file names are stored either absolute (Win10+) or relative to the filename
  string section (Win7/8) — both are tried;
* the volume device path is UTF-16LE and its length field counts bytes on some
  builds and characters on others — both are tried;
* sanity checks turn impossible values (out-of-range timestamps, implausible
  run counts) into `warning:` fields.

### Shell Link (`.lnk`) — `src/parsers/lnk.cpp`

Modern Windows 10/11 shortcuts **do not** have trustworthy header offsets, so
PIVOT *scans* for the sections and validates them instead of blindly reading
fixed offsets:

* **LinkInfo** — local base path, header size, optional volume + drive type
* **StringData** — relative path, working directory, arguments, icon location
  (name strings may lack their NUL terminator and sit at odd offsets)
* **ExtraData** — known signatures (`0xA0000001/02/03/06/09/1B`), e.g. the
  `EnvironmentVariableDataBlock` and `DarwinDataBlock`
* **IDList** — shell item names, parsed recursively
* timestamps from the fixed 76-byte header, AUMID and SID when present

### PE/COFF — `src/parsers/pe.cpp`

Sections, import table (→ imphash), MD5 of the file, `TimeDateStamp`,
Rich header (XOR key, hash and the full toolchain table).

### Planned

Amcache (`.hve`), MFT, USN journal, Registry hives, EVTX.

---

## Data model

```cpp
struct Record {
    std::string kind;    // prefetch | prefetch.ref | lnk | pe
    std::string source;  // artifact the record was parsed from
    std::string title;   // one-line summary
    std::vector<std::string> ids;      // pivot identifiers
    std::vector<std::pair<std::string, std::string>> fields;  // key/value details
    std::vector<i64> times;            // unix epoch seconds (UTC)
    u64 offset; u32 size;              // evidence offset/length in the source file
};
```

* **Store**: a compact binary format (`PVS1`) — magic, record count, then
  length-prefixed records. Fast to re-read, no re-parsing of evidence needed.
* **Export**: JSON array (`--json F`) plus a JSONL sidecar for streaming
  consumers.
* `ingest` is **idempotent**: re-ingesting the same artifact adds no
  duplicates.

---

## Project layout

```
src/main.cpp              CLI, artifact detection, ingest
src/index.{h,cpp}         pivot index, hash resolution, timeline, store
src/record.{h,cpp}        record model, identifiers, JSON
src/util.{h,cpp}          byte readers, UTF-16, time conversion, MD5
src/parsers/prefetch.*    SCCA parser + hash variants
src/parsers/lnk.*         shell link parser
src/parsers/pe.*          PE parser
tools/                    test fixture generator
tests/                    fixtures + regression suite
```

---

## Testing

```cmd
powershell -ExecutionPolicy Bypass -File tests\run_tests.ps1
```

The suite builds the tool, ingests the synthetic prefetch fixtures and asserts
22 conditions across parsing, hash resolution, the index, the timeline and the
JSON export. CI runs it on every push.

Because `C:\Windows\Prefetch` is not readable in a test environment, the
fixtures are generated by `tools\make_prefetch_fixture.py`, which writes
realistic SCCA files (v17, v26, v30):

```cmd
python tools\make_prefetch_fixture.py --version 30 ^
    --exe "C:\Program Files\TestApp\TestApp.exe" ^
    --ref "C:\Windows\System32\ntdll.dll" ^
    --out tests\fixtures\TESTAPP.EXE-7438817F.pf
```

---

## Limitations

Being explicit about this, because it matters when the output goes into a
report:

* **The prefetch hash algorithm is not verified against a real Windows
  Prefetch file.** PIVOT covers eight documented variants and several path
  shapes, but the match shown in the output is a *candidate*, not a proof. The
  matching variant is always printed so it can be sanity-checked.
* Prefetch files reference files by **name only**; full paths must come from
  other sources (MFT, Amcache, an LNK, or a `--candidates` list).
* Registry, Amcache, MFT, USN and EVTX are **not implemented yet**.
* The LNK parser is targeted at Windows 10/11 shortcuts. Exotic layouts
  (very old, or hand-crafted) may be partially parsed; warnings are attached
  to the record in that case.
* Volume serial numbers are treated as 32-bit — a 64-bit serial is truncated
  to its lower half.
* Timestamps are UTC, converted from FILETIME where the format uses it.

---

## Roadmap

- [ ] Amcache parser → real full-path candidates for prefetch hash resolution
- [ ] MFT parser → file paths, timestamps, `$FILE_NAME` resident data
- [ ] USN journal parser → file creation/rename timeline
- [ ] Registry hive parser (`SYSTEM` → UsnJournal, Services, etc.)
- [ ] EVTX parser → process/user execution events
- [ ] Batch correlation: one command that pivots a set of input handles
- [ ] Timeline export (JSON/CSV) and simple frequency charts

---

## License

MIT — see [LICENSE](LICENSE).
