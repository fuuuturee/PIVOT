# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-10-21

### Added
- Artifact ingest pipeline with automatic type detection (Prefetch, Shell Link, PE)
- Prefetch (SCCA/MAM) parser for versions 17 and 23-34, including run times,
  referenced files, volumes and volume serials
- Shell Link parser with section scanning for modern Windows 10/11 shortcuts
  (LinkInfo, StringData, ExtraData, IDList, AUMID, SID)
- PE parser with sections, imports, imphash, MD5 and Rich header analysis
- Pivot index over typed identifiers (`path:`, `pfhash:`, `vserial:`, `md5:`,
  `imphash:`, `richkey:`, `richhash:`, `linktime:`, `pref:`, `device:`)
- Prefetch hash resolution against a candidate path pool using eight
  documented hash variants and multiple path shapes
- `unresolved` report for prefetch hashes that match no candidate path
- Chronological timeline with kind and date-range filters
- Binary record store (`PVS1`) plus JSON and JSONL export
- Idempotent ingest (re-ingesting the same artifact creates no duplicates)
- Synthetic prefetch fixture generator and a 22-check regression suite
- GitHub Actions build for release and debug

[Unreleased]: https://github.com/OWNER/PIVOT/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/OWNER/PIVOT/releases/tag/v0.1.0
