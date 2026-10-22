# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-10-22

### Added
- Dark mode for the GUI (Windows 11 native, light fallback)
- Collapsible detail groups (Allgemein, Zeit, Details, Identifier, Warnungen)
- Identifier pane with record counts and double click to copy
- Pivot indicator showing the currently selected identifier
- Column click sorting in the records pane
- Context menus for copy, pivot and "show in Explorer"
- Keyboard shortcuts (Ctrl+F search, Ctrl+I ingest, Ctrl+O open store, Ctrl+E export,
  Ctrl+C copy records, Esc reset)

### Changed
- GUI rebuilt from scratch with a cleaner three pane layout: command bar, filter bar
  and the Identifier / Records / Details panes
- Details pane is now a two column table instead of a tree, because the Win32
  tree control offers no column API
- Fonts are now created and applied explicitly (Segoe UI, Consolas for values)
- Shared ISO-8601 UTC parsing between CLI and GUI via `parse_iso_utc`
- CLI and GUI report the same version

### Fixed
- GUI no longer leaks handles on store reload and no longer mixes up the
  record/identifier selection after filtering

[Unreleased]: compare/v0.2.0...HEAD
[0.2.0]: releases/tag/v0.2.0
[0.1.0]: releases/tag/v0.1.0

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

[Unreleased]: compare/v0.2.0...HEAD
[0.2.0]: releases/tag/v0.2.0
[0.1.0]: releases/tag/v0.1.0
