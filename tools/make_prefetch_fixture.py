#!/usr/bin/env python3
"""Generate synthetic Windows Prefetch (SCCA) files for testing PIVOT.

The files follow the documented SCCA layouts:

  v17  Vista / 2008      60 byte file metrics entries, inline file names
  v23  Windows 7         60 byte entries, name offsets relative to the
                         filename string section
  v26  Windows 8 / 8.1   36 byte entries, name offsets relative
  v30  Windows 10        32 byte entries, absolute name offsets
  v31+ Windows 11        32 byte entries

The prefetch hash of the executed image is computed with the ROR13/ADD variant
over the upper case path, which is the algorithm most Windows 10 builds use.
"""

import argparse
import struct
import sys

FILETIME_EPOCH_DELTA = 116444736000000000


def ror13(value: int) -> int:
    return ((value >> 13) | (value << 19)) & 0xFFFFFFFF


def prefetch_hash(path: str) -> int:
    """ROR13/ADD over the upper case path (no length term)."""
    h = 0
    for ch in path.upper():
        h = (ror13(h) + ord(ch)) & 0xFFFFFFFF
    return h


def filetime(seconds: int) -> int:
    return (seconds + 11644473600) * 10000000


def entry_size(version: int) -> int:
    if version <= 23:
        return 60
    if version <= 29:
        return 36
    return 32


def build(version: int, exe: str, refs, out_path: str, runs: int, last_run: int,
          volume: str, serial: int) -> bytes:
    exe_name = exe.replace("/", "\\").rsplit("\\", 1)[-1]
    exe_hash = prefetch_hash(exe)

    header_size = 0x100 if version >= 23 else 0x98
    metrics_off = header_size
    metrics_size = entry_size(version) * len(refs)

    # filename string section
    strings = bytearray()
    string_offsets = []
    for r in refs:
        name = r.replace("/", "\\").rsplit("\\", 1)[-1]
        string_offsets.append(len(strings))
        strings += name.encode("ascii") + b"\x00"
    strings_off = metrics_off + metrics_size
    strings_size = len(strings)

    # volume information
    vol_off = strings_off + strings_size
    device = volume.encode("utf-16-le") + b"\x00\x00"
    device_off = vol_off + 40
    vol_entry = struct.pack("<IIIIQ", device_off, len(device) // 2, 0, 0, serial)
    vol_entry += b"\x00" * 16

    total = device_off + len(device)

    buf = bytearray(total)

    # ---- header
    buf[0:4] = b"SCCA"
    struct.pack_into("<I", buf, 0x04, version)
    buf[0x08:0x0C] = b"SCCA"
    struct.pack_into("<I", buf, 0x0C, 0x24 if version >= 23 else 0x1C)

    name_off = 0x18
    buf[name_off:name_off + len(exe_name)] = exe_name.encode("ascii")

    if version >= 23:
        struct.pack_into("<I", buf, 0x58, exe_hash)
        struct.pack_into("<I", buf, 0x60, metrics_off)
        struct.pack_into("<I", buf, 0x64, len(refs))
        struct.pack_into("<I", buf, 0x68, 0)
        struct.pack_into("<I", buf, 0x6C, 0)
        struct.pack_into("<I", buf, 0x78, strings_off)
        struct.pack_into("<I", buf, 0x7C, strings_size)
        struct.pack_into("<I", buf, 0x80, vol_off)
        struct.pack_into("<I", buf, 0x84, 1)
        struct.pack_into("<Q", buf, 0x8C, filetime(last_run))
        for i in range(8):
            t = last_run - i * 3600 if i < runs else 0
            struct.pack_into("<Q", buf, 0x9C + i * 8, filetime(t) if t else 0)
        struct.pack_into("<I", buf, 0xDC, runs)
    else:
        # v17: single run time, no volumes
        struct.pack_into("<I", buf, 0x54, exe_hash)
        struct.pack_into("<Q", buf, 0x60, filetime(last_run))
        struct.pack_into("<I", buf, 0x70, runs)
        struct.pack_into("<I", buf, 0x7C, metrics_off)
        struct.pack_into("<I", buf, 0x80, len(refs))

    # ---- file metrics
    size = entry_size(version)
    for i, r in enumerate(refs):
        e = metrics_off + i * size
        name = r.replace("/", "\\").rsplit("\\", 1)[-1]
        if version >= 30:
            name_off_in_file = strings_off + string_offsets[i]
        elif version >= 23:
            name_off_in_file = string_offsets[i]
        else:
            name_off_in_file = e
        struct.pack_into("<II", buf, e, name_off_in_file, len(name))
        struct.pack_into("<I", buf, e + 0x08, 4096 * (i + 1))
        struct.pack_into("<I", buf, e + 0x0C, 0x20)
        struct.pack_into("<I", buf, e + 0x10, 0x00000002)  # imported
        if version >= 30:
            struct.pack_into("<I", buf, e + 0x1C, serial & 0xFFFFFFFF)
        if version < 23:
            # Vista keeps the ANSI name at the end of the entry
            buf[e + 0x2C:e + 0x2C + len(name)] = name.encode("ascii")

    buf[strings_off:strings_off + strings_size] = strings
    buf[vol_off:vol_off + 40] = vol_entry
    buf[device_off:device_off + len(device)] = device

    with open(out_path, "wb") as fh:
        fh.write(buf)
    return exe_hash


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", type=int, default=30)
    ap.add_argument("--exe", required=True)
    ap.add_argument("--ref", action="append", default=[])
    ap.add_argument("--out", required=True)
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--volume", default="C:\\")
    ap.add_argument("--serial", type=lambda s: int(s, 0), default=0x1234ABCD)
    args = ap.parse_args()

    h = build(args.version, args.exe, args.ref, args.out, args.runs, 1767225600,
              args.volume, args.serial)
    print("%s  hash=%08X" % (args.out, h))
    return 0


if __name__ == "__main__":
    sys.exit(main())
