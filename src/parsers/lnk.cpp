// PIVOT - Windows Shortcut (LNK) parser
//
// Layout notes (empirically verified on Windows 10/11 shortcuts):
//   * The fixed 76 byte shell link header is always reliable (flags, timestamps,
//     target size, icon index, show command).
//   * The four section offsets in the header (0x48..0x5C) are NOT reliable:
//     modern shortcuts (Explorer, Squirrel, MSIX) either store garbage there or
//     use a different section order. The sections are therefore located by
//     scanning and validating them.
//   * LinkInfo:  u32 size, u32 headerSize(0x1C), u32 flags, u32 volOff,
//                u32 localBasePathOff, u32 netOff, u32 commonSuffixOff
//   * StringData: sequence of COUNT_STRING blocks (u16 count, chars, NUL)
//   * ExtraData:  sequence of (u32 size, u32 signature) blocks

#include "lnk.h"

#include <algorithm>
#include <cstring>

namespace pv {

namespace {

constexpr u32 kHasLinkTargetIDList = 0x01;
constexpr u32 kHasLinkInfo = 0x02;
constexpr u32 kHasName = 0x04;
constexpr u32 kHasRelativePath = 0x08;
constexpr u32 kHasWorkingDir = 0x10;
constexpr u32 kHasArguments = 0x20;
constexpr u32 kHasIconLocation = 0x40;
constexpr u32 kIsUnicode = 0x80;

constexpr u32 kSigEnvironment = 0xA0000001;
constexpr u32 kSigTracker = 0xA0000002;
constexpr u32 kSigWin10IdList = 0xA0000003;
constexpr u32 kSigRunInfo = 0xA0000006;
constexpr u32 kSigPropertyStore = 0xA0000009;
constexpr u32 kSigWin10IdList2 = 0xA000001B;

bool known_signature(u32 sig) {
    switch (sig) {
        case kSigEnvironment:
        case kSigTracker:
        case kSigWin10IdList:
        case kSigRunInfo:
        case kSigPropertyStore:
        case kSigWin10IdList2:
            return true;
        default:
            return false;
    }
}

std::string read_ansi(const u8* p, std::size_t max) {
    std::string s;
    for (std::size_t i = 0; i < max && p[i]; ++i) s.push_back(static_cast<char>(p[i]));
    return s;
}

std::string read_utf16(const u8* p, std::size_t max_bytes) {
    std::string s;
    for (std::size_t i = 0; i + 1 < max_bytes; i += 2) {
        u16 c = rd16(p, i);
        if (c == 0) break;
        s.push_back(c < 0x80 ? static_cast<char>(c) : '?');
    }
    return s;
}

bool looks_like_drive_string(const u8* p) {
    if (!p) return false;
    bool alpha = (p[0] >= 'A' && p[0] <= 'Z') || (p[0] >= 'a' && p[0] <= 'z');
    if (!alpha || p[1] != ':') return false;
    return p[2] == '\\' || p[2] == 0;
}

bool looks_like_path(const std::string& s) {
    if (s.size() < 3) return false;
    if (!printable(s)) return false;
    if (s.find('?') != std::string::npos) return false;  // mis-decoded unicode
    return s.find('\\') != std::string::npos || s.find(':') != std::string::npos;
}

std::string path_at(const u8* p, std::size_t max_bytes) {
    std::string a = read_ansi(p, max_bytes);
    if (looks_like_path(a)) return a;
    std::string w = read_utf16(p, max_bytes);
    if (looks_like_path(w)) return w;
    return {};
}

std::string last_component(const std::string& p) {
    std::size_t pos = p.find_last_of("\\/");
    return pos == std::string::npos ? p : p.substr(pos + 1);
}

bool has_extension(const std::string& comp) {
    std::size_t dot = comp.find_last_of('.');
    return dot != std::string::npos && dot + 1 < comp.size();
}

// ---------------------------------------------------------------- link info

struct LinkInfoHit {
    std::size_t off = 0;
    u32 size = 0;
    u32 header_size = 0;
    u32 flags = 0;
    u32 vol_off = 0;
    u32 lbp_off = 0;
    u32 net_off = 0;
    u32 cps_off = 0;
    int score = 0;
};

LinkInfoHit find_linkinfo(const u8* d, std::size_t total) {
    LinkInfoHit best;
    for (std::size_t p = 0x4C; p + 0x1C <= total; ++p) {
        u32 size = rd32(d, p);
        if (size < 0x1C || p + size > total) continue;
        u32 hdr = rd32(d, p + 4);
        if (hdr != 0x1C && hdr != 0x24) continue;
        u32 flags = rd32(d, p + 8);
        if (flags & ~0x01u) continue;
        u32 vol = rd32(d, p + 0x0C);
        u32 lbp = rd32(d, p + 0x10);
        u32 net = rd32(d, p + 0x14);
        u32 cps = rd32(d, p + 0x18);
        if (vol >= size || lbp >= size || cps >= size) continue;

        int score = 0;
        const u8* vi = d + p + vol;
        u32 v1 = rd32(vi, 0);
        u32 v2 = rd32(vi, 8);
        if (v1 < size && looks_like_drive_string(vi + v1))
            score += 2;
        else if (v2 < size && looks_like_drive_string(vi + v2))
            score += 2;
        else if (looks_like_drive_string(vi + 12))
            score += 2;

        if (lbp) {
            std::string lp = path_at(d + p + lbp, 1040);
            if (looks_like_path(lp)) score += 2;
        }
        if (score < 2) continue;
        if (score > best.score) {
            best.off = p;
            best.size = size;
            best.header_size = hdr;
            best.flags = flags;
            best.vol_off = vol;
            best.lbp_off = lbp;
            best.net_off = net;
            best.cps_off = cps;
            best.score = score;
        }
    }
    return best;
}

// ---------------------------------------------------------------- string data

bool read_count_string(const u8* d, std::size_t total, std::size_t& p, bool unicode, std::string& out) {
    if (!in_range(p, 2, total)) return false;
    u32 count = rd16(d, p);
    if (count == 0 || count > 4096) return false;
    std::size_t bytes = unicode ? static_cast<std::size_t>(count) * 2 : count;
    if (!in_range(p + 2, bytes, total)) return false;
    std::string s = unicode ? utf16le_to_utf8(d + p + 2, bytes)
                            : std::string(reinterpret_cast<const char*>(d + p + 2), count);
    if (!printable(s)) return false;
    p += 2 + bytes;
    // The NUL terminator is present in classic shortcuts but omitted by some
    // modern writers, so it is consumed only when it is actually there.
    if (unicode) {
        if (in_range(p, 2, total) && rd16(d, p) == 0) p += 2;
    } else {
        if (in_range(p, 1, total) && d[p] == 0) p += 1;
    }
    out = s;
    return true;
}

struct StringChain {
    std::size_t off = 0;
    std::size_t end = 0;
    int count = 0;
    bool unicode = true;
    std::vector<std::string> values;
};

StringChain find_stringdata(const u8* d, std::size_t total, bool prefer_unicode) {
    StringChain best;
    for (int pass = 0; pass < 2; ++pass) {
        bool unicode = prefer_unicode ? (pass == 0) : (pass == 1);
        for (std::size_t p = 0x4C; p + 2 <= total; ++p) {
            std::size_t q = p;
            std::vector<std::string> vals;
            std::string tmp;
            while (vals.size() < 5 && read_count_string(d, total, q, unicode, tmp)) vals.push_back(tmp);
            if (vals.size() < 2) continue;
            if (static_cast<int>(vals.size()) < best.count) continue;
            if (static_cast<int>(vals.size()) == best.count && !unicode && best.unicode) continue;
            best.off = p;
            best.end = q;
            best.count = static_cast<int>(vals.size());
            best.unicode = unicode;
            best.values = vals;
        }
        if (best.count >= 3) break;
    }
    return best;
}

// ---------------------------------------------------------------- string harvest

void harvest_utf16(const u8* d, std::size_t start, std::size_t end, std::vector<std::string>& out,
                   std::size_t min_len = 3) {
    for (std::size_t p = start; p + 1 < end; p += 2) {
        u16 c = rd16(d, p);
        if (c < 0x20 || c >= 0x7F) continue;
        std::size_t q = p;
        std::string s;
        while (q + 1 < end) {
            u16 ch = rd16(d, q);
            if (ch < 0x20 || ch >= 0x7F) break;
            s.push_back(static_cast<char>(ch));
            q += 2;
        }
        if (s.size() >= min_len && q + 1 < end && rd16(d, q) == 0) {
            out.push_back(s);
            p = q;
        }
    }
}

bool is_sid(const std::string& s) {
    return s.size() > 8 && s.compare(0, 3, "S-1") == 0;
}

bool is_aumid(const std::string& s) {
    if (s.size() < 4 || s.size() > 200) return false;
    if (s.find(' ') != std::string::npos) return false;
    return s.find('.') != std::string::npos;
}

// ---------------------------------------------------------------- extra data

void scan_extra_data(const u8* d, std::size_t total, std::size_t start, LnkInfo& info) {
    // Blocks are located by their signature, so a misaligned start does not
    // prevent the remaining blocks from being recovered.
    for (std::size_t p = start; p + 8 <= total; p += 4) {
        u32 size = rd32(d, p);
        u32 sig = rd32(d, p + 4);
        if (!known_signature(sig)) continue;
        if (size < 8 || size % 4 != 0 || p + 4 + size > total) continue;
        const u8* body = d + p + 8;
        std::size_t blen = size - 4;

        switch (sig) {
            case kSigEnvironment: {
                std::size_t q = 0;
                while (q + 2 <= blen) {
                    u32 n = rd16(body, q);
                    if (n == 0 || n > 4096) break;
                    std::size_t data_off = q + 2;
                    std::string s = read_ansi(body + data_off, n);
                    if (s.empty()) s = read_utf16(body + data_off, n * 2);
                    if (!s.empty()) info.env_vars.push_back(s);
                    q = data_off + n + 2;
                }
                break;
            }
            case kSigTracker: {
                if (blen < 8) break;
                u32 idlen = rd32(body, 0);
                if (idlen && idlen < 256 && in_range(8, idlen, blen)) {
                    info.machine_id = read_ansi(body + 8, idlen);
                }
                std::size_t droid_off = 8 + ((idlen + 3) & ~3u);
                if (in_range(droid_off, 16, blen)) {
                    const u8* dr = body + droid_off;
                    u32 mac = (static_cast<u32>(dr[12]) << 24) | (static_cast<u32>(dr[13]) << 16) |
                              (static_cast<u32>(dr[14]) << 8) | static_cast<u32>(dr[15]);
                    mac = ~mac;
                    char buf[32];
                    std::snprintf(buf, sizeof buf, "%02x:%02x:%02x:%02x:%02x:%02x",
                                  (mac >> 24) & 0xFF, (mac >> 16) & 0xFF, (mac >> 8) & 0xFF, mac & 0xFF,
                                  (mac >> 24) & 0xFF, (mac >> 16) & 0xFF);
                    info.mac = buf;
                    info.droid_birth = in_range(droid_off + 16, 8, blen) ? rd64(body, droid_off + 16) : 0;
                }
                std::size_t t_off = droid_off + 32;
                if (in_range(t_off, 8, blen)) info.tracker_birth = rd64(body, t_off);
                break;
            }
            case kSigRunInfo: {
                if (blen >= 8) {
                    info.has_run_info = true;
                    info.shell_id = rd32(body, 4);
                }
                break;
            }
            default: break;
        }

        // harvest strings from every block (SID, AUMID, friendly names, ...)
        std::vector<std::string> found;
        harvest_utf16(body, 0, blen, found, 4);
        for (const auto& s : found) {
            if (info.sid.empty() && is_sid(s)) {
                info.sid = s;
            } else if (info.aumid.empty() && is_aumid(s)) {
                info.aumid = s;
            } else if (info.extra_strings.size() < 32) {
                info.extra_strings.push_back(s);
            }
        }
    }
}

}  // namespace

bool parse_lnk(const std::vector<u8>& data, LnkInfo& out) {
    const std::size_t total = data.size();
    if (total < 0x4C) return false;
    const u8* d = data.data();

    u32 header_size = rd32(d, 0x00);
    if (header_size < 0x4C || header_size > total) {
        out.warnings.push_back("unexpected header size");
        return false;
    }

    out.link_flags = rd32(d, 0x14);
    out.file_attributes = rd32(d, 0x18);
    out.creation_time = rd64(d, 0x1C);
    out.access_time = rd64(d, 0x24);
    out.write_time = rd64(d, 0x2C);
    out.file_size = rd32(d, 0x34);
    const bool unicode = (out.link_flags & kIsUnicode) != 0;

    // ---- locate the sections
    LinkInfoHit li = find_linkinfo(d, total);
    StringChain sc = find_stringdata(d, total, unicode);

    if (li.off)
        out.layout = "scanned";
    else
        out.layout = "header-only";
    if (li.header_size >= 0x24) out.layout += "+unicode-paths";

    // ---- string data (name, relative path, working dir, arguments, icon)
    if (sc.count > 0) {
        std::size_t idx = 0;
        if (out.link_flags & kHasName) out.name = sc.values[idx++];
        if (out.link_flags & kHasRelativePath && idx < sc.values.size())
            out.relative_path = sc.values[idx++];
        if (out.link_flags & kHasWorkingDir && idx < sc.values.size())
            out.working_dir = sc.values[idx++];
        if (out.link_flags & kHasArguments && idx < sc.values.size())
            out.arguments = sc.values[idx++];
        if (out.link_flags & kHasIconLocation && idx < sc.values.size())
            out.icon_location = sc.values[idx++];
    }

    // ---- link info (volume serial, local base path, common suffix)
    if (li.off) {
        const u8* lp = d + li.off;
        if (li.vol_off) {
            const u8* vi = lp + li.vol_off;
            out.volume_serial = rd32(vi, 4);
            u32 v1 = rd32(vi, 0);
            u32 v2 = rd32(vi, 8);
            if (v1 < li.size && looks_like_drive_string(vi + v1))
                out.drive_type = read_ansi(vi + v1, 3);
            else if (v2 < li.size && looks_like_drive_string(vi + v2))
                out.drive_type = read_ansi(vi + v2, 3);
            else
                out.drive_type = read_ansi(vi + 12, 13);
            while (!out.drive_type.empty() && out.drive_type.back() == '\0') out.drive_type.pop_back();
        }
        if (li.lbp_off) out.local_base_path = path_at(lp + li.lbp_off, 1040);
        if (li.cps_off) {
            std::string cps = path_at(lp + li.cps_off, 1040);
            // Some writers point the common suffix at the file name instead of
            // storing an empty suffix; a local base path that already carries a
            // file name means the suffix is redundant.
            bool lbp_is_file = has_extension(last_component(out.local_base_path));
            if (!lbp_is_file) out.common_suffix = cps;
        }
        if (li.net_off) {
            const u8* nb = lp + li.net_off;
            u32 nlen = rd32(nb, 0x10);
            if (nlen && in_range(li.net_off + 0x14, nlen, li.size))
                out.network_path = read_ansi(nb + 0x14, nlen);
        }
    }

    if (!out.local_base_path.empty() && !out.common_suffix.empty())
        out.target_path = out.local_base_path + out.common_suffix;
    else if (!out.local_base_path.empty())
        out.target_path = out.local_base_path;
    else if (!out.relative_path.empty())
        out.target_path = out.relative_path;
    if (!out.volume_device.empty()) {
        out.target_path = out.volume_device + out.target_path;
    }

    // ---- id list region: harvest the embedded strings
    std::size_t idlist_start = 0x4C;
    std::size_t idlist_end = total;
    if (li.off) idlist_end = li.off;
    if (sc.off && sc.off < idlist_end) idlist_end = sc.off;
    if (idlist_end > idlist_start) {
        harvest_utf16(d, idlist_start, idlist_end, out.idlist_strings, 3);
        if (out.name.empty() && !out.idlist_strings.empty()) {
            // the last id list string is usually the leaf name
            for (auto it = out.idlist_strings.rbegin(); it != out.idlist_strings.rend(); ++it) {
                if (it->size() <= 128 && it->find('\\') == std::string::npos) {
                    out.name = *it;
                    break;
                }
            }
        }
    }

    // ---- extra data blocks
    std::size_t extra_start = 0;
    if (li.off) extra_start = li.off + li.size;
    if (sc.end > extra_start) extra_start = sc.end;
    if (extra_start < total) scan_extra_data(d, total, extra_start, out);

    if (out.target_path.empty() && out.name.empty() && out.relative_path.empty())
        out.warnings.push_back("no target information recovered");
    return true;
}

void lnk_records(const std::string& source, LnkInfo& info, std::vector<Record>& out) {
    Record r;
    r.kind = "lnk";
    r.source = source;
    r.title = "LNK " + (info.name.empty() ? std::string("<unnamed>") : info.name);
    r.add("name", info.name);
    if (!info.target_path.empty()) r.add("target", info.target_path);
    if (!info.relative_path.empty()) r.add("relative_path", info.relative_path);
    if (!info.working_dir.empty()) r.add("working_dir", info.working_dir);
    if (!info.arguments.empty()) r.add("arguments", info.arguments);
    if (!info.icon_location.empty()) r.add("icon_location", info.icon_location);
    if (!info.local_base_path.empty()) r.add("local_base_path", info.local_base_path);
    if (!info.common_suffix.empty()) r.add("common_suffix", info.common_suffix);
    if (!info.network_path.empty()) r.add("network_path", info.network_path);
    if (!info.volume_device.empty()) r.add("volume_device", info.volume_device);
    if (!info.drive_type.empty()) r.add("drive_type", info.drive_type);
    if (info.volume_serial) r.add("volume_serial", hex(info.volume_serial, 8));
    if (info.file_size) r.add("file_size", std::to_string(info.file_size));
    if (!info.machine_id.empty()) r.add("machine_id", info.machine_id);
    if (!info.mac.empty()) r.add("mac", info.mac);
    if (!info.aumid.empty()) r.add("aumid", info.aumid);
    if (!info.sid.empty()) r.add("sid", info.sid);
    if (!info.layout.empty()) r.add("layout", info.layout);
    for (const auto& e : info.env_vars) r.add("env_var", e);
    for (const auto& s : info.idlist_strings) r.add("idlist_string", s);
    for (const auto& s : info.extra_strings) r.add("extra_string", s);
    if (info.creation_time) r.add("created_utc", filetime_to_iso(info.creation_time));
    if (info.write_time) r.add("written_utc", filetime_to_iso(info.write_time));
    if (info.access_time) r.add("accessed_utc", filetime_to_iso(info.access_time));
    if (info.has_run_info) r.add("shell_id", hex(info.shell_id, 8));
    for (const auto& w : info.warnings) r.add("warning", w);

    if (!info.name.empty()) r.add_id(id_path(info.name));
    if (!info.target_path.empty()) r.add_id(id_path(info.target_path));
    if (!info.relative_path.empty()) r.add_id(id_path(info.relative_path));
    if (!info.working_dir.empty()) r.add_id(id_path(info.working_dir));
    if (!info.network_path.empty()) r.add_id(id_path(info.network_path));
    if (info.volume_serial) r.add_id(id_u32("vserial", info.volume_serial));
    if (!info.machine_id.empty()) r.add_id(id_raw("machine:" + lower(info.machine_id)));
    if (!info.mac.empty()) r.add_id(id_raw("mac:" + info.mac));
    if (!info.aumid.empty()) r.add_id(id_raw("aumid:" + lower(info.aumid)));
    if (!info.sid.empty()) r.add_id(id_raw("sid:" + lower(info.sid)));

    r.add_time(filetime_to_unix(info.creation_time));
    r.add_time(filetime_to_unix(info.write_time));
    r.add_time(filetime_to_unix(info.access_time));
    r.add_time(filetime_to_unix(info.droid_birth));
    r.add_time(filetime_to_unix(info.tracker_birth));
    out.push_back(r);
}

}  // namespace pv
