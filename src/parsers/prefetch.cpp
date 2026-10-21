#include "prefetch.h"

#include <algorithm>

namespace pv {

namespace {

inline u32 rol13(u32 v) { return (v << 13) | (v >> 19); }
inline u32 ror13(u32 v) { return (v >> 13) | (v << 19); }

// Reads a null terminated ASCII string at off, bounded by limit.
std::string cstr(const u8* d, std::size_t total, std::size_t off, std::size_t limit = 512) {
    std::string s;
    if (off >= total) return s;
    std::size_t end = std::min(total, off + limit);
    for (std::size_t i = off; i < end; ++i) {
        if (!d[i]) break;
        s.push_back(static_cast<char>(d[i]));
    }
    return s;
}

// Filename strings of the referenced files are stored in a dedicated section.
// The offset inside a file information entry is either absolute (Win10+) or
// relative to that section (Win7/8). We resolve both and pick the one that
// yields a sane, printable name.
std::string resolve_name(const u8* d, std::size_t total, u32 stored_off, u32 strings_off,
                         u32 strings_size, std::size_t strings_end) {
    auto try_at = [&](std::size_t off) -> std::string {
        if (off >= total) return {};
        std::string s = cstr(d, total, off, 320);
        if (!printable(s)) return {};
        for (char c : s)
            if (c == '\t') return {};
        return s;
    };

    // absolute first (Win10+), then relative to the string section
    if (strings_off && stored_off >= strings_off && stored_off < strings_end) {
        std::string s = try_at(stored_off);
        if (!s.empty()) return s;
    }
    std::string s = try_at(strings_off + stored_off);
    if (!s.empty()) return s;
    s = try_at(stored_off);
    return s;
}

// The device path of a volume is stored as UTF-16LE. Depending on the Windows
// build the length field counts bytes or characters, so both readings are
// tried and the one that yields a printable path wins.
std::string read_device_path(const u8* d, std::size_t total, u32 dp_off, u32 dp_len) {
    if (!dp_len || dp_len > 1024) return {};

    auto utf16_ok = [&](std::size_t chars) -> std::string {
        if (chars == 0) return {};
        std::size_t bytes = chars * 2;
        if (!in_range(dp_off, bytes, total)) return {};
        for (std::size_t i = 0; i < bytes; i += 2)
            if (d[dp_off + i + 1] != 0) return {};  // not plain ASCII UTF-16
        std::string s = utf16le_to_utf8(d + dp_off, bytes);
        while (!s.empty() && s.back() == '\0') s.pop_back();
        return printable(s) ? s : std::string();
    };
    auto ansi = [&]() -> std::string {
        if (!in_range(dp_off, dp_len, total)) return {};
        std::string s(reinterpret_cast<const char*>(d + dp_off), dp_len);
        while (!s.empty() && s.back() == '\0') s.pop_back();
        return printable(s) ? s : std::string();
    };

    std::string s = utf16_ok(dp_len);  // length given in characters
    if (!s.empty()) return s;
    s = utf16_ok(dp_len / 2);  // length given in bytes
    if (!s.empty()) return s;
    return ansi();
}

}  // namespace

bool parse_prefetch(const std::vector<u8>& data, PrefetchInfo& out) {
    const std::size_t total = data.size();
    if (total < 0x100) return false;
    const u8* d = data.data();

    std::string sig0(reinterpret_cast<const char*>(d), 4);
    if (sig0 != "SCCA" && sig0 != "MAM") return false;

    out.version = rd32(d, 0x04);
    std::string sig1(reinterpret_cast<const char*>(d + 0x08), 4);
    if (sig1 != "SCCA" && sig1 != "MAM") {
        out.warnings.push_back("unexpected secondary signature: " + sig1);
    }

    if (out.version == 17) {
        // Vista/2008: single run time, fixed size file information entries
        out.exe = trim(cstr(d, total, 0x18, 64));
        out.exe_hash = rd32(d, 0x54);
        out.last_run = rd64(d, 0x60);
        out.run_count = rd32(d, 0x70);
        u32 fi_off = rd32(d, 0x7C);
        u32 fi_cnt = rd32(d, 0x80);
        for (u32 i = 0; i < fi_cnt && i < 4096; ++i) {
            std::size_t e = fi_off + static_cast<std::size_t>(i) * 60;
            if (!in_range(e, 60, total)) break;
            PrefetchRef r;
            // Vista stores the ANSI name at the end of the entry, some tools
            // write it at the beginning
            r.name = trim(cstr(d, total, e + 0x2C, 16));
            if (r.name.empty() || !printable(r.name)) r.name = trim(cstr(d, total, e, 16));
            if (r.name.empty() || !printable(r.name)) continue;
            r.size = rd32(d, e);
            r.flags = rd32(d, e + 0x08);
            out.refs.push_back(r);
        }
    } else if (out.version >= 23 && out.version <= 34) {
        // Win7 / Win8 / Win8.1 / Win10 / Win11
        out.exe = trim(cstr(d, total, 0x18, 64));
        out.exe_hash = rd32(d, 0x58);

        u32 fi_off = rd32(d, 0x60);
        u32 fi_cnt = rd32(d, 0x64);
        u32 strings_off = rd32(d, 0x78);
        u32 strings_size = rd32(d, 0x7C);
        u32 vol_off = rd32(d, 0x80);
        u32 vol_cnt = rd32(d, 0x84);

        out.last_run = rd64(d, 0x8C);
        for (int i = 0; i < 8; ++i) {
            u64 ft = rd64(d, 0x9C + static_cast<std::size_t>(i) * 8);
            if (ft) out.run_times.push_back(ft);
        }
        out.run_count = rd32(d, 0xDC);

        // referenced files
        const std::size_t entry_size = prefetch_entry_size(out.version);
        for (u32 i = 0; i < fi_cnt && i < 65536; ++i) {
            std::size_t e = fi_off + static_cast<std::size_t>(i) * entry_size;
            if (!in_range(e, entry_size, total)) break;
            u32 name_off = rd32(d, e);
            u32 fsize = rd32(d, e + 0x08);
            u32 flags = rd32(d, e + 0x10);
            PrefetchRef r;
            r.size = fsize;
            r.flags = flags;
            r.name = resolve_name(d, total, name_off, strings_off, strings_size,
                                  strings_off + strings_size);
            if (r.name.empty()) continue;
            out.refs.push_back(r);
        }

        // volumes
        const std::size_t vol_entry = 40;
        for (u32 i = 0; i < vol_cnt && i < 256; ++i) {
            std::size_t e = vol_off + static_cast<std::size_t>(i) * vol_entry;
            if (!in_range(e, vol_entry, total)) break;
            u32 dp_off = rd32(d, e);
            u32 dp_len = rd32(d, e + 0x04);
            u64 serial = rd64(d, e + 0x10);
            std::string dp = read_device_path(d, total, dp_off, dp_len);
            if (!dp.empty()) out.volumes.push_back(dp);
            if (serial) out.volume_serials.push_back(static_cast<u32>(serial & 0xFFFFFFFFu));
        }
    } else {
        out.warnings.push_back("unsupported prefetch version " + std::to_string(out.version));
        return false;
    }

    // sanity checks - a parser that silently returns garbage is worse than one
    // that refuses to parse
    if (out.exe.empty()) out.warnings.push_back("executable name could not be read");
    i64 lr = filetime_to_unix(out.last_run);
    if (out.last_run && (lr < 946684800LL || lr > 2200000000LL))
        out.warnings.push_back("last run time out of sane range");
    if (out.run_count > 1000000) out.warnings.push_back("implausible run count");
    if (out.refs.empty()) out.warnings.push_back("no referenced files resolved");
    return true;
}

// ---------------------------------------------------------------- records

void prefetch_records(const std::vector<u8>& data, const std::string& source, PrefetchInfo& info,
                      std::vector<Record>& out) {
    Record main;
    main.kind = "prefetch";
    main.source = source;
    main.title = "PREFETCH " + info.exe + " (v" + std::to_string(info.version) + ", " +
                 std::to_string(info.run_count) + " runs)";
    main.add("executable", info.exe);
    main.add("version", std::to_string(info.version));
    main.add("run_count", std::to_string(info.run_count));
    if (info.last_run) main.add("last_run_utc", filetime_to_iso(info.last_run));
    if (info.exe_hash) main.add("exe_hash", hex(info.exe_hash, 8));
    for (u32 s : info.volume_serials) main.add("volume_serial", hex(s, 8));
    for (const auto& v : info.volumes) main.add("device", v);

    if (!info.exe.empty()) {
        main.add_id(id_path(info.exe));
        main.add_id(id_path("\\" + info.exe));
    }
    if (info.exe_hash) main.add_id(id_u32("pfhash", info.exe_hash));
    for (u32 s : info.volume_serials) main.add_id(id_u32("vserial", s));
    for (const auto& v : info.volumes) main.add_id(id_raw("device:" + lower(v)));
    main.add_time(filetime_to_unix(info.last_run));
    for (u64 t : info.run_times) main.add_time(filetime_to_unix(t));
    for (const auto& w : info.warnings) main.add("warning", w);
    out.push_back(main);

    // one record per referenced file -> these carry the hashes we can resolve
    for (const auto& r : info.refs) {
        Record rec;
        rec.kind = "prefetch.ref";
        rec.source = source;
        rec.title = "PREFETCH REF " + r.name;
        rec.add("name", r.name);
        rec.add("size", std::to_string(r.size));
        rec.add("flags", hex(r.flags, 8));
        rec.add_id(id_path(r.name));
        rec.add_id(id_path("\\" + r.name));
        rec.add_id(id_raw("pref:" + lower(info.exe)));
        out.push_back(rec);
    }
}

// ---------------------------------------------------------------- hashing

u32 prefetch_hash(const std::string& path, const PfHashVariant& variant) {
    u32 h = 0;
    for (unsigned char c : path) {
        switch (variant.form) {
            case PfHashForm::Rol13Sub: h = rol13(h) - c; break;
            case PfHashForm::Ror13Add: h = ror13(h) + c; break;
            case PfHashForm::Rol13Add: h = rol13(h) + c; break;
            case PfHashForm::Ror13Sub: h = ror13(h) - c; break;
        }
    }
    if (variant.add_length) h += static_cast<u32>(path.size());
    return h;
}

const std::vector<PfHashVariant>& prefetch_hash_variants() {
    static const std::vector<PfHashVariant> v = {
        {PfHashForm::Ror13Add, false, "ror13-add"},
        {PfHashForm::Ror13Add, true, "ror13-add+len"},
        {PfHashForm::Rol13Add, false, "rol13-add"},
        {PfHashForm::Rol13Add, true, "rol13-add+len"},
        {PfHashForm::Ror13Sub, false, "ror13-sub"},
        {PfHashForm::Ror13Sub, true, "ror13-sub+len"},
        {PfHashForm::Rol13Sub, false, "rol13-sub"},
        {PfHashForm::Rol13Sub, true, "rol13-sub+len"},
    };
    return v;
}

std::vector<std::string> prefetch_path_forms(const std::string& full_path) {
    std::vector<std::string> forms;
    std::string p = full_path;
    std::replace(p.begin(), p.end(), '/', '\\');

    std::string base = p;
    std::size_t slash = base.find_last_of('\\');
    std::string fname = (slash == std::string::npos) ? base : base.substr(slash + 1);

    auto add = [&](const std::string& s) {
        if (!s.empty() && std::find(forms.begin(), forms.end(), s) == forms.end()) forms.push_back(s);
    };
    auto add_case = [&](const std::string& s) {
        add(s);
        add(lower(s));
        add(s);
        std::string up = s;
        for (auto& c : up)
            if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
        add(up);
    };

    add_case(p);
    add_case("\\" + p);
    if (!p.empty() && p[0] == '\\') add_case(p.substr(1));
    add_case(fname);
    return forms;
}

std::size_t prefetch_entry_size(u32 version) {
    if (version <= 23) return 60;  // Vista / Windows 7
    if (version <= 29) return 36;  // Windows 8 / 8.1
    return 32;                     // Windows 10 / 11
}

}  // namespace pv
