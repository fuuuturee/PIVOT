#include "pe.h"

#include <algorithm>
#include <cstdio>

namespace pv {

namespace {

struct Section {
    u32 va = 0;
    u32 vsize = 0;
    u32 raw = 0;
    u32 raw_size = 0;
};

u32 rva_to_offset(const std::vector<Section>& secs, u32 rva) {
    for (const auto& s : secs) {
        u32 size = s.vsize ? s.vsize : s.raw_size;
        if (rva >= s.va && rva < s.va + size) {
            u32 delta = rva - s.va;
            if (delta < s.raw_size) return s.raw + delta;
            return 0;
        }
    }
    return 0;
}

std::string cstr_at(const u8* d, std::size_t total, std::size_t off, std::size_t limit = 512) {
    std::string s;
    if (off >= total) return s;
    std::size_t end = std::min(total, off + limit);
    for (std::size_t i = off; i < end; ++i) {
        if (!d[i]) break;
        s.push_back(static_cast<char>(d[i]));
    }
    return s;
}

void decode_rich(const u8* d, std::size_t total, u32 pe_off, PeInfo& out) {
    // The Rich header lives between the DOS stub and the PE header.
    if (pe_off < 0x40) return;
    std::size_t rich_pos = 0;
    for (std::size_t i = pe_off; i >= 0x20; --i) {
        if (d[i] == 'R' && d[i + 1] == 'i' && d[i + 2] == 'c' && d[i + 3] == 'h') {
            rich_pos = i;
            break;
        }
    }
    if (!rich_pos || rich_pos + 8 > total) return;
    u32 key = rd32(d, rich_pos + 4);

    // find "DanS" (xor'ed) backwards
    std::size_t dans = 0;
    for (std::size_t i = rich_pos; i >= 0x20; i -= 4) {
        if ((rd32(d, i) ^ key) == 0x536E6144u) {  // "DanS"
            dans = i;
            break;
        }
    }
    if (!dans) return;

    out.has_rich = true;
    out.rich_key = key;

    std::string chain;
    std::size_t p = dans + 16;  // skip "DanS" + 3 padding dwords
    while (p + 8 <= rich_pos) {
        u32 comp = rd32(d, p) ^ key;
        u32 count = rd32(d, p + 4) ^ key;
        if (comp == 0 && count == 0) break;
        out.tools.push_back({comp, count});
        char buf[64];
        std::snprintf(buf, sizeof buf, "%u.%u,", comp, count);
        chain += buf;
        p += 8;
    }
    if (!chain.empty()) {
        chain.pop_back();
        out.rich_hash = md5_hex(std::vector<u8>(chain.begin(), chain.end()));
    }
}

}  // namespace

bool parse_pe(const std::vector<u8>& data, PeInfo& out) {
    const std::size_t total = data.size();
    if (total < 0x40) return false;
    const u8* d = data.data();
    if (d[0] != 'M' || d[1] != 'Z') return false;

    out.size = total;
    out.md5 = md5_hex(data);

    u32 pe_off = rd32(d, 0x3C);
    if (!in_range(pe_off, 0x18, total)) return false;
    if (std::memcmp(d + pe_off, "PE\0\0", 4) != 0) return false;

    const u8* coff = d + pe_off + 4;
    out.machine = rd16(coff, 0);
    u16 n_sections = rd16(coff, 2);
    out.timestamp = rd32(coff, 4);
    u16 opt_size = rd16(coff, 16);
    out.characteristics = rd16(coff, 18);
    out.is_dll = (out.characteristics & 0x2000) != 0;

    const u8* opt = coff + 20;
    if (!in_range(static_cast<std::size_t>(opt - d), 0x70, total)) return false;
    u16 magic = rd16(opt, 0);
    out.is_64 = magic == 0x20B;
    if (!out.is_64 && magic != 0x10B) return false;

    u32 entry = rd32(opt, 16);
    out.entry_point = entry;
    if (out.is_64) {
        out.image_base = rd64(opt, 24);
        out.subsystem = rd16(opt, 68);
    } else {
        out.image_base = rd32(opt, 28);
        out.subsystem = rd16(opt, 68);
    }

    u32 num_dirs = out.is_64 ? rd32(opt, 108) : rd32(opt, 92);
    std::size_t dir_off = out.is_64 ? 112 : 96;
    if (!in_range(static_cast<std::size_t>(opt - d) + dir_off, 8, total)) return false;

    const u8* sect_tbl = opt + opt_size;
    std::vector<Section> secs;
    for (u16 i = 0; i < n_sections && i < 96; ++i) {
        std::size_t o = static_cast<std::size_t>(sect_tbl - d) + i * 40;
        if (!in_range(o, 40, total)) break;
        Section s;
        s.vsize = rd32(d, o + 8);
        s.va = rd32(d, o + 12);
        s.raw_size = rd32(d, o + 16);
        s.raw = rd32(d, o + 20);
        secs.push_back(s);
        char nm[9] = {0};
        std::memcpy(nm, d + o, 8);
        out.sections.push_back(std::string(nm));
    }

    decode_rich(d, total, pe_off, out);

    // imports -> imphash
    if (num_dirs > 1) {
        u32 import_rva = rd32(opt + dir_off, 8);
        u32 import_size = rd32(opt + dir_off, 12);
        u32 imp_off = import_rva ? rva_to_offset(secs, import_rva) : 0;
        if (imp_off && import_size) {
            std::string imphash_parts;
            for (std::size_t desc = imp_off; desc + 20 <= total; desc += 20) {
                u32 oft = rd32(d, desc);
                u32 name_rva = rd32(d, desc + 12);
                u32 ft = rd32(d, desc + 16);
                if (!name_rva && !oft && !ft) break;
                u32 name_off = rva_to_offset(secs, name_rva);
                std::string dll = lower(cstr_at(d, total, name_off));
                if (dll.empty()) continue;
                out.imports.push_back(dll);
                u32 thunk_rva = oft ? oft : ft;
                u32 thunk_off = rva_to_offset(secs, thunk_rva);
                std::size_t step = out.is_64 ? 8 : 4;
                for (std::size_t t = thunk_off; t && t + step <= total; t += step) {
                    u64 val = out.is_64 ? rd64(d, t) : rd32(d, t);
                    if (!val) break;
                    u64 ordinal_flag = out.is_64 ? 0x8000000000000000ull : 0x80000000ull;
                    if (val & ordinal_flag) continue;
                    u32 hint_off = rva_to_offset(secs, static_cast<u32>(val));
                    if (!hint_off) continue;
                    std::string fn = cstr_at(d, total, hint_off + 2);
                    if (fn.empty()) continue;
                    if (!imphash_parts.empty()) imphash_parts += ",";
                    imphash_parts += dll + "." + lower(fn);
                }
            }
            if (!imphash_parts.empty()) out.imphash = md5_hex(std::vector<u8>(imphash_parts.begin(),
                                                                             imphash_parts.end()));
        }
    }
    return true;
}

void pe_records(const std::string& source, PeInfo& info, std::vector<Record>& out) {
    Record r;
    r.kind = "pe";
    r.source = source;
    r.title = "PE " + path_basename(source) + (info.is_64 ? " (x64)" : " (x86)");
    r.add("md5", info.md5);
    r.add("size", std::to_string(info.size));
    r.add("machine", hex(info.machine, 4));
    r.add("subsystem", std::to_string(info.subsystem));
    r.add("entry_point", hex(info.entry_point, 8));
    r.add("characteristics", hex(info.characteristics, 4));
    if (info.timestamp) {
        // the PE time date stamp is already a unix epoch value
        r.add("link_time_utc", unix_to_iso(static_cast<i64>(info.timestamp)));
        r.add("link_time_raw", std::to_string(info.timestamp));
    }
    if (info.has_rich) {
        r.add("rich_key", hex(info.rich_key, 8));
        r.add("rich_hash", info.rich_hash);
        std::string tools;
        for (const auto& t : info.tools) {
            char buf[64];
            std::snprintf(buf, sizeof buf, "%u.%u ", t.comp_id, t.count);
            tools += buf;
        }
        r.add("rich_tools", trim(tools));
    }
    if (!info.imphash.empty()) r.add("imphash", info.imphash);
    if (!info.imports.empty()) {
        std::string imports;
        for (const auto& i : info.imports) {
            if (!imports.empty()) imports += ",";
            imports += i;
        }
        r.add("imports", imports);
    }
    if (!info.sections.empty()) {
        std::string secs;
        for (const auto& s : info.sections) {
            if (!secs.empty()) secs += ",";
            secs += s;
        }
        r.add("sections", secs);
    }
    for (const auto& w : info.warnings) r.add("warning", w);

    r.add_id(id_raw("md5:" + info.md5));
    if (!info.imphash.empty()) r.add_id(id_raw("imphash:" + info.imphash));
    // the file path of the image is the pivot anchor towards shortcuts,
    // prefetch entries and other artifacts that reference the file
    r.add_id(id_path(source));
    r.add_id(id_path(path_basename(source)));
    if (info.has_rich) {
        r.add_id(id_raw("richkey:" + hex(info.rich_key, 8)));
        if (!info.rich_hash.empty()) r.add_id(id_raw("richhash:" + info.rich_hash));
    }
    if (info.timestamp) r.add_id(id_u32("linktime", info.timestamp));

    if (info.timestamp) r.add_time(static_cast<i64>(info.timestamp));
    out.push_back(r);
}

}  // namespace pv
