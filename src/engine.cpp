// PIVOT - shared artifact engine
#include "engine.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <filesystem>
#include <unordered_set>

#include "parsers/lnk.h"
#include "parsers/pe.h"
#include "parsers/prefetch.h"

namespace pv {

const char* kind_name(Kind k) {
    switch (k) {
        case Kind::Prefetch: return "prefetch";
        case Kind::Lnk: return "lnk";
        case Kind::Pe: return "pe";
        default: return "unknown";
    }
}

Kind detect_kind(const std::vector<u8>& data, const std::string& path) {
    std::string ext = lower(path_extension(path));
    if (ext == ".pf") return Kind::Prefetch;
    if (ext == ".lnk") return Kind::Lnk;
    if (ext == ".exe" || ext == ".dll" || ext == ".sys" || ext == ".ocx") return Kind::Pe;
    if (data.size() >= 8 &&
        (std::memcmp(data.data(), "SCCA", 4) == 0 || std::memcmp(data.data(), "MAM", 4) == 0))
        return Kind::Prefetch;
    if (data.size() >= 0x50 && data[0] == 'M' && data[1] == 'Z') return Kind::Pe;
    if (data.size() >= 0x4C && rd32(data.data(), 0) == 0x4C && data[4] == 0x01 && data[5] == 0x14 &&
        data[6] == 0x02)
        return Kind::Lnk;
    return Kind::Unknown;
}

bool prefetch_hash_from_name(const std::string& path, u32& out) {
    std::string base = path_basename(path);
    std::size_t dot = base.find_last_of('.');
    if (dot != std::string::npos) base = base.substr(0, dot);
    std::size_t dash = base.find_last_of('-');
    if (dash == std::string::npos) return false;
    std::string h = base.substr(dash + 1);
    if (h.size() != 8) return false;
    for (char c : h)
        if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
    out = static_cast<u32>(std::strtoul(h.c_str(), nullptr, 16));
    return true;
}

std::string record_key(const Record& r) {
    std::string k = r.kind;
    k += "|";
    k += r.source;
    k += "|";
    k += r.title;
    for (const auto& id : r.ids) {
        k += "|";
        k += id;
    }
    return k;
}

bool parse_artifact(const std::vector<u8>& data, const std::string& path,
                    std::vector<Record>& out) {
    Kind k = detect_kind(data, path);
    switch (k) {
        case Kind::Prefetch: {
            PrefetchInfo info;
            if (!parse_prefetch(data, info)) return false;
            prefetch_records(data, path, info, out);
            u32 h = 0;
            if (prefetch_hash_from_name(path, h) && !out.empty()) {
                out[0].add("pf_hash", hex(h, 8));
                out[0].add_id(id_u32("pfhash", h));
            }
            return true;
        }
        case Kind::Lnk: {
            LnkInfo info;
            if (!parse_lnk(data, info)) return false;
            lnk_records(path, info, out);
            return true;
        }
        case Kind::Pe: {
            PeInfo info;
            if (!parse_pe(data, info)) return false;
            pe_records(path, info, out);
            return true;
        }
        default:
            return false;
    }
}

std::vector<std::string> expand_inputs(const std::vector<std::string>& inputs, bool recursive) {
    std::vector<std::string> files;
    for (const auto& p : inputs) {
        std::error_code ec;
        if (std::filesystem::is_directory(p, ec)) {
            auto list = list_dir(p, recursive);
            files.insert(files.end(), list.begin(), list.end());
        } else {
            files.push_back(p);
        }
    }
    return files;
}

IngestStats ingest_files(const std::vector<std::string>& files, std::vector<Record>& records) {
    IngestStats st;

    std::unordered_set<std::string> seen;
    seen.reserve(records.size() * 2 + 16);
    for (const auto& r : records) seen.insert(record_key(r));

    for (const auto& f : files) {
        std::vector<u8> data;
        if (!read_file(f, data)) {
            ++st.skipped;
            continue;
        }
        std::vector<Record> produced;
        if (!parse_artifact(data, f, produced) || produced.empty()) {
            ++st.skipped;
            continue;
        }
        ++st.files;
        for (auto& r : produced) {
            if (!seen.insert(record_key(r)).second) {
                ++st.duplicates;
                continue;
            }
            records.push_back(std::move(r));
            ++st.records;
        }
    }
    return st;
}

}  // namespace pv
