#include "index.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <sstream>

#include "parsers/prefetch.h"

namespace pv {

namespace {

}  // namespace

void Index::build() {
    ids_.clear();
    for (std::size_t i = 0; i < records_.size(); ++i) {
        for (const auto& id : records_[i].ids) {
            if (id.empty()) continue;
            ids_[id].push_back(i);
            // a path identifier is also a candidate for hash resolution
            if (id.rfind("path:", 0) == 0) {
                std::string p = id.substr(5);
                if (!p.empty()) add_candidate_path(p);
            }
        }
    }
    id_counts_.clear();
    for (const auto& kv : ids_) id_counts_.emplace_back(kv.first, kv.second.size());
    std::sort(id_counts_.begin(), id_counts_.end(),
              [](const auto& a, const auto& b) {
                  if (a.second != b.second) return a.second > b.second;
                  return a.first < b.first;
              });
}

std::vector<std::size_t> Index::by_id(const std::string& id) const {
    std::vector<std::size_t> out;
    auto it = ids_.find(id);
    if (it != ids_.end()) return it->second;
    // prefix / substring search for convenience
    std::string q = lower(id);
    for (const auto& kv : ids_) {
        if (lower(kv.first).find(q) != std::string::npos)
            out.insert(out.end(), kv.second.begin(), kv.second.end());
    }
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

std::vector<std::pair<std::string, std::size_t>> Index::id_counts() const { return id_counts_; }

std::vector<std::pair<std::string, std::size_t>> Index::id_counts(const std::string& kind) const {
    std::map<std::string, std::size_t> counts;
    for (const auto& r : records_) {
        if (!kind.empty() && r.kind != kind) continue;
        for (const auto& id : r.ids) {
            if (id.empty()) continue;
            counts[id]++;
        }
    }
    std::vector<std::pair<std::string, std::size_t>> out(counts.begin(), counts.end());
    std::sort(out.begin(), out.end(), [](const auto& a, const auto& b) {
        if (a.second != b.second) return a.second > b.second;
        return a.first < b.first;
    });
    return out;
}

void Index::add_candidate_path(const std::string& p) {
    if (p.empty()) return;
    if (std::find(candidates_.begin(), candidates_.end(), p) == candidates_.end())
        candidates_.push_back(p);
}

std::vector<Index::Resolution> Index::resolve_hash(u32 hash) const {
    std::vector<Resolution> out;
    for (const auto& cand : candidates_) {
        for (const auto& form : prefetch_path_forms(cand)) {
            for (const auto& v : prefetch_hash_variants()) {
                if (prefetch_hash(form, v) == hash) {
                    Resolution res;
                    res.path = cand;
                    res.variant = v.label + " " + form;
                    if (std::find_if(out.begin(), out.end(), [&](const Resolution& r) {
                            return r.path == res.path;
                        }) == out.end())
                        out.push_back(res);
                }
            }
        }
    }
    return out;
}

std::vector<Index::Unresolved> Index::unresolved_hashes() const {
    std::vector<Unresolved> out;
    for (const auto& r : records_) {
        if (r.kind != "prefetch") continue;
        std::string exe, hash;
        for (const auto& kv : r.fields) {
            if (kv.first == "executable") exe = kv.second;
        }
        for (const auto& id : r.ids) {
            if (id.rfind("pfhash:", 0) != 0) continue;
            hash = id.substr(7);
            if (hash.empty()) continue;
            u32 hv = static_cast<u32>(std::strtoul(hash.c_str(), nullptr, 16));
            if (resolve_hash(hv).empty()) {
                Unresolved u;
                u.hash = hash;
                u.exe = exe;
                u.source = r.source;
                out.push_back(u);
            }
        }
    }
    return out;
}

std::vector<const Record*> Index::timeline(const std::string& kind_filter, i64 from, i64 to) const {
    std::vector<const Record*> out;
    for (const auto& r : records_) {
        if (!kind_filter.empty() && r.kind != kind_filter) continue;
        bool keep = false;
        for (i64 t : r.times) {
            if (from && t < from) continue;
            if (to && t > to) continue;
            keep = true;
            break;
        }
        if (r.times.empty() && !from && !to) keep = true;
        if (keep) out.push_back(&r);
    }
    std::stable_sort(out.begin(), out.end(), [](const Record* a, const Record* b) {
        return a->first_time() < b->first_time();
    });
    return out;
}

// ---------------------------------------------------------------- store

namespace {

template <typename Stream>
void put_str(Stream& o, const std::string& s) {
    u32 n = static_cast<u32>(s.size());
    o.write(reinterpret_cast<const char*>(&n), 4);
    if (n) o.write(s.data(), n);
}

template <typename Stream>
bool get_str(Stream& in, std::string& s) {
    u32 n = 0;
    in.read(reinterpret_cast<char*>(&n), 4);
    if (!in || n > (1u << 24)) return false;
    s.resize(n);
    if (n) in.read(s.data(), n);
    return static_cast<bool>(in);
}

}  // namespace

bool save_store(const std::string& path, const std::vector<Record>& records) {
    std::ofstream o(path, std::ios::binary | std::ios::trunc);
    if (!o) return false;
    const char magic[4] = {'P', 'V', 'S', '1'};
    o.write(magic, 4);
    u32 count = static_cast<u32>(records.size());
    o.write(reinterpret_cast<const char*>(&count), 4);
    for (const auto& r : records) {
        std::ostringstream ss;
        put_str(ss, r.kind);
        put_str(ss, r.source);
        put_str(ss, r.title);
        u32 n = static_cast<u32>(r.ids.size());
        ss.write(reinterpret_cast<const char*>(&n), 4);
        for (const auto& id : r.ids) put_str(ss, id);
        n = static_cast<u32>(r.fields.size());
        ss.write(reinterpret_cast<const char*>(&n), 4);
        for (const auto& f : r.fields) {
            put_str(ss, f.first);
            put_str(ss, f.second);
        }
        n = static_cast<u32>(r.times.size());
        ss.write(reinterpret_cast<const char*>(&n), 4);
        for (i64 t : r.times) ss.write(reinterpret_cast<const char*>(&t), 8);
        ss.write(reinterpret_cast<const char*>(&r.offset), 8);
        ss.write(reinterpret_cast<const char*>(&r.size), 4);
        std::string blob = ss.str();
        u32 len = static_cast<u32>(blob.size());
        o.write(reinterpret_cast<const char*>(&len), 4);
        o.write(blob.data(), len);
    }
    return static_cast<bool>(o);
}

bool load_store(const std::string& path, std::vector<Record>& records) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    char magic[4];
    in.read(magic, 4);
    if (!in || std::memcmp(magic, "PVS1", 4) != 0) return false;
    u32 count = 0;
    in.read(reinterpret_cast<char*>(&count), 4);
    for (u32 i = 0; i < count; ++i) {
        u32 len = 0;
        in.read(reinterpret_cast<char*>(&len), 4);
        if (!in) return false;
        std::string blob(len, '\0');
        in.read(blob.data(), len);
        std::istringstream ss(blob);
        Record r;
        if (!get_str(ss, r.kind)) return false;
        if (!get_str(ss, r.source)) return false;
        if (!get_str(ss, r.title)) return false;
        u32 n = 0;
        ss.read(reinterpret_cast<char*>(&n), 4);
        for (u32 k = 0; k < n; ++k) {
            std::string id;
            if (!get_str(ss, id)) return false;
            r.ids.push_back(id);
        }
        ss.read(reinterpret_cast<char*>(&n), 4);
        for (u32 k = 0; k < n; ++k) {
            std::string a, b;
            if (!get_str(ss, a)) return false;
            if (!get_str(ss, b)) return false;
            r.fields.emplace_back(a, b);
        }
        ss.read(reinterpret_cast<char*>(&n), 4);
        for (u32 k = 0; k < n; ++k) {
            i64 t = 0;
            ss.read(reinterpret_cast<char*>(&t), 8);
            r.times.push_back(t);
        }
        ss.read(reinterpret_cast<char*>(&r.offset), 8);
        ss.read(reinterpret_cast<char*>(&r.size), 4);
        records.push_back(std::move(r));
    }
    return true;
}

}  // namespace pv
