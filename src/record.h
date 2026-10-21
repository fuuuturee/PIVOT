// PIVOT - common record model
#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "util.h"

namespace pv {

// Every artifact produces Records. A Record is the normalised unit that all
// modules emit, so that different artifacts can be merged, pivoted and
// rendered with one code path.
struct Record {
    std::string kind;  // prefetch | lnk | pe | ...
    std::string source;  // artifact file the record came from
    std::string title;   // one-line human readable summary
    std::vector<std::string> ids;                            // pivot identifiers
    std::vector<std::pair<std::string, std::string>> fields;  // key/value detail
    std::vector<i64> times;                                  // unix epoch seconds (UTC)
    u64 offset = 0;                                          // evidence offset in source
    u32 size = 0;                                            // evidence length

    void add(const std::string& k, const std::string& v) { fields.emplace_back(k, v); }
    void add_id(const std::string& id) {
        // an identifier must stay unique inside a record, otherwise the pivot
        // index reports the same record twice
        for (const auto& x : ids)
            if (x == id) return;
        ids.push_back(id);
    }
    void add_time(i64 t) {
        // a negative timestamp is never a real artifact time
        if (t > 0) times.push_back(t);
    }
    i64 first_time() const { return times.empty() ? 0 : times.front(); }
};

// identifier helpers -----------------------------------------------------------

inline std::string id_path(const std::string& p) { return "path:" + lower(p); }
inline std::string id_hash(const std::string& kind, const std::string& hexv) {
    return kind + ":" + lower(hexv);
}
inline std::string id_u32(const std::string& kind, u32 v) { return kind + ":" + hex(v, 8); }
inline std::string id_u64(const std::string& kind, u64 v) { return kind + ":" + hex(v, 16); }
inline std::string id_raw(const std::string& s) { return s; }

// JSON ------------------------------------------------------------------------

std::string json_escape(const std::string& s);
std::string record_to_json(const Record& r);
std::string records_to_json(const std::vector<Record>& rs);

}  // namespace pv
