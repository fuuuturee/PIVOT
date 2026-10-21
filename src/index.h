// PIVOT - pivot index: identifier graph, hash resolution, timeline merge
#pragma once

#include <map>
#include <string>
#include <unordered_map>
#include <vector>

#include "record.h"

namespace pv {

class Index {
  public:
    void add(const Record& r) { records_.push_back(r); }

    const std::vector<Record>& records() const { return records_; }
    std::vector<Record>& records_mut() { return records_; }

    void build();

    // records carrying a given identifier (exact match, or prefix when the
    // query does not contain ':')
    std::vector<std::size_t> by_id(const std::string& id) const;

    // all identifiers grouped by type with the number of records carrying them
    std::vector<std::pair<std::string, std::size_t>> id_counts() const;

    // same, but restricted to records of one artifact kind (e.g. "pe")
    std::vector<std::pair<std::string, std::size_t>> id_counts(const std::string& kind) const;

    void add_candidate_path(const std::string& p);
    const std::vector<std::string>& candidates() const { return candidates_; }

    // resolve a prefetch hash (8 hex chars) to candidate paths
    struct Resolution {
        std::string path;
        std::string variant;
    };
    std::vector<Resolution> resolve_hash(u32 hash) const;

    // prefetch hashes that could not be matched against any candidate path
    struct Unresolved {
        std::string hash;
        std::string exe;
        std::string source;
    };
    std::vector<Unresolved> unresolved_hashes() const;

    // merged, chronologically sorted records
    std::vector<const Record*> timeline(const std::string& kind_filter, i64 from, i64 to) const;

  private:
    std::vector<Record> records_;
    std::unordered_map<std::string, std::vector<std::size_t>> ids_;
    std::vector<std::string> candidates_;
    std::vector<std::pair<std::string, std::size_t>> id_counts_;
};

// ---------------------------------------------------------------- store

bool save_store(const std::string& path, const std::vector<Record>& records);
bool load_store(const std::string& path, std::vector<Record>& records);

}  // namespace pv
