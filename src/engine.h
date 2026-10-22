// PIVOT - shared artifact engine
// The command line client and the Windows GUI both use this module, so an
// artifact is always parsed in exactly the same way.
#pragma once

#include <string>
#include <vector>

#include "record.h"
#include "util.h"

namespace pv {

enum class Kind { Unknown, Prefetch, Lnk, Pe };

const char* kind_name(Kind k);

// guess the artifact type from the extension and the magic bytes
Kind detect_kind(const std::vector<u8>& data, const std::string& path);

// "NOTEPAD.EXE-1B67C0AE.pf" -> 0x1b67c0ae
bool prefetch_hash_from_name(const std::string& path, u32& out);

// key that makes ingesting the same artifact twice a no-op
std::string record_key(const Record& r);

// parse a single artifact into zero or more records
bool parse_artifact(const std::vector<u8>& data, const std::string& path,
                    std::vector<Record>& out);

struct IngestStats {
    size_t files = 0;       // artifacts that produced records
    size_t records = 0;     // new records added
    size_t skipped = 0;     // unreadable or unsupported
    size_t duplicates = 0;  // already known
};

// expand folders and files into a flat list of artifact files
std::vector<std::string> expand_inputs(const std::vector<std::string>& inputs, bool recursive);

// ingest artifacts into an existing record set, skipping known duplicates
IngestStats ingest_files(const std::vector<std::string>& files, std::vector<Record>& records);

}  // namespace pv
