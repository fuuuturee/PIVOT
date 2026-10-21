// PIVOT - Prefetch (SCCA/MAM) parser
#pragma once

#include <string>
#include <vector>

#include "../record.h"
#include "../util.h"

namespace pv {

struct PrefetchRef {
    std::string name;
    u32 size = 0;
    u32 flags = 0;
    u32 hash = 0;  // prefetch path hash (v17-v8) or 0
};

struct PrefetchInfo {
    u32 version = 0;
    std::string exe;
    u32 exe_hash = 0;
    u32 run_count = 0;
    u64 last_run = 0;
    std::vector<u64> run_times;          // FILETIME
    std::vector<PrefetchRef> refs;       // referenced files
    std::vector<std::string> volumes;    // device paths
    std::vector<u32> volume_serials;
    std::vector<std::string> warnings;
};

bool parse_prefetch(const std::vector<u8>& data, PrefetchInfo& out);
void prefetch_records(const std::vector<u8>& data, const std::string& source, PrefetchInfo& info,
                      std::vector<Record>& out);

// Prefetch path hashing -------------------------------------------------------
// Windows hashes the *uppercase* path of the executed image. Depending on the
// Windows build the rotation direction, the add/subtract and the handling of
// the path length differ, so all known combinations are tried when a hash is
// resolved back to a path.
enum class PfHashForm { Rol13Sub, Ror13Add, Rol13Add, Ror13Sub };

struct PfHashVariant {
    PfHashForm form = PfHashForm::Ror13Add;
    bool add_length = true;
    std::string label;
};

u32 prefetch_hash(const std::string& path, const PfHashVariant& variant);
const std::vector<PfHashVariant>& prefetch_hash_variants();
// path shapes that are hashed for a given file name
std::vector<std::string> prefetch_path_forms(const std::string& full_path);
// size of one file metrics entry for a given prefetch version
std::size_t prefetch_entry_size(u32 version);

}  // namespace pv
