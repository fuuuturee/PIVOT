// PIVOT - PE / Rich header parser
#pragma once

#include <string>
#include <vector>

#include "../record.h"
#include "../util.h"

namespace pv {

struct RichTool {
    u32 comp_id = 0;
    u32 count = 0;
};

struct PeInfo {
    u16 machine = 0;
    u32 timestamp = 0;
    u16 characteristics = 0;
    u64 image_base = 0;
    bool is_64 = false;
    bool is_dll = false;
    u32 subsystem = 0;
    u32 entry_point = 0;

    std::string md5;
    u64 size = 0;

    bool has_rich = false;
    u32 rich_key = 0;
    std::string rich_hash;  // md5 over the decoded comp.id/count chain
    std::vector<RichTool> tools;

    std::vector<std::string> imports;
    std::vector<std::string> sections;
    std::string imphash;
    std::vector<std::string> warnings;
};

bool parse_pe(const std::vector<u8>& data, PeInfo& out);
void pe_records(const std::string& source, PeInfo& info, std::vector<Record>& out);

}  // namespace pv
