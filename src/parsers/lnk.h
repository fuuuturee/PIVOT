// PIVOT - Windows Shortcut (LNK) parser
#pragma once

#include <string>
#include <vector>

#include "../record.h"
#include "../util.h"

namespace pv {

struct LnkInfo {
    std::string name;
    std::string relative_path;
    std::string working_dir;
    std::string arguments;
    std::string icon_location;

    std::string local_base_path;   // e.g. C:\Windows
    std::string common_suffix;     // e.g. system32\cmd.exe
    std::string network_path;      // UNC target if any
    std::string target_path;       // resolved combination
    std::string volume_device;     // \\Device\HarddiskVolume3
    std::string drive_type;        // e.g. drive letter + colon + slash
    u32 volume_serial = 0;
    u32 file_size = 0;
    u32 file_attributes = 0;
    u32 link_flags = 0;
    u64 creation_time = 0;
    u64 access_time = 0;
    u64 write_time = 0;

    std::string machine_id;        // tracker data block: PC name
    std::string mac;               // derived from tracker droid
    u64 droid_birth = 0;
    u64 tracker_birth = 0;
    std::vector<std::string> env_vars;
    u32 shell_id = 0;
    bool has_run_info = false;

    std::string aumid;             // AppUserModelID (Win10 property store)
    std::string sid;               // user SID (Win10 IDList)
    std::vector<std::string> idlist_strings;  // strings harvested from the IDList
    std::vector<std::string> extra_strings;   // strings harvested from extra data

    std::string layout;            // how the file was interpreted
    std::vector<std::string> warnings;
};

bool parse_lnk(const std::vector<u8>& data, LnkInfo& out);
void lnk_records(const std::string& source, LnkInfo& info, std::vector<Record>& out);

}  // namespace pv
