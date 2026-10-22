// PIVOT - Forensic Artifact Pivot Engine
// util.h: byte readers, string helpers, time conversion, MD5
#pragma once

#include <cstdint>
#include <cstdio>
#include <ctime>
#include <cstring>
#include <string>
#include <vector>

namespace pv {

using u8 = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;
using i64 = std::int64_t;

// ---------------------------------------------------------------- byte access

inline bool in_range(std::size_t off, std::size_t len, std::size_t total) {
    return off <= total && len <= total - off;
}

inline u16 rd16(const u8* p, std::size_t off) {
    return static_cast<u16>(p[off] | (p[off + 1] << 8));
}

inline u32 rd32(const u8* p, std::size_t off) {
    return static_cast<u32>(p[off]) | (static_cast<u32>(p[off + 1]) << 8) |
           (static_cast<u32>(p[off + 2]) << 16) | (static_cast<u32>(p[off + 3]) << 24);
}

inline u64 rd64(const u8* p, std::size_t off) {
    return static_cast<u64>(rd32(p, off)) | (static_cast<u64>(rd32(p, off + 4)) << 32);
}

// ---------------------------------------------------------------- string utils

inline std::string lower(std::string s) {
    for (auto& c : s)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return s;
}

inline std::string trim(std::string s) {
    std::size_t a = 0, b = s.size();
    while (a < b && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '\n')) ++a;
    while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r' || s[b - 1] == '\n')) --b;
    return s.substr(a, b - a);
}

inline std::string hex(u64 v, int width = 0) {
    static const char* d = "0123456789abcdef";
    std::string s;
    if (!width) {
        char buf[32];
        std::snprintf(buf, sizeof buf, "%llx", static_cast<unsigned long long>(v));
        return buf;
    }
    for (int i = width - 1; i >= 0; --i) s.push_back(d[(v >> (i * 4)) & 0xF]);
    return s;
}

inline std::string hexbytes(const u8* p, std::size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s;
    for (std::size_t i = 0; i < n; ++i) {
        s.push_back(d[p[i] >> 4]);
        s.push_back(d[p[i] & 0xF]);
    }
    return s;
}

inline bool printable(const std::string& s) {
    for (unsigned char c : s)
        if (c < 0x20 || c > 0x7e) return false;
    return !s.empty();
}

// UTF-16LE -> UTF-8 (best effort, no surrogate pair merging beyond BMP)
std::string utf16le_to_utf8(const u8* p, std::size_t bytes);

// ---------------------------------------------------------------- time helpers

// FILETIME (100ns since 1601-01-01) -> unix epoch seconds
inline i64 filetime_to_unix(u64 ft) {
    if (ft == 0) return 0;
    return static_cast<i64>(ft / 10000000ULL) - 11644473600LL;
}

inline u64 unix_to_filetime(i64 sec) {
    return static_cast<u64>((sec + 11644473600LL) * 10000000LL);
}

// unix epoch seconds -> "YYYY-MM-DDTHH:MM:SSZ"
std::string unix_to_iso(i64 sec);
std::string filetime_to_iso(u64 ft);

// ISO-8601 -> unix epoch seconds (UTC).
// Accepts "YYYY-MM-DD" as well as "YYYY-MM-DDTHH:MM:SS" (the trailing "Z" and
// any offset are ignored). Returns 0 when the value cannot be parsed, which
// the callers read as "no filter".
i64 parse_iso_utc(const std::string& s);

// ---------------------------------------------------------------- file helpers

bool read_file(const std::string& path, std::vector<u8>& out);
bool file_exists(const std::string& path);
u64 file_size(const std::string& path);
std::vector<std::string> list_dir(const std::string& dir, bool recursive);
std::string path_basename(const std::string& p);
std::string path_extension(const std::string& p);

// ---------------------------------------------------------------- md5

std::string md5_hex(const std::vector<u8>& data);

}  // namespace pv
