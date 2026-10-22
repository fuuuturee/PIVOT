#include "util.h"

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <system_error>

namespace fs = std::filesystem;

namespace pv {

// ---------------------------------------------------------------- utf16

std::string utf16le_to_utf8(const u8* p, std::size_t bytes) {
    std::string out;
    std::size_t n = bytes / 2;
    for (std::size_t i = 0; i < n; ++i) {
        u32 c = rd16(p, i * 2);
        if (c >= 0xD800 && c <= 0xDBFF && i + 1 < n) {
            u32 lo = rd16(p, (i + 1) * 2);
            if (lo >= 0xDC00 && lo <= 0xDFFF) {
                c = 0x10000 + ((c - 0xD800) << 10) + (lo - 0xDC00);
                ++i;
            }
        }
        if (c < 0x80) {
            out.push_back(static_cast<char>(c));
        } else if (c < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (c >> 6)));
            out.push_back(static_cast<char>(0x80 | (c & 0x3F)));
        } else if (c < 0x10000) {
            out.push_back(static_cast<char>(0xE0 | (c >> 12)));
            out.push_back(static_cast<char>(0x80 | ((c >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (c & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xF0 | (c >> 18)));
            out.push_back(static_cast<char>(0x80 | ((c >> 12) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | ((c >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (c & 0x3F)));
        }
    }
    return out;
}

// ---------------------------------------------------------------- time

std::string unix_to_iso(i64 sec) {
    if (!sec) return std::string();
    // keep the formatter inside the range the calendar functions accept
    if (sec < 0 || sec > 253402300799LL) return std::string();
    std::time_t t = static_cast<std::time_t>(sec);
    std::tm tm{};
#if defined(_WIN32)
    if (gmtime_s(&tm, &t) != 0) return std::string();
#else
    if (!gmtime_r(&t, &tm)) return std::string();
#endif
    char buf[32];
    std::snprintf(buf, sizeof buf, "%04d-%02d-%02dT%02d:%02d:%02dZ", tm.tm_year + 1900,
                  tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
    return buf;
}

std::string filetime_to_iso(u64 ft) { return unix_to_iso(filetime_to_unix(ft)); }

i64 parse_iso_utc(const std::string& s) {
    std::string t = trim(s);
    if (t.empty()) return 0;
    int y = 0, m = 0, d = 0, hh = 0, mm = 0, ss = 0;
    int n = std::sscanf(t.c_str(), "%d-%d-%dT%d:%d:%d", &y, &m, &d, &hh, &mm, &ss);
    if (n < 3) {
        // also accept a plain date with a space separator
        n = std::sscanf(t.c_str(), "%d-%d-%d %d:%d:%d", &y, &m, &d, &hh, &mm, &ss);
        if (n < 3) return 0;
    }
    if (y < 1970 || y > 9999) return 0;
    if (m < 1 || m > 12) return 0;
    if (d < 1 || d > 31) return 0;
    std::tm tm{};
    tm.tm_year = y - 1900;
    tm.tm_mon = m - 1;
    tm.tm_mday = d;
    tm.tm_hour = hh;
    tm.tm_min = mm;
    tm.tm_sec = ss;
    tm.tm_isdst = 0;
#if defined(_WIN32)
    i64 sec = static_cast<i64>(_mkgmtime(&tm));
#else
    i64 sec = static_cast<i64>(timegm(&tm));
#endif
    return sec > 0 ? sec : 0;
}

// ---------------------------------------------------------------- files

bool read_file(const std::string& path, std::vector<u8>& out) {
    std::error_code ec;
    if (!fs::exists(path, ec) || fs::is_directory(path, ec)) return false;
    auto size = fs::file_size(path, ec);
    if (ec) return false;
    FILE* f = nullptr;
    if (_wfopen_s(&f, fs::path(path).c_str(), L"rb") != 0 || !f) return false;
    out.resize(static_cast<std::size_t>(size));
    std::size_t got = out.empty() ? 0 : std::fread(out.data(), 1, out.size(), f);
    std::fclose(f);
    out.resize(got);
    return true;
}

bool file_exists(const std::string& path) {
    std::error_code ec;
    return fs::exists(path, ec) && !fs::is_directory(path, ec);
}

u64 file_size(const std::string& path) {
    std::error_code ec;
    auto s = fs::file_size(path, ec);
    return ec ? 0 : static_cast<u64>(s);
}

std::vector<std::string> list_dir(const std::string& dir, bool recursive) {
    std::vector<std::string> out;
    std::error_code ec;
    if (!fs::exists(dir, ec) || !fs::is_directory(dir, ec)) return out;
    if (recursive) {
        for (auto it = fs::recursive_directory_iterator(
                 dir, fs::directory_options::skip_permission_denied, ec);
             it != fs::recursive_directory_iterator(); it.increment(ec)) {
            std::error_code e2;
            if (it->is_regular_file(e2)) out.push_back(it->path().string());
            if (ec) break;
        }
    } else {
        for (auto it = fs::directory_iterator(dir, fs::directory_options::skip_permission_denied, ec);
             it != fs::directory_iterator(); it.increment(ec)) {
            std::error_code e2;
            if (it->is_regular_file(e2)) out.push_back(it->path().string());
            if (ec) break;
        }
    }
    std::sort(out.begin(), out.end());
    return out;
}

std::string path_basename(const std::string& p) {
    std::error_code ec;
    auto b = fs::path(p).filename().string();
    (void)ec;
    return b;
}

std::string path_extension(const std::string& p) {
    std::error_code ec;
    auto e = fs::path(p).extension().string();
    (void)ec;
    return e;
}

// ---------------------------------------------------------------- md5

namespace {

struct Md5Ctx {
    u32 a = 0x67452301, b = 0xefcdab89, c = 0x98badcfe, d = 0x10325476;
    u64 len = 0;
    u8 buf[64];
    std::size_t buflen = 0;
};

inline u32 rol(u32 x, int c) { return (x << c) | (x >> (32 - c)); }

const u32 kMd5K[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

const int kMd5S[64] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                        5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20,
                        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

void md5_block(Md5Ctx& ctx, const u8* p) {
    u32 m[16];
    for (int i = 0; i < 16; ++i) m[i] = rd32(p, i * 4);
    u32 A = ctx.a, B = ctx.b, C = ctx.c, D = ctx.d;
    for (int i = 0; i < 64; ++i) {
        u32 F;
        int g;
        if (i < 16) {
            F = (B & C) | (~B & D);
            g = i;
        } else if (i < 32) {
            F = (D & B) | (~D & C);
            g = (5 * i + 1) % 16;
        } else if (i < 48) {
            F = B ^ C ^ D;
            g = (3 * i + 5) % 16;
        } else {
            F = C ^ (B | ~D);
            g = (7 * i) % 16;
        }
        F = F + A + kMd5K[i] + m[g];
        A = D;
        D = C;
        C = B;
        B = B + rol(F, kMd5S[i]);
    }
    ctx.a += A;
    ctx.b += B;
    ctx.c += C;
    ctx.d += D;
}

}  // namespace

std::string md5_hex(const std::vector<u8>& data) {
    Md5Ctx ctx;
    ctx.len = data.size();
    std::size_t i = 0;
    for (; i + 64 <= data.size(); i += 64) md5_block(ctx, data.data() + i);

    u8 tail[128];
    std::size_t rem = data.size() - i;
    std::memcpy(tail, data.data() + i, rem);
    tail[rem++] = 0x80;
    std::size_t total = (rem <= 56) ? 64 : 128;
    std::memset(tail + rem, 0, total - rem - 8);
    u64 bits = ctx.len * 8;
    for (int k = 0; k < 8; ++k) tail[total - 8 + k] = static_cast<u8>((bits >> (8 * k)) & 0xFF);
    for (std::size_t off = 0; off < total; off += 64) md5_block(ctx, tail + off);

    u32 words[4] = {ctx.a, ctx.b, ctx.c, ctx.d};
    std::string out;
    for (int w = 0; w < 4; ++w)
        for (int b = 3; b >= 0; --b) out += hexbytes(reinterpret_cast<const u8*>(&words[w]) + b, 1);
    return out;
}

}  // namespace pv
