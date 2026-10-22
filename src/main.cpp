#include <cctype>
#include <conio.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <io.h>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

#include "engine.h"
#include "index.h"
#include "record.h"
#include "util.h"

using namespace pv;

namespace {

constexpr const char* kVersion = "0.2.0";

std::string default_store() { return "pivot.store"; }

struct Args {
    std::vector<std::string> positional;
    std::string store = default_store();
    std::string json;
    std::string kind;
    std::string from, to;
    std::string candidates;
    bool recursive = false;
    int limit = 50;
};

Args parse_args(int argc, char** argv) {
    Args a;
    for (int i = 2; i < argc; ++i) {
        std::string s = argv[i];
        auto next = [&](std::string& dst) {
            if (i + 1 < argc) dst = argv[++i];
        };
        if (s == "--store") next(a.store);
        else if (s == "--json") next(a.json);
        else if (s == "--kind") next(a.kind);
        else if (s == "--from") next(a.from);
        else if (s == "--to") next(a.to);
        else if (s == "--candidates") next(a.candidates);
        else if (s == "--limit") { std::string v; next(v); a.limit = std::atoi(v.c_str()); }
        else if (s == "--recursive" || s == "-r") a.recursive = true;
        else a.positional.push_back(s);
    }
    return a;
}

void print_record(const Record& r, bool verbose) {
    std::string t;
    for (i64 ts : r.times) {
        if (!t.empty()) t += " ";
        t += unix_to_iso(ts);
        if (t.size() > 19) break;
    }
    std::printf("%-20s %-9s %s\n", t.empty() ? "-" : t.c_str(), r.kind.c_str(), r.title.c_str());
    std::printf("    source : %s", r.source.c_str());
    if (r.offset || r.size) std::printf("  (+0x%llx, %u bytes)", (unsigned long long)r.offset, r.size);
    std::printf("\n");
    if (verbose) {
        for (const auto& f : r.fields) std::printf("    %-18s: %s\n", f.first.c_str(), f.second.c_str());
        for (const auto& id : r.ids) std::printf("    id                 : %s\n", id.c_str());
    }
}

int cmd_ingest(const Args& a) {
    std::vector<std::string> files = expand_inputs(a.positional, a.recursive);
    if (files.empty()) {
        std::fprintf(stderr, "ingest: no input files\n");
        return 2;
    }

    std::vector<Record> records;
    load_store(a.store, records);
    size_t before = records.size();

    IngestStats st = ingest_files(files, records);
    save_store(a.store, records);

    if (!a.json.empty()) {
        std::ofstream o(a.json, std::ios::trunc);
        o << records_to_json(records);
    }
    if (!a.json.empty()) {
        // also keep a stable jsonl sidecar next to the store
        std::ofstream o(a.json + ".jsonl", std::ios::trunc);
        for (const auto& r : records) o << record_to_json(r) << "\n";
    }

    std::printf("ingested %zu files (%zu records, %zu skipped, %zu duplicates) -> %s\n", st.files,
                records.size() - before, st.skipped, st.duplicates, a.store.c_str());
    if (!a.json.empty()) std::printf("json export: %s\n", a.json.c_str());
    return 0;
}

Index build_index(const Args& a) {
    Index idx;
    load_store(a.store, idx.records_mut());
    if (!a.candidates.empty()) {
        std::ifstream in(a.candidates);
        std::string line;
        while (std::getline(in, line)) {
            line = trim(line);
            if (!line.empty()) idx.add_candidate_path(line);
        }
    }
    idx.build();
    return idx;
}

int cmd_ids(const Args& a) {
    Index idx = build_index(a);
    auto counts = idx.id_counts(a.kind);
    int shown = 0;
    for (const auto& kv : counts) {
        if (shown++ >= a.limit) {
            std::printf("... (%zu identifiers total)\n", counts.size());
            break;
        }
        std::printf("%-10zu %s\n", kv.second, kv.first.c_str());
    }
    return 0;
}

int cmd_show(const Args& a) {
    if (a.positional.empty()) {
        std::fprintf(stderr, "show: <identifier> required\n");
        return 2;
    }
    Index idx = build_index(a);
    auto hits = idx.by_id(a.positional[0]);
    std::printf("%zu record(s) for '%s'\n\n", hits.size(), a.positional[0].c_str());
    for (auto i : hits) print_record(idx.records()[i], true);
    return 0;
}

int cmd_resolve(const Args& a) {
    if (a.positional.empty()) {
        std::fprintf(stderr, "resolve: <hash> required\n");
        return 2;
    }
    Index idx = build_index(a);
    std::string h = a.positional[0];
    if (h.rfind("pfhash:", 0) == 0) h = h.substr(7);
    u32 hash = static_cast<u32>(std::strtoul(h.c_str(), nullptr, 16));
    auto res = idx.resolve_hash(hash);
    std::printf("hash %s -> %zu candidate path(s) [%zu candidates tested]\n", hex(hash, 8).c_str(),
                res.size(), idx.candidates().size());
    for (const auto& r : res) std::printf("  %-8s %s\n", r.variant.c_str(), r.path.c_str());
    return 0;
}

int cmd_unresolved(const Args& a) {
    Index idx = build_index(a);
    auto u = idx.unresolved_hashes();
    std::printf("%zu unresolved prefetch hash(es)\n\n", u.size());
    for (const auto& x : u)
        std::printf("  %s  %-28s %s\n", x.hash.c_str(), x.exe.c_str(), x.source.c_str());
    return 0;
}

int cmd_timeline(const Args& a) {
    Index idx = build_index(a);
    i64 from = parse_iso_utc(a.from);
    i64 to = parse_iso_utc(a.to);
    auto tl = idx.timeline(a.kind, from, to);
    std::printf("%zu entries\n\n", tl.size());
    for (const auto* r : tl) print_record(*r, false);
    return 0;
}

int cmd_stats(const Args& a) {
    Index idx = build_index(a);
    std::map<std::string, size_t> per_kind;
    i64 lo = 0, hi = 0;
    size_t ids = 0;
    for (const auto& r : idx.records()) {
        per_kind[r.kind]++;
        ids += r.ids.size();
        for (i64 t : r.times) {
            if (!lo || t < lo) lo = t;
            if (t > hi) hi = t;
        }
    }
    std::printf("records    : %zu\n", idx.records().size());
    std::printf("identifiers: %zu\n", ids);
    std::printf("candidates : %zu\n", idx.candidates().size());
    for (const auto& kv : per_kind) std::printf("  %-12s %zu\n", kv.first.c_str(), kv.second);
    if (lo) std::printf("time range : %s .. %s\n", unix_to_iso(lo).c_str(), unix_to_iso(hi).c_str());
    return 0;
}

int cmd_records(const Args& a) {
    Index idx = build_index(a);
    std::vector<Record> sel;
    for (const auto& r : idx.records()) {
        if (!a.kind.empty() && r.kind != a.kind) continue;
        sel.push_back(r);
    }
    if (!a.json.empty()) {
        std::ofstream o(a.json, std::ios::trunc);
        o << records_to_json(sel);
        std::printf("%zu records -> %s\n", sel.size(), a.json.c_str());
        return 0;
    }
    for (const auto& r : sel) print_record(r, false);
    return 0;
}

void usage() {
    std::printf(
        "PIVOT - forensic artifact pivot engine\n\n"
        "  pivot ingest <paths...> [--store F] [--json F] [--candidates F] [-r]\n"
        "  pivot ids [--kind TYPE] [--limit N] [--store F]\n"
        "  pivot show <identifier> [--store F]\n"
        "  pivot resolve <hash> [--store F] [--candidates F]\n"
        "  pivot unresolved [--store F] [--candidates F]\n"
        "  pivot timeline [--kind K] [--from ISO] [--to ISO] [--store F]\n"
        "  pivot records [--kind K] [--json F] [--store F]\n"
        "  pivot stats [--store F]\n"
        "  pivot --version\n\n"
        "identifier kinds: path: pfhash: vserial: richkey: richhash: imphash: md5: machine: mac:\n\n"
        "get started:\n"
        "  pivot ingest <folder> --store case.store --json case.json\n"
        "  pivot ids --store case.store\n"
        "  pivot show \"path:c:\\windows\\system32\\notepad.exe\" --store case.store -v\n");
}

// When the tool is started by double clicking the exe the console window would
// close right away - keep it open until a key is pressed. Only done when both
// streams are a console, so scripts and pipelines are never blocked.
void wait_for_key() {
    if (!_isatty(_fileno(stdin)) || !_isatty(_fileno(stdout))) return;
    std::printf("\nPress any key to close this window . . .");
    (void)_getch();
    std::printf("\n");
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        usage();
        wait_for_key();
        return 1;
    }
    std::string cmd = argv[1];
    Args a = parse_args(argc, argv);

    if (cmd == "--version" || cmd == "-V") {
        std::printf("pivot %s\n", kVersion);
        return 0;
    }
    if (cmd == "ingest") return cmd_ingest(a);
    if (cmd == "ids") return cmd_ids(a);
    if (cmd == "show") return cmd_show(a);
    if (cmd == "resolve") return cmd_resolve(a);
    if (cmd == "unresolved") return cmd_unresolved(a);
    if (cmd == "timeline") return cmd_timeline(a);
    if (cmd == "records") return cmd_records(a);
    if (cmd == "stats") return cmd_stats(a);
    if (cmd == "-h" || cmd == "--help" || cmd == "help") {
        usage();
        return 0;
    }
    std::fprintf(stderr, "unknown command '%s'\n", cmd.c_str());
    usage();
    return 1;
}
