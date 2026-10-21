#include "record.h"

namespace pv {

std::string json_escape(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"': o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n"; break;
            case '\r': o += "\\r"; break;
            case '\t': o += "\\t"; break;
            case '\b': o += "\\b"; break;
            case '\f': o += "\\f"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof buf, "\\u%04x", c);
                    o += buf;
                } else {
                    o.push_back(static_cast<char>(c));
                }
        }
    }
    return o;
}

std::string record_to_json(const Record& r) {
    std::string o = "{";
    o += "\"kind\":\"" + json_escape(r.kind) + "\"";
    o += ",\"source\":\"" + json_escape(r.source) + "\"";
    o += ",\"title\":\"" + json_escape(r.title) + "\"";
    o += ",\"offset\":" + std::to_string(r.offset);
    o += ",\"size\":" + std::to_string(r.size);

    o += ",\"ids\":[";
    for (std::size_t i = 0; i < r.ids.size(); ++i) {
        if (i) o += ",";
        o += "\"" + json_escape(r.ids[i]) + "\"";
    }
    o += "]";

    o += ",\"fields\":{";
    for (std::size_t i = 0; i < r.fields.size(); ++i) {
        if (i) o += ",";
        o += "\"" + json_escape(r.fields[i].first) + "\":\"" + json_escape(r.fields[i].second) + "\"";
    }
    o += "}";

    o += ",\"times\":[";
    for (std::size_t i = 0; i < r.times.size(); ++i) {
        if (i) o += ",";
        o += "\"" + unix_to_iso(r.times[i]) + "\"";
    }
    o += "]";
    o += "}";
    return o;
}

std::string records_to_json(const std::vector<Record>& rs) {
    std::string o = "[\n";
    for (std::size_t i = 0; i < rs.size(); ++i) {
        o += record_to_json(rs[i]);
        if (i + 1 < rs.size()) o += ",";
        o += "\n";
    }
    o += "]\n";
    return o;
}

}  // namespace pv
