// PIVOT - native Windows GUI
//
// A forensic workbench on top of the shared engine: ingest artifacts, pivot
// over the identifier graph, inspect the details of every record and export
// the result. Pure Win32 so the binary stays self contained.
//
// Layout
//   row 0   command bar   Artefakte | Store oeffnen | Export || Statistik | Reset
//   row 1   filter bar    Suchen | Typ | Zeit ab/bis | Timeline || Pivot indicator
//   body    three panes   Identifier (Typ | Identifier | Records)
//                          Records   (Zeit | Typ | Titel | Quelle | Anker)
//                          Details   (Feld | Wert, gruppiert und einklappbar)
//   bottom  status bar    counts | store | pivot
//
// Everything that is drawn follows the same rules: one font per role, one
// spacing grid, German labels, and the dark mode of Windows is honoured
// instead of being fought with a custom colour scheme.
// windows.h defines min/max as macros - the standard templates are used here
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

#include <commctrl.h>
#include <commdlg.h>
#include <dwmapi.h>
#include <shellapi.h>
#include <shobjidl.h>
#include <uxtheme.h>
#include <windowsx.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <map>
#include <set>
#include <string>
#include <system_error>
#include <vector>

#include "engine.h"
#include "index.h"
#include "record.h"
#include "util.h"

using namespace pv;

namespace {

constexpr const char* kVersion = "0.2.0";
constexpr wchar_t kWindowClass[] = L"PIVOT.Gui.Window";
constexpr int kMaxRows = 5000;  // guard against huge stores freezing the list

// ---------------------------------------------------------------- control ids

enum : int {
    IDC_IDS = 101,
    IDC_RECORDS = 102,
    IDC_DETAILS = 103,
    IDC_STATUS = 104,

    IDC_INGEST = 201,
    IDC_OPEN = 202,
    IDC_EXPORT = 203,
    IDC_STATS = 204,
    IDC_RESET = 205,
    IDC_RECURSIVE = 206,

    IDC_SEARCH = 220,
    IDC_KIND = 221,
    IDC_FROM = 222,
    IDC_TO = 223,
    IDC_TIMELINE = 224,

    IDC_GROUP_IDS = 240,
    IDC_GROUP_RECORDS = 241,
    IDC_GROUP_DETAILS = 242,

    IDC_LABEL_SEARCH = 250,
    IDC_LABEL_KIND = 251,
    IDC_LABEL_FROM = 252,
    IDC_LABEL_TO = 253,
    IDC_PIVOT = 254,

    IDC_CMD_FOCUS_SEARCH = 300,
    IDC_CMD_COPY_RECORDS = 301,
};

// ---------------------------------------------------------------- palette

struct Theme {
    COLORREF window = RGB(240, 240, 240);
    COLORREF text = RGB(24, 24, 24);
    COLORREF panel = RGB(32, 32, 32);
};

Theme g_theme;
HBRUSH g_brush = nullptr;

// ---------------------------------------------------------------- detail rows

// The detail pane is a flat list of rows that carry their group. The group
// name is stored on every row, so a group can be collapsed without losing the
// order of the details.
struct DetailRow {
    std::string group;
    std::string key;
    std::string value;
    bool is_group = false;
};

// ---------------------------------------------------------------- app state

struct App {
    HINSTANCE inst = nullptr;
    HWND hwnd = nullptr;
    HWND list_ids = nullptr;
    HWND list_records = nullptr;
    HWND list_details = nullptr;
    HWND status = nullptr;
    HWND search = nullptr;
    HWND kind = nullptr;
    HWND from_edit = nullptr;
    HWND to_edit = nullptr;
    HWND timeline = nullptr;
    HWND pivot_label = nullptr;
    HWND group_ids = nullptr;
    HWND group_records = nullptr;
    HWND group_details = nullptr;

    HWND btn_ingest = nullptr;
    HWND btn_open = nullptr;
    HWND btn_export = nullptr;
    HWND btn_stats = nullptr;
    HWND btn_reset = nullptr;
    HWND btn_recursive = nullptr;

    HFONT font = nullptr;
    HFONT font_bold = nullptr;
    HFONT font_mono = nullptr;
    int dpi = 96;

    std::vector<Record> records;
    Index index;
    std::vector<std::size_t> shown;        // record indices currently listed
    std::vector<std::pair<std::string, std::size_t>> id_list;
    std::vector<std::string> visible_ids;  // id of every row in the id list
    std::string selected_id;
    std::string store_path;
    bool recursive = true;
    bool timeline_mode = false;
    bool dark = false;
    int sort_column = 0;
    bool sort_asc = true;
    bool dirty = false;

    std::vector<DetailRow> detail_rows;         // all rows of the current record
    std::vector<std::size_t> detail_shown;      // row -> index in detail_rows
    std::set<std::string> collapsed_groups;
};

App g_app;

// ---------------------------------------------------------------- helpers

std::string to_utf8(const std::wstring& w) {
    if (w.empty()) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr,
                                nullptr);
    if (n <= 0) return std::string();
    std::string s(static_cast<std::size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), s.data(), n, nullptr,
                        nullptr);
    return s;
}

std::wstring from_utf8(const std::string& s) {
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (n <= 0) return std::wstring();
    std::wstring w(static_cast<std::size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(), n);
    return w;
}

int scaled(const App& app, int v) { return MulDiv(v, app.dpi, 96); }

void set_text(HWND hwnd, const std::string& text) {
    std::wstring w = from_utf8(text);
    SetWindowTextW(hwnd, w.c_str());
}

std::string get_text(HWND hwnd) {
    int len = GetWindowTextLengthW(hwnd);
    std::wstring w(static_cast<std::size_t>(len) + 1, L'\0');
    GetWindowTextW(hwnd, w.data(), len + 1);
    w.resize(static_cast<std::size_t>(len));
    return to_utf8(w);
}

bool contains_ci(const std::string& haystack, const std::string& needle) {
    if (needle.empty()) return true;
    return lower(haystack).find(lower(needle)) != std::string::npos;
}

// The identifier that anchors a record: the path it belongs to, otherwise the
// first identifier the record carries.
std::string anchor_id(const Record& r) {
    for (const auto& id : r.ids)
        if (id.rfind("path:", 0) == 0) return id;
    if (!r.ids.empty()) return r.ids.front();
    return std::string();
}

// The type prefix of an identifier ("path", "pfhash", ...) used as a facet.
std::string id_type(const std::string& id) {
    std::size_t colon = id.find(':');
    return colon == std::string::npos ? std::string() : id.substr(0, colon);
}

// read and write the text of a list view cell.
// The SDK macros ListView_SetItemText / ListView_GetItemText build an
// uninitialised LV_ITEM, so the items are sent directly with a valid mask.
std::wstring list_get_text(HWND list, int row, int sub) {
    wchar_t buf[2048] = {0};
    LVITEMW item{};
    item.mask = LVIF_TEXT;
    item.iSubItem = sub;
    item.pszText = buf;
    item.cchTextMax = 2047;
    SendMessageW(list, LVM_GETITEMTEXTW, static_cast<WPARAM>(row), reinterpret_cast<LPARAM>(&item));
    return buf;
}

void list_set_text(HWND list, int row, int sub, const wchar_t* text) {
    LVITEMW item{};
    item.mask = LVIF_TEXT;
    item.iSubItem = sub;
    item.pszText = const_cast<wchar_t*>(text);
    SendMessageW(list, LVM_SETITEMTEXTW, static_cast<WPARAM>(row), reinterpret_cast<LPARAM>(&item));
}

void status_text(App& app, int part, const std::string& text) {
    if (!app.status) return;
    SendMessageW(app.status, SB_SETTEXTW, static_cast<WPARAM>(part),
                 reinterpret_cast<LPARAM>(from_utf8(text).c_str()));
}

void info_box(HWND parent, const std::string& title, const std::string& text) {
    MessageBoxW(parent, from_utf8(text).c_str(), from_utf8(title).c_str(),
                 MB_OK | MB_ICONINFORMATION);
}

void error_box(HWND parent, const std::string& title, const std::string& text) {
    MessageBoxW(parent, from_utf8(text).c_str(), from_utf8(title).c_str(), MB_OK | MB_ICONERROR);
}

// ---------------------------------------------------------------- fonts

HFONT make_font(const wchar_t* family, int points, int weight) {
    LOGFONTW lf{};
    lf.lfHeight = -MulDiv(points, g_app.dpi, 72);
    lf.lfWeight = weight;
    lf.lfCharSet = DEFAULT_CHARSET;
    lf.lfQuality = CLEARTYPE_QUALITY;
    lf.lfOutPrecision = OUT_TT_PRECIS;
    lf.lfPitchAndFamily = DEFAULT_PITCH | FF_SWISS;
    wcscpy_s(lf.lfFaceName, family);
    return CreateFontIndirectW(&lf);
}

void create_fonts(App& app) {
    if (app.font) DeleteObject(app.font);
    if (app.font_bold) DeleteObject(app.font_bold);
    if (app.font_mono) DeleteObject(app.font_mono);

    HFONT base = make_font(L"Segoe UI", 9, FW_NORMAL);
    if (!base) base = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
    app.font = base;

    LOGFONTW lf{};
    GetObjectW(app.font, sizeof(lf), &lf);
    lf.lfWeight = FW_BOLD;
    app.font_bold = CreateFontIndirectW(&lf);

    app.font_mono = make_font(L"Consolas", 9, FW_NORMAL);
}

void apply_font(App& app, HWND hwnd, HFONT font = nullptr) {
    if (hwnd) SendMessageW(hwnd, WM_SETFONT, reinterpret_cast<WPARAM>(font ? font : app.font), TRUE);
}

// ---------------------------------------------------------------- dark mode

using FnAllowDarkMode = bool(WINAPI*)(HWND, bool);
using FnRefreshNonClientArea = void(WINAPI*)(HWND);

bool system_is_dark() {
    HKEY key = nullptr;
    DWORD value = 1;
    DWORD size = sizeof(value);
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
                      L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize", 0,
                      KEY_READ, &key) == ERROR_SUCCESS) {
        RegQueryValueExW(key, L"AppsUseLightTheme", nullptr, nullptr,
                         reinterpret_cast<LPBYTE>(&value), &size);
        RegCloseKey(key);
    }
    return value == 0;
}

// Dark mode needs the (undocumented but public) helpers of uxtheme. When they
// are missing the application stays in the light system theme instead of
// showing a half painted window.
bool dark_supported() {
    static int state = -1;
    if (state < 0) {
        HMODULE ux = LoadLibraryW(L"uxtheme.dll");
        state = (ux && GetProcAddress(ux, "AllowDarkModeForWindow")) ? 1 : 0;
    }
    return state == 1;
}

void enable_dark(HWND hwnd) {
    if (!g_app.dark || !hwnd) return;
    static HMODULE ux = LoadLibraryW(L"uxtheme.dll");
    if (!ux) return;
    SetWindowTheme(hwnd, L"DarkMode_Explorer", nullptr);
    auto allow = reinterpret_cast<FnAllowDarkMode>(GetProcAddress(ux, "AllowDarkModeForWindow"));
    auto allow_list = reinterpret_cast<FnAllowDarkMode>(GetProcAddress(ux, "AllowDarkModeForListView"));
    auto allow_scroll = reinterpret_cast<FnAllowDarkMode>(GetProcAddress(ux, "AllowDarkModeForScrollBar"));
    auto refresh = reinterpret_cast<FnRefreshNonClientArea>(GetProcAddress(ux, "RefreshNonClientArea"));
    if (allow) allow(hwnd, TRUE);
    if (allow_list) allow_list(hwnd, TRUE);
    if (allow_scroll) allow_scroll(hwnd, TRUE);
    if (refresh) refresh(hwnd);
}

void style_list(App& app, HWND list) {
    enable_dark(list);
    if (app.dark) {
        ListView_SetBkColor(list, g_theme.panel);
        ListView_SetTextColor(list, g_theme.text);
    }
}

void apply_theme(App& app) {
    if (app.dark) {
        g_theme.window = RGB(32, 32, 32);
        g_theme.text = RGB(238, 238, 238);
        g_theme.panel = RGB(26, 26, 26);
    } else {
        g_theme.window = RGB(240, 240, 240);
        g_theme.text = RGB(24, 24, 24);
        g_theme.panel = RGB(255, 255, 255);
    }
    if (g_brush) DeleteObject(g_brush);
    g_brush = CreateSolidBrush(g_theme.window);

    HWND controls[] = {app.btn_ingest,   app.btn_open,     app.btn_export,  app.btn_stats,
                       app.btn_reset,    app.btn_recursive, app.kind,      app.timeline,
                       app.hwnd};
    for (HWND c : controls) enable_dark(c);

    style_list(app, app.list_ids);
    style_list(app, app.list_records);
    style_list(app, app.list_details);
    enable_dark(app.status);

    if (app.hwnd) {
        SetClassLongPtrW(app.hwnd, GCLP_HBRBACKGROUND, reinterpret_cast<LONG_PTR>(g_brush));
        InvalidateRect(app.hwnd, nullptr, TRUE);
        RedrawWindow(app.hwnd, nullptr, nullptr, RDW_ERASE | RDW_INVALIDATE | RDW_ALLCHILDREN);
    }
}

// ---------------------------------------------------------------- data flow

void rebuild_index(App& app) {
    app.index.records_mut() = app.records;
    app.index.build();
    app.id_list = app.index.id_counts();
}

// The kind combo is filled from the data, so unknown artifact types never get
// lost and the list never shows empty entries.
void refresh_kind_combo(App& app) {
    std::set<std::string> kinds;
    for (const auto& r : app.records) kinds.insert(r.kind);
    std::string current = get_text(app.kind);

    std::vector<std::string> want;
    want.push_back("alle Typen");
    for (const auto& k : kinds) want.push_back(k);

    std::vector<std::string> have;
    int count = static_cast<int>(SendMessageW(app.kind, CB_GETCOUNT, 0, 0));
    for (int i = 0; i < count; ++i) {
        wchar_t buf[128] = {0};
        SendMessageW(app.kind, CB_GETLBTEXT, static_cast<WPARAM>(i), reinterpret_cast<LPARAM>(buf));
        have.push_back(to_utf8(buf));
    }
    if (have == want) return;

    SendMessageW(app.kind, CB_RESETCONTENT, 0, 0);
    for (const auto& k : want) {
        std::wstring w = from_utf8(k);
        SendMessageW(app.kind, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(w.c_str()));
    }
    int sel = 0;
    for (std::size_t i = 0; i < want.size(); ++i) {
        if (want[i] == current) {
            sel = static_cast<int>(i);
            break;
        }
    }
    SendMessageW(app.kind, CB_SETCURSEL, sel, 0);
}

std::string current_kind(App& app) {
    int sel = static_cast<int>(SendMessageW(app.kind, CB_GETCURSEL, 0, 0));
    if (sel <= 0) return std::string();
    wchar_t buf[64] = {0};
    SendMessageW(app.kind, CB_GETLBTEXT, static_cast<WPARAM>(sel), reinterpret_cast<LPARAM>(buf));
    std::string k = to_utf8(buf);
    return k == "alle Typen" ? std::string() : k;
}

void fill_identifier_list(App& app) {
    SendMessageW(app.list_ids, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(app.list_ids);
    app.visible_ids.clear();

    std::string needle = get_text(app.search);
    for (const auto& kv : app.id_list) {
        if (!contains_ci(kv.first, needle)) continue;
        app.visible_ids.push_back(kv.first);

        std::wstring w_type = from_utf8(id_type(kv.first));
        std::wstring w_id = from_utf8(kv.first);
        std::wstring w_count = from_utf8(std::to_string(kv.second));

        LVITEMW item{};
        item.mask = LVIF_TEXT;
        item.iItem = static_cast<int>(ListView_GetItemCount(app.list_ids));
        item.pszText = const_cast<wchar_t*>(w_type.c_str());
        int row = ListView_InsertItem(app.list_ids, &item);
        if (row < 0) continue;
        list_set_text(app.list_ids, row, 1, w_id.c_str());
        list_set_text(app.list_ids, row, 2, w_count.c_str());
    }
    SendMessageW(app.list_ids, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(app.list_ids, nullptr, TRUE);
}

bool record_in_range(const Record& r, i64 from, i64 to) {
    if (!from && !to) return true;
    if (r.times.empty()) return false;
    for (i64 t : r.times) {
        if (from && t < from) continue;
        if (to && t > to) continue;
        return true;
    }
    return false;
}

void apply_filter(App& app) {
    std::string needle = get_text(app.search);
    std::string kind = current_kind(app);
    i64 from = parse_iso_utc(get_text(app.from_edit));
    i64 to = parse_iso_utc(get_text(app.to_edit));

    std::vector<std::size_t> hits;
    if (!app.selected_id.empty()) {
        hits = app.index.by_id(app.selected_id);
    } else {
        for (std::size_t i = 0; i < app.records.size(); ++i) hits.push_back(i);
    }

    std::vector<std::size_t> keep;
    keep.reserve(hits.size());
    for (std::size_t idx : hits) {
        const Record& r = app.records[idx];
        if (!kind.empty() && r.kind != kind) continue;
        if (!record_in_range(r, from, to)) continue;
        if (app.timeline_mode && r.times.empty()) continue;
        if (!needle.empty()) {
            bool hit = contains_ci(r.title, needle) || contains_ci(r.source, needle);
            if (!hit)
                for (const auto& id : r.ids)
                    if (contains_ci(id, needle)) {
                        hit = true;
                        break;
                    }
            if (!hit) continue;
        }
        keep.push_back(idx);
    }
    app.shown = std::move(keep);
}

void sort_shown(App& app) {
    int col = app.sort_column;
    bool asc = app.sort_asc;
    if (app.timeline_mode) {
        col = 0;
        asc = true;
    }
    std::stable_sort(app.shown.begin(), app.shown.end(), [&](std::size_t a, std::size_t b) {
        const Record& ra = app.records[a];
        const Record& rb = app.records[b];
        int cmp = 0;
        switch (col) {
            case 0:
                cmp = ra.first_time() < rb.first_time() ? -1 : (ra.first_time() > rb.first_time() ? 1 : 0);
                break;
            case 1: cmp = ra.kind.compare(rb.kind); break;
            case 2: cmp = ra.title.compare(rb.title); break;
            case 3: cmp = ra.source.compare(rb.source); break;
            default:
                cmp = ra.ids.size() < rb.ids.size() ? -1 : (ra.ids.size() > rb.ids.size() ? 1 : 0);
                break;
        }
        return asc ? cmp < 0 : cmp > 0;
    });
}

void fill_record_list(App& app) {
    sort_shown(app);
    SendMessageW(app.list_records, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(app.list_records);
    std::size_t count = std::min<std::size_t>(app.shown.size(), kMaxRows);
    for (std::size_t i = 0; i < count; ++i) {
        const Record& r = app.records[app.shown[i]];
        std::string when = r.first_time() ? unix_to_iso(r.first_time()) : std::string("-");
        std::wstring w_when = from_utf8(when);
        std::wstring w_kind = from_utf8(r.kind);
        std::wstring w_title = from_utf8(r.title);
        std::wstring w_source = from_utf8(r.source);
        std::wstring w_anchor = from_utf8(anchor_id(r));

        LVITEMW item{};
        item.mask = LVIF_TEXT | LVIF_PARAM;
        item.iItem = static_cast<int>(i);
        item.pszText = const_cast<wchar_t*>(w_when.c_str());
        item.lParam = static_cast<LPARAM>(app.shown[i]);
        int row = ListView_InsertItem(app.list_records, &item);
        if (row < 0) break;

        list_set_text(app.list_records, row, 1, w_kind.c_str());
        list_set_text(app.list_records, row, 2, w_title.c_str());
        list_set_text(app.list_records, row, 3, w_source.c_str());
        list_set_text(app.list_records, row, 4, w_anchor.c_str());
    }
    SendMessageW(app.list_records, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(app.list_records, nullptr, TRUE);
}

// ---------------------------------------------------------------- detail pane

// UTF-8 markers for the collapsible group rows.
constexpr const char* kMarkOpen[] = {"\xE2\x96\xBE", "\xE2\x96\xB8"};

void detail_add_group(App& app, const std::string& name) {
    DetailRow row;
    row.group = name;
    row.key = name;
    row.is_group = true;
    app.detail_rows.push_back(row);
}

void detail_add(App& app, const std::string& group, const std::string& key,
                const std::string& value) {
    DetailRow row;
    row.group = group;
    row.key = key;
    row.value = value;
    app.detail_rows.push_back(row);
}

void render_details(App& app) {
    SendMessageW(app.list_details, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(app.list_details);
    app.detail_shown.clear();

    for (std::size_t i = 0; i < app.detail_rows.size(); ++i) {
        const DetailRow& row = app.detail_rows[i];
        if (!row.is_group && app.collapsed_groups.count(row.group)) continue;

        std::wstring w_key;
        if (row.is_group) {
            bool open = app.collapsed_groups.count(row.group) == 0;
            w_key = from_utf8(std::string(kMarkOpen[open ? 0 : 1]) + " " + row.key);
        } else {
            w_key = from_utf8("   " + row.key);
        }
        std::wstring w_value = from_utf8(row.value);

        LVITEMW item{};
        item.mask = LVIF_TEXT | LVIF_PARAM;
        item.iItem = static_cast<int>(ListView_GetItemCount(app.list_details));
        item.pszText = const_cast<wchar_t*>(w_key.c_str());
        item.lParam = static_cast<LPARAM>(i);
        int row_index = ListView_InsertItem(app.list_details, &item);
        if (row_index < 0) break;
        list_set_text(app.list_details, row_index, 1, w_value.c_str());
        app.detail_shown.push_back(i);
    }
    SendMessageW(app.list_details, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(app.list_details, nullptr, TRUE);
}

void fill_details(App& app, std::size_t record_index) {
    app.detail_rows.clear();
    app.collapsed_groups.clear();

    if (record_index < app.records.size()) {
        const Record& r = app.records[record_index];

        std::vector<std::string> warnings;
        std::vector<std::pair<std::string, std::string>> plain;
        for (const auto& f : r.fields) {
            if (f.first == "warning")
                warnings.push_back(f.second);
            else
                plain.push_back(f);
        }

        detail_add_group(app, "Allgemein");
        detail_add(app, "Allgemein", "Typ", r.kind);
        detail_add(app, "Allgemein", "Titel", r.title);
        detail_add(app, "Allgemein", "Quelle", r.source);
        if (r.offset || r.size) {
            char buf[64];
            std::snprintf(buf, sizeof buf, "+0x%llx  (%u Bytes)",
                          static_cast<unsigned long long>(r.offset), r.size);
            detail_add(app, "Allgemein", "Offset", buf);
        }

        if (!r.times.empty()) {
            detail_add_group(app, "Zeit");
            for (std::size_t i = 0; i < r.times.size(); ++i)
                detail_add(app, "Zeit", "Zeit " + std::to_string(i + 1), unix_to_iso(r.times[i]));
        }

        if (!plain.empty()) {
            detail_add_group(app, "Details");
            for (const auto& f : plain) detail_add(app, "Details", f.first, f.second);
        }

        if (!r.ids.empty()) {
            detail_add_group(app, "Identifier");
            for (const auto& id : r.ids) detail_add(app, "Identifier", id_type(id), id);
        }

        if (!warnings.empty()) {
            detail_add_group(app, "Warnungen");
            for (const auto& w : warnings) detail_add(app, "Warnungen", "Warnung", w);
        }
    }
    render_details(app);
}

void update_pivot_label(App& app) {
    if (app.selected_id.empty()) {
        set_text(app.pivot_label, "Kein Pivot aktiv");
        apply_font(app, app.pivot_label, app.font);
    } else {
        set_text(app.pivot_label, "Pivot: " + app.selected_id);
        apply_font(app, app.pivot_label, app.font_bold);
    }
}

void update_status(App& app) {
    std::map<std::string, std::size_t> per_kind;
    for (const auto& r : app.records) per_kind[r.kind]++;
    std::string left = std::to_string(app.shown.size()) + " von " + std::to_string(app.records.size()) +
                       " Records";
    for (const auto& kv : per_kind) left += "   " + kv.first + ": " + std::to_string(kv.second);
    if (app.shown.size() > kMaxRows)
        left += "   (Anzeige auf " + std::to_string(kMaxRows) + " begrenzt)";
    if (app.records.empty()) left = "Keine Records - ueber 'Artefakte...' ingestieren";
    status_text(app, 0, left);
    status_text(app, 1, "Store: " + app.store_path);
    status_text(app, 2, app.selected_id.empty() ? std::string("kein Pivot")
                                                 : ("Pivot: " + app.selected_id));
}

void refresh_all(App& app) {
    rebuild_index(app);
    refresh_kind_combo(app);
    fill_identifier_list(app);
    apply_filter(app);
    fill_record_list(app);
    update_pivot_label(app);
    update_status(app);
}

void select_record(App& app, int row) {
    if (row < 0) {
        fill_details(app, static_cast<std::size_t>(-1));
        return;
    }
    LVITEMW item{};
    item.mask = LVIF_PARAM;
    item.iItem = row;
    if (ListView_GetItem(app.list_records, &item)) {
        fill_details(app, static_cast<std::size_t>(item.lParam));
    }
}

// ---------------------------------------------------------------- ingest

void persist_store(App& app) {
    if (app.store_path.empty()) return;
    std::error_code ec;
    std::filesystem::path p(app.store_path);
    if (p.has_parent_path()) std::filesystem::create_directories(p.parent_path(), ec);
    if (!save_store(app.store_path, app.records)) {
        error_box(app.hwnd, "PIVOT", "Der Store konnte nicht gespeichert werden:\n" + app.store_path);
    } else {
        app.dirty = false;
    }
}

void do_ingest(App& app, const std::vector<std::string>& inputs) {
    if (inputs.empty()) return;
    std::vector<std::string> files = expand_inputs(inputs, app.recursive);
    if (files.empty()) {
        error_box(app.hwnd, "PIVOT", "In den gewaehlten Pfaden wurden keine Dateien gefunden.");
        return;
    }
    SetCursor(LoadCursorW(nullptr, IDC_WAIT));
    IngestStats st = ingest_files(files, app.records);
    SetCursor(nullptr);
    if (st.records || st.files) {
        app.dirty = true;
        persist_store(app);
    }
    refresh_all(app);

    std::string msg = "Dateien: " + std::to_string(st.files) + "\n" +
                      "Neue Records: " + std::to_string(st.records) + "\n" +
                      "Uebersprungen: " + std::to_string(st.skipped) + "\n" +
                      "Duplikate: " + std::to_string(st.duplicates);
    status_text(app, 0, "Ingest: " + std::to_string(st.files) + " Dateien, " +
                           std::to_string(st.records) + " neue Records");
    info_box(app.hwnd, "Ingest abgeschlossen", msg);
}

// ---------------------------------------------------------------- dialogs

bool pick_folders(HWND owner, std::vector<std::string>& out) {
    IFileOpenDialog* dlg = nullptr;
    if (FAILED(CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER,
                                IID_PPV_ARGS(&dlg))))
        return false;
    DWORD opts = 0;
    dlg->GetOptions(&opts);
    opts |= FOS_PICKFOLDERS | FOS_ALLOWMULTISELECT | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST;
    dlg->SetOptions(opts);
    if (SUCCEEDED(dlg->Show(owner))) {
        IShellItemArray* items = nullptr;
        if (SUCCEEDED(dlg->GetResults(&items)) && items) {
            DWORD count = 0;
            items->GetCount(&count);
            for (DWORD i = 0; i < count; ++i) {
                IShellItem* item = nullptr;
                if (SUCCEEDED(items->GetItemAt(i, &item)) && item) {
                    PWSTR path = nullptr;
                    if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &path)) && path) {
                        out.push_back(to_utf8(path));
                        CoTaskMemFree(path);
                    }
                    item->Release();
                }
            }
            items->Release();
        }
    }
    dlg->Release();
    return !out.empty();
}

bool pick_store(HWND owner, const std::string& current, std::string& out) {
    IFileOpenDialog* dlg = nullptr;
    if (FAILED(CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER,
                                IID_PPV_ARGS(&dlg))))
        return false;
    DWORD opts = 0;
    dlg->GetOptions(&opts);
    opts |= FOS_FORCEFILESYSTEM | FOS_FILEMUSTEXIST;
    dlg->SetOptions(opts);
    COMDLG_FILTERSPEC spec[] = {{L"PIVOT Store", L"*.store"}, {L"Alle Dateien", L"*.*"}};
    dlg->SetFileTypes(ARRAYSIZE(spec), spec);
    if (!current.empty()) {
        IShellItem* item = nullptr;
        if (SUCCEEDED(SHCreateItemFromParsingName(from_utf8(current).c_str(), nullptr,
                                                    IID_PPV_ARGS(&item))) &&
            item) {
            dlg->SetFolder(item);
            item->Release();
        }
    }
    bool ok = false;
    if (SUCCEEDED(dlg->Show(owner))) {
        IShellItem* item = nullptr;
        if (SUCCEEDED(dlg->GetResult(&item)) && item) {
            PWSTR path = nullptr;
            if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &path)) && path) {
                out = to_utf8(path);
                ok = true;
                CoTaskMemFree(path);
            }
            item->Release();
        }
    }
    dlg->Release();
    return ok;
}

bool pick_json_target(HWND owner, std::string& out) {
    IFileSaveDialog* dlg = nullptr;
    if (FAILED(CoCreateInstance(CLSID_FileSaveDialog, nullptr, CLSCTX_INPROC_SERVER,
                                IID_PPV_ARGS(&dlg))))
        return false;
    DWORD opts = 0;
    dlg->GetOptions(&opts);
    opts |= FOS_FORCEFILESYSTEM | FOS_OVERWRITEPROMPT;
    dlg->SetOptions(opts);
    COMDLG_FILTERSPEC spec[] = {{L"JSON", L"*.json"}, {L"Alle Dateien", L"*.*"}};
    dlg->SetFileTypes(ARRAYSIZE(spec), spec);
    dlg->SetFileName(L"pivot-export.json");
    bool ok = false;
    if (SUCCEEDED(dlg->Show(owner))) {
        IShellItem* item = nullptr;
        if (SUCCEEDED(dlg->GetResult(&item)) && item) {
            PWSTR path = nullptr;
            if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &path)) && path) {
                out = to_utf8(path);
                ok = true;
                CoTaskMemFree(path);
            }
            item->Release();
        }
    }
    dlg->Release();
    return ok;
}

void export_json(App& app) {
    std::string target;
    if (!pick_json_target(app.hwnd, target)) return;
    FILE* f = nullptr;
    if (fopen_s(&f, target.c_str(), "wb") != 0 || !f) {
        error_box(app.hwnd, "PIVOT", "Die Datei konnte nicht geschrieben werden:\n" + target);
        return;
    }
    std::string json = records_to_json(app.records);
    fwrite(json.data(), 1, json.size(), f);
    fclose(f);

    std::string side = target + ".jsonl";
    if (FILE* g = nullptr; fopen_s(&g, side.c_str(), "wb") == 0 && g) {
        for (const auto& r : app.records) {
            std::string line = record_to_json(r);
            line += "\n";
            fwrite(line.data(), 1, line.size(), g);
        }
        fclose(g);
    }
    status_text(app, 0, "Exportiert: " + target);
    info_box(app.hwnd, "Export", "Export geschrieben:\n" + target + "\n" + side);
}

void show_stats(App& app) {
    std::map<std::string, std::size_t> per_kind;
    i64 lo = 0, hi = 0;
    std::size_t ids = 0;
    for (const auto& r : app.records) {
        per_kind[r.kind]++;
        ids += r.ids.size();
        for (i64 t : r.times) {
            if (!lo || t < lo) lo = t;
            if (t > hi) hi = t;
        }
    }
    std::string text = "Records      : " + std::to_string(app.records.size()) + "\n" +
                       "Identifier   : " + std::to_string(ids) + "\n" +
                       "Distinct IDs : " + std::to_string(app.id_list.size()) + "\n";
    for (const auto& kv : per_kind)
        text += "  " + kv.first + std::string(9 - std::min<size_t>(9, kv.first.size()), ' ') + ": " +
                std::to_string(kv.second) + "\n";
    if (lo) text += "Zeitraum     : " + unix_to_iso(lo) + " .. " + unix_to_iso(hi) + "\n";
    text += "Store        : " + app.store_path;
    info_box(app.hwnd, "Statistik", text);
}

// ---------------------------------------------------------------- settings

void load_settings(App& app) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\fuuuturee\\PIVOT", 0, KEY_READ, &key) !=
        ERROR_SUCCESS)
        return;
    wchar_t path[MAX_PATH * 2] = {0};
    DWORD cb = sizeof(path);
    if (RegQueryValueExW(key, L"StorePath", nullptr, nullptr, reinterpret_cast<LPBYTE>(path), &cb) ==
        ERROR_SUCCESS)
        app.store_path = to_utf8(path);
    DWORD flag = 1;
    cb = sizeof(flag);
    if (RegQueryValueExW(key, L"Recursive", nullptr, nullptr, reinterpret_cast<LPBYTE>(&flag), &cb) ==
        ERROR_SUCCESS)
        app.recursive = flag != 0;
    RegCloseKey(key);
}

void save_settings(App& app) {
    HKEY key = nullptr;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\fuuuturee\\PIVOT", 0, nullptr,
                        REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &key, nullptr) != ERROR_SUCCESS)
        return;
    std::wstring path = from_utf8(app.store_path);
    RegSetValueExW(key, L"StorePath", 0, REG_SZ, reinterpret_cast<const BYTE*>(path.c_str()),
                   static_cast<DWORD>((path.size() + 1) * sizeof(wchar_t)));
    DWORD flag = app.recursive ? 1 : 0;
    RegSetValueExW(key, L"Recursive", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&flag),
                   sizeof(flag));
    RegCloseKey(key);
}

// ---------------------------------------------------------------- layout

void place(HWND hwnd, int x, int y, int w, int h) {
    if (hwnd) SetWindowPos(hwnd, nullptr, x, y, w, h, SWP_NOZORDER | SWP_NOACTIVATE);
}

// A pane is a group box with a caption and a list inside it.
void place_pane(App& app, HWND group, HWND list, int x, int y, int w, int h) {
    int inset = scaled(app, 6);
    int title = scaled(app, 18);
    place(group, x, y, w, h);
    place(list, x + inset, y + title, w - inset * 2, h - title - inset);
}

void update_status_parts(App& app, int width) {
    int parts[3] = {0, 0, 0};
    parts[0] = width * 45 / 100;
    parts[1] = parts[0] + width * 30 / 100;
    parts[2] = width;
    SendMessageW(app.status, SB_SETPARTS, 3, reinterpret_cast<LPARAM>(parts));
}

void layout(App& app) {
    RECT rc{};
    GetClientRect(app.hwnd, &rc);
    int w = rc.right;
    int h = rc.bottom;

    int pad = scaled(app, 8);
    int cmd_h = scaled(app, 28);
    int filt_h = scaled(app, 26);
    int row1 = scaled(app, 6);
    int row2 = cmd_h + scaled(app, 6);
    int top = row2 + filt_h + scaled(app, 8);
    int status_h = scaled(app, 22);

    // ---- row 0: command bar
    int x = pad;
    place(app.btn_ingest, x, row1, scaled(app, 104), cmd_h);
    x += scaled(app, 110);
    place(app.btn_open, x, row1, scaled(app, 112), cmd_h);
    x += scaled(app, 118);
    place(app.btn_export, x, row1, scaled(app, 112), cmd_h);
    x += scaled(app, 120);
    place(app.btn_recursive, x, row1 + scaled(app, 4), scaled(app, 112), cmd_h - scaled(app, 8));
    x += scaled(app, 120);
    place(app.btn_stats, x, row1, scaled(app, 92), cmd_h);
    x += scaled(app, 98);
    place(app.btn_reset, x, row1, scaled(app, 122), cmd_h);

    // ---- row 1: filter bar
    int y = row2;
    int edit_w = scaled(app, 150);
    HWND lbl = GetDlgItem(app.hwnd, IDC_LABEL_SEARCH);
    place(app.search, x + scaled(app, 52), y, edit_w, filt_h - scaled(app, 4));
    if (lbl) place(lbl, x, y + scaled(app, 3), scaled(app, 48), filt_h);
    x += scaled(app, 52) + edit_w + scaled(app, 10);

    place(app.kind, x + scaled(app, 30), y, scaled(app, 124), filt_h - scaled(app, 4));
    lbl = GetDlgItem(app.hwnd, IDC_LABEL_KIND);
    if (lbl) place(lbl, x, y + scaled(app, 3), scaled(app, 26), filt_h);
    x += scaled(app, 30) + scaled(app, 124) + scaled(app, 10);

    place(app.from_edit, x + scaled(app, 52), y, scaled(app, 98), filt_h - scaled(app, 4));
    lbl = GetDlgItem(app.hwnd, IDC_LABEL_FROM);
    if (lbl) place(lbl, x, y + scaled(app, 3), scaled(app, 48), filt_h);
    x += scaled(app, 52) + scaled(app, 98) + scaled(app, 6);

    place(app.to_edit, x + scaled(app, 26), y, scaled(app, 98), filt_h - scaled(app, 4));
    lbl = GetDlgItem(app.hwnd, IDC_LABEL_TO);
    if (lbl) place(lbl, x, y + scaled(app, 3), scaled(app, 22), filt_h);
    x += scaled(app, 26) + scaled(app, 98) + scaled(app, 14);

    place(app.timeline, x, y + scaled(app, 2), scaled(app, 96), filt_h);
    x += scaled(app, 108);

    int right = w - pad;
    place(app.pivot_label, right - scaled(app, 340), y, scaled(app, 340), filt_h);

    // ---- body: three panes
    int body_h = h - top - status_h;
    int left_w = scaled(app, 310);
    int right_w = scaled(app, 400);
    int center_w = w - left_w - right_w;
    if (center_w < scaled(app, 240)) {
        center_w = scaled(app, 240);
        right_w = w - left_w - center_w;
        if (right_w < scaled(app, 220)) {
            right_w = scaled(app, 220);
            left_w = w - center_w - right_w;
        }
    }

    place_pane(app, app.group_ids, app.list_ids, 0, top, left_w, body_h);
    place_pane(app, app.group_records, app.list_records, left_w, top, center_w, body_h);
    place_pane(app, app.group_details, app.list_details, w - right_w, top, right_w, body_h);

    place(app.status, 0, h - status_h, w, status_h);
    update_status_parts(app, w);

    // column widths: the fixed columns keep their size, the last one fills up
    int rec_w = center_w - scaled(app, 12);
    ListView_SetColumnWidth(app.list_records, 0, scaled(app, 132));
    ListView_SetColumnWidth(app.list_records, 1, scaled(app, 74));
    ListView_SetColumnWidth(app.list_records, 2, scaled(app, 200));
    ListView_SetColumnWidth(app.list_records, 3, scaled(app, 200));
    ListView_SetColumnWidth(app.list_records, 4, std::max(scaled(app, 120), rec_w - scaled(app, 606)));

    int id_w = left_w - scaled(app, 12);
    ListView_SetColumnWidth(app.list_ids, 0, scaled(app, 76));
    ListView_SetColumnWidth(app.list_ids, 1, std::max(scaled(app, 150), id_w - scaled(app, 128)));
    ListView_SetColumnWidth(app.list_ids, 2, scaled(app, 52));

    int det_w = right_w - scaled(app, 12);
    ListView_SetColumnWidth(app.list_details, 0, scaled(app, 140));
    ListView_SetColumnWidth(app.list_details, 1, std::max(scaled(app, 140), det_w - scaled(app, 140)));
}

// ---------------------------------------------------------------- clipboard

void copy_to_clipboard(const std::string& text) {
    if (text.empty()) return;
    if (!OpenClipboard(g_app.hwnd)) return;
    EmptyClipboard();
    HGLOBAL mem = GlobalAlloc(GMEM_MOVEABLE, text.size() + 1);
    if (mem) {
        char* dst = static_cast<char*>(GlobalLock(mem));
        if (dst) {
            memcpy(dst, text.data(), text.size());
            dst[text.size()] = '\0';
            GlobalUnlock(mem);
            SetClipboardData(CF_UNICODETEXT, mem);
        }
    }
    CloseClipboard();
}

std::string records_as_text(App& app) {
    std::string out;
    for (std::size_t idx : app.shown) {
        const Record& r = app.records[idx];
        out += (r.first_time() ? unix_to_iso(r.first_time()) : std::string("-"));
        out += "\t" + r.kind + "\t" + r.title + "\t" + r.source + "\t" + anchor_id(r) + "\r\n";
    }
    return out;
}

std::string details_as_text(App& app) {
    std::string out;
    for (std::size_t idx : app.detail_shown) {
        const DetailRow& row = app.detail_rows[idx];
        if (row.is_group)
            out += "[" + row.key + "]\r\n";
        else
            out += "  " + row.key + ": " + row.value + "\r\n";
    }
    return out;
}

// ---------------------------------------------------------------- commands

void reset_filters(App& app) {
    app.selected_id.clear();
    SetWindowTextW(app.search, L"");
    SetWindowTextW(app.from_edit, L"");
    SetWindowTextW(app.to_edit, L"");
    SendMessageW(app.kind, CB_SETCURSEL, 0, 0);
    app.timeline_mode = false;
    SendMessageW(app.timeline, BM_SETCHECK, BST_UNCHECKED, 0);
    refresh_all(app);
}

void do_ingest_inputs_from_dialog(App& app) {
    std::vector<std::string> dirs;
    if (pick_folders(app.hwnd, dirs)) do_ingest(app, dirs);
}

void open_store(App& app) {
    std::string path;
    if (!pick_store(app.hwnd, app.store_path, path)) return;
    std::vector<Record> loaded;
    if (!load_store(path, loaded)) {
        error_box(app.hwnd, "PIVOT", "Der Store konnte nicht gelesen werden:\n" + path);
        return;
    }
    app.records = std::move(loaded);
    app.store_path = path;
    app.selected_id.clear();
    app.dirty = false;
    save_settings(app);
    refresh_all(app);
}

void on_command(App& app, int id, int code, HWND ctrl) {
    switch (id) {
        case IDC_INGEST:
            do_ingest_inputs_from_dialog(app);
            break;
        case IDC_OPEN:
            open_store(app);
            break;
        case IDC_EXPORT:
            export_json(app);
            break;
        case IDC_STATS:
            show_stats(app);
            break;
        case IDC_RESET:
            reset_filters(app);
            break;
        case IDC_RECURSIVE: {
            app.recursive = (SendMessageW(app.btn_recursive, BM_GETCHECK, 0, 0) == BST_CHECKED);
            save_settings(app);
            break;
        }
        case IDC_SEARCH: {
            if (code == EN_CHANGE) {
                fill_identifier_list(app);
                apply_filter(app);
                fill_record_list(app);
                update_status(app);
            }
            break;
        }
        case IDC_KIND: {
            if (code == CBN_SELCHANGE) {
                apply_filter(app);
                fill_record_list(app);
                update_status(app);
            }
            break;
        }
        case IDC_FROM:
        case IDC_TO: {
            if (code == EN_CHANGE) {
                apply_filter(app);
                fill_record_list(app);
                update_status(app);
            }
            break;
        }
        case IDC_TIMELINE: {
            if (code == BN_CLICKED) {
                app.timeline_mode = (SendMessageW(app.timeline, BM_GETCHECK, 0, 0) == BST_CHECKED);
                apply_filter(app);
                fill_record_list(app);
                update_status(app);
            }
            break;
        }
        case IDC_CMD_FOCUS_SEARCH:
            SetFocus(app.search);
            SendMessageW(app.search, EM_SETSEL, 0, -1);
            break;
        case IDC_CMD_COPY_RECORDS:
            copy_to_clipboard(records_as_text(app));
            break;
        default:
            (void)ctrl;
            break;
    }
}

LRESULT details_custom_draw(App& app, NMLVCUSTOMDRAW* cd) {
    if (cd->nmcd.dwDrawStage == CDDS_PREPAINT) return CDRF_DODEFAULT;
    if (cd->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) {
        int row = static_cast<int>(cd->nmcd.dwItemSpec);
        if (row >= 0 && row < static_cast<int>(app.detail_shown.size())) {
            const DetailRow& d = app.detail_rows[app.detail_shown[row]];
            if (d.is_group) {
                cd->nmcd.uItemState &= ~CDIS_FOCUS;
                SelectObject(cd->nmcd.hdc, app.font_bold);
                return CDRF_NEWFONT;
            }
        }
    }
    return CDRF_DODEFAULT;
}

void on_notify(App& app, NMHDR* hdr) {
    if (hdr->idFrom == IDC_IDS) {
        if (hdr->code == LVN_ITEMCHANGED) {
            auto* ch = reinterpret_cast<NMLISTVIEW*>(hdr);
            if (!(ch->uChanged & LVIF_STATE)) return;
            if (!(ch->uNewState & LVIS_SELECTED)) return;
            int row = ch->iItem;
            if (row < 0 || row >= static_cast<int>(app.visible_ids.size())) return;
            app.selected_id = app.visible_ids[row];
            apply_filter(app);
            fill_record_list(app);
            update_pivot_label(app);
            update_status(app);
            return;
        }
        if (hdr->code == NM_DBLCLK) {
            int row = ListView_GetNextItem(app.list_ids, -1, LVNI_FOCUSED);
            if (row < 0 || row >= static_cast<int>(app.visible_ids.size())) return;
            copy_to_clipboard(app.visible_ids[row]);
            return;
        }
        if (hdr->code == NM_RCLICK) {
            int row = ListView_GetNextItem(app.list_ids, -1, LVNI_FOCUSED);
            if (row < 0 || row >= static_cast<int>(app.visible_ids.size())) return;
            HMENU menu = CreatePopupMenu();
            AppendMenuW(menu, MF_STRING, 1, L"Identifier kopieren");
            AppendMenuW(menu, MF_STRING, 2, L"Pivot setzen");
            POINT pt{};
            GetCursorPos(&pt);
            SetForegroundWindow(app.hwnd);
            int cmd = TrackPopupMenu(menu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, app.hwnd, nullptr);
            if (cmd == 1) {
                copy_to_clipboard(app.visible_ids[row]);
            } else if (cmd == 2) {
                app.selected_id = app.visible_ids[row];
                apply_filter(app);
                fill_record_list(app);
                update_pivot_label(app);
                update_status(app);
            }
            DestroyMenu(menu);
            return;
        }
    }
    if (hdr->idFrom == IDC_RECORDS) {
        if (hdr->code == LVN_ITEMCHANGED) {
            auto* ch = reinterpret_cast<NMLISTVIEW*>(hdr);
            if (ch->uChanged & LVIF_STATE) select_record(app, ch->iItem);
        } else if (hdr->code == LVN_COLUMNCLICK) {
            auto* click = reinterpret_cast<NMLISTVIEW*>(hdr);
            if (static_cast<int>(click->iSubItem) == app.sort_column)
                app.sort_asc = !app.sort_asc;
            else {
                app.sort_column = click->iSubItem;
                app.sort_asc = true;
            }
            fill_record_list(app);
        } else if (hdr->code == NM_DBLCLK) {
            int row = ListView_GetNextItem(app.list_records, -1, LVNI_FOCUSED);
            if (row < 0) return;
            LVITEMW item{};
            item.mask = LVIF_PARAM;
            item.iItem = row;
            if (!ListView_GetItem(app.list_records, &item)) return;
            const Record& r = app.records[static_cast<std::size_t>(item.lParam)];
            std::wstring cmd = L"explorer.exe /select,\"" + from_utf8(r.source) + L"\"";
            ShellExecuteW(nullptr, L"open", cmd.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
        } else if (hdr->code == NM_RCLICK) {
            HMENU menu = CreatePopupMenu();
            AppendMenuW(menu, MF_STRING, 1, L"Zeile kopieren");
            AppendMenuW(menu, MF_STRING, 2, L"Alles kopieren");
            AppendMenuW(menu, MF_STRING, 3, L"Im Explorer anzeigen");
            POINT pt{};
            GetCursorPos(&pt);
            SetForegroundWindow(app.hwnd);
            int cmd = TrackPopupMenu(menu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, app.hwnd, nullptr);
            int row = ListView_GetNextItem(app.list_records, -1, LVNI_FOCUSED);
            LVITEMW item{};
            item.mask = LVIF_PARAM;
            item.iItem = row;
            bool have = row >= 0 && ListView_GetItem(app.list_records, &item) != 0;
            if (cmd == 1 && have) {
                const Record& r = app.records[static_cast<std::size_t>(item.lParam)];
                std::string line = (r.first_time() ? unix_to_iso(r.first_time()) : std::string("-"));
                line += "\t" + r.kind + "\t" + r.title + "\t" + r.source + "\t" + anchor_id(r);
                copy_to_clipboard(line);
            } else if (cmd == 2) {
                copy_to_clipboard(records_as_text(app));
            } else if (cmd == 3 && have) {
                const Record& r = app.records[static_cast<std::size_t>(item.lParam)];
                std::wstring w = L"explorer.exe /select,\"" + from_utf8(r.source) + L"\"";
                ShellExecuteW(nullptr, L"open", w.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
            }
            DestroyMenu(menu);
            return;
        }
        return;
    }
    if (hdr->idFrom == IDC_DETAILS) {
        if (hdr->code == NM_CUSTOMDRAW) {
            details_custom_draw(app, reinterpret_cast<NMLVCUSTOMDRAW*>(hdr));
            return;
        }
        if (hdr->code == NM_CLICK) {
            // a click on a group row folds the group away
            auto* click = reinterpret_cast<NMITEMACTIVATE*>(hdr);
            int row = static_cast<int>(click->iItem);
            if (row < 0 || row >= static_cast<int>(app.detail_shown.size())) return;
            const DetailRow& d = app.detail_rows[app.detail_shown[row]];
            if (!d.is_group) return;
            if (app.collapsed_groups.count(d.group))
                app.collapsed_groups.erase(d.group);
            else
                app.collapsed_groups.insert(d.group);
            render_details(app);
            return;
        }
        if (hdr->code == NM_RCLICK) {
            HMENU menu = CreatePopupMenu();
            AppendMenuW(menu, MF_STRING, 1, L"Wert kopieren");
            AppendMenuW(menu, MF_STRING, 2, L"Alles kopieren");
            POINT pt{};
            GetCursorPos(&pt);
            SetForegroundWindow(app.hwnd);
            int cmd = TrackPopupMenu(menu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, app.hwnd, nullptr);
            int row = ListView_GetNextItem(app.list_details, -1, LVNI_FOCUSED);
            if (cmd == 1 && row >= 0 && row < static_cast<int>(app.detail_shown.size())) {
                const DetailRow& d = app.detail_rows[app.detail_shown[row]];
                copy_to_clipboard(d.is_group ? d.key : d.value);
            } else if (cmd == 2) {
                copy_to_clipboard(details_as_text(app));
            }
            DestroyMenu(menu);
            return;
        }
    }
}

// ---------------------------------------------------------------- window proc

LRESULT CALLBACK wnd_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    App& app = g_app;
    switch (msg) {
        case WM_CREATE: {
            create_fonts(app);

            // ---- command bar
            app.btn_ingest = CreateWindowExW(0, L"BUTTON", L"Artefakte...",
                                             WS_CHILD | WS_VISIBLE | WS_TABSTOP, 0, 0, 0, 0, hwnd,
                                             reinterpret_cast<HMENU>(IDC_INGEST), app.inst, nullptr);
            app.btn_open = CreateWindowExW(0, L"BUTTON", L"Store öffnen...",
                                            WS_CHILD | WS_VISIBLE | WS_TABSTOP, 0, 0, 0, 0, hwnd,
                                            reinterpret_cast<HMENU>(IDC_OPEN), app.inst, nullptr);
            app.btn_export = CreateWindowExW(0, L"BUTTON", L"JSON-Export...",
                                              WS_CHILD | WS_VISIBLE | WS_TABSTOP, 0, 0, 0, 0, hwnd,
                                              reinterpret_cast<HMENU>(IDC_EXPORT), app.inst, nullptr);
            app.btn_stats = CreateWindowExW(0, L"BUTTON", L"Statistik",
                                             WS_CHILD | WS_VISIBLE | WS_TABSTOP, 0, 0, 0, 0, hwnd,
                                             reinterpret_cast<HMENU>(IDC_STATS), app.inst, nullptr);
            app.btn_reset = CreateWindowExW(0, L"BUTTON", L"Zurücksetzen",
                                             WS_CHILD | WS_VISIBLE | WS_TABSTOP, 0, 0, 0, 0, hwnd,
                                             reinterpret_cast<HMENU>(IDC_RESET), app.inst, nullptr);
            app.btn_recursive = CreateWindowExW(0, L"BUTTON", L"Unterordner",
                                                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
                                                0, 0, 0, 0, hwnd,
                                                reinterpret_cast<HMENU>(IDC_RECURSIVE), app.inst,
                                                nullptr);

            // ---- filter bar
            CreateWindowExW(0, L"STATIC", L"Suchen:", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd,
                            reinterpret_cast<HMENU>(IDC_LABEL_SEARCH), app.inst, nullptr);
            app.search = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                         WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL, 0, 0, 0, 0,
                                         hwnd, reinterpret_cast<HMENU>(IDC_SEARCH), app.inst, nullptr);
            CreateWindowExW(0, L"STATIC", L"Typ:", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd,
                            reinterpret_cast<HMENU>(IDC_LABEL_KIND), app.inst, nullptr);
            app.kind = CreateWindowExW(0, L"COMBOBOX", L"",
                                       WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST, 0, 0, 0, 0,
                                       hwnd, reinterpret_cast<HMENU>(IDC_KIND), app.inst, nullptr);
            CreateWindowExW(0, L"STATIC", L"Zeit ab:", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd,
                            reinterpret_cast<HMENU>(IDC_LABEL_FROM), app.inst, nullptr);
            app.from_edit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL, 0, 0,
                                            0, 0, hwnd, reinterpret_cast<HMENU>(IDC_FROM), app.inst,
                                            nullptr);
            CreateWindowExW(0, L"STATIC", L"bis:", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd,
                            reinterpret_cast<HMENU>(IDC_LABEL_TO), app.inst, nullptr);
            app.to_edit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                          WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL, 0, 0, 0,
                                          0, hwnd, reinterpret_cast<HMENU>(IDC_TO), app.inst, nullptr);
            app.timeline = CreateWindowExW(0, L"BUTTON", L"Timeline",
                                           WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX, 0, 0,
                                           0, 0, hwnd, reinterpret_cast<HMENU>(IDC_TIMELINE), app.inst,
                                           nullptr);
            app.pivot_label = CreateWindowExW(0, L"STATIC", L"Kein Pivot aktiv",
                                               WS_CHILD | WS_VISIBLE | SS_ENDELLIPSIS, 0, 0, 0, 0,
                                               hwnd, reinterpret_cast<HMENU>(IDC_PIVOT), app.inst,
                                               nullptr);

            // ---- panes
            app.group_ids = CreateWindowExW(0, L"BUTTON", L"Identifier",
                                             WS_CHILD | WS_VISIBLE | WS_GROUP | BS_GROUPBOX, 0, 0, 0, 0,
                                             hwnd, reinterpret_cast<HMENU>(IDC_GROUP_IDS), app.inst,
                                             nullptr);
            app.list_ids = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
                                            WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT |
                                                LVS_SHOWSELALWAYS | LVS_SINGLESEL,
                                            0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_IDS), app.inst,
                                            nullptr);
            app.group_records = CreateWindowExW(0, L"BUTTON", L"Records",
                                                 WS_CHILD | WS_VISIBLE | WS_GROUP | BS_GROUPBOX, 0, 0,
                                                 0, 0, hwnd,
                                                 reinterpret_cast<HMENU>(IDC_GROUP_RECORDS), app.inst,
                                                 nullptr);
            app.list_records = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
                                                WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT |
                                                    LVS_SHOWSELALWAYS | LVS_SINGLESEL,
                                                0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_RECORDS),
                                                app.inst, nullptr);
            app.group_details = CreateWindowExW(0, L"BUTTON", L"Details",
                                                 WS_CHILD | WS_VISIBLE | WS_GROUP | BS_GROUPBOX, 0, 0,
                                                 0, 0, hwnd,
                                                 reinterpret_cast<HMENU>(IDC_GROUP_DETAILS), app.inst,
                                                 nullptr);
            app.list_details = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
                                                WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT |
                                                    LVS_SHOWSELALWAYS | LVS_SINGLESEL,
                                                0, 0, 0, 0, hwnd,
                                                reinterpret_cast<HMENU>(IDC_DETAILS), app.inst, nullptr);
            app.status = CreateWindowExW(0, STATUSCLASSNAMEW, L"", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0,
                                         hwnd, reinterpret_cast<HMENU>(IDC_STATUS), app.inst, nullptr);

            ListView_SetExtendedListViewStyle(app.list_records,
                                               LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES |
                                                   LVS_EX_DOUBLEBUFFER);
            ListView_SetExtendedListViewStyle(app.list_ids,
                                               LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES |
                                                   LVS_EX_DOUBLEBUFFER);
            ListView_SetExtendedListViewStyle(app.list_details,
                                               LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES |
                                                   LVS_EX_DOUBLEBUFFER);

            LVCOLUMNW col{};
            col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
            col.pszText = const_cast<wchar_t*>(L"Typ");
            ListView_InsertColumn(app.list_ids, 0, &col);
            col.pszText = const_cast<wchar_t*>(L"Identifier");
            ListView_InsertColumn(app.list_ids, 1, &col);
            col.pszText = const_cast<wchar_t*>(L"Records");
            col.fmt = LVCFMT_RIGHT;
            ListView_InsertColumn(app.list_ids, 2, &col);
            col.fmt = LVCFMT_LEFT;

            col.pszText = const_cast<wchar_t*>(L"Zeit");
            ListView_InsertColumn(app.list_records, 0, &col);
            col.pszText = const_cast<wchar_t*>(L"Typ");
            ListView_InsertColumn(app.list_records, 1, &col);
            col.pszText = const_cast<wchar_t*>(L"Titel");
            ListView_InsertColumn(app.list_records, 2, &col);
            col.pszText = const_cast<wchar_t*>(L"Quelle");
            ListView_InsertColumn(app.list_records, 3, &col);
            col.pszText = const_cast<wchar_t*>(L"Anker");
            ListView_InsertColumn(app.list_records, 4, &col);

            col.pszText = const_cast<wchar_t*>(L"Feld");
            ListView_InsertColumn(app.list_details, 0, &col);
            col.pszText = const_cast<wchar_t*>(L"Wert");
            ListView_InsertColumn(app.list_details, 1, &col);

            const wchar_t* kinds[] = {L"alle Typen"};
            for (const auto* k : kinds)
                SendMessageW(app.kind, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(k));
            SendMessageW(app.kind, CB_SETCURSEL, 0, 0);

            int parts[3] = {0, 0, 0};
            SendMessageW(app.status, SB_SETPARTS, 3, reinterpret_cast<LPARAM>(parts));

            SendMessageW(app.btn_recursive, BM_SETCHECK, app.recursive ? BST_CHECKED : BST_UNCHECKED,
                         0);

            HWND controls[] = {app.btn_ingest,     app.btn_open,      app.btn_export,
                               app.btn_stats,     app.btn_reset,     app.btn_recursive,
                               app.search,       app.kind,          app.from_edit,
                               app.to_edit,      app.timeline,      app.pivot_label,
                               app.list_ids,     app.list_records,  app.list_details,
                               app.status};
            for (HWND c : controls) apply_font(app, c);
            // identifiers and details are technical - a monospaced font keeps
            // paths and hashes aligned
            apply_font(app, app.list_ids, app.font_mono);
            apply_font(app, app.list_details, app.font_mono);

            DragAcceptFiles(hwnd, TRUE);
            layout(app);
            return 0;
        }
        case WM_SIZE:
            layout(app);
            return 0;
        case WM_GETMINMAXINFO: {
            auto* mmi = reinterpret_cast<MINMAXINFO*>(lparam);
            mmi->ptMinTrackSize.x = scaled(app, 1024);
            mmi->ptMinTrackSize.y = scaled(app, 580);
            return 0;
        }
        case WM_COMMAND:
            on_command(app, LOWORD(wparam), HIWORD(wparam), reinterpret_cast<HWND>(lparam));
            return 0;
        case WM_NOTIFY:
            on_notify(app, reinterpret_cast<NMHDR*>(lparam));
            return 0;
        case WM_CTLCOLORSTATIC:
        case WM_CTLCOLOREDIT:
        case WM_CTLCOLORBTN: {
            if (!app.dark) break;
            HDC dc = reinterpret_cast<HDC>(wparam);
            SetTextColor(dc, g_theme.text);
            SetBkColor(dc, g_theme.window);
            return reinterpret_cast<LRESULT>(g_brush);
        }
        case WM_ERASEBKGND: {
            if (!app.dark) break;
            HDC dc = reinterpret_cast<HDC>(wparam);
            RECT rc{};
            GetClientRect(hwnd, &rc);
            FillRect(dc, &rc, g_brush);
            return 1;
        }
        case WM_DROPFILES: {
            HDROP drop = reinterpret_cast<HDROP>(wparam);
            UINT count = DragQueryFileW(drop, 0xFFFFFFFF, nullptr, 0);
            std::vector<std::string> paths;
            for (UINT i = 0; i < count; ++i) {
                wchar_t buf[MAX_PATH * 2];
                if (DragQueryFileW(drop, i, buf, ARRAYSIZE(buf)))
                    paths.push_back(to_utf8(buf));
            }
            DragFinish(drop);
            if (!paths.empty()) do_ingest(app, paths);
            return 0;
        }
        case WM_CLOSE: {
            if (app.dirty) persist_store(app);
            save_settings(app);
            DestroyWindow(hwnd);
            return 0;
        }
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
        default:
            break;
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

// ---------------------------------------------------------------- startup

std::string default_store_path() {
    wchar_t local[MAX_PATH] = {0};
    if (GetEnvironmentVariableW(L"LOCALAPPDATA", local, ARRAYSIZE(local)) == 0) return "pivot.store";
    std::wstring p(local);
    if (!p.empty() && p.back() != L'\\') p += L'\\';
    p += L"fuuuturee\\PIVOT\\case.store";
    return to_utf8(p);
}

}  // namespace

int WINAPI wWinMain(HINSTANCE inst, HINSTANCE, PWSTR, int) {
    g_app.inst = inst;
    g_app.dpi = GetDpiForSystem();
    if (g_app.dpi <= 0) g_app.dpi = 96;
    g_app.dark = system_is_dark() && dark_supported();

    INITCOMMONCONTROLSEX icc{};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icc);

    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

    // command line: --self-test [--ingest <path>]...
    bool selftest = false;
    std::string log_path;
    std::vector<std::string> pre_ingest;
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    for (int i = 1; argv && i < argc; ++i) {
        std::wstring a = argv[i];
        if (a == L"--self-test") {
            selftest = true;
        } else if (a == L"--log" && i + 1 < argc) {
            log_path = to_utf8(argv[++i]);
            ++i;
        } else if (a == L"--ingest" && i + 1 < argc) {
            pre_ingest.push_back(to_utf8(argv[++i]));
            ++i;
        }
    }
    if (argv) LocalFree(argv);

    if (selftest) {
        // make the output visible for the test runner
        AttachConsole(ATTACH_PARENT_PROCESS);
        FILE* dummy = nullptr;
        freopen_s(&dummy, "CONOUT$", "w", stdout);
        freopen_s(&dummy, "CONOUT$", "w", stderr);
    }

    load_settings(g_app);
    if (g_app.store_path.empty()) g_app.store_path = default_store_path();
    load_store(g_app.store_path, g_app.records);

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = wnd_proc;
    wc.hInstance = inst;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wc.lpszClassName = kWindowClass;
    wc.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    RegisterClassExW(&wc);

    g_app.hwnd = CreateWindowExW(0, kWindowClass, L"PIVOT - forensic artifact pivot engine",
                                 WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN, CW_USEDEFAULT, CW_USEDEFAULT,
                                 scaled(g_app, 1280), scaled(g_app, 740), nullptr, nullptr, inst,
                                 nullptr);
    if (!g_app.hwnd) {
        CoUninitialize();
        return 1;
    }

    apply_theme(g_app);

    if (!pre_ingest.empty()) {
        std::vector<std::string> files = expand_inputs(pre_ingest, g_app.recursive);
        IngestStats st = ingest_files(files, g_app.records);
        g_app.dirty = true;
        persist_store(g_app);
        if (selftest)
            std::printf("self-test: ingested %zu files, %zu new records\n", st.files, st.records);
    }

    refresh_all(g_app);

    if (selftest) {
        // drive the window once to make sure the controls work
        ShowWindow(g_app.hwnd, SW_HIDE);
        MSG msg{};
        for (int i = 0; i < 50 && PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE); ++i) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        int rows = ListView_GetItemCount(g_app.list_records);
        int ids = ListView_GetItemCount(g_app.list_ids);
        int details = ListView_GetItemCount(g_app.list_details);
        bool ok = rows > 0 && ids > 0 && !g_app.records.empty();
        std::string report = "self-test: record rows=" + std::to_string(rows) +
                             ", identifier rows=" + std::to_string(ids) +
                             ", detail rows=" + std::to_string(details) +
                             ", records=" + std::to_string(g_app.records.size()) +
                             ", shown=" + std::to_string(g_app.shown.size()) + "\n";
        std::printf("%s", report.c_str());
        std::printf("self-test: %s\n", ok ? "ok" : "FAILED");
        if (!log_path.empty()) {
            FILE* log = nullptr;
            if (fopen_s(&log, log_path.c_str(), "wb") == 0 && log) {
                std::string out = report + std::string("self-test: ") + (ok ? "ok" : "FAILED") + "\n";
                fwrite(out.data(), 1, out.size(), log);
                fclose(log);
            }
        }
        DestroyWindow(g_app.hwnd);
        MSG m{};
        while (PeekMessageW(&m, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&m);
            DispatchMessageW(&m);
        }
        CoUninitialize();
        return ok ? 0 : 1;
    }

    ShowWindow(g_app.hwnd, SW_SHOW);
    UpdateWindow(g_app.hwnd);

    // keyboard shortcuts: Ctrl+F search, Ctrl+I ingest, Ctrl+O open,
    // Ctrl+E export, Ctrl+C copy the record list, Esc resets the filters
    ACCEL accels[] = {
        {FVIRTKEY | FCONTROL, 'F', IDC_CMD_FOCUS_SEARCH},
        {FVIRTKEY | FCONTROL, 'I', IDC_INGEST},
        {FVIRTKEY | FCONTROL, 'O', IDC_OPEN},
        {FVIRTKEY | FCONTROL, 'E', IDC_EXPORT},
        {FVIRTKEY | FCONTROL, 'C', IDC_CMD_COPY_RECORDS},
        {FVIRTKEY, VK_ESCAPE, IDC_RESET},
    };
    HACCEL hacc = CreateAcceleratorTable(accels, static_cast<int>(std::size(accels)));

    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        if (hacc && TranslateAccelerator(g_app.hwnd, hacc, &msg)) continue;
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    if (hacc) DestroyAcceleratorTable(hacc);

    CoUninitialize();
    return static_cast<int>(msg.wParam);
}
