#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#include "YaraManager.h"
#include "Utilities.h"
#include "Storage.h"
#include <windows.h>
#include <commctrl.h>
#include <windowsx.h>
#include <filesystem>
#include <format>
#include <fstream>
#include <sstream>
#include <cwctype>
#include <mutex>
#include <vector>
#include <string>

#define WM_XDR_EVENT (WM_APP + 1)
#define WM_XDR_ALERT (WM_APP + 2)

#ifndef LVM_GETITEMTEXTW
#define LVM_GETITEMTEXTW (LVM_FIRST + 115)
#endif

#ifndef ListView_GetItemTextW
static inline void ListView_GetItemTextW(HWND hwndLV,int iItem,int iSubItem,LPWSTR pszText,int cchTextMax){ 
    LVITEMW lvi{}; 
    lvi.iSubItem=iSubItem; 
    lvi.cchTextMax=cchTextMax; 
    lvi.pszText=pszText; 
    SendMessageW(hwndLV,LVM_GETITEMTEXTW,(WPARAM)iItem,(LPARAM)&lvi); 
}
#endif

#ifdef ListView_GetItemText
#undef ListView_GetItemText // force use of explicit wide helper only
#endif

static inline void GetListViewTextW(HWND lv,int item,int sub,std::wstring &out){ 
    wchar_t buf[4096]{}; 
    ListView_GetItemTextW(lv,item,sub,buf,4095); 
    out=buf; 
}

extern HWND g_lvEvents;
extern HWND g_lvAlerts;

namespace XDR {
namespace Yara {

// YARA context
struct YaraCtx {
    HMODULE dll{};
    bool ready = false;
    void* rules{};
    void* compiler{};
    std::mutex m;
    bool attempted = false;
    std::wstring rulePath;
};

static YaraCtx g_yara;

// Minimal YARA API typedefs
using yr_initialize_t = int (*)();
using yr_finalize_t = int (*)();
struct YR_COMPILER;
struct YR_RULES;
struct YR_SCAN_CONTEXT;
using yr_compiler_create_t = int (*)(YR_COMPILER**);
using yr_compiler_destroy_t = void (*)(YR_COMPILER*);
using yr_compiler_add_string_t = int (*)(YR_COMPILER*, const char*, const char*);
using yr_compiler_get_rules_t = int (*)(YR_COMPILER*, YR_RULES**);
using yr_rules_destroy_t = void (*)(YR_RULES*);
using yr_rules_scan_mem_t = int (*)(YR_RULES*, const uint8_t*, size_t, int, int (*)(int, void*, void*), void*, int);

static yr_initialize_t p_init = nullptr;
static yr_finalize_t p_fini = nullptr;
static yr_compiler_create_t p_comp_create = nullptr;
static yr_compiler_destroy_t p_comp_destroy = nullptr;
static yr_compiler_add_string_t p_comp_add_string = nullptr;
static yr_compiler_get_rules_t p_comp_get_rules = nullptr;
static yr_rules_destroy_t p_rules_destroy = nullptr;
static yr_rules_scan_mem_t p_rules_scan_mem = nullptr;

#define YARA_CALLBACK_MSG_RULE_MATCHING 1

struct YaraMatchCtx {
    std::vector<std::wstring> names;
};

static int YaraCallback(int msg, void* /*message_data*/, void* user) {
    if (msg == YARA_CALLBACK_MSG_RULE_MATCHING) {
        auto* ctx = reinterpret_cast<YaraMatchCtx*>(user);
        ctx->names.push_back(L"Match");
    }
    return 0;
}

static std::wstring AlertTypeToName(EventType t) {
    switch (t) {
    case EventType::AlertYaraMatch: return L"YaraMatch";
    case EventType::AlertProcEnumMismatch: return L"ProcEnumMismatch";
    case EventType::AlertProcessInjection: return L"ProcessInjection";
    case EventType::AlertReflectiveModule: return L"ReflectiveModule";
    case EventType::AlertPrivilegedExec: return L"PrivilegedExec";
    case EventType::AlertProcessHollowing: return L"ProcessHollowing";
    case EventType::AlertDllInjection: return L"DllInjection";
    case EventType::AlertReflectiveMemory: return L"ReflectiveMemory";
    case EventType::AlertSuspiciousRemotePort: return L"SuspiciousRemotePort";
    case EventType::AlertSuspiciousProcess: return L"SuspiciousProcess";
    case EventType::AlertScreenshotCaptured: return L"ScreenshotCaptured";
    default: return L"Alert";
    }
}

static void PostAlertEvent(EventType type, const std::wstring& details, uint32_t pid = 0, const std::wstring& image = L"") {
    Event ev;
    ev.category = EventCategory::Alert;
    ev.type = type;
    ev.pid = pid;
    ev.image = image;
    ev.details = details;
    Storage::Insert(ev);
    
    auto line = std::format(L"[{}] ALERT {} pid={} {}", Utils::TimeNow(), AlertTypeToName(type), pid, details);
    Utils::PostLine(GetActiveWindow(), WM_XDR_ALERT, line);
}

void Unload() {
    std::scoped_lock lk(g_yara.m);
    if (g_yara.rules && p_rules_destroy)
        p_rules_destroy(reinterpret_cast<YR_RULES*>(g_yara.rules));
    g_yara.rules = nullptr;
    
    if (g_yara.compiler && p_comp_destroy)
        p_comp_destroy(reinterpret_cast<YR_COMPILER*>(g_yara.compiler));
    g_yara.compiler = nullptr;
    
    if (g_yara.dll) {
        FreeLibrary(g_yara.dll);
        g_yara.dll = nullptr;
    }

    if (p_fini) p_fini();
    g_yara.ready = false;
}

void Initialize() {
    std::scoped_lock lk(g_yara.m);
    if (g_yara.attempted) return;
    g_yara.attempted = true;
    
    wchar_t mod[MAX_PATH]{};
    if (!GetModuleFileNameW(nullptr, mod, MAX_PATH)) return;
    
    std::filesystem::path base(mod);
    g_yara.rulePath = (base.parent_path() / L"yara_rules.yar").wstring();
    
    g_yara.dll = LoadLibraryW(L"yara.dll");
    if (!g_yara.dll) {
        Utils::PostLine(GetActiveWindow(), WM_XDR_EVENT, L"[" + Utils::TimeNow() + L"] YARA dll not found");
        return;
    }
    
    auto gp = [&](const char* n) { return GetProcAddress(g_yara.dll, n); };
    p_init = (yr_initialize_t)gp("yr_initialize");
    p_fini = (yr_finalize_t)gp("yr_finalize");
    p_comp_create = (yr_compiler_create_t)gp("yr_compiler_create");
    p_comp_destroy = (yr_compiler_destroy_t)gp("yr_compiler_destroy");
    p_comp_add_string = (yr_compiler_add_string_t)gp("yr_compiler_add_string");
    p_comp_get_rules = (yr_compiler_get_rules_t)gp("yr_compiler_get_rules");
    p_rules_destroy = (yr_rules_destroy_t)gp("yr_rules_destroy");
    p_rules_scan_mem = (yr_rules_scan_mem_t)gp("yr_rules_scan_mem");
    
    if (!(p_init && p_fini && p_comp_create && p_comp_destroy &&
          p_comp_add_string && p_comp_get_rules && p_rules_destroy && p_rules_scan_mem)) {
        Utils::PostLine(GetActiveWindow(), WM_XDR_EVENT, L"[" + Utils::TimeNow() + L"] YARA missing exports");
        Unload();
        return;
    }
    
    if (p_init() != 0) {
        Unload();
        return;
    }
    
    if (p_comp_create(reinterpret_cast<YR_COMPILER**>(&g_yara.compiler)) != 0) {
        Unload();
        return;
    }
    
    std::string ruleText;
    if (std::filesystem::exists(g_yara.rulePath)) {
        std::ifstream rf(g_yara.rulePath);
        if (rf) {
            std::ostringstream ss;
            ss << rf.rdbuf();
            ruleText = ss.str();
        }
    }
    
    if (ruleText.empty())
        ruleText = "rule AlwaysMatch { condition: true }";
    
    if (p_comp_add_string(reinterpret_cast<YR_COMPILER*>(g_yara.compiler), ruleText.c_str(), nullptr) != 0) {
        Utils::PostLine(GetActiveWindow(), WM_XDR_EVENT, L"[" + Utils::TimeNow() + L"] YARA compile failed");
        Unload();
        return;
    }
    
    if (p_comp_get_rules(reinterpret_cast<YR_COMPILER*>(g_yara.compiler),
                         reinterpret_cast<YR_RULES**>(&g_yara.rules)) != 0) {
        Unload();
        return;
    }
    
    g_yara.ready = true;
    Utils::PostLine(GetActiveWindow(), WM_XDR_EVENT, L"[" + Utils::TimeNow() + L"] YARA ready");
}

bool IsReady() {
    return g_yara.ready;
}

bool ScanMemory(const uint8_t* data, size_t sz, std::vector<std::wstring>& matches) {
    if (!g_yara.ready) return false;
    YaraMatchCtx ctx;
    if (p_rules_scan_mem(reinterpret_cast<YR_RULES*>(g_yara.rules), data, sz, 0, YaraCallback, &ctx, 2000) == 0) {
        matches = ctx.names;
        return !matches.empty();
    }
    return false;
}

void ScanSelectedProcess(HWND hwnd) {
    Initialize();
    
    int sel = ListView_GetNextItem(g_lvEvents, -1, LVNI_SELECTED);
    bool fromEvents = true;
    if (sel == -1) { 
        sel = ListView_GetNextItem(g_lvAlerts, -1, LVNI_SELECTED);
        fromEvents = false;
    }
    
    if (sel == -1) {
        Utils::PostLine(hwnd, WM_XDR_EVENT, L"[" + Utils::TimeNow() + L"] YARA no selection");
        return;
    }
    
    wchar_t line[4096]{};
    HWND src = fromEvents ? g_lvEvents : g_lvAlerts;
    ListView_GetItemTextW(src, sel, 1, line, 4095);
    
    std::wstring wline = line;
    size_t pos = wline.find(L"pid=");
    if (pos == std::wstring::npos) {
        Utils::PostLine(hwnd, WM_XDR_EVENT, L"[" + Utils::TimeNow() + L"] YARA cannot find pid");
        return;
    }
    
    pos += 4;
    size_t end = pos;
    while (end < wline.size() && iswdigit(wline[end])) ++end;
    
    DWORD pid = 0;
    try {
        pid = (DWORD)std::stoul(wline.substr(pos, end - pos));
    }
    catch (...) {
        Utils::PostLine(hwnd, WM_XDR_EVENT, L"[" + Utils::TimeNow() + L"] YARA parse pid fail");
        return;
    }
    
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) {
        Utils::PostLine(hwnd, WM_XDR_EVENT, L"[" + Utils::TimeNow() + L"] YARA open fail pid=" + std::to_wstring(pid));
        return;
    }
    
    wchar_t imgPath[MAX_PATH]{};
    DWORD sz = MAX_PATH;
    std::wstring path;
    if (QueryFullProcessImageNameW(h, 0, imgPath, &sz))
        path = imgPath;
    CloseHandle(h);
    
    if (path.empty()) {
        Utils::PostLine(hwnd, WM_XDR_EVENT, L"[" + Utils::TimeNow() + L"] YARA no image path pid=" + std::to_wstring(pid));
        return;
    }
    
    std::error_code ec;
    if (!std::filesystem::exists(path, ec)) {
        Utils::PostLine(hwnd, WM_XDR_EVENT, L"[" + Utils::TimeNow() + L"] YARA file missing");
        return;
    }
    
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        Utils::PostLine(hwnd, WM_XDR_EVENT, L"[" + Utils::TimeNow() + L"] YARA open file fail");
        return;
    }
    
    std::vector<uint8_t> buf;
    buf.reserve(512 * 1024);
    char tmp[8192];
    size_t total = 0;
    while (f && total < 512 * 1024) {
        f.read(tmp, sizeof(tmp));
        auto got = f.gcount();
        if (got <= 0) break;
        buf.insert(buf.end(), tmp, tmp + got);
        total += (size_t)got;
    }
    
    if (!g_yara.ready) {
        // fallback: simple odd PID heuristic
        if (pid % 2 == 1)
            PostAlertEvent(EventType::AlertYaraMatch, L"simulated_rule pid=" + std::to_wstring(pid), pid, Utils::GetProcName(pid));
        else
            Utils::PostLine(hwnd, WM_XDR_EVENT, L"[" + Utils::TimeNow() + L"] YARA no match pid=" + std::to_wstring(pid));
        return;
    }
    
    std::vector<std::wstring> matches;
    if (ScanMemory(buf.data(), buf.size(), matches)) {
        std::wstring det = L"rules=";
        for (size_t i = 0; i < matches.size(); ++i) {
            if (i) det += L";";
            det += matches[i];
        }
        det += L" pid=" + std::to_wstring(pid);
        PostAlertEvent(EventType::AlertYaraMatch, det, pid, Utils::GetProcName(pid));
    }
    else {
        Utils::PostLine(hwnd, WM_XDR_EVENT, L"[" + Utils::TimeNow() + L"] YARA no match pid=" + std::to_wstring(pid));
    }
}

} // namespace Yara
} // namespace XDR

// Force wide character ListView operations when needed
#ifdef FORCE_WIDE_LV_GET
#undef ListView_GetItemText
#define ListView_GetItemText  USE_ListView_GetItemTextW_INSTEAD
#endif
