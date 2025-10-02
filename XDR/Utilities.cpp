#include "Utilities.h"
#include <chrono>
#include <format>
#include <cwctype>
#include <ctime>
#include <psapi.h>

namespace XDR {
namespace Utils {

std::wstring TimeNow() {
    auto n = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(n.time_since_epoch()) % 1000;
    std::time_t tt = std::chrono::system_clock::to_time_t(n);
    std::tm tm{};
    localtime_s(&tm, &tt);
    return std::format(L"{:02}:{:02}:{:02}.{:03}", tm.tm_hour, tm.tm_min, tm.tm_sec, ms.count());
}

std::wstring ToLower(std::wstring s) {
    for (auto& c : s) c = (wchar_t)towlower(c);
    return s;
}

std::wstring IPv4(DWORD ip) {
    BYTE b1 = ip & 0xFF, b2 = (ip >> 8) & 0xFF, b3 = (ip >> 16) & 0xFF, b4 = (ip >> 24) & 0xFF;
    return std::format(L"{}.{}.{}.{}", b1, b2, b3, b4);
}

std::wstring GetProcName(DWORD pid) {
    if (pid == 0 || pid == 4) return L"System";
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return L"<NA>";
    wchar_t buf[MAX_PATH];
    DWORD sz = MAX_PATH;
    std::wstring r = L"<NA>";
    if (QueryFullProcessImageNameW(h, 0, buf, &sz)) {
        std::wstring fp(buf);
        size_t p = fp.find_last_of(L'\\');
        r = p == std::wstring::npos ? fp : fp.substr(p + 1);
    }
    CloseHandle(h);
    return r;
}

std::wstring FormatPtr(uintptr_t v) {
    wchar_t buf[32];
    swprintf_s(buf, L"0x%llX", (unsigned long long)v);
    return buf;
}

void PostLine(HWND hwnd, UINT msg, const std::wstring& line) {
    if (!hwnd) return;
    auto* p = new std::wstring(line);
    PostMessageW(hwnd, msg, reinterpret_cast<WPARAM>(p), 0);
}

} // namespace Utils
} // namespace XDR
