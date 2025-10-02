#pragma once
#include <string>
#include <windows.h>

namespace XDR {
namespace Utils {

// Time formatting
std::wstring TimeNow();

// String utilities
std::wstring ToLower(std::wstring s);

// Network utilities
std::wstring IPv4(DWORD ip);

// Process utilities
std::wstring GetProcName(DWORD pid);

// Pointer formatting
std::wstring FormatPtr(uintptr_t v);

// Message posting
void PostLine(HWND hwnd, UINT msg, const std::wstring& line);

} // namespace Utils
} // namespace XDR
