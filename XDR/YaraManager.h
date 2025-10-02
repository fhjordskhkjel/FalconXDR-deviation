#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <mutex>

namespace XDR {
namespace Yara {

void Initialize();
void Unload();
bool IsReady();
void ScanSelectedProcess(HWND hwnd);
bool ScanMemory(const uint8_t* data, size_t size, std::vector<std::wstring>& matches);

} // namespace Yara
} // namespace XDR
