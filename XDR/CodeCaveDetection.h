#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <cstdint>

namespace CodeCaveDetection {

// Code cave detection result
struct CodeCave {
    uintptr_t location;
    size_t size;
    BYTE originalBytes[16];
    bool isHooked;
    std::wstring moduleContext;
    std::wstring detectionReason;
};

// Main detection function
// Scans process for:
// - INT3 breakpoints (0xCC) outside debugger context
// - Unusual jumps to RWX memory regions
// - Patches in known clean modules (compared to on-disk)
std::vector<CodeCave> DetectCodeCaves(DWORD pid);

}
