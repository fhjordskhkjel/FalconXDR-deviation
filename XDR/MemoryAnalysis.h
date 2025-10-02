#pragma once

#include <Windows.h>
#include <string>
#include <vector>

namespace MemoryAnalysis {
    // Memory region information
    struct MemoryRegionInfo {
        LPVOID baseAddress;
        SIZE_T regionSize;
        DWORD protection;
        bool isExecutable;
        bool isWritable;
        bool isMapped;
        bool isPrivate;
        bool isPEHeader;
        bool isSuspicious;
    };

    // Detection functions
    bool DetectProcessHollowing(DWORD pid, std::wstring& details);
    bool DetectDllInjection(DWORD pid, std::wstring& details);
    bool DetectReflectiveLoading(DWORD pid, std::wstring& details);
    
    // Scanning functions
    std::vector<MemoryRegionInfo> ScanProcessMemoryRegions(DWORD pid);
    
    // Helper functions
    bool IsExecutableMemory(DWORD protection);
    bool IsPEHeader(LPVOID address, SIZE_T size, HANDLE process);
}