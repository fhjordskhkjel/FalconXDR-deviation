#include "MemoryAnalysis.h"
#include <Psapi.h>
#include <TlHelp32.h>
#include <unordered_set>
#include <unordered_map>
#include <vector>

namespace MemoryAnalysis {
    // Keeps track of modules per process to detect new injections
    static std::unordered_map<DWORD, std::unordered_set<std::wstring>> g_processModules;

    bool IsExecutableMemory(DWORD protection) {
        return (protection & PAGE_EXECUTE) || 
               (protection & PAGE_EXECUTE_READ) || 
               (protection & PAGE_EXECUTE_READWRITE) || 
               (protection & PAGE_EXECUTE_WRITECOPY);
    }

    bool IsPEHeader(LPVOID address, SIZE_T size, HANDLE process) {
        if (size < sizeof(IMAGE_DOS_HEADER)) return false;
        
        IMAGE_DOS_HEADER dosHeader = {0};
        SIZE_T bytesRead = 0;
        
        if (!ReadProcessMemory(process, address, &dosHeader, sizeof(IMAGE_DOS_HEADER), &bytesRead)) {
            return false;
        }
        
        // Check for "MZ" signature
        if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) return false;
        
        // Check if there's enough space for the NT headers
        if (size < dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS)) return false;
        
        // Read NT headers
        IMAGE_NT_HEADERS ntHeaders = {0};
        if (!ReadProcessMemory(process, 
                            (BYTE*)address + dosHeader.e_lfanew, 
                            &ntHeaders, 
                            sizeof(IMAGE_NT_HEADERS), 
                            &bytesRead)) {
            return false;
        }
        
        // Check for "PE" signature
        return ntHeaders.Signature == IMAGE_NT_SIGNATURE;
    }

    std::vector<MemoryRegionInfo> ScanProcessMemoryRegions(DWORD pid) {
        std::vector<MemoryRegionInfo> regions;
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!hProcess) return regions;
        
        MEMORY_BASIC_INFORMATION mbi = {0};
        LPVOID address = nullptr;
        
        while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT) {
                MemoryRegionInfo region;
                region.baseAddress = mbi.BaseAddress;
                region.regionSize = mbi.RegionSize;
                region.protection = mbi.Protect;
                region.isExecutable = IsExecutableMemory(mbi.Protect);
                region.isWritable = (mbi.Protect & PAGE_READWRITE) || (mbi.Protect & PAGE_WRITECOPY) || 
                                   (mbi.Protect & PAGE_EXECUTE_READWRITE) || (mbi.Protect & PAGE_EXECUTE_WRITECOPY);
                region.isMapped = (mbi.Type == MEM_MAPPED);
                region.isPrivate = (mbi.Type == MEM_PRIVATE);
                region.isPEHeader = IsPEHeader(mbi.BaseAddress, mbi.RegionSize, hProcess);
                region.isSuspicious = region.isExecutable && !region.isMapped && region.isPEHeader;
                
                regions.push_back(region);
            }
            
            address = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
        }
        
        CloseHandle(hProcess);
        return regions;
    }

    std::vector<std::wstring> GetProcessModules(DWORD pid) {
        std::vector<std::wstring> moduleNames;
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!hProcess) return moduleNames;
        
        HMODULE hMods[1024];
        DWORD cbNeeded;
        
        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                wchar_t szModName[MAX_PATH];
                if (GetModuleFileNameExW(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(wchar_t))) {
                    moduleNames.push_back(szModName);
                }
            }
        }
        
        CloseHandle(hProcess);
        return moduleNames;
    }

    bool DetectProcessHollowing(DWORD pid, std::wstring& details) {
        bool hollowingDetected = false;
        details.clear();
        
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!hProcess) return false;
        
        // Get process image name
        wchar_t imagePath[MAX_PATH] = {0};
        DWORD pathSize = MAX_PATH;
        if (!QueryFullProcessImageNameW(hProcess, 0, imagePath, &pathSize)) {
            CloseHandle(hProcess);
            return false;
        }
        
        auto regions = ScanProcessMemoryRegions(pid);
        
        // Check for executable memory with PE headers that aren't part of loaded modules
        for (const auto& region : regions) {
            if (region.isExecutable && region.isPEHeader) {
                // Check if this is the main image base or a legitimately loaded DLL
                bool isKnownModule = false;
                
                // Get module list - in a real implementation, you'd cache this
                HMODULE hMods[1024];
                DWORD cbNeeded;
                
                if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
                    for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                        if (hMods[i] == region.baseAddress) {
                            isKnownModule = true;
                            break;
                        }
                    }
                }
                
                if (!isKnownModule) {
                    hollowingDetected = true;
                    details += L"Executable memory with PE header found outside of loaded modules at 0x" + 
                               std::to_wstring((uintptr_t)region.baseAddress) + L". ";
                }
            }
        }
        
        // Check for unmapped executable memory
        for (const auto& region : regions) {
            if (region.isExecutable && region.isPrivate && !region.isPEHeader) {
                hollowingDetected = true;
                details += L"Executable private memory without PE header at 0x" + 
                           std::to_wstring((uintptr_t)region.baseAddress) + L". ";
            }
        }
        
        CloseHandle(hProcess);
        return hollowingDetected;
    }

    bool DetectDllInjection(DWORD pid, std::wstring& details) {
        details.clear();
        bool injectionDetected = false;
        
        // Get current modules
        auto currentModules = GetProcessModules(pid);
        
        // Initialize process modules if this is the first check
        if (g_processModules.find(pid) == g_processModules.end()) {
            std::unordered_set<std::wstring> modules;
            for (const auto& module : currentModules) {
                modules.insert(module);
            }
            g_processModules[pid] = modules;
            return false;
        }
        
        // Check for new modules
        for (const auto& module : currentModules) {
            if (g_processModules[pid].find(module) == g_processModules[pid].end()) {
                // New module found
                g_processModules[pid].insert(module);
                
                // Check if module path is suspicious
                bool isSuspicious = false;
                
                // In temp directory?
                if (module.find(L"\\Temp\\") != std::wstring::npos ||
                    module.find(L"\\AppData\\Local\\Temp\\") != std::wstring::npos) {
                    isSuspicious = true;
                }
                
                // Non-standard location?
                if (module.find(L"\\Windows\\") == std::wstring::npos &&
                    module.find(L"\\Program Files\\") == std::wstring::npos &&
                    module.find(L"\\Program Files (x86)\\") == std::wstring::npos) {
                    isSuspicious = true;
                }
                
                if (isSuspicious) {
                    injectionDetected = true;
                    details += L"Suspicious DLL loaded: " + module + L". ";
                }
            }
        }
        
        return injectionDetected;
    }

    bool DetectReflectiveLoading(DWORD pid, std::wstring& details) {
        details.clear();
        bool reflectiveLoadingDetected = false;
        
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!hProcess) return false;
        
        auto regions = ScanProcessMemoryRegions(pid);
        
        // Check for executable memory regions with no associated module
        std::vector<HMODULE> modules;
        DWORD cbNeeded;
        HMODULE hMods[1024];
        
        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            DWORD moduleCount = cbNeeded / sizeof(HMODULE);
            modules.assign(hMods, hMods + moduleCount);
        }
        
        for (const auto& region : regions) {
            // Is this region executable?
            if (region.isExecutable) {
                // Is it part of any known module?
                bool isPartOfModule = false;
                for (HMODULE module : modules) {
                    MODULEINFO modInfo;
                    if (GetModuleInformation(hProcess, module, &modInfo, sizeof(MODULEINFO))) {
                        if ((BYTE*)region.baseAddress >= (BYTE*)modInfo.lpBaseOfDll && 
                            (BYTE*)region.baseAddress < ((BYTE*)modInfo.lpBaseOfDll + modInfo.SizeOfImage)) {
                            isPartOfModule = true;
                            break;
                        }
                    }
                }
                
                // If executable but not part of a module, it might be reflectively loaded code
                if (!isPartOfModule) {
                    reflectiveLoadingDetected = true;
                    details += L"Executable memory outside module boundaries at 0x" + 
                               std::to_wstring((uintptr_t)region.baseAddress) + 
                               L" size: " + std::to_wstring(region.regionSize) + L" bytes. ";
                }
            }
        }
        
        CloseHandle(hProcess);
        return reflectiveLoadingDetected;
    }
}