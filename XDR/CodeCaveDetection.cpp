#include "CodeCaveDetection.h"
#include <psapi.h>
#include <algorithm>
#include <memory>

#pragma comment(lib, "psapi.lib")

namespace CodeCaveDetection {

// Helper to convert string to lowercase
static std::wstring Lower(const std::wstring& s) {
    std::wstring result = s;
    for (auto& c : result) c = (wchar_t)towlower(c);
    return result;
}

// TOCTOU-protected memory read
// Reads memory twice and compares to detect modification during scan (evasion attempt)
static bool SecureMemoryRead(HANDLE hProcess, LPVOID address, void* buffer, SIZE_T size, SIZE_T* bytesRead = nullptr) {
    if (!hProcess || !address || !buffer || size == 0) return false;
    
    std::vector<uint8_t> temp1(size), temp2(size);
    SIZE_T read1 = 0, read2 = 0;
    
    // First read
    if (!ReadProcessMemory(hProcess, address, temp1.data(), size, &read1) || read1 == 0) {
        return false;
    }
    
    // Small delay to allow potential evasion to manifest
    Sleep(1);
    
    // Second read
    if (!ReadProcessMemory(hProcess, address, temp2.data(), size, &read2) || read2 == 0) {
        return false;
    }
    
    // Compare read sizes
    if (read1 != read2) {
        // Memory changed size - potential evasion
        return false;
    }
    
    // Compare contents
    if (memcmp(temp1.data(), temp2.data(), read1) != 0) {
        // Memory modified during read - potential evasion detected
        return false;
    }
    
    // Consistent read - copy to output buffer
    memcpy(buffer, temp1.data(), read1);
    if (bytesRead) *bytesRead = read1;
    return true;
}

// Check for suspicious INT3 breakpoints
static bool HasSuspiciousBreakpoints(const uint8_t* data, size_t size, size_t& count) {
    count = 0;
    if (!data || size < 4) return false;
    
    // Count INT3 instructions (0xCC)
    for (size_t i = 0; i < size; i++) {
        if (data[i] == 0xCC) ++count;
    }
    
    // Suspicious if more than 3 INT3s or if INT3 appears in first 16 bytes (likely modified prologue)
    if (count > 3) return true;
    if (size >= 16) {
        for (size_t i = 0; i < 16; i++) {
            if (data[i] == 0xCC) return true;
        }
    }
    
    return false;
}

// Check if memory region protection is RWX
static bool IsRWX(DWORD protect) {
    return (protect & PAGE_EXECUTE_READWRITE) != 0;
}

// Detect unusual jumps to RWX regions
static bool HasSuspiciousJumps(HANDLE hp, const uint8_t* data, size_t size, uintptr_t baseAddr) {
    if (!data || size < 5) return false;
    
    // Scan for jump/call instructions
    for (size_t i = 0; i < size - 5; i++) {
        uintptr_t targetAddr = 0;
        bool isJump = false;
        
        // JMP rel32 (E9)
        if (data[i] == 0xE9) {
            int32_t rel = *reinterpret_cast<const int32_t*>(data + i + 1);
            targetAddr = baseAddr + i + 5 + rel;
            isJump = true;
        }
        // CALL rel32 (E8)
        else if (data[i] == 0xE8) {
            int32_t rel = *reinterpret_cast<const int32_t*>(data + i + 1);
            targetAddr = baseAddr + i + 5 + rel;
            isJump = true;
        }
        // JMP [rip+disp32] (FF 25)
        else if (i < size - 6 && data[i] == 0xFF && data[i+1] == 0x25) {
            int32_t rel = *reinterpret_cast<const int32_t*>(data + i + 2);
            uintptr_t ptrAddr = baseAddr + i + 6 + rel;
            
            // Read the pointer value
            uintptr_t ptrValue = 0;
            SIZE_T tr = 0;
            if (ReadProcessMemory(hp, (LPCVOID)ptrAddr, &ptrValue, sizeof(ptrValue), &tr) && tr == sizeof(ptrValue)) {
                targetAddr = ptrValue;
                isJump = true;
            }
        }
        
        if (isJump && targetAddr) {
            // Check if target is in RWX region
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQueryEx(hp, (LPCVOID)targetAddr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
                if (mbi.State == MEM_COMMIT && IsRWX(mbi.Protect)) {
                    return true;
                }
            }
        }
    }
    
    return false;
}

// Detect patches in modules by comparing to on-disk image
static bool DetectModulePatches(HANDLE hp, HMODULE hMod, std::vector<CodeCave>& caves) {
    wchar_t modPath[MAX_PATH];
    if (!GetModuleFileNameExW(hp, hMod, modPath, MAX_PATH)) return false;
    
    // Get module info
    MODULEINFO mi{};
    if (!GetModuleInformation(hp, hMod, &mi, sizeof(mi))) return false;
    
    // Open the file on disk
    HANDLE hFile = CreateFileW(modPath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    
    // Map the file
    HANDLE hMapping = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    CloseHandle(hFile);
    if (!hMapping) return false;
    
    BYTE* pDiskImage = (BYTE*)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pDiskImage) {
        CloseHandle(hMapping);
        return false;
    }
    
    bool foundPatches = false;
    
    // Parse PE headers to find .text section
    IMAGE_DOS_HEADER* pDos = (IMAGE_DOS_HEADER*)pDiskImage;
    if (pDos->e_magic == IMAGE_DOS_SIGNATURE) {
        IMAGE_NT_HEADERS* pNt = (IMAGE_NT_HEADERS*)(pDiskImage + pDos->e_lfanew);
        if (pNt->Signature == IMAGE_NT_SIGNATURE) {
            IMAGE_SECTION_HEADER* pSect = IMAGE_FIRST_SECTION(pNt);
            
            for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
                // Look for .text section
                if (strncmp((char*)pSect[i].Name, ".text", 5) == 0) {
                    SIZE_T sectSize = pSect[i].Misc.VirtualSize;
                    uintptr_t sectRVA = pSect[i].VirtualAddress;
                    uintptr_t sectMemAddr = (uintptr_t)mi.lpBaseOfDll + sectRVA;
                    
                    // Read memory from process
                    std::vector<BYTE> memBuf(sectSize);
                    SIZE_T br = 0;
                    if (!SecureMemoryRead(hp, (LPCVOID)sectMemAddr, memBuf.data(), sectSize, &br) || br < sectSize) {
                        continue;
                    }
                    
                    // Compare with disk
                    BYTE* diskBuf = pDiskImage + pSect[i].PointerToRawData;
                    SIZE_T cmpSize = (std::min)(sectSize, (SIZE_T)pSect[i].SizeOfRawData);
                    
                    // Scan for differences (skip first few bytes as they can be relocated)
                    for (size_t j = 16; j < cmpSize; j++) {
                        if (memBuf[j] != diskBuf[j]) {
                            // Found a patch - record it
                            CodeCave cave;
                            cave.location = sectMemAddr + j;
                            cave.isHooked = true;
                            cave.moduleContext = modPath;
                            cave.detectionReason = L"module_patch";
                            
                            // Find extent of patch
                            size_t patchSize = 1;
                            while (j + patchSize < cmpSize && memBuf[j + patchSize] != diskBuf[j + patchSize] && patchSize < 256) {
                                patchSize++;
                            }
                            cave.size = patchSize;
                            
                            // Store original bytes
                            size_t cpySize = (std::min)(patchSize, sizeof(cave.originalBytes));
                            memcpy(cave.originalBytes, diskBuf + j, cpySize);
                            
                            caves.push_back(cave);
                            foundPatches = true;
                            
                            // Skip past this patch
                            j += patchSize;
                        }
                    }
                    
                    break;
                }
            }
        }
    }
    
    UnmapViewOfFile(pDiskImage);
    CloseHandle(hMapping);
    
    return foundPatches;
}

// Main detection function
std::vector<CodeCave> DetectCodeCaves(DWORD pid) {
    std::vector<CodeCave> caves;
    
    HANDLE hp = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hp) return caves;
    
    // Check if process is being debugged (to filter out legitimate breakpoints)
    BOOL isDebugged = FALSE;
    CheckRemoteDebuggerPresent(hp, &isDebugged);
    
    // Enumerate modules
    HMODULE mods[512];
    DWORD need = 0;
    if (EnumProcessModules(hp, mods, sizeof(mods), &need)) {
        size_t cnt = need / sizeof(HMODULE);
        
        for (size_t i = 0; i < cnt; i++) {
            MODULEINFO mi{};
            if (!GetModuleInformation(hp, mods[i], &mi, sizeof(mi))) continue;
            
            wchar_t modName[MAX_PATH];
            if (!GetModuleFileNameExW(hp, mods[i], modName, MAX_PATH)) continue;
            
            // Skip system modules unless they're commonly hooked
            std::wstring modLower = Lower(modName);
            bool isSystemModule = (modLower.find(L"\\windows\\system32\\") != std::wstring::npos ||
                                   modLower.find(L"\\windows\\syswow64\\") != std::wstring::npos);
            bool isTargetModule = (modLower.find(L"ntdll.dll") != std::wstring::npos ||
                                   modLower.find(L"kernel32.dll") != std::wstring::npos ||
                                   modLower.find(L"kernelbase.dll") != std::wstring::npos);
            
            if (isSystemModule && !isTargetModule) continue;
            
            // Read module memory (sample first 64KB of each module)
            size_t sampleSize = (std::min<SIZE_T>)(mi.SizeOfImage, 65536);
            std::vector<BYTE> buf(sampleSize);
            SIZE_T br = 0;
            if (!ReadProcessMemory(hp, mi.lpBaseOfDll, buf.data(), sampleSize, &br) || br < 512) {
                continue;
            }
            
            // Check for suspicious breakpoints (if not being debugged)
            if (!isDebugged) {
                size_t bpCount = 0;
                if (HasSuspiciousBreakpoints(buf.data(), br, bpCount)) {
                    CodeCave cave;
                    cave.location = (uintptr_t)mi.lpBaseOfDll;
                    cave.size = br;
                    cave.isHooked = true;
                    cave.moduleContext = modName;
                    cave.detectionReason = L"suspicious_breakpoints count=" + std::to_wstring(bpCount);
                    caves.push_back(cave);
                }
            }
            
            // Check for unusual jumps to RWX regions
            if (HasSuspiciousJumps(hp, buf.data(), br, (uintptr_t)mi.lpBaseOfDll)) {
                CodeCave cave;
                cave.location = (uintptr_t)mi.lpBaseOfDll;
                cave.size = br;
                cave.isHooked = true;
                cave.moduleContext = modName;
                cave.detectionReason = L"jump_to_rwx";
                caves.push_back(cave);
            }
            
            // Detect patches in known clean modules
            if (isTargetModule) {
                DetectModulePatches(hp, mods[i], caves);
            }
        }
    }
    
    CloseHandle(hp);
    return caves;
}

} // namespace CodeCaveDetection
