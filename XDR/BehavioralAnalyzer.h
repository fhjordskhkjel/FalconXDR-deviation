#pragma once
#include <windows.h>
#include <string>
#include <cstdint>

namespace Behavioral {
    struct Settings {
        bool enableThreadScan = true;
        bool enableProtTransitions = true;
        bool enableReflectiveScan = true;
        bool enableIntegrityDeltaAlert = true;
        bool enableYaraRegionScan = true; // new: queue suspicious regions
        size_t yaraMaxRegionSize = 512 * 1024; // 512 KB cap per region
        // New feature toggles
        bool enableUnsignedModuleAlert = true;      // allow turning off unsigned module detection
        bool enableApiHookScan = true;              // toggle API hook heuristic
        bool enableExecRegionClassifier = true;     // toggle entropy/density exec region classifier
        bool enableInjectionHeuristic = true;       // toggle legacy injection heuristic scan
    };
    // set/get global settings
    void SetSettings(const Settings& s);
    Settings GetSettings();

    void OnProcessStart(DWORD pid, const std::wstring& image, HWND hwnd);
    void OnProcessStop(DWORD pid);
    void Periodic(HWND hwnd);
    void AnalyzeProcessMemory(DWORD pid, HWND hwnd);
    void AnalyzeProcessMemoryAsync(DWORD pid, HWND hwnd);
    void StartBackground(HWND hwnd);
    void StopBackground();
}
