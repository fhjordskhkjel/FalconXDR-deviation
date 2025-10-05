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
        bool enableParentChildAnomaly = true;       // toggle parent-child anomaly and cmdline checks
        bool enableCodeCaveDetection = true;        // toggle code cave detection
        bool enableCodeCaveBreakpointDetect = true; // toggle suspicious INT3 breakpoint heuristic in codecaves
        // Persistence / registry
        bool enableAutorunScan = true;              // monitor autorun keys
        bool enableServiceScan = true;              // monitor new/modified services
        bool enablePolicyScan = true;               // monitor security / system policy changes
        
        // Throttling/intervals (seconds)
        int execClassifyIntervalSec = 30;           // cadence for exec region classifier
        int injHeurIntervalSec = 20;                // cadence for injection heuristic
        int injHeurMaxRuns = 5;                     // cap injection heuristic runs per process
        int hollowCheckIntervalSec = 30;            // cadence for hollowing check per process
        int hollowCheckMaxRuns = 8;                 // cap hollowing checks
        int reflectiveCheckIntervalSec = 30;        // cadence for reflective loading check
        int reflectiveCheckMaxRuns = 8;             // cap reflective checks
        int codeCaveCheckIntervalSec = 45;          // cadence for code cave detection
        int codeCaveCheckMaxRuns = 6;               // cap code cave checks
        
        // YARA throttling budgets
        size_t yaraGlobalBytesPerMin = 8ull * 1024ull * 1024ull; // global per-minute scan budget
        size_t yaraPerPidBytesPerMin = 2ull * 1024ull * 1024ull; // per-pid per-minute budget
        size_t yaraPerPidMaxQueued = 8;             // per-pid queued tasks cap
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
    
    // Queue statistics
    struct QueueStats {
        size_t scanQueueSize;
        size_t yaraQueueSize;
        size_t scanQueueHighPrio;
        size_t scanQueueCriticalPrio;
    };
    QueueStats GetQueueStats();
}
