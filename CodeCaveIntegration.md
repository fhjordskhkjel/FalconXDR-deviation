# Code Cave Detection Integration Guide

## Overview
This guide explains how to integrate the code cave detection functionality into BehavioralAnalyzer.cpp.

## Files Created
1. **XDR\CodeCaveDetection.h** - Header with CodeCave struct and DetectCodeCaves function
2. **XDR\CodeCaveDetection.cpp** - Implementation of code cave detection

## Detection Capabilities
The code cave detector scans for:
- **INT3 breakpoints (0xCC)** outside debugger context
- **Unusual jumps** to RWX memory regions  
- **Module patches** by comparing in-memory code to on-disk images in ntdll.dll, kernel32.dll, kernelbase.dll

## Integration Steps

### Step 1: Add to Project
Add both files to your Visual Studio project.

### Step 2: Update BehavioralAnalyzer.h
Add the following settings to the `Settings` struct (around line 30):

```cpp
bool enableCodeCaveDetection = true;        // toggle code cave detection
int codeCaveCheckIntervalSec = 45;          // cadence for code cave detection
int codeCaveCheckMaxRuns = 6;               // cap code cave checks
```

### Step 3: Update BehavioralAnalyzer.cpp - Add Include
At the top of BehavioralAnalyzer.cpp, add after other includes:

```cpp
#include "CodeCaveDetection.h"
```

### Step 4: Update ProcInfo Struct
Add these fields to the `ProcInfo` struct (around line 290):

```cpp
steady_clock::time_point nextCodeCaveScan{};
int codeCaveScanRuns=0;
std::unordered_set<uintptr_t> alertedCodeCaves;
```

### Step 5: Add Alert Emitter Function
Add this function after the `EmitPrivDelta` function (around line 680):

```cpp
static void EmitCodeCaveAlert(HWND hwnd, DWORD pid, const std::wstring& image, const CodeCaveDetection::CodeCave& cave) {
    std::wstringstream ds;
    ds << L"event=code_cave location=0x" << std::hex << cave.location
       << L" size=" << std::dec << cave.size
       << L" reason=" << cave.detectionReason
       << L" module=" << cave.moduleContext;
    
    if (cave.isHooked) {
        ds << L" hooked=1 original_bytes=";
        for (size_t i = 0; i < std::min<size_t>(cave.size, 16); i++) {
            if (i > 0) ds << L" ";
            ds << std::hex << std::uppercase << std::setw(2) << std::setfill(L'0') << (int)cave.originalBytes[i];
        }
    }
    
    auto line = std::format(L"[{}] ALERT CodeCave pid={} name={} {}",
        (long long)duration_cast<seconds>(system_clock::now().time_since_epoch()).count(),
        pid, image, ds.str());
    
    Logger::Write(line);
    
    XDR::Event ev;
    ev.category = XDR::EventCategory::Alert;
    ev.type = XDR::EventType::AlertApiHook; // Reuse ApiHook type as caves often indicate hooks
    ev.pid = pid;
    ev.image = image;
    ev.details = ds.str();
    XDR::Storage::Insert(ev);
    
    auto* msg = new std::wstring(line);
    PostMessageW(hwnd, WM_APP + 2, (WPARAM)msg, 0);
}
```

### Step 6: Initialize in OnProcessStart
In the `OnProcessStart` function, after initializing other time points (around line 725):

```cpp
int d5 = g_settings.codeCaveCheckIntervalSec/2; if(d5<5) d5=5;
pi.nextCodeCaveScan = now + seconds(d5);
```

### Step 7: Add to Periodic Scanning
In the `Periodic` function, add this code after the reflective memory check (around line 770):

```cpp
// Code cave detection
if(g_settings.enableCodeCaveDetection && alive>=5 && alive<=600 && 
   now>=pi.nextCodeCaveScan && pi.codeCaveScanRuns<g_settings.codeCaveCheckMaxRuns) {
    pi.nextCodeCaveScan = now + seconds(g_settings.codeCaveCheckIntervalSec);
    ++pi.codeCaveScanRuns;
    
    auto caves = CodeCaveDetection::DetectCodeCaves(pi.pid);
    for(const auto& cave : caves) {
        if(pi.alertedCodeCaves.insert(cave.location).second && 
           AlertAllowed(pi.pid, XDR::EventType::AlertApiHook, cave.location)) {
            EmitCodeCaveAlert(hwnd, pi.pid, pi.image, cave);
        }
    }
}
```

## Testing
After integration, you can test by:
1. Building the project
2. Running the XDR agent
3. Looking for "ALERT CodeCave" entries in the logs when processes with hooks/patches are detected

## Configuration
You can disable code cave detection by setting:
```cpp
settings.enableCodeCaveDetection = false;
```

Or adjust the scan frequency:
```cpp
settings.codeCaveCheckIntervalSec = 60; // Check every 60 seconds
settings.codeCaveCheckMaxRuns = 10;     // Check up to 10 times per process
```
