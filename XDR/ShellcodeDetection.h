#pragma once
#include <cstdint>
#include <cstddef>
#include <string>

namespace ShellcodeDetection {

struct ShellcodeIndicators {
    bool hasGetProcAddress = false;      // Common API resolution
    bool hasPEB_Walk = false;            // Manual API resolution via PEB
    bool hasStackPivot = false;          // Stack manipulation
    bool hasNopSled = false;             // NOP sleds (0x90)
    bool hasEggHunter = false;           // Egg hunter patterns
    bool suspiciousAPISequence = false;  // VirtualAlloc->WriteProcessMemory->CreateRemoteThread
    double entropy = 0.0;
    double instructionDensity = 0.0;
};

// Analyze a buffer and compute indicators
ShellcodeIndicators Analyze(const uint8_t* data, size_t size);

// Utility to format indicators as key=value pairs string
std::wstring ToDetails(const ShellcodeIndicators& ind);

}
