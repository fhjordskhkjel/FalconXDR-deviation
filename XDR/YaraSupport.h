#pragma once
#include <cstddef>
#include <vector>
#include <string>

namespace YaraSupport {
    // Ensure YARA is initialized (lazy)
    void EnsureInit();
    bool Initialized();
    // Scan a memory buffer (in-process) returning rule names (placeholder names in current impl)
    bool ScanBuffer(const uint8_t* data, size_t size, std::vector<std::wstring>& matches);
}
