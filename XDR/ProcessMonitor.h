#pragma once
#include <windows.h>
#include <thread>
#include <atomic>
#include <unordered_map>
#include <string>

namespace XDR {

class ProcessMonitor {
public:
    ProcessMonitor() = default;
    ~ProcessMonitor() = default;
    
    void Start(HWND hwnd);
    void Stop();
    
private:
    void loop();
    
    std::thread th;
    std::atomic_bool running{ false };
    HWND hwnd{};
    std::unordered_map<DWORD, std::wstring> known;
};

} // namespace XDR
