#include "ProcessMonitor.h"
#include "Utilities.h"
#include "Storage.h"
#include "BehavioralAnalyzer.h"
#include <TlHelp32.h>
#include <format>
#include <chrono>

#define WM_XDR_EVENT (WM_APP + 1)

namespace XDR {

extern std::atomic_bool g_collect;

static void StoreProcessEvent(bool start, DWORD pid, const std::wstring& img) {
    Event ev;
    ev.category = EventCategory::Process;
    ev.type = start ? EventType::ProcStart : EventType::ProcStop;
    ev.pid = pid;
    ev.image = img;
    ev.details = start ? L"start" : L"stop";
    Storage::Insert(ev);
}

void ProcessMonitor::Start(HWND h) {
    if (running.load()) return;
    hwnd = h;
    running = true;
    th = std::thread([this] { loop(); });
}

void ProcessMonitor::Stop() {
    running = false;
    if (th.joinable()) th.join();
}

void ProcessMonitor::loop() {
    using namespace std::chrono_literals;
    
    while (running.load()) {
        if (!g_collect.load()) {
            std::this_thread::sleep_for(1s);
            continue;
        }
        
        std::unordered_map<DWORD, std::wstring> current;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe{ sizeof(pe) };
            if (Process32FirstW(snap, &pe)) {
                do {
                    current[pe.th32ProcessID] = pe.szExeFile;
                } while (Process32NextW(snap, &pe));
            }
            CloseHandle(snap);
        }
        
        // detect starts
        for (auto& kv : current) {
            if (known.find(kv.first) == known.end()) { // new
                StoreProcessEvent(true, kv.first, kv.second);
                auto line = std::format(L"[{}] PROC START pid={} image={}",
                    Utils::TimeNow(), kv.first, kv.second);
                Utils::PostLine(hwnd, WM_XDR_EVENT, line);
                // hook into behavioral analyzer
                Behavioral::OnProcessStart(kv.first, kv.second, hwnd);
            }
        }
        
        // detect exits
        for (auto it = known.begin(); it != known.end(); ++it) {
            if (current.find(it->first) == current.end()) {
                StoreProcessEvent(false, it->first, it->second);
                auto line = std::format(L"[{}] PROC STOP pid={} image={}",
                    Utils::TimeNow(), it->first, it->second);
                Utils::PostLine(hwnd, WM_XDR_EVENT, line);
                Behavioral::OnProcessStop(it->first);
            }
        }
        
        known.swap(current);
        
        for (int i = 0; i < 10 && running.load(); ++i)
            std::this_thread::sleep_for(150ms);
    }
}

} // namespace XDR
