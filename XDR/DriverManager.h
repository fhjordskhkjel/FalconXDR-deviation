#pragma once
#include <windows.h>
#include <string>
#include <thread>
#include <atomic>
#include <vector>
#include <cstdint>

// User-mode driver integration scaffold (Phase B)
// Handles optional kernel driver (if present) providing telemetry events.
// Gracefully degrades when driver not installed.

// Device + symbolic link we will expect from future driver (phase A)
#define XDR_DRIVER_SYMLINK   L"\\\\.\\XDR"

// Basic event types expected from kernel
enum class XdrDriverEventType : uint32_t {
    Unknown             = 0,
    ProcCreate          = 1,
    ProcExit            = 2,
    ImageLoad           = 3,
    SuspiciousHandle    = 4,
};

// Structure (must match kernel layout later). Fixed-size path.
#pragma pack(push,1)
struct XDR_DRIVER_EVENT {
    uint32_t Type;        // XdrDriverEventType
    uint32_t Pid;
    uint32_t ParentPid;   // for creates
    uint32_t Reserved;    // alignment / future
    uint64_t Time100ns;   // system time (KeQuerySystemTimePrecise)
    uint64_t Arg1;        // image base or handle target pid
    uint64_t Arg2;        // size / access mask
    wchar_t  Path[260];   // image path / dll path
};
#pragma pack(pop)

// IOCTL definition (placeholder – must match driver)
#ifndef CTL_CODE
#include <winioctl.h>
#endif
#define IOCTL_XDR_GET_EVENTS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

class DriverManager {
public:
    void Start(HWND notifyHwnd){
        m_stop=false; m_hwnd=notifyHwnd; m_thread=std::thread(&DriverManager::ThreadProc,this);
    }
    void Stop(){ m_stop=true; if(m_thread.joinable()) m_thread.join(); if(m_hDriver) { CloseHandle(m_hDriver); m_hDriver=nullptr; } }
    bool IsActive() const { return m_active.load(); }
private:
    void ThreadProc(){
        // Try to open driver (retry few times quietly)
        for(int i=0;i<5 && !m_stop && !m_hDriver;i++){
            m_hDriver=CreateFileW(XDR_DRIVER_SYMLINK, GENERIC_READ|GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if(!m_hDriver || m_hDriver==INVALID_HANDLE_VALUE){ m_hDriver=nullptr; Sleep(500); }
        }
        if(!m_hDriver){ m_active=false; return; }
        m_active=true;
        // Poll loop
        while(!m_stop){
            BYTE buffer[64 * sizeof(XDR_DRIVER_EVENT)]{}; DWORD bytes=0; BOOL ok=DeviceIoControl(m_hDriver, IOCTL_XDR_GET_EVENTS, nullptr,0, buffer, sizeof(buffer), &bytes, nullptr);
            if(ok && bytes>=sizeof(XDR_DRIVER_EVENT)){
                size_t count = bytes / sizeof(XDR_DRIVER_EVENT);
                auto* evts = reinterpret_cast<XDR_DRIVER_EVENT*>(buffer);
                for(size_t i=0;i<count;i++) Emit(evts[i]);
            } else {
                // Backoff if no data
                Sleep(250);
            }
        }
    }
    void Emit(const XDR_DRIVER_EVENT& e){
        if(!m_hwnd) return;
        // Format event line reusing existing UI semantics
        SYSTEMTIME st; FILETIME ft{ (DWORD)(e.Time100ns & 0xFFFFFFFF), (DWORD)(e.Time100ns >>32)}; FileTimeToSystemTime(&ft,&st);
        wchar_t tbuf[32]; swprintf_s(tbuf,L"%02u:%02u:%02u.%03u",st.wHour,st.wMinute,st.wSecond,st.wMilliseconds);
        std::wstring line;
        switch((XdrDriverEventType)e.Type){
            case XdrDriverEventType::ProcCreate:
                line = std::wstring(L"[") + tbuf + L"] KPROC START pid=" + std::to_wstring(e.Pid) + L" ppid=" + std::to_wstring(e.ParentPid) + L" image=" + e.Path; break;
            case XdrDriverEventType::ProcExit:
                line = std::wstring(L"[") + tbuf + L"] KPROC STOP pid=" + std::to_wstring(e.Pid); break;
            case XdrDriverEventType::ImageLoad:
                line = std::wstring(L"[") + tbuf + L"] KIMG LOAD pid=" + std::to_wstring(e.Pid) + L" base=0x" + PtrToHex(e.Arg1) + L" size=" + std::to_wstring(e.Arg2) + L" path=" + e.Path; break;
            case XdrDriverEventType::SuspiciousHandle:
                line = std::wstring(L"[") + tbuf + L"] ALERT KernelHandleAccess src_pid=" + std::to_wstring(e.Pid) + L" target_pid=" + std::to_wstring(e.Arg1) + L" access=0x" + PtrToHex(e.Arg2); break;
            default:
                line = std::wstring(L"[") + tbuf + L"] KDRV EVT type=" + std::to_wstring(e.Type) + L" pid=" + std::to_wstring(e.Pid); break;
        }
        // Post as event or alert depending on prefix
        auto *payload = new std::wstring(line);
        PostMessageW(m_hwnd, (line.find(L"ALERT ")!=std::wstring::npos)? (WM_APP+2):(WM_APP+1), reinterpret_cast<WPARAM>(payload), 0);
    }
    static std::wstring PtrToHex(uint64_t v){ wchar_t b[32]; swprintf_s(b,L"%llX",(unsigned long long)v); return b; }

    std::thread m_thread; std::atomic_bool m_stop{false}; std::atomic_bool m_active{false};
    HANDLE m_hDriver{}; HWND m_hwnd{};
};
