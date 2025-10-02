#include "ScreenshotMonitor.h"
#include <gdiplus.h>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <psapi.h>
#include <algorithm>
#include <format>

#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "psapi.lib")

// Custom message for screenshot events
#define WM_SCREENSHOT_EVENT (WM_APP + 10)

namespace ScreenshotCapture {

namespace {
    // JPEG encoder CLSID - need to get this at runtime
    bool GetEncoderClsid(const WCHAR* format, CLSID* pClsid) {
        UINT num = 0;
        UINT size = 0;
        Gdiplus::ImageCodecInfo* pImageCodecInfo = nullptr;
        Gdiplus::GetImageEncodersSize(&num, &size);
        if (size == 0) return false;
        pImageCodecInfo = (Gdiplus::ImageCodecInfo*)(malloc(size));
        if (pImageCodecInfo == nullptr) return false;
        Gdiplus::GetImageEncoders(num, size, pImageCodecInfo);
        for (UINT j = 0; j < num; ++j) {
            if (wcscmp(pImageCodecInfo[j].MimeType, format) == 0) {
                *pClsid = pImageCodecInfo[j].Clsid;
                free(pImageCodecInfo);
                return true;
            }
        }
        free(pImageCodecInfo);
        return false;
    }
}

ScreenshotMonitor::ScreenshotMonitor() 
    : m_notificationWindow(nullptr)
    , m_running(false)
    , m_captureCount(0)
    , m_failureCount(0)
    , m_totalStorageUsed(0) {
    // default settings
    m_settings.quality = 75;
    m_settings.captureAllMonitors = true;
    m_settings.compressImages = true;
    m_settings.maxFileSize = 5 * 1024 * 1024; // 5MB
    m_settings.enablePeriodicCapture = false;
    m_settings.periodicInterval = std::chrono::minutes(30);
}

ScreenshotMonitor::~ScreenshotMonitor() { Stop(); }

bool ScreenshotMonitor::Initialize(const CaptureSettings& settings) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_settings = settings;
    if (m_settings.outputDirectory.empty()) {
        wchar_t tempPath[MAX_PATH];
        GetTempPathW(MAX_PATH, tempPath);
        m_settings.outputDirectory = std::wstring(tempPath) + L"FalconXDR_Screenshots"; // without trailing slash
    }
    // Init GDI+
    if(m_gdiplusToken==0){
        Gdiplus::GdiplusStartupInput si; if(Gdiplus::GdiplusStartup(&m_gdiplusToken,&si,nullptr)!=Gdiplus::Ok) return false;
    }
    return EnsureOutputDirectory();
}

void ScreenshotMonitor::Start(HWND notificationWindow) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_running.load()) return; 
    m_notificationWindow = notificationWindow;
    m_running = true;
    if (m_settings.enablePeriodicCapture) {
        m_workerThread = std::thread(&ScreenshotMonitor::WorkerThread, this);
    }
}

void ScreenshotMonitor::Stop() {
    m_running = false;
    if (m_workerThread.joinable()) m_workerThread.join();
    if(m_gdiplusToken){ Gdiplus::GdiplusShutdown(m_gdiplusToken); m_gdiplusToken=0; }
}

bool ScreenshotMonitor::CaptureScreenshot(TriggerCondition trigger, DWORD pid, const std::wstring& reason) {
    if (!m_running.load()) return false;
    auto now = std::chrono::steady_clock::now();
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_recentCaptures.erase(std::remove_if(m_recentCaptures.begin(), m_recentCaptures.end(),[now](const auto& e){ return now - e.first > MIN_CAPTURE_INTERVAL; }), m_recentCaptures.end());
        if(pid!=0){ auto it=std::find_if(m_recentCaptures.begin(), m_recentCaptures.end(),[pid](const auto& e){ return e.second==pid; }); if(it!=m_recentCaptures.end()) return false; }
        m_recentCaptures.emplace_back(now,pid);
    }
    std::wstring filename = GenerateFilename(trigger, pid);
    bool success = CaptureScreenshotInternal(filename, trigger, pid, reason);
    if (success) ++m_captureCount; else ++m_failureCount;
    return success;
}

void ScreenshotMonitor::SetCaptureSettings(const CaptureSettings& settings) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_settings = settings; if(m_settings.outputDirectory.empty()){ wchar_t tmp[MAX_PATH]; GetTempPathW(MAX_PATH,tmp); m_settings.outputDirectory=std::wstring(tmp)+L"FalconXDR_Screenshots"; }
    EnsureOutputDirectory();
}

bool ScreenshotMonitor::CaptureScreenshotInternal(const std::wstring& filename, TriggerCondition trigger, DWORD pid, const std::wstring& reason) {
    try {
        int screenWidth = m_settings.captureAllMonitors ? GetSystemMetrics(SM_CXVIRTUALSCREEN) : GetSystemMetrics(SM_CXSCREEN);
        int screenHeight= m_settings.captureAllMonitors ? GetSystemMetrics(SM_CYVIRTUALSCREEN) : GetSystemMetrics(SM_CYSCREEN);
        if(screenWidth<=0||screenHeight<=0) return false;
        HDC hdcScreen=GetDC(nullptr); if(!hdcScreen) return false; HDC hdcMemory=CreateCompatibleDC(hdcScreen); if(!hdcMemory){ ReleaseDC(nullptr,hdcScreen); return false; }
        HBITMAP hbmScreen=CreateCompatibleBitmap(hdcScreen,screenWidth,screenHeight); if(!hbmScreen){ DeleteDC(hdcMemory); ReleaseDC(nullptr,hdcScreen); return false; }
        HBITMAP old=(HBITMAP)SelectObject(hdcMemory,hbmScreen);
        RECT rc{0,0,screenWidth,screenHeight}; bool cap=CaptureDesktop(hdcScreen,hdcMemory,hbmScreen,rc); bool save=false; if(cap) save=SaveBitmapAsJPEG(hbmScreen,filename,m_settings.quality);
        SelectObject(hdcMemory,old); DeleteObject(hbmScreen); DeleteDC(hdcMemory); ReleaseDC(nullptr,hdcScreen);
        if(save){ std::error_code ec; auto fs=std::filesystem::file_size(filename,ec); if(!ec) m_totalStorageUsed+=fs; ScreenshotEvent ev; ev.timestamp=std::chrono::system_clock::now(); ev.triggeringPid=pid; ev.processName=GetProcessNameFromPid(pid); ev.triggerReason=reason; ev.screenshotPath=filename; ev.screenshotSize=ec?0:fs; ev.successful=true; NotifyCapture(ev); CleanupOldScreenshots(); }
        return save;
    } catch(...){ return false; }
}

bool ScreenshotMonitor::CaptureDesktop(HDC hdcScreen, HDC hdcMemory, HBITMAP hbmScreen, const RECT& screenRect) {
    int w=screenRect.right-screenRect.left, h=screenRect.bottom-screenRect.top; return BitBlt(hdcMemory,0,0,w,h,hdcScreen,screenRect.left,screenRect.top,SRCCOPY)!=FALSE; }

bool ScreenshotMonitor::SaveBitmapAsJPEG(HBITMAP hBitmap, const std::wstring& filename, int quality) {
    Gdiplus::Bitmap bmp(hBitmap,nullptr); CLSID clsid; if(!GetEncoderClsid(L"image/jpeg",&clsid)) return false; Gdiplus::EncoderParameters ep; ep.Count=1; ep.Parameter[0].Guid=Gdiplus::EncoderQuality; ep.Parameter[0].Type=Gdiplus::EncoderParameterValueTypeLong; ep.Parameter[0].NumberOfValues=1; ULONG q=quality; ep.Parameter[0].Value=&q; auto dir=std::filesystem::path(filename).parent_path(); std::error_code ec; std::filesystem::create_directories(dir,ec); return bmp.Save(filename.c_str(),&clsid,&ep)==Gdiplus::Ok; }

std::wstring ScreenshotMonitor::GenerateFilename(TriggerCondition trigger, DWORD pid) {
    auto now=std::chrono::system_clock::now(); auto tt=std::chrono::system_clock::to_time_t(now); auto ms=std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch())%1000; std::tm lt; localtime_s(&lt,&tt); std::wstring trig=TriggerConditionToString(trigger); std::wstring pname=GetProcessNameFromPid(pid); std::replace(trig.begin(),trig.end(),L' ',L'_'); std::replace(pname.begin(),pname.end(),L'.',L'_'); return std::format(L"{}\\screenshot_{:04d}{:02d}{:02d}_{:02d}{:02d}{:02d}_{:03d}_{}_{}_pid{}.jpg", m_settings.outputDirectory, lt.tm_year+1900, lt.tm_mon+1, lt.tm_mday, lt.tm_hour, lt.tm_min, lt.tm_sec, (int)ms.count(), trig, pname.empty()?L"unknown":pname, pid); }

std::wstring ScreenshotMonitor::GetProcessNameFromPid(DWORD pid) { if(pid==0) return L""; HANDLE h=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid); if(!h) return L"unknown"; wchar_t buf[MAX_PATH]=L"unknown"; DWORD sz=MAX_PATH; if(QueryFullProcessImageNameW(h,0,buf,&sz)){ std::wstring fp(buf); size_t p=fp.find_last_of(L'\\'); CloseHandle(h); return p==std::wstring::npos?fp:fp.substr(p+1);} CloseHandle(h); return L"unknown"; }

void ScreenshotMonitor::CleanupOldScreenshots() { try { std::error_code ec; if(!std::filesystem::exists(m_settings.outputDirectory,ec)) return; std::vector<std::filesystem::directory_entry> files; for(auto &e: std::filesystem::directory_iterator(m_settings.outputDirectory,ec)){ if(!ec && e.is_regular_file() && e.path().extension()==L".jpg") files.push_back(e);} std::sort(files.begin(),files.end(),[](auto &a,auto &b){ std::error_code e1,e2; auto ta=a.last_write_time(e1); auto tb=b.last_write_time(e2); if(e1||e2) return false; return ta<tb; }); const size_t MAX_FILES=100; const size_t MAX_TOTAL=500ull*1024*1024; size_t total=0, keep=0; for(auto it=files.rbegin(); it!=files.rend(); ++it){ auto sz=it->file_size(ec); if(ec) continue; if(total+sz<=MAX_TOTAL && keep<MAX_FILES){ total+=sz; ++keep; } else break; } for(size_t i=0;i<files.size()-keep;++i){ std::filesystem::remove(files[i].path(),ec); } } catch(...){} }

void ScreenshotMonitor::NotifyCapture(const ScreenshotEvent& event) { if(m_notificationWindow){ auto *copy=new ScreenshotEvent(event); PostMessageW(m_notificationWindow,WM_SCREENSHOT_EVENT,reinterpret_cast<WPARAM>(copy),0);} }

bool ScreenshotMonitor::EnsureOutputDirectory() { try { std::error_code ec; std::filesystem::create_directories(m_settings.outputDirectory,ec); return !ec; } catch(...) { return false; } }

void ScreenshotMonitor::WorkerThread() { while(m_running.load()){ auto interval=m_settings.periodicInterval; auto start=std::chrono::steady_clock::now(); while(m_running.load() && (std::chrono::steady_clock::now()-start)<interval) std::this_thread::sleep_for(std::chrono::seconds(1)); if(!m_running.load()) break; CaptureScreenshot(TriggerCondition::PeriodicCapture,0,L"Periodic capture"); } }

std::wstring TriggerConditionToString(TriggerCondition condition) {
    switch (condition) {
        case TriggerCondition::SuspiciousProcess: return L"Suspicious_Process";
        case TriggerCondition::ProcessHollowing: return L"Process_Hollowing";
        case TriggerCondition::DllInjection: return L"DLL_Injection";
        case TriggerCondition::CredentialAccess: return L"Credential_Access";
        case TriggerCondition::NetworkActivity: return L"Network_Activity";
        case TriggerCondition::ManualTrigger: return L"Manual_Trigger";
        case TriggerCondition::PeriodicCapture: return L"Periodic_Capture";
        default: return L"Unknown";
    }
}

std::wstring FormatScreenshotEvent(const ScreenshotEvent& event) {
    auto tt=std::chrono::system_clock::to_time_t(event.timestamp); std::tm lt; localtime_s(&lt,&tt); return std::format(L"Screenshot captured: {:02d}:{:02d}:{:02d} | Process: {}({}) | Reason: {} | Size: {} bytes | Path: {}", lt.tm_hour, lt.tm_min, lt.tm_sec, event.processName, event.triggeringPid, event.triggerReason, event.screenshotSize, event.screenshotPath); }

} // namespace ScreenshotCapture