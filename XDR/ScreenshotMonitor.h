#pragma once

#include <windows.h>
#include <string>
#include <chrono>
#include <vector>
#include <memory>
#include <functional>
#include <thread>
#include <mutex>
#include <atomic>

namespace ScreenshotCapture {
    
    // Screenshot event information
    struct ScreenshotEvent {
        std::chrono::system_clock::time_point timestamp;
        DWORD triggeringPid;
        std::wstring processName;
        std::wstring triggerReason;
        std::wstring screenshotPath;
        SIZE_T screenshotSize;
        bool successful;
    };

    // Screenshot trigger conditions
    enum class TriggerCondition {
        SuspiciousProcess,
        ProcessHollowing,
        DllInjection,
        CredentialAccess,
        NetworkActivity,
        ManualTrigger,
        PeriodicCapture
    };

    // Screenshot quality settings
    struct CaptureSettings {
        int quality = 75;           // JPEG quality 1-100
        bool captureAllMonitors = true;
        bool compressImages = true;
        SIZE_T maxFileSize = 5 * 1024 * 1024; // 5MB max
        std::wstring outputDirectory;         // if empty a temp path will be used
        bool enablePeriodicCapture = false;
        std::chrono::minutes periodicInterval{30};
    };

    // Main screenshot monitor class
    class ScreenshotMonitor {
    public:
        ScreenshotMonitor();
        ~ScreenshotMonitor();

        bool Initialize(const CaptureSettings& settings);
        void Start(HWND notificationWindow);
        void Stop();
        
        // Trigger screenshot capture
        bool CaptureScreenshot(TriggerCondition trigger, DWORD pid = 0, const std::wstring& reason = L"");
        
        // Configuration
        void SetCaptureSettings(const CaptureSettings& settings);
        const CaptureSettings& GetCaptureSettings() const { return m_settings; }
        
        // Statistics
        size_t GetCaptureCount() const { return m_captureCount; }
        size_t GetFailureCount() const { return m_failureCount; }
        SIZE_T GetTotalStorageUsed() const { return m_totalStorageUsed; }

    private:
        // Core capture functionality
        bool CaptureScreenshotInternal(const std::wstring& filename, TriggerCondition trigger, DWORD pid, const std::wstring& reason);
        bool CaptureDesktop(HDC hdcScreen, HDC hdcMemory, HBITMAP hbmScreen, const RECT& screenRect);
        bool SaveBitmapAsJPEG(HBITMAP hBitmap, const std::wstring& filename, int quality);
        
        // Utility functions
        std::wstring GenerateFilename(TriggerCondition trigger, DWORD pid);
        std::wstring GetProcessNameFromPid(DWORD pid);
        void CleanupOldScreenshots();
        void NotifyCapture(const ScreenshotEvent& event);
        bool EnsureOutputDirectory();
        
        // Worker thread for periodic captures
        void WorkerThread();
        
        // Settings and state
        CaptureSettings m_settings;
        HWND m_notificationWindow;
        std::atomic<bool> m_running;
        std::thread m_workerThread;
        ULONG_PTR m_gdiplusToken{}; // store GDI+ token properly
        
        // Statistics
        std::atomic<size_t> m_captureCount;
        std::atomic<size_t> m_failureCount;
        std::atomic<SIZE_T> m_totalStorageUsed;
        
        // Synchronization
        mutable std::mutex m_mutex;
        
        // Recent captures tracking (to avoid spam)
        std::vector<std::pair<std::chrono::steady_clock::time_point, DWORD>> m_recentCaptures;
        static constexpr std::chrono::seconds MIN_CAPTURE_INTERVAL{10}; // Minimum 10 seconds between captures for same process
    };

    // Helper functions for trigger condition conversion
    std::wstring TriggerConditionToString(TriggerCondition condition);
    std::wstring FormatScreenshotEvent(const ScreenshotEvent& event);
}