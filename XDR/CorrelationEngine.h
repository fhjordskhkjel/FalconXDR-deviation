#pragma once
#include "Storage.h"
#include <windows.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <deque>
#include <chrono>
#include <mutex>

namespace XDR {

// Correlation score and context
struct CorrelationMatch {
    std::vector<uint64_t> eventIds;
    std::wstring pattern;
    std::wstring description;
    double score;
    std::chrono::system_clock::time_point firstSeen;
    std::chrono::system_clock::time_point lastSeen;
};

// Correlation patterns
enum class CorrelationPattern {
    // Attack chain patterns
    CredentialAccess,           // LSASS + dbghelp/comsvcs + high priv
    LateralMovement,            // SMB/RDP + process injection + remote exec
    PersistenceEstablishment,   // Registry + service + autorun changes
    DefenseEvasion,             // API hooks + unsigned modules + hollowing
    CommandAndControl,          // Beaconing + TOR/C2 + fast flux
    DataExfiltration,           // High network + file access + compression
    PrivilegeEscalation,        // Token manipulation + SeDebug + integrity change
    ReflectiveExecution,        // Reflective loading + shellcode + YARA hits
    ProcessChain,               // Suspicious parent-child relationships
    MultiStagePayload           // Multiple memory transitions + injections
};

class CorrelationEngine {
public:
    void Initialize(HWND notifyWnd);
    void Shutdown();
    
    // Process new events
    void OnEvent(const Event& ev);
    
    // Query correlations
    std::vector<CorrelationMatch> GetCorrelationsForPid(DWORD pid);
    std::vector<CorrelationMatch> GetCorrelationsForProcess(const std::wstring& image);
    std::vector<CorrelationMatch> GetRecentCorrelations(size_t limit);
    
private:
    struct ProcessContext {
        DWORD pid;
        std::wstring image;
        std::deque<Event> recentEvents;
        std::unordered_set<EventType> seenTypes;
        std::chrono::system_clock::time_point firstSeen;
        double threatScore = 0.0;
    };
    
    struct NetworkContext {
        DWORD raddr;
        uint16_t rport;
        std::deque<std::chrono::system_clock::time_point> connections;
        std::unordered_set<DWORD> pids;
    };
    
    void processLoop();
    void analyzeCorrelations();
    
    // Pattern detectors
    void detectCredentialAccess(ProcessContext& ctx);
    void detectLateralMovement(ProcessContext& ctx);
    void detectPersistence(ProcessContext& ctx);
    void detectDefenseEvasion(ProcessContext& ctx);
    void detectC2(ProcessContext& ctx);
    void detectPrivilegeEscalation(ProcessContext& ctx);
    void detectReflectiveExecution(ProcessContext& ctx);
    void detectProcessChain(ProcessContext& ctx);
    void detectMultiStage(ProcessContext& ctx);
    
    // Emit correlation alert
    void emitCorrelation(CorrelationPattern pattern, DWORD pid, const std::wstring& image, 
                         const std::vector<uint64_t>& eventIds, double score, const std::wstring& details);
    
    // Helper
    bool hasEventTypes(const ProcessContext& ctx, const std::vector<EventType>& types, size_t minCount = 1);
    std::chrono::seconds timeSinceFirst(const ProcessContext& ctx);
    
    HWND m_hwnd = nullptr;
    std::mutex m_mutex;
    std::unordered_map<DWORD, ProcessContext> m_processContexts;
    std::unordered_map<std::pair<DWORD, uint16_t>, NetworkContext, 
                       std::hash<uint64_t>> m_networkContexts; // key: (raddr, rport) as uint64
    std::deque<CorrelationMatch> m_recentMatches;
    std::atomic_bool m_running{false};
    std::thread m_thread;
    
    static constexpr size_t kMaxEventsPerProcess = 200;
    static constexpr size_t kMaxRecentMatches = 500;
    static constexpr auto kContextTimeout = std::chrono::minutes(30);
};

} // namespace XDR
