#include "CorrelationEngine.h"
#include "Logger.h"
#include <format>
#include <algorithm>

#define WM_XDR_ALERT (WM_APP + 2)

namespace XDR {

void CorrelationEngine::Initialize(HWND notifyWnd) {
    if (m_running.load()) return;
    m_hwnd = notifyWnd;
    m_running = true;
    m_thread = std::thread([this] { processLoop(); });
}

void CorrelationEngine::Shutdown() {
    m_running = false;
    if (m_thread.joinable()) m_thread.join();
}

void CorrelationEngine::OnEvent(const Event& ev) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (ev.pid == 0) return;
    
    auto& ctx = m_processContexts[ev.pid];
    if (ctx.pid == 0) {
        ctx.pid = ev.pid;
        ctx.image = ev.image;
        ctx.firstSeen = ev.ts;
    }
    
    ctx.recentEvents.push_back(ev);
    ctx.seenTypes.insert(ev.type);
    
    // Trim old events
    while (ctx.recentEvents.size() > kMaxEventsPerProcess) {
        ctx.recentEvents.pop_front();
    }
    
    // Update network context for network events
    if (ev.category == EventCategory::Network || ev.category == EventCategory::Alert) {
        // Parse network details if present (raddr, rport)
        // Simplified: would need actual parsing
    }
}

void CorrelationEngine::processLoop() {
    using namespace std::chrono_literals;
    while (m_running.load()) {
        std::this_thread::sleep_for(5s);
        analyzeCorrelations();
    }
}

void CorrelationEngine::analyzeCorrelations() {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto now = std::chrono::system_clock::now();
    
    // Clean up old contexts
    for (auto it = m_processContexts.begin(); it != m_processContexts.end();) {
        if (!it->second.recentEvents.empty()) {
            auto age = now - it->second.recentEvents.back().ts;
            if (age > kContextTimeout) {
                it = m_processContexts.erase(it);
                continue;
            }
        }
        ++it;
    }
    
    // Analyze each process context
    for (auto& [pid, ctx] : m_processContexts) {
        if (ctx.recentEvents.size() < 2) continue;
        
        detectCredentialAccess(ctx);
        detectLateralMovement(ctx);
        detectPersistence(ctx);
        detectDefenseEvasion(ctx);
        detectC2(ctx);
        detectPrivilegeEscalation(ctx);
        detectReflectiveExecution(ctx);
        detectProcessChain(ctx);
        detectMultiStage(ctx);
    }
}

bool CorrelationEngine::hasEventTypes(const ProcessContext& ctx, const std::vector<EventType>& types, size_t minCount) {
    size_t count = 0;
    for (auto t : types) {
        if (ctx.seenTypes.contains(t)) count++;
    }
    return count >= minCount;
}

std::chrono::seconds CorrelationEngine::timeSinceFirst(const ProcessContext& ctx) {
    if (ctx.recentEvents.empty()) return std::chrono::seconds(0);
    auto now = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::seconds>(now - ctx.firstSeen);
}

void CorrelationEngine::detectCredentialAccess(ProcessContext& ctx) {
    // Pattern: LSASS handle + (dbghelp/comsvcs) + privileged execution
    std::vector<EventType> indicators = {
        EventType::AlertPrivilegedExec,
        EventType::AlertProcessInjection
    };
    
    if (!hasEventTypes(ctx, indicators, 1)) return;
    
    // Check for LSASS in details
    bool hasLsass = false;
    bool hasDbgOrCom = false;
    std::vector<uint64_t> eventIds;
    
    for (const auto& ev : ctx.recentEvents) {
        if (ev.details.find(L"lsass") != std::wstring::npos || 
            ev.details.find(L"lsass_handle=1") != std::wstring::npos) {
            hasLsass = true;
            eventIds.push_back(ev.id);
        }
        if (ev.image.find(L"dbghelp") != std::wstring::npos || 
            ev.image.find(L"comsvcs") != std::wstring::npos ||
            ev.details.find(L"dbghelp") != std::wstring::npos ||
            ev.details.find(L"comsvcs") != std::wstring::npos) {
            hasDbgOrCom = true;
            eventIds.push_back(ev.id);
        }
    }
    
    if (hasLsass && hasDbgOrCom && eventIds.size() >= 2) {
        double score = 0.9;
        emitCorrelation(CorrelationPattern::CredentialAccess, ctx.pid, ctx.image, eventIds, score,
                       L"LSASS access with credential dumping tools detected");
    }
}

void CorrelationEngine::detectLateralMovement(ProcessContext& ctx) {
    // Pattern: Remote port (SMB 445, RDP 3389) + injection/execution
    std::vector<EventType> indicators = {
        EventType::AlertSuspiciousRemotePort,
        EventType::AlertProcessInjection,
        EventType::AlertReflectiveMemory
    };
    
    if (!hasEventTypes(ctx, indicators, 2)) return;
    
    std::vector<uint64_t> eventIds;
    bool hasRemote = false;
    bool hasInjection = false;
    
    for (const auto& ev : ctx.recentEvents) {
        if (ev.type == EventType::AlertSuspiciousRemotePort) {
            if (ev.details.find(L"445") != std::wstring::npos || 
                ev.details.find(L"3389") != std::wstring::npos) {
                hasRemote = true;
                eventIds.push_back(ev.id);
            }
        }
        if (ev.type == EventType::AlertProcessInjection || 
            ev.type == EventType::AlertReflectiveMemory) {
            hasInjection = true;
            eventIds.push_back(ev.id);
        }
    }
    
    if (hasRemote && hasInjection) {
        double score = 0.85;
        emitCorrelation(CorrelationPattern::LateralMovement, ctx.pid, ctx.image, eventIds, score,
                       L"Lateral movement indicators: remote connection + code injection");
    }
}

void CorrelationEngine::detectPersistence(ProcessContext& ctx) {
    // Pattern: Multiple persistence mechanisms
    std::vector<EventType> indicators = {
        EventType::AlertAutorunChange,
        EventType::AlertServicePersistence,
        EventType::AlertRegistryPersistence
    };
    
    if (!hasEventTypes(ctx, indicators, 2)) return;
    
    std::vector<uint64_t> eventIds;
    for (const auto& ev : ctx.recentEvents) {
        if (ev.type == EventType::AlertAutorunChange ||
            ev.type == EventType::AlertServicePersistence ||
            ev.type == EventType::AlertRegistryPersistence) {
            eventIds.push_back(ev.id);
        }
    }
    
    if (eventIds.size() >= 2) {
        double score = 0.8;
        emitCorrelation(CorrelationPattern::PersistenceEstablishment, ctx.pid, ctx.image, eventIds, score,
                       std::format(L"Multiple persistence mechanisms: {} techniques", eventIds.size()));
    }
}

void CorrelationEngine::detectDefenseEvasion(ProcessContext& ctx) {
    // Pattern: API hooks + hollowing/injection + unsigned modules
    std::vector<EventType> indicators = {
        EventType::AlertApiHook,
        EventType::AlertProcessHollowing,
        EventType::AlertUnsignedModule,
        EventType::AlertReflectiveMemory
    };
    
    if (!hasEventTypes(ctx, indicators, 2)) return;
    
    std::vector<uint64_t> eventIds;
    for (const auto& ev : ctx.recentEvents) {
        if (ev.type == EventType::AlertApiHook ||
            ev.type == EventType::AlertProcessHollowing ||
            ev.type == EventType::AlertUnsignedModule ||
            ev.type == EventType::AlertReflectiveMemory) {
            eventIds.push_back(ev.id);
        }
    }
    
    if (eventIds.size() >= 2) {
        double score = 0.85;
        emitCorrelation(CorrelationPattern::DefenseEvasion, ctx.pid, ctx.image, eventIds, score,
                       L"Defense evasion chain: hooks/hollowing/unsigned modules");
    }
}

void CorrelationEngine::detectC2(ProcessContext& ctx) {
    // Pattern: Beaconing + (TOR/I2P/C2) + fast flux
    std::vector<EventType> indicators = {
        EventType::AlertBeaconing,
        EventType::AlertTorI2P,
        EventType::AlertKnownC2,
        EventType::AlertFastFluxDNS
    };
    
    if (!hasEventTypes(ctx, indicators, 1)) return;
    
    std::vector<uint64_t> eventIds;
    int c2Indicators = 0;
    
    for (const auto& ev : ctx.recentEvents) {
        if (ev.type == EventType::AlertBeaconing ||
            ev.type == EventType::AlertTorI2P ||
            ev.type == EventType::AlertKnownC2 ||
            ev.type == EventType::AlertFastFluxDNS) {
            eventIds.push_back(ev.id);
            c2Indicators++;
        }
    }
    
    if (c2Indicators >= 1) {
        double score = 0.75 + (c2Indicators * 0.1); // Higher score with more indicators
        emitCorrelation(CorrelationPattern::CommandAndControl, ctx.pid, ctx.image, eventIds, score,
                       std::format(L"C2 communication detected: {} indicators", c2Indicators));
    }
}

void CorrelationEngine::detectPrivilegeEscalation(ProcessContext& ctx) {
    // Pattern: Token manipulation + SeDebug + integrity change
    std::vector<EventType> indicators = {
        EventType::AlertTokenManipulation,
        EventType::AlertPrivilegedExec
    };
    
    if (!hasEventTypes(ctx, indicators, 2)) return;
    
    std::vector<uint64_t> eventIds;
    for (const auto& ev : ctx.recentEvents) {
        if (ev.type == EventType::AlertTokenManipulation ||
            ev.type == EventType::AlertPrivilegedExec) {
            eventIds.push_back(ev.id);
        }
    }
    
    if (eventIds.size() >= 2) {
        double score = 0.9;
        emitCorrelation(CorrelationPattern::PrivilegeEscalation, ctx.pid, ctx.image, eventIds, score,
                       L"Privilege escalation chain: token manipulation + elevated execution");
    }
}

void CorrelationEngine::detectReflectiveExecution(ProcessContext& ctx) {
    // Pattern: Reflective loading + shellcode indicators + YARA hits
    std::vector<EventType> indicators = {
        EventType::AlertReflectiveMemory,
        EventType::AlertReflectiveModule,
        EventType::AlertSuspiciousExecRegion,
        EventType::AlertYaraMatch
    };
    
    if (!hasEventTypes(ctx, indicators, 2)) return;
    
    std::vector<uint64_t> eventIds;
    bool hasShellcodeHints = false;
    
    for (const auto& ev : ctx.recentEvents) {
        if (ev.type == EventType::AlertReflectiveMemory ||
            ev.type == EventType::AlertReflectiveModule ||
            ev.type == EventType::AlertSuspiciousExecRegion ||
            ev.type == EventType::AlertYaraMatch) {
            eventIds.push_back(ev.id);
            
            if (ev.details.find(L"getproc=1") != std::wstring::npos ||
                ev.details.find(L"peb_walk=1") != std::wstring::npos ||
                ev.details.find(L"shellcode") != std::wstring::npos) {
                hasShellcodeHints = true;
            }
        }
    }
    
    if (eventIds.size() >= 2) {
        double score = hasShellcodeHints ? 0.95 : 0.8;
        emitCorrelation(CorrelationPattern::ReflectiveExecution, ctx.pid, ctx.image, eventIds, score,
                       L"Reflective code execution with shellcode patterns");
    }
}

void CorrelationEngine::detectProcessChain(ProcessContext& ctx) {
    // Pattern: Suspicious parent-child relationships
    // Check if this process has suspicious ancestry or spawns suspicious children
    if (ctx.image.find(L"powershell") != std::wstring::npos ||
        ctx.image.find(L"cmd.exe") != std::wstring::npos ||
        ctx.image.find(L"wscript") != std::wstring::npos) {
        
        std::vector<uint64_t> eventIds;
        bool hasInjection = false;
        
        for (const auto& ev : ctx.recentEvents) {
            if (ev.type == EventType::AlertSuspiciousProcess ||
                ev.type == EventType::AlertProcessInjection) {
                eventIds.push_back(ev.id);
                hasInjection = true;
            }
        }
        
        if (hasInjection) {
            double score = 0.7;
            emitCorrelation(CorrelationPattern::ProcessChain, ctx.pid, ctx.image, eventIds, score,
                           L"Suspicious process chain: script interpreter with injection");
        }
    }
}

void CorrelationEngine::detectMultiStage(ProcessContext& ctx) {
    // Pattern: Multiple memory protection changes + injections within short time
    int protChanges = 0;
    int injections = 0;
    std::vector<uint64_t> eventIds;
    
    for (const auto& ev : ctx.recentEvents) {
        if (ev.type == EventType::MemProtChange) protChanges++;
        if (ev.type == EventType::AlertProcessInjection ||
            ev.type == EventType::AlertReflectiveMemory) {
            injections++;
            eventIds.push_back(ev.id);
        }
    }
    
    if (protChanges >= 3 && injections >= 2) {
        auto timeWindow = timeSinceFirst(ctx);
        if (timeWindow < std::chrono::minutes(5)) {
            double score = 0.85;
            emitCorrelation(CorrelationPattern::MultiStagePayload, ctx.pid, ctx.image, eventIds, score,
                           std::format(L"Multi-stage payload: {} prot changes, {} injections in {}s",
                                     protChanges, injections, timeWindow.count()));
        }
    }
}

void CorrelationEngine::emitCorrelation(CorrelationPattern pattern, DWORD pid, const std::wstring& image,
                                        const std::vector<uint64_t>& eventIds, double score, const std::wstring& details) {
    // Check if already alerted for this pattern recently
    for (const auto& match : m_recentMatches) {
        if (match.pattern == std::to_wstring(static_cast<int>(pattern)) && 
            match.eventIds == eventIds) {
            auto age = std::chrono::system_clock::now() - match.lastSeen;
            if (age < std::chrono::minutes(10)) return; // Don't re-alert within 10 min
        }
    }
    
    CorrelationMatch match;
    match.eventIds = eventIds;
    match.pattern = std::to_wstring(static_cast<int>(pattern));
    match.description = details;
    match.score = score;
    match.firstSeen = match.lastSeen = std::chrono::system_clock::now();
    
    m_recentMatches.push_back(match);
    while (m_recentMatches.size() > kMaxRecentMatches) {
        m_recentMatches.pop_front();
    }
    
    // Store as event
    Event ev;
    ev.category = EventCategory::Alert;
    ev.type = EventType::AlertSuspiciousProcess; // Reuse or add new CorrelationAlert type
    ev.pid = pid;
    ev.image = image;
    ev.details = std::format(L"CORRELATION pattern={} score={:.2f} events={} {}", 
                            static_cast<int>(pattern), score, eventIds.size(), details);
    Storage::Insert(ev);
    
    auto line = std::format(L"[{}] CORRELATION {} pid={} image={} score={:.2f} {}",
                           std::chrono::duration_cast<std::chrono::seconds>(
                               std::chrono::system_clock::now().time_since_epoch()).count(),
                           static_cast<int>(pattern), pid, image, score, details);
    Logger::Write(line);
    
    auto* msg = new std::wstring(line);
    PostMessageW(m_hwnd, WM_XDR_ALERT, (WPARAM)msg, 0);
}

std::vector<CorrelationMatch> CorrelationEngine::GetCorrelationsForPid(DWORD pid) {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<CorrelationMatch> result;
    
    for (const auto& match : m_recentMatches) {
        // Check if any event in this correlation is for this PID
        auto it = m_processContexts.find(pid);
        if (it != m_processContexts.end()) {
            for (auto eid : match.eventIds) {
                for (const auto& ev : it->second.recentEvents) {
                    if (ev.id == eid) {
                        result.push_back(match);
                        break;
                    }
                }
            }
        }
    }
    return result;
}

std::vector<CorrelationMatch> CorrelationEngine::GetCorrelationsForProcess(const std::wstring& image) {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<CorrelationMatch> result;
    
    for (auto& [pid, ctx] : m_processContexts) {
        if (ctx.image.find(image) != std::wstring::npos) {
            auto pidMatches = GetCorrelationsForPid(pid);
            result.insert(result.end(), pidMatches.begin(), pidMatches.end());
        }
    }
    return result;
}

std::vector<CorrelationMatch> CorrelationEngine::GetRecentCorrelations(size_t limit) {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<CorrelationMatch> result(m_recentMatches.begin(), m_recentMatches.end());
    if (result.size() > limit) {
        result.resize(limit);
    }
    return result;
}

} // namespace XDR
