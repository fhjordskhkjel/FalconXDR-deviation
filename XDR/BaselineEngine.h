#pragma once
#include <windows.h>
#include <string>
#include <map>
#include <set>
#include <unordered_map>
#include <vector>
#include <mutex>
#include <chrono>

namespace XDR {

class BaselineEngine {
public:
    struct ProcessProfile {
        std::set<std::wstring> typicalDlls;
        std::set<uint16_t> typicalPorts;
        std::set<std::wstring> typicalChildren;
        std::set<std::wstring> typicalParents;
        std::set<std::wstring> typicalCmdLineTokens;
        
        // Statistical baselines
        double avgMemoryUsage = 0.0;
        double maxMemoryUsage = 0.0;
        double avgCpuUsage = 0.0;
        double avgThreadCount = 0.0;
        double avgHandleCount = 0.0;
        
        // Behavioral baselines
        uint32_t typicalNetworkConnections = 0;
        uint32_t typicalFileAccess = 0;
        uint32_t typicalRegistryAccess = 0;
        
        // Learning metadata
        uint32_t observationCount = 0;
        std::chrono::system_clock::time_point firstSeen;
        std::chrono::system_clock::time_point lastUpdated;
        
        // Integrity tracking
        bool usuallyElevated = false;
        std::set<std::wstring> typicalIntegrityLevels;
    };
    
    struct AnomalyScore {
        double overall = 0.0;
        double dllAnomaly = 0.0;
        double portAnomaly = 0.0;
        double childAnomaly = 0.0;
        double parentAnomaly = 0.0;
        double memoryAnomaly = 0.0;
        double behaviorAnomaly = 0.0;
        double integrityAnomaly = 0.0;
        std::wstring reason;
    };
    
    static BaselineEngine& Instance();
    
    // Learning phase
    void LearnProcess(const std::wstring& imageName, 
                      DWORD pid,
                      const std::wstring& parentImage,
                      const std::set<std::wstring>& loadedDlls,
                      const std::vector<uint16_t>& activePorts,
                      double memoryMB,
                      double cpuPercent,
                      const std::wstring& integrity);
    
    void LearnChild(const std::wstring& parentImage, const std::wstring& childImage);
    void LearnCommandLine(const std::wstring& imageName, const std::wstring& cmdLine);
    
    // Detection phase
    AnomalyScore CalculateAnomalyScore(const std::wstring& imageName,
                                       DWORD pid,
                                       const std::wstring& parentImage,
                                       const std::set<std::wstring>& loadedDlls,
                                       const std::vector<uint16_t>& activePorts,
                                       double memoryMB,
                                       const std::wstring& integrity);
    
    // Baseline management
    void SaveBaseline(const std::wstring& filePath);
    void LoadBaseline(const std::wstring& filePath);
    void ResetBaseline();
    bool IsLearningPhase() const { return m_learningPhase; }
    void SetLearningPhase(bool enable) { m_learningPhase = enable; }
    
    // Queries
    bool HasBaseline(const std::wstring& imageName) const;
    ProcessProfile GetProfile(const std::wstring& imageName) const;
    std::vector<std::wstring> GetAllProfiles() const;
    
    // Statistics
    size_t GetProfileCount() const;
    uint32_t GetObservationCount(const std::wstring& imageName) const;
    
private:
    BaselineEngine();
    ~BaselineEngine() = default;
    BaselineEngine(const BaselineEngine&) = delete;
    BaselineEngine& operator=(const BaselineEngine&) = delete;
    
    std::map<std::wstring, ProcessProfile> m_profiles;
    mutable std::mutex m_mutex;
    bool m_learningPhase = true;
    
    // Minimum observations before profile is considered stable
    static constexpr uint32_t MIN_OBSERVATIONS = 10;
    
    // Anomaly scoring helpers
    double CalculateDllAnomaly(const ProcessProfile& profile, 
                               const std::set<std::wstring>& currentDlls) const;
    double CalculatePortAnomaly(const ProcessProfile& profile, 
                                const std::vector<uint16_t>& currentPorts) const;
    double CalculateChildAnomaly(const ProcessProfile& profile, 
                                 const std::wstring& child) const;
    double CalculateParentAnomaly(const ProcessProfile& profile,
                                  const std::wstring& parent) const;
    double CalculateMemoryAnomaly(const ProcessProfile& profile, 
                                  double currentMemory) const;
    double CalculateIntegrityAnomaly(const ProcessProfile& profile,
                                     const std::wstring& integrity) const;
    
    // Normalization helpers
    std::wstring NormalizeImageName(const std::wstring& image) const;
    std::set<std::wstring> ExtractCommandTokens(const std::wstring& cmdLine) const;
};

} // namespace XDR
