#pragma once
#include <string>
#include <cstdint>
#include <optional>
#include <chrono>
#include <vector>
#include <string_view>

// Basic unified event schema
namespace XDR
{
    enum class EventCategory : uint8_t { Process, Network, Alert, Screenshot };
    enum class EventType : uint8_t {
        ProcStart, ProcStop,
        NetConnNew,
        AlertSuspiciousProcess,
        AlertSuspiciousRemotePort,
        ScreenshotCaptured,
        AlertScreenshotCaptured,
        AlertProcessInjection,
        AlertReflectiveModule, // reflective loading detection
        AlertPrivilegedExec,     // new privileged execution / elevation alert
        AlertProcessHollowing,      // new
        AlertDllInjection,          // new
        AlertReflectiveMemory,      // new reflective loading (memory region)
        AlertYaraMatch,             // YARA on-demand match
        AlertProcEnumMismatch,       // process enumeration discrepancy (anti-evasion)
        // New types
        AlertUnsignedModule,          // unsigned / untrusted module load
        AlertSuspiciousExecRegion,    // anomalous executable private region
        AlertApiHook,                 // API hooking / prologue tamper
        AlertTokenManipulation,       // token steal/impersonation detected
        AlertCorrelation,             // correlated attack pattern detection
        // Network advanced detections
        AlertBeaconing,               // periodic beacons
        AlertDNSTunneling,            // suspected DNS tunneling activity
        AlertUnusualProtocol,         // uncommon protocol/port use
        AlertTorI2P,                  // Tor/I2P indicators
        AlertFastFluxDNS,             // fast-flux like pattern
        AlertKnownC2,                 // matched threat intel C2
        // Persistence / registry monitoring
        AlertAutorunChange,           // change in autorun (Run / RunOnce) entries
        AlertServicePersistence,      // new or modified service entry
        AlertPolicyModification,      // security / system policy registry value change
        AlertRegistryPersistence,     // generic registry-based persistence artifact
        // Process telemetry
        MemProtChange,                // memory protection change (timeline telemetry)
        MemRegionOrigin               // initial origin for a newly observed region
    };

    struct Event
    {
        uint64_t id{}; // database row id (0 if unknown)
        EventCategory category{};
        EventType     type{};
        std::chrono::system_clock::time_point ts{ std::chrono::system_clock::now() };
        uint32_t pid{};                 // optional meaning for network events (owning PID)
        std::wstring image;             // process image / context
        std::wstring details;           // free-form details (JSON-like or key=value list)
    };

    namespace Storage
    {
        void Init();
        void Shutdown();
        void Insert(const Event& ev);
        bool UsingSQLite();
        std::wstring BackendDescription();
        std::vector<Event> QueryRecent(std::size_t limit);
        std::vector<Event> QueryRecentFiltered(std::optional<EventCategory> category, std::wstring_view contains, std::size_t limit);
        std::vector<Event> QuerySinceFiltered(uint64_t lastId, std::optional<EventCategory> category, std::wstring_view contains, std::size_t limit);
        std::vector<Event> QueryRecentAdvanced(std::optional<EventCategory> category, std::wstring_view contains, std::optional<uint32_t> pid, std::size_t limit);
        std::vector<Event> QuerySinceAdvanced(uint64_t lastId, std::optional<EventCategory> category, std::wstring_view contains, std::optional<uint32_t> pid, std::size_t limit);
        // New: token based filters (each token must appear in details)
        std::vector<Event> QueryRecentAdvancedTokens(std::optional<EventCategory> category, std::wstring_view contains, std::optional<uint32_t> pid, const std::vector<std::wstring>& tokens, std::size_t limit);
        std::vector<Event> QuerySinceAdvancedTokens(uint64_t lastId, std::optional<EventCategory> category, std::wstring_view contains, std::optional<uint32_t> pid, const std::vector<std::wstring>& tokens, std::size_t limit);
    }
}
