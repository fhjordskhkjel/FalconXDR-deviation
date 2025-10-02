#pragma once
#include <cstdint>
#include <chrono>

namespace XDR::Config {
    // Polling intervals
    inline constexpr int ProcessPollSleepMs    = 200;   // inner loop sleep
    inline constexpr int ProcessPollCycles     = 10;    // cycles * sleep = scan cadence (2s)
    inline constexpr int NetworkPollSleepMs    = 200;   // inner loop sleep
    inline constexpr int NetworkPollCycles     = 25;    // 5s cadence

    // Throughput / flood guards
    inline constexpr uint32_t MaxProcessStartEventsPerSecond = 150; // cap burst
    inline constexpr uint32_t MaxProcessStopEventsPerSecond  = 150;
    inline constexpr uint32_t MaxNewNetConnPerScan           = 500; // per network scan iteration

    // Rarity & anomaly thresholds (placeholders for future rule engine)
    inline constexpr uint32_t RarePortMinGlobalCount    = 3;  // first N times considered rare
    inline constexpr double   EntropyLowThreshold       = 4.5; // section entropy too low
    inline constexpr double   EntropyHighThreshold      = 7.5; // section entropy too high
    inline constexpr uint32_t HollowingSizeDeltaBytes   = 64 * 1024; // size mismatch threshold
    inline constexpr uint32_t NetCorrelationWindowSec   = 5;  // process start to first net conn

    // Persistence scan intervals
    inline constexpr std::chrono::seconds AutorunScanInterval { 60 }; // future use
    inline constexpr std::chrono::seconds ServiceScanInterval { 120 };
    inline constexpr std::chrono::seconds TaskScanInterval    { 120 };

    // UI / logging guards
    inline constexpr uint32_t SuppressionLogEveryN = 500; // re-log suppression every N suppressed events
}
