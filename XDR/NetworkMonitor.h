#pragma once

#include <windows.h>
#include <iphlpapi.h>
#pragma comment(lib,"iphlpapi.lib")
#include <thread>
#include <atomic>
#include <unordered_set>
#include <unordered_map>
#include <deque>
#include <set>
#include <cstdint>
#include <chrono>

namespace XDR {

struct NetConnKey { DWORD pid; DWORD raddr; uint16_t rport; DWORD laddr; uint16_t lport; bool operator==(const NetConnKey& o) const noexcept { return pid==o.pid && raddr==o.raddr && rport==o.rport && laddr==o.laddr && lport==o.lport; } };
struct NetConnKeyHash { size_t operator()(const NetConnKey& k) const noexcept { size_t h=std::hash<DWORD>{}(k.pid); h^=std::hash<DWORD>{}(k.raddr)+0x9e3779b9+(h<<6)+(h>>2); h^=std::hash<uint16_t>{}(k.rport)+0x9e3779b9+(h<<6)+(h>>2); return h; } };

struct BeaconKey { DWORD pid; DWORD raddr; uint16_t rport; bool operator==(const BeaconKey& o) const noexcept { return pid==o.pid && raddr==o.raddr && rport==o.rport; } };
struct BeaconKeyHash { size_t operator()(const BeaconKey& k) const noexcept { size_t h=std::hash<DWORD>{}(k.pid); h^=std::hash<DWORD>{}(k.raddr)+0x9e3779b9+(h<<6)+(h>>2); h^=std::hash<uint16_t>{}(k.rport)+0x9e3779b9+(h<<6)+(h>>2); return h; } };

class NetworkMonitor {
public:
    void Start(HWND hwnd);
    void Stop();
private:
    void loop();
    // advanced detections helpers/state
    using clock = std::chrono::steady_clock;
    void onNewConnection(const NetConnKey& key, const std::wstring& image);
    void checkBeaconing(const BeaconKey& bk, const std::wstring& image, clock::time_point now);
    void checkDnsHeuristics(const NetConnKey& key, const std::wstring& image, clock::time_point now);
    void checkIntel(const NetConnKey& key, const std::wstring& image);
    void checkFastFluxHeuristic(const NetConnKey& key, const std::wstring& image, clock::time_point now);
    struct Cidr { uint32_t net; uint32_t mask; };
    void loadIntel();
    bool inList(uint32_t ipHost, const std::vector<Cidr>& list) const;

    std::thread th; std::atomic_bool running{false}; HWND hwnd{};
    std::unordered_set<NetConnKey,NetConnKeyHash> known;
    // state
    std::unordered_map<BeaconKey,std::deque<clock::time_point>,BeaconKeyHash> beaconTimes;
    std::unordered_map<BeaconKey,clock::time_point,BeaconKeyHash> lastBeaconAlert;
    std::unordered_map<DWORD,std::deque<clock::time_point>> dnsTcpConnectTimes; // per pid
    std::unordered_map<DWORD,std::unordered_map<uint16_t,std::pair<std::set<DWORD>,std::deque<std::pair<DWORD,clock::time_point>>>> > distinctIpPerPort; // pid -> port -> (ip set, deque of (ip,time))
    // intel feeds
    std::vector<Cidr> torList; std::vector<Cidr> i2pList; std::vector<Cidr> c2List;
    bool intelLoaded=false;
};

} // namespace XDR
