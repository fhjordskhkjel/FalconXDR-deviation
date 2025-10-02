#pragma once

#include <windows.h>
#include <iphlpapi.h>
#pragma comment(lib,"iphlpapi.lib")
#include <thread>
#include <atomic>
#include <unordered_set>
#include <cstdint>

namespace XDR {

struct NetConnKey { DWORD pid; DWORD raddr; uint16_t rport; DWORD laddr; uint16_t lport; bool operator==(const NetConnKey& o) const noexcept { return pid==o.pid && raddr==o.raddr && rport==o.rport && laddr==o.laddr && lport==o.lport; } };
struct NetConnKeyHash { size_t operator()(const NetConnKey& k) const noexcept { size_t h=std::hash<DWORD>{}(k.pid); h^=std::hash<DWORD>{}(k.raddr)+0x9e3779b9+(h<<6)+(h>>2); h^=std::hash<uint16_t>{}(k.rport)+0x9e3779b9+(h<<6)+(h>>2); return h; } };

class NetworkMonitor { public: void Start(HWND hwnd); void Stop(); private: void loop(); std::thread th; std::atomic_bool running{false}; HWND hwnd{}; std::unordered_set<NetConnKey,NetConnKeyHash> known; };

} // namespace XDR
