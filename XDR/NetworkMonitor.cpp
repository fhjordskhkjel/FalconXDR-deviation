#include "framework.h"
#include "NetworkMonitor.h"
#include "Utilities.h"
#include "Storage.h"
#include <unordered_set>
#include <format>
#include <chrono>

#define WM_XDR_EVENT (WM_APP + 1)
#define WM_XDR_ALERT (WM_APP + 2)

namespace XDR {
extern std::atomic_bool g_collect;

static const uint16_t kSuspiciousPorts[] = {4444,3389,5985};
static constexpr size_t kSuspiciousPortCount = sizeof(kSuspiciousPorts)/sizeof(kSuspiciousPorts[0]);

static void StoreNetConn(DWORD pid,const std::wstring& d){ Event ev; ev.category=EventCategory::Network; ev.type=EventType::NetConnNew; ev.pid=pid; ev.details=d; Storage::Insert(ev);} 
static void StoreAlertPort(DWORD pid,uint16_t port){ Event ev; ev.category=EventCategory::Alert; ev.type=EventType::AlertSuspiciousRemotePort; ev.pid=pid; ev.details=L"remote_port="+std::to_wstring(port); Storage::Insert(ev);} 

static inline uint16_t ConvPort(DWORD v){ return ntohs((u_short)v); }

void NetworkMonitor::Start(HWND h){ if(running.load()) return; hwnd=h; running=true; th=std::thread([this]{ loop(); }); }
void NetworkMonitor::Stop(){ running=false; if(th.joinable()) th.join(); }

void NetworkMonitor::loop(){ using namespace std::chrono_literals; while(running.load()){ if(!g_collect.load()){ std::this_thread::sleep_for(1s); continue; }
        PMIB_TCPTABLE_OWNER_PID table=nullptr; DWORD sz=0; DWORD res=GetExtendedTcpTable(nullptr,&sz,false,AF_INET,TCP_TABLE_OWNER_PID_ALL,0); if(res==ERROR_INSUFFICIENT_BUFFER){ table=(PMIB_TCPTABLE_OWNER_PID)malloc(sz); if(table){ if(GetExtendedTcpTable(table,&sz,false,AF_INET,TCP_TABLE_OWNER_PID_ALL,0)!=NO_ERROR){ free(table); table=nullptr; } } }
        std::unordered_set<NetConnKey,NetConnKeyHash> current;
        if(table){ for(DWORD i=0;i<table->dwNumEntries;++i){ auto &r=table->table[i]; if(r.dwState!=MIB_TCP_STATE_ESTAB) continue; NetConnKey key{ r.dwOwningPid, r.dwRemoteAddr, ConvPort(r.dwRemotePort), r.dwLocalAddr, ConvPort(r.dwLocalPort) }; current.insert(key); if(!known.contains(key)){ std::wstring img=Utils::GetProcName(key.pid); std::wstring details=std::format(L"pid={} image={} l={}:{} r={}:{}", key.pid,img,Utils::IPv4(key.laddr),key.lport,Utils::IPv4(key.raddr),key.rport); StoreNetConn(key.pid,details); Utils::PostLine(hwnd,WM_XDR_EVENT,std::format(L"[{}] NET NEW {}",Utils::TimeNow(),details)); for(size_t pi=0;pi<kSuspiciousPortCount;++pi){ uint16_t sp=kSuspiciousPorts[pi]; if(key.rport==sp){ StoreAlertPort(key.pid,key.rport); Utils::PostLine(hwnd,WM_XDR_ALERT,std::format(L"[{}] ALERT SuspiciousRemotePort pid={} port={} image={}",Utils::TimeNow(),key.pid,key.rport,img)); break; } } } } }
        if(table) free(table); known.swap(current); for(int i=0;i<10 && running.load();++i) std::this_thread::sleep_for(200ms); } }

} // namespace XDR
