#include "framework.h"
#include "NetworkMonitor.h"
#include "Utilities.h"
#include "Storage.h"
#include <unordered_set>
#include <format>
#include <chrono>
#include <sstream>

#define WM_XDR_EVENT (WM_APP + 1)
#define WM_XDR_ALERT (WM_APP + 2)

namespace XDR {
extern std::atomic_bool g_collect;

static const uint16_t kSuspiciousPorts[] = {4444,3389,5985};
static constexpr size_t kSuspiciousPortCount = sizeof(kSuspiciousPorts)/sizeof(kSuspiciousPorts[0]);

static void StoreNetConn(DWORD pid,const std::wstring& d){ Event ev; ev.category=EventCategory::Network; ev.type=EventType::NetConnNew; ev.pid=pid; ev.details=d; Storage::Insert(ev);} 
static void StoreAlertPort(DWORD pid,uint16_t port){ Event ev; ev.category=EventCategory::Alert; ev.type=EventType::AlertSuspiciousRemotePort; ev.pid=pid; ev.details=L"remote_port="+std::to_wstring(port); Storage::Insert(ev);} 
static void StoreAlert(DWORD pid, EventType t, const std::wstring& details){ Event ev; ev.category=EventCategory::Alert; ev.type=t; ev.pid=pid; ev.details=details; Storage::Insert(ev);} 

static inline uint16_t ConvPort(DWORD v){ return ntohs((u_short)v); }
static inline uint32_t HostIPv4(DWORD v){ return ntohl(v); }

void NetworkMonitor::Start(HWND h){ if(running.load()) return; hwnd=h; running=true; th=std::thread([this]{ loop(); }); }
void NetworkMonitor::Stop(){ running=false; if(th.joinable()) th.join(); }

void NetworkMonitor::loadIntel(){ if(intelLoaded) return; intelLoaded=true; // simple hard-coded minimal placeholder, expected to be loaded from file/URL in real-world
    // Example CIDRs (not real): 185.220.101.0/24 TOR, 204.17.56.0/24 I2P, sample C2 45.155.204.0/24
    torList.push_back({0xB9DC6500,0xFFFFFF00}); // 185.220.101.0/24 in network byte order? we use host order lists, fill using HostIPv4 later
    i2pList.push_back({0xCC113800,0xFFFFFF00}); // 204.17.56.0/24
    c2List.push_back({0x2D9BCC00,0xFFFFFF00}); // 45.155.204.0/24
}

bool NetworkMonitor::inList(uint32_t ipHost, const std::vector<Cidr>& list) const{ for(const auto& c:list){ if((ipHost & c.mask)==c.net) return true; } return false; }

void NetworkMonitor::checkIntel(const NetConnKey& key, const std::wstring& image){ loadIntel(); uint32_t hip=HostIPv4(key.raddr); if(inList(hip,torList)){ auto d=std::format(L"tor_hit pid={} image={} r={}:{}",key.pid,image,Utils::IPv4(key.raddr),key.rport); StoreAlert(key.pid,EventType::AlertTorI2P,d); Utils::PostLine(hwnd,WM_XDR_ALERT,std::format(L"[{}] ALERT TorI2P {}",Utils::TimeNow(),d)); }
    if(inList(hip,i2pList)){ auto d=std::format(L"i2p_hit pid={} image={} r={}:{}",key.pid,image,Utils::IPv4(key.raddr),key.rport); StoreAlert(key.pid,EventType::AlertTorI2P,d); Utils::PostLine(hwnd,WM_XDR_ALERT,std::format(L"[{}] ALERT TorI2P {}",Utils::TimeNow(),d)); }
    if(inList(hip,c2List)){ auto d=std::format(L"known_c2 pid={} image={} r={}:{}",key.pid,image,Utils::IPv4(key.raddr),key.rport); StoreAlert(key.pid,EventType::AlertKnownC2,d); Utils::PostLine(hwnd,WM_XDR_ALERT,std::format(L"[{}] ALERT KnownC2 {}",Utils::TimeNow(),d)); }
}

void NetworkMonitor::checkBeaconing(const BeaconKey& bk, const std::wstring& image, clock::time_point now){ auto &dq=beaconTimes[bk]; dq.push_back(now); while(!dq.empty() && (now - dq.front())>std::chrono::minutes(5)) dq.pop_front(); if(dq.size()<5) return; // need a handful
    // compute intervals
    std::vector<double> intervals; intervals.reserve(dq.size()-1); for(size_t i=1;i<dq.size();++i){ auto ms=std::chrono::duration_cast<std::chrono::milliseconds>(dq[i]-dq[i-1]).count(); intervals.push_back((double)ms); }
    // assess periodicity: coefficient of variation
    double mean=0; for(double v:intervals) mean+=v; mean/=intervals.size(); double var=0; for(double v:intervals){ double d=v-mean; var+=d*d; } var/=intervals.size(); double cv=(mean>0)? std::sqrt(var)/mean : 1.0; if(cv<0.15 && mean>15000){ // very regular >15s
        auto lastA=lastBeaconAlert[bk]; if(lastA.time_since_epoch().count()==0 || (now-lastA)>std::chrono::minutes(10)){ lastBeaconAlert[bk]=now; auto d=std::format(L"beacon pid={} image={} r={}:{} mean_ms={:.0f} cv={:.2f}",bk.pid,image,Utils::IPv4(bk.raddr),bk.rport,mean,cv); StoreAlert(bk.pid,EventType::AlertBeaconing,d); Utils::PostLine(hwnd,WM_XDR_ALERT,std::format(L"[{}] ALERT Beaconing {}",Utils::TimeNow(),d)); }
    }
}

void NetworkMonitor::checkDnsHeuristics(const NetConnKey& key, const std::wstring& image, clock::time_point now){ if(key.rport!=53 && key.lport!=53) return; auto &dq=dnsTcpConnectTimes[key.pid]; dq.push_back(now); while(!dq.empty() && (now - dq.front())>std::chrono::minutes(1)) dq.pop_front(); if(dq.size()>60){ auto d=std::format(L"dns_tunnel_freq pid={} image={} r={}:{} count={}",key.pid,image,Utils::IPv4(key.raddr),key.rport,dq.size()); StoreAlert(key.pid,EventType::AlertDNSTunneling,d); Utils::PostLine(hwnd,WM_XDR_ALERT,std::format(L"[{}] ALERT DNSTunneling {}",Utils::TimeNow(),d)); }
}

void NetworkMonitor::checkFastFluxHeuristic(const NetConnKey& key, const std::wstring& image, clock::time_point now){ // track distinct raddr per (pid,port) in 5 min
    auto &perPort = distinctIpPerPort[key.pid][key.rport]; auto &ipset=perPort.first; auto &dq=perPort.second; ipset.insert(key.raddr); dq.emplace_back(key.raddr,now); while(!dq.empty() && (now - dq.front().second)>std::chrono::minutes(5)){ // evict old
        // attempt cleanup: if raddr not present elsewhere in deque, remove from set
        DWORD old=dq.front().first; dq.pop_front(); bool present=false; for(auto &p:dq){ if(p.first==old){ present=true; break; } } if(!present) ipset.erase(old);
    }
    if(ipset.size()>=15){ auto d=std::format(L"fast_flux_like pid={} image={} port={} distinct_ips_5m={}",key.pid,image,key.rport,ipset.size()); StoreAlert(key.pid,EventType::AlertFastFluxDNS,d); Utils::PostLine(hwnd,WM_XDR_ALERT,std::format(L"[{}] ALERT FastFlux {}",Utils::TimeNow(),d)); }
}

void NetworkMonitor::onNewConnection(const NetConnKey& key, const std::wstring& image){ using clock=NetworkMonitor::clock; auto now=clock::now(); BeaconKey bk{key.pid,key.raddr,key.rport}; checkBeaconing(bk,image,now); checkDnsHeuristics(key,image,now); checkIntel(key,image); checkFastFluxHeuristic(key,image,now); }

void NetworkMonitor::loop(){ using namespace std::chrono_literals; while(running.load()){ if(!g_collect.load()){ std::this_thread::sleep_for(1s); continue; }
        PMIB_TCPTABLE_OWNER_PID table=nullptr; DWORD sz=0; DWORD res=GetExtendedTcpTable(nullptr,&sz,false,AF_INET,TCP_TABLE_OWNER_PID_ALL,0); if(res==ERROR_INSUFFICIENT_BUFFER){ table=(PMIB_TCPTABLE_OWNER_PID)malloc(sz); if(table){ if(GetExtendedTcpTable(table,&sz,false,AF_INET,TCP_TABLE_OWNER_PID_ALL,0)!=NO_ERROR){ free(table); table=nullptr; } } }
        std::unordered_set<NetConnKey,NetConnKeyHash> current;
        if(table){ for(DWORD i=0;i<table->dwNumEntries;++i){ auto &r=table->table[i]; if(r.dwState!=MIB_TCP_STATE_ESTAB) continue; NetConnKey key{ r.dwOwningPid, r.dwRemoteAddr, ConvPort(r.dwRemotePort), r.dwLocalAddr, ConvPort(r.dwLocalPort) }; current.insert(key); if(!known.contains(key)){ std::wstring img=Utils::GetProcName(key.pid); std::wstring details=std::format(L"pid={} image={} l={}:{} r={}:{}", key.pid,img,Utils::IPv4(key.laddr),key.lport,Utils::IPv4(key.raddr),key.rport); StoreNetConn(key.pid,details); Utils::PostLine(hwnd,WM_XDR_EVENT,std::format(L"[{}] NET NEW {}",Utils::TimeNow(),details)); for(size_t pi=0;pi<kSuspiciousPortCount;++pi){ uint16_t sp=kSuspiciousPorts[pi]; if(key.rport==sp){ StoreAlertPort(key.pid,key.rport); Utils::PostLine(hwnd,WM_XDR_ALERT,std::format(L"[{}] ALERT SuspiciousRemotePort pid={} port={} image={}",Utils::TimeNow(),key.pid,key.rport,img)); break; } } onNewConnection(key,img); } } }
        if(table) free(table); known.swap(current); for(int i=0;i<10 && running.load();++i) std::this_thread::sleep_for(200ms); } }

} // namespace XDR
