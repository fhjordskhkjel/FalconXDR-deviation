#include "PersistenceMonitor.h"
#include "BehavioralAnalyzer.h"
#include "Storage.h"
#include "Logger.h"
#include <windows.h>
#include <chrono>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <format>
#include <vector>

using namespace std::chrono;

namespace {
    struct AutorunState { std::unordered_set<std::wstring> entries; };
    struct ServiceInfo { uint64_t hash{}; };
    struct PolicyInfo { uint64_t hash{}; };

    static AutorunState g_autorun;
    static std::unordered_map<std::wstring,ServiceInfo> g_services; // name->hash
    static std::unordered_map<std::wstring,PolicyInfo> g_policies;  // path|value -> hash

    static steady_clock::time_point g_lastAutorunScan{};
    static steady_clock::time_point g_lastServiceScan{};
    static steady_clock::time_point g_lastPolicyScan{};

    static const seconds kAutorunInterval{60};
    static const seconds kServiceInterval{120};
    static const seconds kPolicyInterval{120};

    static uint64_t HashWide(const std::wstring& s){ uint64_t h=1469598103934665603ULL; for(auto c:s){ h^=(uint16_t)c; h*=1099511628211ULL; } return h; }

    static void Emit(HWND hwnd, XDR::EventType t, const std::wstring& det){
        XDR::Event ev; ev.category=XDR::EventCategory::Alert; ev.type=t; ev.details=det; XDR::Storage::Insert(ev);
        auto line=std::format(L"[{}] ALERT {} {}", (long long)duration_cast<seconds>(system_clock::now().time_since_epoch()).count(), (int)t, det);
        Logger::Write(line); auto* msg=new std::wstring(line); PostMessageW(hwnd,WM_APP+2,(WPARAM)msg,0);
    }

    static std::wstring RegReadSz(HKEY root,const std::wstring& path,const std::wstring& value){ HKEY h; if(RegOpenKeyExW(root,path.c_str(),0,KEY_READ,&h)!=ERROR_SUCCESS) return L""; wchar_t buf[1024]; DWORD type=0,sz=sizeof(buf); std::wstring out; if(RegQueryValueExW(h,value.c_str(),nullptr,&type,(LPBYTE)buf,&sz)==ERROR_SUCCESS && (type==REG_SZ||type==REG_EXPAND_SZ)) out.assign(buf); RegCloseKey(h); return out; }
    static DWORD RegReadDw(HKEY root,const std::wstring& path,const std::wstring& value,DWORD def=0xFFFFFFFF){ HKEY h; if(RegOpenKeyExW(root,path.c_str(),0,KEY_READ,&h)!=ERROR_SUCCESS) return def; DWORD type=0,val=def,sz=sizeof(val); if(RegQueryValueExW(h,value.c_str(),nullptr,&type,(LPBYTE)&val,&sz)!=ERROR_SUCCESS||type!=REG_DWORD) val=def; RegCloseKey(h); return val; }

    static void ScanAutoruns(HWND hwnd, const Behavioral::Settings& cfg){ if(!cfg.enableAutorunScan) return; auto now=steady_clock::now(); if(now - g_lastAutorunScan < kAutorunInterval) return; g_lastAutorunScan=now; const HKEY roots[]={HKEY_CURRENT_USER,HKEY_LOCAL_MACHINE}; const wchar_t* subs[]={L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"}; std::unordered_set<std::wstring> cur; for(auto r:roots){ for(auto s:subs){ HKEY h; if(RegOpenKeyExW(r,s,0,KEY_READ,&h)==ERROR_SUCCESS){ DWORD idx=0; wchar_t name[512]; DWORD n=512; while(true){ n=512; LONG rc=RegEnumValueW(h,idx,name,&n,nullptr,nullptr,nullptr,nullptr); if(rc!=ERROR_SUCCESS) break; cur.insert(name); ++idx; } RegCloseKey(h);} } } for(auto &e:cur){ if(!g_autorun.entries.contains(e)){ g_autorun.entries.insert(e); Emit(hwnd,XDR::EventType::AlertAutorunChange,std::format(L"autorun_add name={}",e)); } } for(auto it=g_autorun.entries.begin(); it!=g_autorun.entries.end();){ if(!cur.contains(*it)){ Emit(hwnd,XDR::EventType::AlertAutorunChange,std::format(L"autorun_del name={}",*it)); it=g_autorun.entries.erase(it);} else ++it; } }

    static void ScanServices(HWND hwnd, const Behavioral::Settings& cfg){ if(!cfg.enableServiceScan) return; auto now=steady_clock::now(); if(now - g_lastServiceScan < kServiceInterval) return; g_lastServiceScan=now; SC_HANDLE scm=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_ENUMERATE_SERVICE); if(!scm) return; DWORD bytes=0,cnt=0,resume=0; EnumServicesStatusExW(scm,SC_ENUM_PROCESS_INFO,SERVICE_WIN32,SERVICE_STATE_ALL,nullptr,0,&bytes,&cnt,&resume,nullptr); if(GetLastError()!=ERROR_MORE_DATA){ CloseServiceHandle(scm); return; } std::vector<BYTE> buf(bytes); if(!EnumServicesStatusExW(scm,SC_ENUM_PROCESS_INFO,SERVICE_WIN32,SERVICE_STATE_ALL,buf.data(),bytes,&bytes,&cnt,&resume,nullptr)){ CloseServiceHandle(scm); return; } auto arr=reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buf.data()); for(DWORD i=0;i<cnt;i++){ std::wstring name=arr[i].lpServiceName?arr[i].lpServiceName:L""; std::wstring key=L"System\\CurrentControlSet\\Services\\"+name; std::wstring img=RegReadSz(HKEY_LOCAL_MACHINE,key,L"ImagePath"); DWORD st=RegReadDw(HKEY_LOCAL_MACHINE,key,L"Start"); DWORD ty=RegReadDw(HKEY_LOCAL_MACHINE,key,L"Type"); uint64_t h=HashWide(img+L"|"+std::to_wstring(st)+L"|"+std::to_wstring(ty)); auto it=g_services.find(name); if(it==g_services.end()){ g_services.emplace(name,ServiceInfo{h}); Emit(hwnd,XDR::EventType::AlertServicePersistence,std::format(L"service_new name={} start={} type={} img={} ",name,st,ty,img)); } else if(it->second.hash!=h){ it->second.hash=h; Emit(hwnd,XDR::EventType::AlertServicePersistence,std::format(L"service_mod name={} start={} type={} img={} ",name,st,ty,img)); } } CloseServiceHandle(scm); }

    static void ScanPolicies(HWND hwnd, const Behavioral::Settings& cfg){ if(!cfg.enablePolicyScan) return; auto now=steady_clock::now(); if(now - g_lastPolicyScan < kPolicyInterval) return; g_lastPolicyScan=now; struct Item{ const wchar_t* path; const wchar_t* val; }; static const Item items[]={ {L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",L"EnableLUA"}, {L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",L"ConsentPromptBehaviorAdmin"} }; for(auto &it: items){ DWORD v=RegReadDw(HKEY_LOCAL_MACHINE,it.path,it.val); std::wstring key=std::wstring(it.path)+L"|"+it.val; uint64_t h=HashWide(std::to_wstring(v)); auto f=g_policies.find(key); if(f==g_policies.end()){ g_policies.emplace(key,PolicyInfo{h}); } else if(f->second.hash!=h){ f->second.hash=h; Emit(hwnd,XDR::EventType::AlertPolicyModification,std::format(L"policy_change path={} value={} new={} ",it.path,it.val,v)); } } }
}

namespace Behavioral {
    void PersistencePeriodic(HWND hwnd){
        auto cfg = GetSettings();
        ScanAutoruns(hwnd,cfg);
        ScanServices(hwnd,cfg);
        ScanPolicies(hwnd,cfg);
    }
}
