#include "BehavioralAnalyzer.h"
#include "Storage.h"
#include "Logger.h"
#include "MemoryAnalysis.h"
#include "YaraSupport.h"
#include "PersistenceMonitor.h" // added

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <wintrust.h>
#include <Softpub.h>
#include <sddl.h>
#include <chrono>
#include <thread>
#include <atomic>
#include <vector>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <queue>
#include <mutex>
#include <string>
#include <sstream>
#include <format>
#include <algorithm>
#include <cmath>
#include <iomanip>

#pragma comment(lib, "wintrust.lib")

using namespace std::chrono;

// ================= Settings =================
static Behavioral::Settings g_settings; // runtime configurable
namespace Behavioral { void SetSettings(const Settings& s){ g_settings=s; } Settings GetSettings(){ return g_settings; } }

// ================= NT decls =================
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif
#ifndef SystemHandleInformation
#define SystemHandleInformation 16
#endif
#ifndef ThreadQuerySetWin32StartAddress
#define ThreadQuerySetWin32StartAddress 9
#endif
#pragma pack(push,1)
struct SYSTEM_HANDLE_ENTRY { ULONG ProcessId; UCHAR ObjectTypeNumber; UCHAR Flags; USHORT Handle; PVOID Object; ACCESS_MASK GrantedAccess; };
struct SYSTEM_HANDLE_INFORMATION_WRAPPER { ULONG HandleCount; SYSTEM_HANDLE_ENTRY Handles[1]; };
#pragma pack(pop)
using NtQuerySystemInformation_t = NTSTATUS (NTAPI*)(ULONG,PVOID,ULONG,PULONG);
using NtQueryInformationThread_t = NTSTATUS (NTAPI*)(HANDLE,ULONG,PVOID,ULONG,PULONG);
static NtQuerySystemInformation_t pNtQuerySystemInformation=nullptr; static NtQueryInformationThread_t pNtQueryInformationThread=nullptr;

// ================= Helpers =================
static std::wstring lower(std::wstring s){ for(auto &c:s) c=(wchar_t)towlower(c); return s; }
static uint64_t Fnv1a64(const uint8_t* d,size_t n){ uint64_t h=1469598103934665603ULL; for(size_t i=0;i<n;i++){ h^=d[i]; h*=1099511628211ULL; } return h; }
static double Entropy(const uint8_t* d,size_t n){ if(n==0) return 0; uint32_t f[256]{}; for(size_t i=0;i<n;i++) ++f[d[i]]; double e=0; for(int i=0;i<256;i++){ if(f[i]){ double p=(double)f[i]/n; e -= p*std::log2(p); } } return e; }
static double InstructionDensity(const uint8_t* d,size_t n){ if(n==0) return 0; size_t inst=0; for(size_t i=0;i<n;i++){ switch(d[i]){ case 0x55:case 0x53:case 0x57:case 0x56:case 0x48:case 0x8B:case 0x89:case 0xE8:case 0xE9:case 0xFF:case 0x41:case 0x40:case 0xB8:case 0xB9:case 0xBA:case 0xEB: ++inst; default: break; } } return (double)inst/n; }
static bool IsWrite(DWORD p){ return p & (PAGE_READWRITE|PAGE_EXECUTE_READWRITE|PAGE_WRITECOPY|PAGE_EXECUTE_WRITECOPY); }
static bool IsExec(DWORD p){ return p & (PAGE_EXECUTE|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY); }
// unified helper for execute+write (any RWX style) check
static bool IsExecWrite(DWORD p){ return IsExec(p) && IsWrite(p); }
static std::wstring ProtToString(DWORD p){ switch(p){ case PAGE_EXECUTE: return L"X"; case PAGE_EXECUTE_READ: return L"RX"; case PAGE_EXECUTE_READWRITE: return L"RWX"; case PAGE_EXECUTE_WRITECOPY: return L"WCX"; case PAGE_READONLY: return L"R"; case PAGE_READWRITE: return L"RW"; case PAGE_WRITECOPY: return L"WC"; case PAGE_NOACCESS: return L"NA"; default: return L"?"; } }

// ================= Alert rate limiting =================
struct AlertKey { DWORD pid; XDR::EventType type; uintptr_t base; bool operator==(const AlertKey&o)const noexcept{ return pid==o.pid && type==o.type && base==o.base; } }; struct AlertKeyHash { size_t operator()(const AlertKey&k)const noexcept{ size_t h=std::hash<DWORD>{}(k.pid); h^=(size_t)k.type+0x9e37+(h<<6)+(h>>2); h^=std::hash<uintptr_t>{}(k.base)+0x9e37+(h<<6)+(h>>2); return h;} }; static std::unordered_map<AlertKey,steady_clock::time_point,AlertKeyHash> g_alertCache; static const auto kAlertTTL=seconds(30); static bool AlertAllowed(DWORD pid,XDR::EventType t,uintptr_t base){ auto now=steady_clock::now(); AlertKey k{pid,t,base}; auto it=g_alertCache.find(k); if(it!=g_alertCache.end()){ if(now-it->second<kAlertTTL) return false; it->second=now; return true;} g_alertCache.emplace(k,now); return true;} static void PruneAlerts(){ auto now=steady_clock::now(); for(auto it=g_alertCache.begin(); it!=g_alertCache.end();){ if(now-it->second>kAlertTTL) it=g_alertCache.erase(it); else ++it; } }

// ================= Process tracking =================
struct ProcInfo { DWORD pid; std::wstring image; steady_clock::time_point start; DWORD parentPid{}; std::wstring integrity; std::wstring parentIntegrity; bool seDebug=false; bool adminGroup=false; bool privAlerted=false; bool followPriv=false; bool injAlerted=false; bool hollowAlerted=false; bool reflMemAlerted=false; bool checkedModules=false; bool hasDbgHelp=false; bool hasComSvcs=false; bool hasLsass=false; std::wstring lastIntegrityDyn; std::set<std::wstring> privSnapshot; std::unordered_map<uintptr_t,DWORD> lastProt; std::unordered_set<DWORD> knownThreads; std::vector<std::pair<uintptr_t,uintptr_t>> moduleRanges; steady_clock::time_point lastModEnum{}; steady_clock::time_point nextRegionScan{}; };
struct ProcExtra { std::unordered_set<std::wstring> unsignedMods; bool apiHooksChecked=false; std::unordered_set<uint64_t> suspiciousExecHashes; };
static std::unordered_map<DWORD,ProcInfo> g_procs; static std::unordered_map<DWORD,ProcExtra> g_extra; static steady_clock::time_point g_lastSweep{steady_clock::now()};

// ================= YARA queue (fairness) =================
struct YaraTask { DWORD pid; uintptr_t base; size_t size; std::wstring ctx; uint32_t prio; uint64_t tick; };
static std::mutex g_yaraM; static std::vector<YaraTask> g_yaraTasks; static std::atomic_bool g_yaraRun{false}; static std::thread g_yaraThread; static uint64_t g_yaraByteWindow=0; struct YWin{ steady_clock::time_point ts; size_t bytes; }; static std::deque<YWin> g_yWin; static const size_t kYaraBytesMin=8*1024*1024; static void TrimYWin(){ auto now=steady_clock::now(); while(!g_yWin.empty() && (now-g_yWin.front().ts)>minutes(1)){ g_yaraByteWindow-=g_yWin.front().bytes; g_yWin.pop_front(); } }
static void EnqueueYara(DWORD pid, uintptr_t base,size_t size,const std::wstring& ctx){ if(!g_settings.enableYaraRegionScan) return; size=std::min<size_t>(size,g_settings.yaraMaxRegionSize); std::lock_guard lk(g_yaraM); if(g_yaraTasks.size()>512) return; g_yaraTasks.push_back({pid,base,size,ctx, (uint32_t)(size>256*1024?2:1), (uint64_t)GetTickCount64()}); }
static bool PopYara(YaraTask& out){ std::lock_guard lk(g_yaraM); if(g_yaraTasks.empty()) return false; auto it=std::max_element(g_yaraTasks.begin(),g_yaraTasks.end(),[](auto&a,auto&b){ if(a.prio==b.prio) return a.tick>b.tick; return a.prio<b.prio; }); out=*it; g_yaraTasks.erase(it); return true; }
static std::atomic<HWND> g_hwndNotify{nullptr};
static void YaraLoop(){
    while(g_yaraRun.load()){
        YaraTask t{};
        if(PopYara(t)){
            TrimYWin();
            if(g_yaraByteWindow + t.size > kYaraBytesMin){
                t.prio=1;
                std::lock_guard lk(g_yaraM);
                g_yaraTasks.push_back(t);
                std::this_thread::sleep_for(150ms);
                continue;
            }
            HANDLE hp=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,FALSE,t.pid);
            if(hp){
                std::vector<uint8_t> buf(t.size); SIZE_T br=0;
                ReadProcessMemory(hp,(LPCVOID)t.base,buf.data(),t.size,&br);
                CloseHandle(hp);
                if(br){
                    buf.resize(br); TrimYWin(); g_yaraByteWindow+=br; g_yWin.push_back({steady_clock::now(),br});
                    std::vector<std::wstring> matches; if(YaraSupport::ScanBuffer(buf.data(),buf.size(),matches)){
                        std::wstringstream ds; ds<<L"event=yara_region pid="<<t.pid<<L" base=0x"<<std::hex<<t.base<<L" size="<<std::dec<<br<<L" matches="; for(size_t i=0;i<matches.size();++i){ if(i) ds<<L";"; ds<<matches[i]; } ds<<L" ctx="<<t.ctx; std::wstring pname=L"<unknown>"; auto it=g_procs.find(t.pid); if(it!=g_procs.end()) pname=it->second.image; XDR::Event ev; ev.category=XDR::EventCategory::Alert; ev.type=XDR::EventType::AlertYaraMatch; ev.pid=t.pid; ev.image=pname; ev.details=ds.str(); XDR::Storage::Insert(ev); auto line=std::format(L"[{}] ALERT YaraMatch pid={} name={} {}", (long long)duration_cast<seconds>(system_clock::now().time_since_epoch()).count(), t.pid, pname, ds.str()); Logger::Write(line); auto* p=new std::wstring(line); PostMessageW(g_hwndNotify.load(),WM_APP+2,(WPARAM)p,0); }
                }
            }
        } else {
            std::this_thread::sleep_for(120ms);
        }
    }
}

// ================= Integrity / privileges =================
static std::wstring IntegrityLevel(HANDLE h){ HANDLE tok{}; if(!OpenProcessToken(h,TOKEN_QUERY,&tok)) return L"unknown"; DWORD len=0; GetTokenInformation(tok,TokenIntegrityLevel,nullptr,0,&len); std::wstring level=L"unknown"; if(GetLastError()==ERROR_INSUFFICIENT_BUFFER){ auto buf=std::unique_ptr<BYTE[]>(new BYTE[len]); if(GetTokenInformation(tok,TokenIntegrityLevel,buf.get(),len,&len)){ auto til=reinterpret_cast<TOKEN_MANDATORY_LABEL*>(buf.get()); DWORD rid=*GetSidSubAuthority(til->Label.Sid,(DWORD)(*GetSidSubAuthorityCount(til->Label.Sid)-1)); if(rid>=SECURITY_MANDATORY_SYSTEM_RID) level=L"System"; else if(rid>=SECURITY_MANDATORY_HIGH_RID) level=L"High"; else if(rid>=SECURITY_MANDATORY_MEDIUM_RID) level=L"Medium"; else level=L"Low"; }} CloseHandle(tok); return level; }
static bool HasSeDebug(HANDLE h){ HANDLE tok{}; if(!OpenProcessToken(h,TOKEN_QUERY,&tok)) return false; DWORD len=0; GetTokenInformation(tok,TokenPrivileges,nullptr,0,&len); bool found=false; if(GetLastError()==ERROR_INSUFFICIENT_BUFFER){ auto buf=std::unique_ptr<BYTE[]>(new BYTE[len]); if(GetTokenInformation(tok,TokenPrivileges,buf.get(),len,&len)){ auto tp=reinterpret_cast<TOKEN_PRIVILEGES*>(buf.get()); LUID luid; if(LookupPrivilegeValue(nullptr,SE_DEBUG_NAME,&luid)){ for(DWORD i=0;i<tp->PrivilegeCount;i++){ if(tp->Privileges[i].Luid.LowPart==luid.LowPart && (tp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED)){ found=true; break; } } } } } CloseHandle(tok); return found; }
static bool IsAdminGroup(HANDLE h){ bool admin=false; HANDLE tok{}; if(!OpenProcessToken(h,TOKEN_QUERY,&tok)) return false; BYTE buf[4096]; DWORD len=0; if(GetTokenInformation(tok,TokenGroups,buf,sizeof(buf),&len)){ auto groups=(TOKEN_GROUPS*)buf; SID_IDENTIFIER_AUTHORITY NtAuth=SECURITY_NT_AUTHORITY; PSID adminSid=nullptr; if(AllocateAndInitializeSid(&NtAuth,2,SECURITY_BUILTIN_DOMAIN_RID,DOMAIN_ALIAS_RID_ADMINS,0,0,0,0,0,0,&adminSid)){ for(DWORD i=0;i<groups->GroupCount;i++){ if(EqualSid(adminSid,groups->Groups[i].Sid) && (groups->Groups[i].Attributes & SE_GROUP_ENABLED)){ admin=true; break; } } FreeSid(adminSid);} } CloseHandle(tok); return admin; }
static std::set<std::wstring> GetEnabledPrivs(HANDLE h){ std::set<std::wstring> out; HANDLE tok{}; if(!OpenProcessToken(h,TOKEN_QUERY,&tok)) return out; DWORD len=0; GetTokenInformation(tok,TokenPrivileges,nullptr,0,&len); if(GetLastError()==ERROR_INSUFFICIENT_BUFFER){ auto buf=std::unique_ptr<BYTE[]>(new BYTE[len]); if(GetTokenInformation(tok,TokenPrivileges,buf.get(),len,&len)){ auto tp=reinterpret_cast<TOKEN_PRIVILEGES*>(buf.get()); wchar_t name[128]; DWORD nlen; for(DWORD i=0;i<tp->PrivilegeCount;i++){ if(tp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED){ nlen=128; if(LookupPrivilegeNameW(nullptr,&tp->Privileges[i].Luid,name,&nlen)) out.insert(name); } } } } CloseHandle(tok); return out; }
static const std::set<std::wstring> kHighRiskPrivs={L"SeDebugPrivilege",L"SeTcbPrivilege",L"SeBackupPrivilege",L"SeRestorePrivilege",L"SeImpersonatePrivilege",L"SeLoadDriverPrivilege",L"SeTakeOwnershipPrivilege"};
static DWORD ParentPid(DWORD pid){ DWORD ppid=0; HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0); if(snap==INVALID_HANDLE_VALUE) return 0; PROCESSENTRY32W pe{sizeof(pe)}; if(Process32FirstW(snap,&pe)){ do{ if(pe.th32ProcessID==pid){ ppid=pe.th32ParentProcessID; break;} } while(Process32NextW(snap,&pe)); } CloseHandle(snap); return ppid; }

// ================= Module enumeration cache =================
static void RefreshModuleRanges(ProcInfo& pi){ auto now=steady_clock::now(); if(now - pi.lastModEnum < seconds(10)) return; pi.moduleRanges.clear(); HANDLE h=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,FALSE,pi.pid); if(!h) return; HMODULE mods[512]; DWORD need=0; if(EnumProcessModules(h,mods,sizeof(mods),&need)){ size_t cnt=need/sizeof(HMODULE); for(size_t i=0;i<cnt;i++){ MODULEINFO mi{}; if(GetModuleInformation(h,mods[i],&mi,sizeof(mi))){ uintptr_t b=(uintptr_t)mods[i]; pi.moduleRanges.emplace_back(b,b+mi.SizeOfImage); } } } CloseHandle(h); pi.lastModEnum=steady_clock::now(); }
static bool AddrInModules(const ProcInfo& pi, uintptr_t a){ for(auto &r:pi.moduleRanges) if(a>=r.first && a<r.second) return true; return false; }
static bool EnumHas(HANDLE h,const std::wstring& n){ HMODULE mods[512]; DWORD need=0; if(!EnumProcessModules(h,mods,sizeof(mods),&need)) return false; size_t cnt=need/sizeof(HMODULE); wchar_t path[MAX_PATH]; auto needle=lower(n); for(size_t i=0;i<cnt;i++){ if(GetModuleFileNameExW(h,mods[i],path,MAX_PATH)){ std::wstring p=lower(path); if(p.find(needle)!=std::wstring::npos) return true; } } return false; }

// ================= Unsigned module (with signature cache) =================
static std::mutex g_sigCacheMutex; static std::unordered_map<std::wstring,bool> g_sigCache; 
static bool IsModuleSigned(const std::wstring& path){
    if(path.empty()) return false;
    std::wstring norm=lower(path);
    {
        std::scoped_lock lk(g_sigCacheMutex);
        auto it=g_sigCache.find(norm);
        if(it!=g_sigCache.end()) return it->second;
    }
    WINTRUST_FILE_INFO fi{sizeof(fi)}; fi.pcwszFilePath=path.c_str();
    GUID action=WINTRUST_ACTION_GENERIC_VERIFY_V2; WINTRUST_DATA wd{sizeof(wd)}; wd.dwUIChoice=WTD_UI_NONE; wd.fdwRevocationChecks=WTD_REVOKE_NONE; wd.dwUnionChoice=WTD_CHOICE_FILE; wd.pFile=&fi; wd.dwStateAction=WTD_STATEACTION_IGNORE; wd.dwProvFlags=WTD_SAFER_FLAG|WTD_HASH_ONLY_FLAG; 
    bool ok = WinVerifyTrust(nullptr,&action,&wd)==ERROR_SUCCESS; 
    {
        std::scoped_lock lk(g_sigCacheMutex);
        g_sigCache.emplace(norm,ok);
    }
    return ok; }
static void CheckUnsignedModules(HWND hwnd, ProcInfo& pi){ if(pi.checkedModules) return; if(!g_settings.enableUnsignedModuleAlert) { pi.checkedModules = true; return; } HANDLE h=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,FALSE,pi.pid); if(!h) return; auto &ex=g_extra[pi.pid]; HMODULE mods[512]; DWORD need=0; if(EnumProcessModules(h,mods,sizeof(mods),&need)){ size_t cnt=need/sizeof(HMODULE); wchar_t path[MAX_PATH]; for(size_t i=0;i<cnt;i++){ if(GetModuleFileNameExW(h,mods[i],path,MAX_PATH)){ std::wstring p=path; if(p.empty()||ex.unsignedMods.contains(p)) continue; if(!IsModuleSigned(p)){ ex.unsignedMods.insert(p); if(AlertAllowed(pi.pid,XDR::EventType::AlertUnsignedModule,(uintptr_t)mods[i])){ auto line=std::format(L"[{}] ALERT UnsignedModule pid={} name={} module={} base=0x{}", (long long)duration_cast<seconds>(system_clock::now().time_since_epoch()).count(), pi.pid, pi.image, p,(uintptr_t)mods[i]); Logger::Write(line); XDR::Event ev; ev.category=XDR::EventCategory::Alert; ev.type=XDR::EventType::AlertUnsignedModule; ev.pid=pi.pid; ev.image=pi.image; ev.details=std::format(L"module={} base=0x{}",p,(uintptr_t)mods[i]); XDR::Storage::Insert(ev); auto* msg=new std::wstring(line); PostMessageW(hwnd,WM_APP+2,(WPARAM)msg,0); } } } } } CloseHandle(h); }

// ================= API hook heuristic (original logic, could be refactored to use IsExecWrite) =================
static bool SuspiciousPrologue(const uint8_t* b,size_t n){ if(n<5) return false; if(b[0]==0xE9||b[0]==0xE8||(b[0]==0xFF&&(b[1]==0x25||b[1]==0x15))) return true; if(b[0]==0x48 && b[1]==0xB8) return true; return false; }
static void CheckApiHooks(HWND hwnd, ProcInfo& pi){ if(!g_settings.enableApiHookScan) return; auto &ex=g_extra[pi.pid]; if(ex.apiHooksChecked) return; ex.apiHooksChecked=true; HMODULE ntdll=GetModuleHandleW(L"ntdll.dll"); if(!ntdll) return; HANDLE h=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,FALSE,pi.pid); if(!h) return; const char* apis[] = {"NtOpenProcess","NtWriteVirtualMemory","NtCreateThreadEx","NtAllocateVirtualMemory","NtProtectVirtualMemory"}; for(const char* a: apis){ FARPROC fp=GetProcAddress(ntdll,a); if(!fp) continue; uint8_t buf[32]{}; SIZE_T br=0; if(!ReadProcessMemory(h,fp,buf,sizeof(buf),&br) || br<5) continue; if(!SuspiciousPrologue(buf,br)) continue; if(!AlertAllowed(pi.pid,XDR::EventType::AlertApiHook,(uintptr_t)fp)) continue; std::wstringstream bhex; size_t show=std::min<SIZE_T>(br,16); for(size_t i=0;i<show;i++){ if(i) bhex<<L" "; bhex<<std::hex<<std::uppercase<<std::setw(2)<<std::setfill(L'0')<<(int)buf[i]; } std::wstring apiName; apiName.assign(a,a+strlen(a)); std::wstring disasm=L"unknown"; uintptr_t target=0; bool haveTarget=false; if(buf[0]==0xE9 && br>=5){ int32_t rel=*reinterpret_cast<const int32_t*>(buf+1); target=(uintptr_t)fp+5+rel; disasm=std::format(L"jmp 0x{:X}",target); haveTarget=true; } else if(buf[0]==0xE8 && br>=5){ int32_t rel=*reinterpret_cast<const int32_t*>(buf+1); target=(uintptr_t)fp+5+rel; disasm=std::format(L"call 0x{:X}",target); haveTarget=true; } else if(buf[0]==0xFF && buf[1]==0x25 && br>=6){ int32_t rel=*reinterpret_cast<const int32_t*>(buf+2); uintptr_t rip=(uintptr_t)fp+6; uintptr_t ptrAddr=rip+rel; uintptr_t ptrValue=0; SIZE_T tr=0; if(ReadProcessMemory(h,(LPCVOID)ptrAddr,&ptrValue,sizeof(ptrValue),&tr) && tr==sizeof(ptrValue) && ptrValue){ target=ptrValue; haveTarget=true; disasm=std::format(L"jmp [rip+0x{:X}] -> 0x{:X}",ptrAddr-rip,target); } else disasm=std::format(L"jmp [rip+0x{:X}]",ptrAddr-rip); } else if(buf[0]==0x48 && buf[1]==0xB8 && br>=12){ uint64_t imm=*reinterpret_cast<const uint64_t*>(buf+2); if(br>=12 && buf[10]==0xFF && buf[11]==0xE0){ target=(uintptr_t)imm; disasm=std::format(L"mov rax,0x{:X}; jmp rax",target); haveTarget=true; } else disasm=std::format(L"mov rax,0x{:X}",(uint64_t)imm); } bool rwxTarget=false; std::wstring tgtProt=L"?"; if(haveTarget){ MEMORY_BASIC_INFORMATION mbi{}; if(VirtualQueryEx(h,(LPCVOID)target,&mbi,sizeof(mbi))==sizeof(mbi)){ DWORD p=mbi.Protect; bool exec=(p & (PAGE_EXECUTE|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY))!=0; bool write=(p & (PAGE_READWRITE|PAGE_EXECUTE_READWRITE|PAGE_WRITECOPY|PAGE_EXECUTE_WRITECOPY))!=0; if(exec && write) rwxTarget=true; switch(p){ case PAGE_EXECUTE: tgtProt=L"X"; break; case PAGE_EXECUTE_READ: tgtProt=L"RX"; break; case PAGE_EXECUTE_READWRITE: tgtProt=L"RWX"; break; case PAGE_EXECUTE_WRITECOPY: tgtProt=L"WCX"; break; case PAGE_READONLY: tgtProt=L"R"; break; case PAGE_READWRITE: tgtProt=L"RW"; break; case PAGE_WRITECOPY: tgtProt=L"WC"; break; case PAGE_NOACCESS: tgtProt=L"NA"; break; default: tgtProt=L"?"; break; } } } const wchar_t* label = rwxTarget? L"ApiHookSuspicious" : L"ApiHook"; auto line=std::format(L"[{}] ALERT {} pid={} name={} api={} addr=0x{:X} bytes={} {}{}", (long long)duration_cast<seconds>(system_clock::now().time_since_epoch()).count(), label, pi.pid, pi.image, apiName,(uintptr_t)fp,bhex.str(),disasm, rwxTarget?L" (RWX target)":L""); Logger::Write(line); XDR::Event ev; ev.category=XDR::EventCategory::Alert; ev.type=XDR::EventType::AlertApiHook; ev.pid=pi.pid; ev.image=pi.image; ev.details=std::format(L"api={} addr=0x{:X} bytes={} disasm={} target=0x{:X} targetProt={} rwxTarget={}",apiName,(uintptr_t)fp,bhex.str(),disasm,haveTarget?target:0,tgtProt,rwxTarget?1:0); XDR::Storage::Insert(ev); auto* msg=new std::wstring(line); PostMessageW(hwnd,WM_APP+2,(WPARAM)msg,0); } CloseHandle(h); }

// ================= Suspicious exec region classifier =================
static void ClassifyExecRegions(HWND hwnd, ProcInfo& pi){ if(!g_settings.enableExecRegionClassifier) return; HANDLE h=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,FALSE,pi.pid); if(!h) return; auto &ex=g_extra[pi.pid]; MEMORY_BASIC_INFORMATION mbi; unsigned char* addr=nullptr; int scanned=0; while(VirtualQueryEx(h,addr,&mbi,sizeof(mbi))==sizeof(mbi)){ if(mbi.State==MEM_COMMIT && mbi.Type==MEM_PRIVATE && IsExec(mbi.Protect) && !IsWrite(mbi.Protect) && mbi.RegionSize>=0x800){ size_t sample=std::min<SIZE_T>(mbi.RegionSize,4096); std::vector<uint8_t> buf(sample); SIZE_T br=0; if(ReadProcessMemory(h,addr,buf.data(),sample,&br) && br>512){ double ent=Entropy(buf.data(),br); double dens=InstructionDensity(buf.data(),br); uint64_t hsh=Fnv1a64(buf.data(),std::min<size_t>(br,256)); if(!ex.suspiciousExecHashes.contains(hsh) && (ent>7.2 || dens<0.03 || dens>0.6)){ ex.suspiciousExecHashes.insert(hsh); if(AlertAllowed(pi.pid,XDR::EventType::AlertSuspiciousExecRegion,(uintptr_t)addr)){ std::wstringstream ds; ds<<L"event=susp_exec base=0x"<<std::hex<<(uintptr_t)addr<<L" size="<<std::dec<<mbi.RegionSize<<L" ent="<<std::fixed<<std::setprecision(2)<<ent<<L" dens="<<dens<<L" hash=0x"<<std::hex<<hsh; auto line=std::format(L"[{}] ALERT SuspiciousExecRegion pid={} name={} base=0x{} size={} ent={:.2f} dens={:.2f}", (long long)duration_cast<seconds>(system_clock::now().time_since_epoch()).count(), pi.pid, pi.image,(uintptr_t)addr,(SIZE_T)mbi.RegionSize,ent,dens); Logger::Write(line); XDR::Event ev; ev.category=XDR::EventCategory::Alert; ev.type=XDR::EventType::AlertSuspiciousExecRegion; ev.pid=pi.pid; ev.image=pi.image; ev.details=ds.str(); XDR::Storage::Insert(ev); auto* msg=new std::wstring(line); PostMessageW(hwnd,WM_APP+2,(WPARAM)msg,0); EnqueueYara(pi.pid,(uintptr_t)addr,std::min<size_t>(mbi.RegionSize,g_settings.yaraMaxRegionSize),L"susp_exec"); } } } }
        addr += mbi.RegionSize; if(++scanned>4096) break; }
    CloseHandle(h); }

// ================= Injection scan (legacy heuristic) =================
struct InjectionScanResult { bool suspicious=false; int execRegions=0; int writableExecRegions=0; int privateExecRegions=0; SIZE_T execBytes=0; SIZE_T writableExecBytes=0; std::wstring sample; };
static InjectionScanResult ScanForInjectionVerbose(DWORD pid){ InjectionScanResult r; HANDLE h=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,FALSE,pid); if(!h) return r; MEMORY_BASIC_INFORMATION mbi; unsigned char* addr=nullptr; int scanned=0; while(VirtualQueryEx(h,addr,&mbi,sizeof(mbi))==sizeof(mbi)){ if(mbi.State==MEM_COMMIT){ bool exec=(mbi.Protect & (PAGE_EXECUTE|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY))!=0; bool we=(mbi.Protect & PAGE_EXECUTE_READWRITE)!=0; if(exec){ ++r.execRegions; r.execBytes+=mbi.RegionSize; if(we){ ++r.writableExecRegions; r.writableExecBytes+=mbi.RegionSize;} if(mbi.Type==MEM_PRIVATE) ++r.privateExecRegions; if(r.sample.empty()){ std::wstringstream ss; ss<<L"0x"<<std::hex<<(uintptr_t)addr<<L":"<<std::dec<<mbi.RegionSize<<L":"<<ProtToString(mbi.Protect); r.sample=ss.str(); } } } addr+=mbi.RegionSize; if((SIZE_T)addr==0) break; if(++scanned>4096) break; } CloseHandle(h); if(r.writableExecRegions>0 || r.privateExecRegions>0) r.suspicious=true; return r; }

// ================= PE quick reflective check =================
static void AnalyzePERegion(HWND hwnd,const ProcInfo& pi,HANDLE hp,uintptr_t base,SIZE_T size,DWORD type){ if(size<0x200 || type==MEM_IMAGE) return; BYTE hdr[256]; SIZE_T br=0; if(!ReadProcessMemory(hp,(LPCVOID)base,hdr,sizeof(hdr),&br)||br<64) return; if(hdr[0]!='M'||hdr[1]!='Z') return; if(AlertAllowed(pi.pid,XDR::EventType::AlertReflectiveModule,base)){ auto line=std::format(L"[{}] ALERT ReflectiveModule pid={} name={} base=0x{} size=0x{}", (long long)duration_cast<seconds>(system_clock::now().time_since_epoch()).count(), pi.pid, pi.image, base,size); Logger::Write(line); XDR::Event ev; ev.category=XDR::EventCategory::Alert; ev.type=XDR::EventType::AlertReflectiveModule; ev.pid=pi.pid; ev.image=pi.image; ev.details=std::format(L"base=0x{} size=0x{}",base,size); XDR::Storage::Insert(ev); auto* msg=new std::wstring(line); PostMessageW(hwnd,WM_APP+2,(WPARAM)msg,0); } }

// ================= LSASS handle scan =================
static DWORD g_lsassPid=0; static steady_clock::time_point g_lastLsass{}; static std::set<DWORD> g_lsassProcs; static DWORD ResolveLsass(){ if(g_lsassPid) return g_lsassPid; HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0); if(snap==INVALID_HANDLE_VALUE) return 0; PROCESSENTRY32W pe{sizeof(pe)}; if(Process32FirstW(snap,&pe)){ do{ if(_wcsicmp(pe.szExeFile,L"lsass.exe")==0){ g_lsassPid=pe.th32ProcessID; break;} } while(Process32NextW(snap,&pe)); } CloseHandle(snap); return g_lsassPid; }
static void ScanLsassHandles(){ auto now=steady_clock::now(); if(now - g_lastLsass < seconds(15)) return; g_lastLsass=now; g_lsassProcs.clear(); DWORD lsass=ResolveLsass(); if(!lsass) return; if(!pNtQuerySystemInformation){ HMODULE ntdll=GetModuleHandleW(L"ntdll.dll"); if(ntdll) pNtQuerySystemInformation=(NtQuerySystemInformation_t)GetProcAddress(ntdll,"NtQuerySystemInformation"); } if(!pNtQuerySystemInformation) return; ULONG len=0x20000; std::unique_ptr<BYTE[]> buf; NTSTATUS st; for(int i=0;i<7;i++){ buf.reset(new BYTE[len]); st=pNtQuerySystemInformation(SystemHandleInformation,buf.get(),len,&len); if(st==0) break; if(st==STATUS_INFO_LENGTH_MISMATCH){ len*=2; continue;} return; } if(!NT_SUCCESS(st)) return; auto info=reinterpret_cast<SYSTEM_HANDLE_INFORMATION_WRAPPER*>(buf.get()); HANDLE self=GetCurrentProcess(); for(ULONG i=0;i<info->HandleCount;i++){ auto &h=info->Handles[i]; if(h.ProcessId==GetCurrentProcessId()) continue; HANDLE src=OpenProcess(PROCESS_DUP_HANDLE|PROCESS_QUERY_LIMITED_INFORMATION,FALSE,h.ProcessId); if(!src) continue; HANDLE dup=nullptr; if(DuplicateHandle(src,(HANDLE)(uintptr_t)h.Handle,self,&dup,0,FALSE,DUPLICATE_SAME_ACCESS)){ if(GetProcessId(dup)==lsass){ if(h.GrantedAccess&(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ|PROCESS_VM_OPERATION)) g_lsassProcs.insert(h.ProcessId); } if(dup) CloseHandle(dup);} CloseHandle(src);} }

// ================= Remote threads =================
static steady_clock::time_point g_lastThreadScan{}; static const auto kThreadScanInterval=seconds(5); static void ScanThreads(HWND hwnd){ auto now=steady_clock::now(); if(!g_settings.enableThreadScan || (now - g_lastThreadScan < kThreadScanInterval)) return; g_lastThreadScan=now; if(!pNtQueryInformationThread){ HMODULE ntdll=GetModuleHandleW(L"ntdll.dll"); if(ntdll) pNtQueryInformationThread=(NtQueryInformationThread_t)GetProcAddress(ntdll,"NtQueryInformationThread"); }
    HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0); if(snap==INVALID_HANDLE_VALUE) return; THREADENTRY32 te{sizeof(te)}; if(!Thread32First(snap,&te)){ CloseHandle(snap); return; }
    do{ auto it=g_procs.find(te.th32OwnerProcessID); if(it==g_procs.end()) continue; auto &pi=it->second; if(pi.knownThreads.insert(te.th32ThreadID).second){ auto age=duration_cast<seconds>(now - pi.start).count(); if(age<2) continue; RefreshModuleRanges(pi); PVOID startAddr=nullptr; if(pNtQueryInformationThread){ HANDLE th=OpenThread(THREAD_QUERY_INFORMATION,FALSE,te.th32ThreadID); if(th){ pNtQueryInformationThread(th,ThreadQuerySetWin32StartAddress,&startAddr,sizeof(startAddr),nullptr); CloseHandle(th);} } uintptr_t start=(uintptr_t)startAddr; if(start && !AddrInModules(pi,start)){ HANDLE hp=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,FALSE,pi.pid); if(hp){ MEMORY_BASIC_INFORMATION mbi{}; if(VirtualQueryEx(hp,(LPCVOID)start,&mbi,sizeof(mbi))==sizeof(mbi)){ bool susp=(mbi.State==MEM_COMMIT)&&IsExec(mbi.Protect)&&(mbi.Type!=MEM_IMAGE)&&(IsWrite(mbi.Protect)||mbi.Type==MEM_PRIVATE); if(susp){ BYTE sample[128]; SIZE_T br=0; ReadProcessMemory(hp,mbi.BaseAddress,sample,sizeof(sample),&br); uint64_t h=Fnv1a64(sample,std::min<SIZE_T>(br,64)); double ent=Entropy(sample,std::min<SIZE_T>(br,128)); if(AlertAllowed(pi.pid,XDR::EventType::AlertProcessInjection,0)){ std::wstringstream ds; ds<<L"event=remote_thread start=0x"<<std::hex<<start<<L" base=0x"<<(uintptr_t)mbi.BaseAddress<<L" size="<<std::dec<<mbi.RegionSize<<L" prot="<<ProtToString(mbi.Protect)<<L" ent="<<std::fixed<<std::setprecision(2)<<ent<<L" hash=0x"<<std::hex<<h; XDR::Event ev; ev.category=XDR::EventCategory::Alert; ev.type=XDR::EventType::AlertProcessInjection; ev.pid=pi.pid; ev.image=pi.image; ev.details=ds.str(); XDR::Storage::Insert(ev); auto line=std::format(L"[{}] ALERT ProcessInjection pid={} name={} {}", (long long)duration_cast<seconds>(system_clock::now().time_since_epoch()).count(), pi.pid, pi.image, ds.str()); Logger::Write(line); auto* msg=new std::wstring(line); PostMessageW(hwnd,WM_APP+2,(WPARAM)msg,0); EnqueueYara(pi.pid,(uintptr_t)mbi.BaseAddress,std::min<size_t>(mbi.RegionSize,g_settings.yaraMaxRegionSize),L"remote_thread"); AnalyzePERegion(hwnd,pi,hp,(uintptr_t)mbi.BaseAddress,mbi.RegionSize,mbi.Type);} } } CloseHandle(hp);} } }
    }while(Thread32Next(snap,&te)); CloseHandle(snap);
}

// ================= Emitters =================
static void EmitGeneric(HWND hwnd,DWORD pid,const std::wstring& img,XDR::EventType t,const std::wstring& det){ auto ep=(long long)duration_cast<seconds>(system_clock::now().time_since_epoch()).count(); auto line=std::format(L"[{}] ALERT {} pid={} name={} {}",ep,(int)t,pid,img,det); Logger::Write(line); XDR::Event ev; ev.category=XDR::EventCategory::Alert; ev.type=t; ev.pid=pid; ev.image=img; ev.details=det; XDR::Storage::Insert(ev); auto* p=new std::wstring(line); PostMessageW(hwnd,WM_APP+2,(WPARAM)p,0); }
static void EmitPriv(HWND hwnd,const ProcInfo& pi,const std::wstring& reason){ EmitGeneric(hwnd,pi.pid,pi.image,XDR::EventType::AlertPrivilegedExec,std::format(L"reason={} integrity={} parent_integrity={} parent={} seDebug={} lsass_handle={}",reason,pi.integrity,pi.parentIntegrity,pi.parentPid,pi.seDebug?1:0,pi.hasLsass?1:0)); }
static void EmitPrivDelta(HWND hwnd,const ProcInfo& pi,const std::wstring& newly){ EmitGeneric(hwnd,pi.pid,pi.image,XDR::EventType::AlertPrivilegedExec,std::format(L"reason=new_priv new_privs={}",newly)); }

// ================= Background loops =================
static std::atomic_bool g_bgRun{false}; static std::thread g_bgThread; static void BgLoop(){ while(g_bgRun.load()){ HWND hwnd=g_hwndNotify.load(); if(hwnd) Behavioral::Periodic(hwnd); for(int i=0;i<10 && g_bgRun.load(); ++i) std::this_thread::sleep_for(100ms);} }
namespace Behavioral { void StartBackground(HWND hwnd){ g_hwndNotify=hwnd; if(g_bgRun.load()) return; g_bgRun=true; g_bgThread=std::thread(BgLoop); if(g_settings.enableYaraRegionScan && !g_yaraRun.load()){ g_yaraRun=true; g_yaraThread=std::thread(YaraLoop);} } void StopBackground(){ g_bgRun=false; if(g_bgThread.joinable()) g_bgThread.join(); g_yaraRun=false; if(g_yaraThread.joinable()) g_yaraThread.join(); } }

// ================= API surface =================
namespace Behavioral {
    void AnalyzeProcessMemory(DWORD pid, HWND hwnd){
        HANDLE h=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid);
        if(!h) return;
        wchar_t buf[MAX_PATH]; DWORD sz=MAX_PATH; std::wstring img=L"pid="+std::to_wstring(pid);
        if(QueryFullProcessImageNameW(h,0,buf,&sz)){ std::wstring full=buf; size_t p=full.find_last_of(L'\\'); img = (p==std::wstring::npos)?full:full.substr(p+1); }
        CloseHandle(h);
        std::wstring det;
        if(MemoryAnalysis::DetectProcessHollowing(pid,det)) EmitGeneric(hwnd,pid,img,XDR::EventType::AlertProcessHollowing,det);
        det.clear();
        if(MemoryAnalysis::DetectDllInjection(pid,det)) EmitGeneric(hwnd,pid,img,XDR::EventType::AlertDllInjection,det);
        det.clear();
        if(MemoryAnalysis::DetectReflectiveLoading(pid,det)) EmitGeneric(hwnd,pid,img,XDR::EventType::AlertReflectiveMemory,det);
    }

    void OnProcessStart(DWORD pid,const std::wstring& image,HWND hwnd){
        ProcInfo pi{pid,image,steady_clock::now()};
        HANDLE h=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,FALSE,pi.pid);
        if(h){ pi.integrity=IntegrityLevel(h); pi.lastIntegrityDyn=pi.integrity; pi.seDebug=HasSeDebug(h); pi.adminGroup=IsAdminGroup(h); pi.privSnapshot=GetEnabledPrivs(h); pi.hasDbgHelp=EnumHas(h,L"dbghelp.dll"); pi.hasComSvcs=EnumHas(h,L"comsvcs.dll"); CloseHandle(h);} 
        pi.parentPid=ParentPid(pid);
        if(pi.parentPid){ HANDLE hp=OpenProcess(PROCESS_QUERY_INFORMATION,FALSE,pi.parentPid); if(hp){ pi.parentIntegrity=IntegrityLevel(hp); CloseHandle(hp);} }
        pi.nextRegionScan=steady_clock::now();
        g_procs[pid]=pi;
        auto lw=lower(image);
        if(lw.find(L"powershell")!=std::wstring::npos || lw.find(L"cmd.exe")!=std::wstring::npos){ EmitGeneric(hwnd,pid,image,XDR::EventType::AlertSuspiciousProcess,L"shell_start"); }
    }

    void OnProcessStop(DWORD pid){ g_procs.erase(pid); g_extra.erase(pid); }

    void Periodic(HWND hwnd){
        auto now=steady_clock::now();
        if(now - g_lastSweep < seconds(3)){ ScanThreads(hwnd); return; }
        g_lastSweep=now; ScanLsassHandles(); ScanThreads(hwnd); PruneAlerts();
        // New: persistence / registry scans moved to separate compilation unit
        Behavioral::PersistencePeriodic(hwnd);
        for(auto &kv: g_procs){
            auto &pi=kv.second; auto alive=duration_cast<seconds>(now - pi.start).count(); pi.hasLsass = g_lsassProcs.contains(pi.pid);
            // Integrity change
            if(alive>=2){ HANDLE h=OpenProcess(PROCESS_QUERY_INFORMATION,FALSE,pi.pid); if(h){ auto cur=IntegrityLevel(h); CloseHandle(h); if(cur!=pi.lastIntegrityDyn){ pi.lastIntegrityDyn=cur; if(AlertAllowed(pi.pid,XDR::EventType::AlertPrivilegedExec,0)) EmitPriv(hwnd,pi,L"integrity_change"); } } }
            // Region protection transitions
            bool doScan = g_settings.enableProtTransitions && ((alive<30) || (now>=pi.nextRegionScan));
            if(doScan){ pi.nextRegionScan=now+seconds(10); HANDLE hp=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,FALSE,pi.pid); if(hp){ MEMORY_BASIC_INFORMATION mbi; unsigned char* addr=nullptr; int rc=0; while(VirtualQueryEx(hp,addr,&mbi,sizeof(mbi))==sizeof(mbi)){ if(mbi.State==MEM_COMMIT){ DWORD prev=pi.lastProt[(uintptr_t)mbi.BaseAddress]; if(prev && prev!=mbi.Protect){ bool newExec=IsExec(mbi.Protect), newWrite=IsWrite(mbi.Protect); bool prevWrite=IsWrite(prev); if(mbi.RegionSize>=0x400 && newExec && !newWrite && prevWrite && mbi.Type!=MEM_IMAGE){ if(AlertAllowed(pi.pid,XDR::EventType::AlertReflectiveMemory,(uintptr_t)mbi.BaseAddress)){ BYTE sample[128]; SIZE_T br=0; ReadProcessMemory(hp,mbi.BaseAddress,sample,sizeof(sample),&br); uint64_t h=Fnv1a64(sample,std::min<SIZE_T>(br,64)); double ent=Entropy(sample,std::min<SIZE_T>(br,128)); std::wstringstream ds; ds<<L"event=prot_transition base=0x"<<std::hex<<(uintptr_t)mbi.BaseAddress<<L" size="<<std::dec<<mbi.RegionSize<<L" oldProt="<<ProtToString(prev)<<L" newProt="<<ProtToString(mbi.Protect)<<L" ent="<<std::fixed<<std::setprecision(2)<<ent<<L" hash=0x"<<std::hex<<h; EmitGeneric(hwnd,pi.pid,pi.image,XDR::EventType::AlertReflectiveMemory,ds.str()); EnqueueYara(pi.pid,(uintptr_t)mbi.BaseAddress,std::min<size_t>(mbi.RegionSize,g_settings.yaraMaxRegionSize),L"prot_transition"); AnalyzePERegion(hwnd,pi,hp,(uintptr_t)mbi.BaseAddress,mbi.RegionSize,mbi.Type); } } } pi.lastProt[(uintptr_t)mbi.BaseAddress]=mbi.Protect; } addr+=mbi.RegionSize; if(++rc>4096) break; if(!addr) break; } CloseHandle(hp);} }
            // Initial module & unsigned
            if(!pi.checkedModules && alive<=30){ HANDLE h=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,FALSE,pi.pid); if(h){ pi.hasDbgHelp=EnumHas(h,L"dbghelp.dll")||pi.hasDbgHelp; pi.hasComSvcs=EnumHas(h,L"comsvcs.dll")||pi.hasComSvcs; CloseHandle(h);} CheckUnsignedModules(hwnd,pi); pi.checkedModules=true; }
            // Priv escalation baseline
            if(!pi.privAlerted && alive>=2){ bool elevated=(pi.integrity==L"High"||pi.integrity==L"System"); bool parentMismatch=elevated && !pi.parentIntegrity.empty() && (pi.parentIntegrity!=L"High" && pi.parentIntegrity!=L"System"); bool heur=pi.hasLsass || (elevated && pi.seDebug); if(elevated && (parentMismatch||heur)){ EmitPriv(hwnd,pi,parentMismatch?L"parent_mismatch":L"privileged"); pi.privAlerted=true; } }
            if(!pi.followPriv && alive>=5 && alive<=600){ HANDLE h=OpenProcess(PROCESS_QUERY_INFORMATION,FALSE,pi.pid); if(h){ auto nowPriv=GetEnabledPrivs(h); CloseHandle(h); std::wstring newly; for(auto &p:nowPriv){ if(!pi.privSnapshot.contains(p) && kHighRiskPrivs.contains(p)){ if(!newly.empty()) newly+=L";"; newly+=p; } } if(!newly.empty()){ EmitPrivDelta(hwnd,pi,newly); pi.followPriv=true; } } }
            if(!pi.injAlerted && alive>=2 && alive<=180){ if(g_settings.enableInjectionHeuristic){ auto res=ScanForInjectionVerbose(pi.pid); if(res.suspicious && AlertAllowed(pi.pid,XDR::EventType::AlertProcessInjection,0)){ pi.injAlerted=true; EmitGeneric(hwnd,pi.pid,pi.image,XDR::EventType::AlertProcessInjection,std::format(L"sample={} private_exec_regions={} writable_exec_regions={}",res.sample,res.privateExecRegions,res.writableExecRegions)); } } }
            if(!pi.hollowAlerted && alive>=3 && alive<=300){ std::wstring det; if(MemoryAnalysis::DetectProcessHollowing(pi.pid,det) && AlertAllowed(pi.pid,XDR::EventType::AlertProcessHollowing,0)){ pi.hollowAlerted=true; EmitGeneric(hwnd,pi.pid,pi.image,XDR::EventType::AlertProcessHollowing,det); } }
            if(!pi.reflMemAlerted && alive>=3 && alive<=300){ std::wstring det; if(MemoryAnalysis::DetectReflectiveLoading(pi.pid,det) && AlertAllowed(pi.pid,XDR::EventType::AlertReflectiveMemory,0)){ pi.reflMemAlerted=true; EmitGeneric(hwnd,pi.pid,pi.image,XDR::EventType::AlertReflectiveMemory,det); } }
            CheckApiHooks(hwnd,pi);
            ClassifyExecRegions(hwnd,pi);
        }
    }

    void AnalyzeProcessMemoryAsync(DWORD pid, HWND hwnd){ std::thread([pid,hwnd]{ AnalyzeProcessMemory(pid,hwnd); }).detach(); }
}
