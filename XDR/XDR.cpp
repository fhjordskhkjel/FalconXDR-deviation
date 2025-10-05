// XDR.cpp - main (cleaned & deduplicated)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include "framework.h"
#include "XDR.h"
#include "Config.h"
#include "Logger.h"
#include "Storage.h"
#include "QueryDialog.h"
#include "ScreenshotMonitor.h"
#include "BehavioralAnalyzer.h"
#include "DriverManager.h"
#include "MemoryAnalysis.h"
#include "Utilities.h"
#include "ProcessMonitor.h"
#include "NetworkMonitor.h"
#include "SettingsManager.h"
#include "YaraManager.h"

#include <atomic>
#include <array>
#include <chrono>
#include <cwctype>
#include <filesystem>
#include <format>
#include <string>
#include <thread>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <sstream>
#include <fstream>
#include <TlHelp32.h>
#include <iphlpapi.h>
#include <commctrl.h>
#include <commdlg.h>
#include <windowsx.h>
#include <psapi.h>
#include <uxtheme.h>
#include <iomanip>
#include <regex>
#include <shlwapi.h>
#include <mutex>
#include <algorithm> // sorting

#pragma comment(lib,"iphlpapi.lib")
#pragma comment(lib,"ws2_32.lib")

using namespace std::chrono;

#define MAX_LOADSTRING 100
#define WM_XDR_EVENT (WM_APP + 1)
#define WM_XDR_ALERT (WM_APP + 2)
#define WM_SCREENSHOT_EVENT (WM_APP + 10)

// Control / command IDs
#define IDC_SEARCH_EDIT 3001
#define IDC_SEARCH_BTN  3002
#define IDC_SPLITTER    3003
#define IDC_TOOLBAR     3004
#define IDC_CLEAR_FILTER 3005
#define IDC_THEME_TOGGLE 3006
#define IDC_LIST_CTX_COPY 5001
#define IDC_LIST_CTX_EXPORT 5002
#define IDC_LIST_CTX_DUMPREGION 5004
#define IDC_LIST_CTX_REGIONS 5005
#define ID_TB_COLLECTION  4001
#define ID_TB_CLEAR       4002
#define ID_TB_EXPORT      4003
#define ID_TB_THEME       4004
#define ID_TB_SCREENSHOT  4006
#define ID_TB_PAUSE       4007
#define ID_TB_YARA        4010
#define ID_TB_AUTOSCROLL  4011 // new

// Region window controls
#define IDC_REGION_LIST 6001
#define IDC_BTN_REFRESH 6002
#define IDC_BTN_DUMP    6003

#ifndef IDD_QUERYDLG
#define IDD_QUERYDLG 200
#define IDC_QUERY_LIST 201
#define IDM_QUERY_RECENT 32780
#endif

#ifndef IDM_BEHAVIOR_UNSIGNED
#define IDM_BEHAVIOR_UNSIGNED 33010
#define IDM_BEHAVIOR_APIHOOKS 33011
#define IDM_BEHAVIOR_EXECREG  33012
#define IDM_BEHAVIOR_INJECTHEUR 33013
#define IDM_BEHAVIOR_THREADSCAN 33014
#define IDM_BEHAVIOR_PROTTRANS 33015
#define IDM_BEHAVIOR_YARAREG 33016
#define IDM_TOGGLE_COLLECTION 33017
#define IDM_RELOAD_RULES 33018
#define IDM_CLEAR_LISTS 33019
#define IDM_PROCESS_REGIONS 33020
#define IDM_YARA_SCAN 33021
#define IDM_QUERY_RECENT 33022
#define IDM_EXIT 0x0010
#endif

HINSTANCE hInst; WCHAR szTitle[MAX_LOADSTRING]; WCHAR szWindowClass[MAX_LOADSTRING];
namespace XDR { std::atomic_bool g_collect{ true }; }
static XDR::Settings::UISettings g_uiSettings; static Behavioral::Settings g_behaviorSettings;
struct UITheme { COLORREF bg,surface,text,alertBg,alertText,splitter; const wchar_t* name; };
static UITheme kThemeDark  { RGB(17,17,17),  RGB(30,30,30),  RGB(235,235,235), RGB(50,20,20),  RGB(255,180,180), RGB(90,90,90),  L"Dark" };
static UITheme kThemeLight { RGB(255,255,255),RGB(240,240,240),RGB(40,40,40),  RGB(255,230,230),RGB(153,27,27), RGB(180,180,180),L"Light" };
static UITheme g_theme = kThemeDark; static bool g_dark=true;
struct Brush { HBRUSH h{}; Brush()=default; explicit Brush(COLORREF c){ h=CreateSolidBrush(c);} Brush(Brush&&o)noexcept:h(o.h){o.h=nullptr;} Brush& operator=(Brush&&o)noexcept{ if(this!=&o){ if(h) DeleteObject(h); h=o.h; o.h=nullptr;} return *this;} ~Brush(){ if(h) DeleteObject(h);} void reset(COLORREF c){ if(h) DeleteObject(h); h=CreateSolidBrush(c);} operator HBRUSH() const { return h; } }; 
struct FontRAII { HFONT h{}; ~FontRAII(){ if(h) DeleteObject(h);} operator HFONT() const { return h; } };
static Brush g_brushBg,g_brushSurface,g_brushAlertBg,g_brushSplitter,g_brushEvenRow,g_brushBtn; // added g_brushBtn
static FontRAII g_fontMono;
static COLORREF Lighten(COLORREF c,int d){ int r=std::clamp((int)GetRValue(c)+d,0,255); int g=std::clamp((int)GetGValue(c)+d,0,255); int b=std::clamp((int)GetBValue(c)+d,0,255); return RGB(r,g,b);} 
// Severity colors - more distinct for better visibility
static COLORREF g_sevCritical=RGB(255,60,60), g_sevHigh=RGB(255,120,80), g_sevMed=RGB(255,180,80), g_sevLow=RGB(255,230,100);

HWND g_lvEvents{}, g_lvAlerts{}; static HWND g_status{}, g_searchEdit{}, g_searchBtn{}, g_clearBtn{}, g_toolbar{}, g_splitter{};
static bool g_dragSplit=false; static bool g_pause=false; static bool g_autoScroll=true; // new auto-scroll flag
static constexpr int kSplitterW=6, kBarH=32, kSearchH=30, kStatusH=22; 
static std::atomic_uint64_t g_evtCount{0}, g_alertCount{0};
static std::vector<std::wstring> g_events, g_alerts; static std::wstring g_evtFilter, g_alertFilter; static constexpr size_t kMaxRows=5000;
static bool g_sortEventsAsc=true; static bool g_sortAlertsAsc=true; 
static ScreenshotCapture::ScreenshotMonitor g_screenshotMonitor; static XDR::ProcessMonitor g_procMon; static XDR::NetworkMonitor g_netMon; static DriverManager g_driverMgr;

static void LoadUI(); static void SaveUI(); static void MakeBrushes(); static void UpdateThemeOnLists(); static void Layout(HWND);
static void UpdateStatus(); static void ToggleTheme(); static void AddColumns(HWND); static void ApplySearch(); static void ExportAll(HWND);
static void ExportSelected(HWND,HWND); static void CopySelected(HWND); static void CreateToolbar(HWND); static void AddListViewLine(HWND,std::vector<std::wstring>&,const std::wstring&,std::wstring&); static void ShowRegionWindow(DWORD); LRESULT CALLBACK RegionWndProc(HWND,UINT,WPARAM,LPARAM); static void UpdateBehaviorMenuChecks(HWND); static void ResortListView(HWND,bool& ascFlag);
static void LoadUI(){ XDR::Settings::LoadSettings(g_uiSettings,g_behaviorSettings); g_dark=g_uiSettings.darkTheme; g_theme=g_dark?kThemeDark:kThemeLight; Behavioral::SetSettings(g_behaviorSettings);} 
static void SaveUI(){ g_uiSettings.darkTheme=g_dark; XDR::Settings::SaveSettings(g_uiSettings,g_behaviorSettings);} 
static void MakeBrushes(){ g_brushBg.reset(g_theme.bg); g_brushSurface.reset(g_theme.surface); g_brushAlertBg.reset(g_theme.alertBg); g_brushSplitter.reset(g_theme.splitter); g_brushEvenRow.reset(Lighten(g_theme.surface,g_dark?8:20)); g_brushBtn.reset(Lighten(g_theme.surface,g_dark?35:10)); }
static void ToggleTheme(){ g_dark=!g_dark; g_theme=g_dark?kThemeDark:kThemeLight; MakeBrushes(); SaveUI(); UpdateThemeOnLists(); UpdateStatus(); }
static void UpdateThemeOnLists(){ if(g_lvEvents){ ListView_SetBkColor(g_lvEvents,g_theme.surface); ListView_SetTextBkColor(g_lvEvents,g_theme.surface); ListView_SetTextColor(g_lvEvents,g_theme.text); InvalidateRect(g_lvEvents,nullptr,TRUE);} if(g_lvAlerts){ ListView_SetBkColor(g_lvAlerts,g_theme.alertBg); ListView_SetTextBkColor(g_lvAlerts,g_theme.alertBg); ListView_SetTextColor(g_lvAlerts,g_theme.alertText); InvalidateRect(g_lvAlerts,nullptr,TRUE);} }
static void AddColumns(HWND lv){ LVCOLUMNW c{}; c.mask=LVCF_TEXT|LVCF_WIDTH|LVCF_FMT; c.fmt=LVCFMT_LEFT; c.cx=60; c.pszText=(LPWSTR)L"#"; ListView_InsertColumn(lv,0,&c); c.cx=1200; c.pszText=(LPWSTR)L"Event"; ListView_InsertColumn(lv,1,&c);} 
static void Layout(HWND hwnd){ RECT rc; GetClientRect(hwnd,&rc); int w=rc.right, h=rc.bottom; int top=kBarH+kSearchH+4, bottom=h-kStatusH; if(g_toolbar) SetWindowPos(g_toolbar,nullptr,0,0,w,kBarH,SWP_NOZORDER); int m=6; if(g_searchEdit) SetWindowPos(g_searchEdit,nullptr,m,kBarH+4,240,kSearchH-8,SWP_NOZORDER); if(g_searchBtn) SetWindowPos(g_searchBtn,nullptr,m+244,kBarH+4,70,kSearchH-8,SWP_NOZORDER); if(g_clearBtn) SetWindowPos(g_clearBtn,nullptr,m+244+74,kBarH+4,70,kSearchH-8,SWP_NOZORDER); if(g_splitter) SetWindowPos(g_splitter,nullptr,g_uiSettings.splitPos,top,kSplitterW,bottom-top,SWP_NOZORDER); if(g_lvEvents) SetWindowPos(g_lvEvents,nullptr,2,top,g_uiSettings.splitPos-2,bottom-top,SWP_NOZORDER); if(g_lvAlerts) SetWindowPos(g_lvAlerts,nullptr,g_uiSettings.splitPos+kSplitterW,top,w-g_uiSettings.splitPos-kSplitterW-2,bottom-top,SWP_NOZORDER); if(g_status){ SetWindowPos(g_status,nullptr,0,bottom,w,kStatusH,SWP_NOZORDER); int parts[4]; parts[0]=250; parts[1]=470; parts[2]=720; parts[3]=-1; SendMessageW(g_status,SB_SETPARTS,4,(LPARAM)parts);} } 
static void UpdateStatus(){ if(!g_status) return; std::wstring counts=std::format(L"Events: {} | Alerts: {}",g_evtCount.load(),g_alertCount.load()); std::wstring state=!XDR::g_collect.load()?L"⏸ STOPPED":(g_pause?L"⏸ DISPLAY PAUSED":L"▶ COLLECTING"); auto qstats=Behavioral::GetQueueStats(); std::wstring queues=std::format(L"Q: Scan:{} Y:{} H:{} C:{}",qstats.scanQueueSize,qstats.yaraQueueSize,qstats.scanQueueHighPrio,qstats.scanQueueCriticalPrio); std::wstring theme=std::format(L"Theme: {}",g_theme.name); SendMessageW(g_status,SB_SETTEXTW,0,(LPARAM)counts.c_str()); SendMessageW(g_status,SB_SETTEXTW,1,(LPARAM)state.c_str()); SendMessageW(g_status,SB_SETTEXTW,2,(LPARAM)queues.c_str()); SendMessageW(g_status,SB_SETTEXTW,3,(LPARAM)theme.c_str()); }
static void AddListViewLine(HWND lv,std::vector<std::wstring>& store,const std::wstring& line,std::wstring& filter){ if(g_pause) return; store.push_back(line); if(store.size()>kMaxRows) store.erase(store.begin()); std::wstring lower=XDR::Utils::ToLower(line), f=XDR::Utils::ToLower(filter); if(!f.empty() && lower.find(f)==std::wstring::npos) return; int idx=ListView_GetItemCount(lv); LVITEMW it{}; it.mask=LVIF_TEXT; it.iItem=idx; auto num=std::to_wstring(idx+1); it.pszText=(LPWSTR)num.c_str(); ListView_InsertItem(lv,&it); ListView_SetItemText(lv,idx,1,(LPWSTR)line.c_str()); if(g_autoScroll) ListView_EnsureVisible(lv,idx,FALSE); }
static void ApplySearch(){ ListView_DeleteAllItems(g_lvEvents); ListView_DeleteAllItems(g_lvAlerts); for(auto &l:g_events){ std::wstring lower=XDR::Utils::ToLower(l),f=XDR::Utils::ToLower(g_evtFilter); if(f.empty()||lower.find(f)!=std::wstring::npos){ int idx=ListView_GetItemCount(g_lvEvents); LVITEMW it{.mask=LVIF_TEXT,.iItem=idx}; auto n=std::to_wstring(idx+1); it.pszText=(LPWSTR)n.c_str(); ListView_InsertItem(g_lvEvents,&it); ListView_SetItemText(g_lvEvents,idx,1,(LPWSTR)l.c_str()); }} for(auto &l:g_alerts){ std::wstring lower=XDR::Utils::ToLower(l),f=XDR::Utils::ToLower(g_alertFilter); if(f.empty()||lower.find(f)!=std::wstring::npos){ int idx=ListView_GetItemCount(g_lvAlerts); LVITEMW it{.mask=LVIF_TEXT,.iItem=idx}; auto n=std::to_wstring(idx+1); it.pszText=(LPWSTR)n.c_str(); ListView_InsertItem(g_lvAlerts,&it); ListView_SetItemText(g_lvAlerts,idx,1,(LPWSTR)l.c_str()); }} if(g_autoScroll){ int c=ListView_GetItemCount(g_lvEvents); if(c>0) ListView_EnsureVisible(g_lvEvents,c-1,FALSE); c=ListView_GetItemCount(g_lvAlerts); if(c>0) ListView_EnsureVisible(g_lvAlerts,c-1,FALSE);} UpdateStatus(); }
static void ExportAll(HWND owner){ wchar_t path[MAX_PATH]=L"export.txt"; OPENFILENAMEW ofn{sizeof(ofn)}; ofn.hwndOwner=owner; ofn.lpstrFile=path; ofn.nMaxFile=MAX_PATH; ofn.lpstrFilter=L"Text Files\0*.txt\0All Files\0*.*\0"; ofn.Flags=OFN_OVERWRITEPROMPT; if(!GetSaveFileNameW(&ofn)) return; std::wofstream f(path); if(!f) return; for(auto&l:g_events) f<<l<<L"\n"; for(auto&l:g_alerts) f<<l<<L"\n"; }
static void ExportSelected(HWND lv,HWND owner){ int sel=ListView_GetNextItem(lv,-1,LVNI_SELECTED); if(sel==-1) return; wchar_t path[MAX_PATH]=L"selected.txt"; OPENFILENAMEW ofn{sizeof(ofn)}; ofn.hwndOwner=owner; ofn.lpstrFile=path; ofn.nMaxFile=MAX_PATH; ofn.lpstrFilter=L"Text Files\0*.txt\0All Files\0*.*\0"; ofn.Flags=OFN_OVERWRITEPROMPT; if(!GetSaveFileNameW(&ofn)) return; std::wofstream f(path); if(!f) return; while(sel!=-1){ wchar_t buf[4096]{}; ListView_GetItemText(lv,sel,1,buf,4095); f<<buf<<L"\n"; sel=ListView_GetNextItem(lv,sel,LVNI_SELECTED);} }
static void CopySelected(HWND lv){ int sel=ListView_GetNextItem(lv,-1,LVNI_SELECTED); if(sel==-1) return; // gather all selected
 std::wstring all; while(sel!=-1){ wchar_t buf[4096]{}; ListView_GetItemText(lv,sel,1,buf,4095); all.append(buf).append(L"\r\n"); sel=ListView_GetNextItem(lv,sel,LVNI_SELECTED);} if(OpenClipboard(nullptr)){ EmptyClipboard(); size_t bytes=(all.size()+1)*sizeof(wchar_t); HGLOBAL h=GlobalAlloc(GMEM_MOVEABLE,bytes); if(h){ void* p=GlobalLock(h); memcpy(p,all.c_str(),bytes); GlobalUnlock(h); SetClipboardData(CF_UNICODETEXT,h);} CloseClipboard(); }}
static void CreateToolbar(HWND hwnd){ g_toolbar=CreateWindowExW(0,TOOLBARCLASSNAME,nullptr,WS_CHILD|WS_VISIBLE|TBSTYLE_FLAT|TBSTYLE_TOOLTIPS,0,0,0,0,hwnd,(HMENU)IDC_TOOLBAR,hInst,nullptr); if(!g_toolbar) return; SendMessageW(g_toolbar,TB_BUTTONSTRUCTSIZE,sizeof(TBBUTTON),0); TBBUTTON btns[]={{0,ID_TB_COLLECTION,TBSTATE_ENABLED,BTNS_BUTTON,{0},0,(INT_PTR)L"Toggle"},{0,ID_TB_CLEAR,TBSTATE_ENABLED,BTNS_BUTTON,{0},0,(INT_PTR)L"Clear"},{0,ID_TB_EXPORT,TBSTATE_ENABLED,BTNS_BUTTON,{0},0,(INT_PTR)L"Export"},{0,ID_TB_THEME,TBSTATE_ENABLED,BTNS_BUTTON,{0},0,(INT_PTR)L"Theme"},{0,ID_TB_YARA,TBSTATE_ENABLED,BTNS_BUTTON,{0},0,(INT_PTR)L"Yara"},{0,ID_TB_SCREENSHOT,TBSTATE_ENABLED,BTNS_BUTTON,{0},0,(INT_PTR)L"Shot"},{0,ID_TB_PAUSE,TBSTATE_ENABLED,BTNS_BUTTON,{0},0,(INT_PTR)L"Pause"},{0,ID_TB_AUTOSCROLL,TBSTATE_ENABLED,BTNS_BUTTON,{0},0,(INT_PTR)L"Auto"}}; SendMessageW(g_toolbar,TB_ADDBUTTONSW,(WPARAM)(sizeof(btns)/sizeof(TBBUTTON)),(LPARAM)&btns);} 
static void UpdateBehaviorMenuChecks(HWND hwnd){ HMENU m=GetMenu(hwnd); if(!m) return; int cnt=GetMenuItemCount(m); for(int i=0;i<cnt;i++){ wchar_t name[64]{}; GetMenuStringW(m,i,name,63,MF_BYPOSITION); if(!wcscmp(name,L"Behavior")){ HMENU sub=GetSubMenu(m,i); if(!sub) return; auto set=[&](UINT id,bool on){ CheckMenuItem(sub,id,MF_BYCOMMAND|(on?MF_CHECKED:MF_UNCHECKED));}; set(IDM_BEHAVIOR_UNSIGNED,g_behaviorSettings.enableUnsignedModuleAlert); set(IDM_BEHAVIOR_APIHOOKS,g_behaviorSettings.enableApiHookScan); set(IDM_BEHAVIOR_EXECREG,g_behaviorSettings.enableExecRegionClassifier); set(IDM_BEHAVIOR_INJECTHEUR,g_behaviorSettings.enableInjectionHeuristic); set(IDM_BEHAVIOR_THREADSCAN,g_behaviorSettings.enableThreadScan); set(IDM_BEHAVIOR_PROTTRANS,g_behaviorSettings.enableProtTransitions); set(IDM_BEHAVIOR_YARAREG,g_behaviorSettings.enableYaraRegionScan); break; } } }

struct RegionWndData { DWORD pid; HWND lvRegions; std::vector<MemoryAnalysis::MemoryRegionInfo> regions; };
static COLORREF g_regionNormal=RGB(240,255,240), g_regionSuspicious=RGB(255,200,200), g_regionRWX=RGB(255,255,200);
LRESULT CALLBACK RegionWndProc(HWND hwnd,UINT msg,WPARAM wParam,LPARAM lParam){ auto* data=reinterpret_cast<RegionWndData*>(GetWindowLongPtrW(hwnd,GWLP_USERDATA)); switch(msg){ case WM_CREATE:{ auto cs=reinterpret_cast<CREATESTRUCT*>(lParam); data=new RegionWndData(); data->pid=(DWORD)(uintptr_t)cs->lpCreateParams; SetWindowLongPtrW(hwnd,GWLP_USERDATA,(LONG_PTR)data); data->lvRegions=CreateWindowExW(WS_EX_CLIENTEDGE,WC_LISTVIEWW,nullptr,WS_CHILD|WS_VISIBLE|LVS_REPORT|LVS_SINGLESEL,10,10,760,480,hwnd,(HMENU)IDC_REGION_LIST,hInst,nullptr); ListView_SetExtendedListViewStyle(data->lvRegions,LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER); LVCOLUMNW c{}; c.mask=LVCF_TEXT|LVCF_WIDTH; const wchar_t* headers[]={L"Address",L"Size",L"Protection",L"Type",L"PE",L"Status"}; int widths[]={140,110,90,90,60,160}; for(int i=0;i<6;i++){ c.pszText=(LPWSTR)headers[i]; c.cx=widths[i]; ListView_InsertColumn(data->lvRegions,i,&c);} CreateWindowW(L"BUTTON",L"Refresh",WS_CHILD|WS_VISIBLE,10,500,80,25,hwnd,(HMENU)IDC_BTN_REFRESH,hInst,nullptr); CreateWindowW(L"BUTTON",L"Dump Selected",WS_CHILD|WS_VISIBLE,100,500,120,25,hwnd,(HMENU)IDC_BTN_DUMP,hInst,nullptr); PostMessage(hwnd,WM_COMMAND,IDC_BTN_REFRESH,0); return 0;} case WM_COMMAND:{ switch(LOWORD(wParam)){ case IDC_BTN_REFRESH:{ if(!data) break; ListView_DeleteAllItems(data->lvRegions); data->regions=MemoryAnalysis::ScanProcessMemoryRegions(data->pid); for(size_t i=0;i<data->regions.size();++i){ auto&r=data->regions[i]; LVITEMW it{}; it.mask=LVIF_TEXT; it.iItem=(int)i; auto addr=std::format(L"0x{:X}",(uintptr_t)r.baseAddress); it.pszText=(LPWSTR)addr.c_str(); ListView_InsertItem(data->lvRegions,&it); auto size=std::format(L"{} KB",r.regionSize/1024); ListView_SetItemText(data->lvRegions,(int)i,1,(LPWSTR)size.c_str()); std::wstring prot = r.isExecutable?(r.isWritable?L"RWX":L"RX"): (r.isWritable?L"RW":L"R"); ListView_SetItemText(data->lvRegions,(int)i,2,(LPWSTR)prot.c_str()); const wchar_t* type=r.isMapped?L"Mapped":(r.isPrivate?L"Private":L"Other"); ListView_SetItemText(data->lvRegions,(int)i,3,(LPWSTR)type); ListView_SetItemText(data->lvRegions,(int)i,4,(LPWSTR)(r.isPEHeader?L"Yes":L"No")); std::wstring status=(r.isSuspicious || (r.isExecutable && r.isWritable && !r.isMapped))?L"⚠ SUSPICIOUS":L"Normal"; ListView_SetItemText(data->lvRegions,(int)i,5,(LPWSTR)status.c_str()); } } break; case IDC_BTN_DUMP:{ if(!data) break; int sel=ListView_GetNextItem(data->lvRegions,-1,LVNI_SELECTED); if(sel==-1){ MessageBoxW(hwnd,L"Select a region",L"Info",MB_OK|MB_ICONINFORMATION); break;} auto& r=data->regions[sel]; wchar_t path[MAX_PATH]; swprintf_s(path,L"memdump_pid%u_0x%zX.bin",data->pid,(uintptr_t)r.baseAddress); OPENFILENAMEW ofn{sizeof(ofn)}; ofn.hwndOwner=hwnd; ofn.lpstrFile=path; ofn.nMaxFile=MAX_PATH; ofn.lpstrFilter=L"Binary Files\0*.bin\0All Files\0*.*\0"; ofn.Flags=OFN_OVERWRITEPROMPT; if(!GetSaveFileNameW(&ofn)) break; HANDLE hp=OpenProcess(PROCESS_VM_READ,FALSE,data->pid); if(!hp){ MessageBoxW(hwnd,L"OpenProcess failed",L"Error",MB_OK|MB_ICONERROR); break;} std::vector<BYTE> buf(r.regionSize); SIZE_T br=0; if(ReadProcessMemory(hp,r.baseAddress,buf.data(),r.regionSize,&br)){ std::ofstream f(path,std::ios::binary); if(f){ f.write((const char*)buf.data(),br); auto msg=std::format(L"Dumped {} bytes",br); MessageBoxW(hwnd,msg.c_str(),L"OK",MB_OK|MB_ICONINFORMATION);} else MessageBoxW(hwnd,L"Write fail",L"Error",MB_OK|MB_ICONERROR);} else MessageBoxW(hwnd,L"ReadProcessMemory failed",L"Error",MB_OK|MB_ICONERROR); CloseHandle(hp);} break; }} break; case WM_NOTIFY:{ auto* hdr=reinterpret_cast<NMHDR*>(lParam); if(data && hdr->hwndFrom==data->lvRegions && hdr->code==NM_CUSTOMDRAW){ auto* cd=reinterpret_cast<NMLVCUSTOMDRAW*>(lParam); switch(cd->nmcd.dwDrawStage){ case CDDS_PREPAINT: return CDRF_NOTIFYITEMDRAW; case CDDS_ITEMPREPAINT:{ int idx=(int)cd->nmcd.dwItemSpec; if(idx>=0 && idx<(int)data->regions.size()){ auto&r=data->regions[idx]; bool suspicious=r.isSuspicious||(r.isExecutable&&r.isWritable&&!r.isMapped); bool rwx=r.isExecutable&&r.isWritable; if(suspicious) cd->clrTextBk=g_regionSuspicious; else if(rwx) cd->clrTextBk=g_regionRWX; else cd->clrTextBk=g_regionNormal; cd->clrText=RGB(0,0,0); return CDRF_NEWFONT; } break; } } } } break; case WM_SIZE:{ if(!data) break; RECT rc; GetClientRect(hwnd,&rc); int margin=10; int btnH=28; int btnGap=6; HWND bR=GetDlgItem(hwnd,IDC_BTN_REFRESH), bD=GetDlgItem(hwnd,IDC_BTN_DUMP); if(bR) SetWindowPos(bR,nullptr,margin,rc.bottom-margin-btnH,90,btnH,SWP_NOZORDER); if(bD) SetWindowPos(bD,nullptr,margin+90+btnGap,rc.bottom-margin-btnH,130,btnH,SWP_NOZORDER); if(data->lvRegions) SetWindowPos(data->lvRegions,nullptr,margin,margin,rc.right-2*margin,rc.bottom-3*margin-btnH,SWP_NOZORDER); break;} case WM_DESTROY: delete data; return 0;} return DefWindowProc(hwnd,msg,wParam,lParam);} 
static void ShowRegionWindow(DWORD pid){ static bool reg=false; if(!reg){ WNDCLASSEXW wc{sizeof(wc)}; wc.lpfnWndProc=RegionWndProc; wc.hInstance=hInst; wc.lpszClassName=L"RegionWnd"; wc.hCursor=LoadCursor(nullptr,IDC_ARROW); wc.hbrBackground=(HBRUSH)(COLOR_WINDOW+1); if(!RegisterClassExW(&wc)) return; reg=true;} auto title=std::format(L"Memory Regions - PID {}",pid); HWND w=CreateWindowExW(0,L"RegionWnd",title.c_str(),WS_OVERLAPPEDWINDOW,CW_USEDEFAULT,CW_USEDEFAULT,900,650,nullptr,nullptr,hInst,(LPVOID)(uintptr_t)pid); if(w){ ShowWindow(w,SW_SHOW); UpdateWindow(w);} }
static void ResortListView(HWND lv,bool& ascFlag){ int cnt=ListView_GetItemCount(lv); if(cnt<=1) return; std::vector<std::wstring> lines; lines.reserve(cnt); wchar_t buf[4096]; for(int i=0;i<cnt;i++){ ListView_GetItemText(lv,i,1,buf,4095); lines.emplace_back(buf);} std::sort(lines.begin(),lines.end(),[&](const std::wstring&a,const std::wstring&b){ return ascFlag? a<b : a>b; }); ListView_DeleteAllItems(lv); for(int i=0;i<(int)lines.size();++i){ LVITEMW it{.mask=LVIF_TEXT,.iItem=i}; auto num=std::to_wstring(i+1); it.pszText=(LPWSTR)num.c_str(); ListView_InsertItem(lv,&it); ListView_SetItemText(lv,i,1,(LPWSTR)lines[i].c_str()); } ascFlag=!ascFlag; }
// Determine severity for alert line with Critical/High/Medium/Low levels
static COLORREF GetSeverityColor(const std::wstring& line){ 
    // Critical severity - most dangerous threats
    if(line.find(L"ProcessHollowing")!=std::wstring::npos||line.find(L"ReflectiveMemory")!=std::wstring::npos||line.find(L"ApiHookSuspicious")!=std::wstring::npos||line.find(L"KerberosExtraction")!=std::wstring::npos) return g_sevCritical; 
    // High severity - serious threats
    if(line.find(L"ProcessInjection")!=std::wstring::npos||line.find(L"DllInjection")!=std::wstring::npos||line.find(L"ReflectiveModule")!=std::wstring::npos||line.find(L"PrivilegedExec")!=std::wstring::npos||line.find(L"LsassAccess")!=std::wstring::npos) return g_sevHigh; 
    // Medium severity - suspicious activity
    if(line.find(L"SuspiciousProcess")!=std::wstring::npos||line.find(L"SuspiciousRemotePort")!=std::wstring::npos||line.find(L"ProcEnumMismatch")!=std::wstring::npos||line.find(L"ApiHook")!=std::wstring::npos||line.find(L"UnsignedModule")!=std::wstring::npos||line.find(L"SuspiciousExecRegion")!=std::wstring::npos) return g_sevMed; 
    // Low severity - informational
    if(line.find(L"YaraMatch")!=std::wstring::npos||line.find(L"ScreenshotCaptured")!=std::wstring::npos) return g_sevLow; 
    return g_theme.alertText; 
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam){
    switch(msg){
    case WM_CREATE:{ LoadUI(); XDR::Yara::Initialize(); MakeBrushes(); if(!g_fontMono.h) g_fontMono.h=CreateFontW(-11,0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,FIXED_PITCH|FF_MODERN,L"Consolas"); CreateToolbar(hwnd); g_searchEdit=CreateWindowExW(WS_EX_CLIENTEDGE,L"EDIT",nullptr,WS_CHILD|WS_VISIBLE|ES_AUTOHSCROLL,0,0,0,0,hwnd,(HMENU)IDC_SEARCH_EDIT,hInst,nullptr); g_searchBtn=CreateWindowW(L"BUTTON",L"Search",WS_CHILD|WS_VISIBLE,0,0,0,0,hwnd,(HMENU)IDC_SEARCH_BTN,hInst,nullptr); g_clearBtn=CreateWindowW(L"BUTTON",L"Clear",WS_CHILD|WS_VISIBLE,0,0,0,0,hwnd,(HMENU)IDC_CLEAR_FILTER,hInst,nullptr); 
        // add owner-draw style to buttons for custom dark-mode rendering
        LONG_PTR s1=GetWindowLongPtr(g_searchBtn,GWL_STYLE); SetWindowLongPtr(g_searchBtn,GWL_STYLE,s1|BS_OWNERDRAW);
        LONG_PTR s2=GetWindowLongPtr(g_clearBtn,GWL_STYLE); SetWindowLongPtr(g_clearBtn,GWL_STYLE,s2|BS_OWNERDRAW);
        g_lvEvents=CreateWindowExW(WS_EX_CLIENTEDGE,WC_LISTVIEWW,nullptr,WS_CHILD|WS_VISIBLE|LVS_REPORT,0,0,0,0,hwnd,(HMENU)1001,hInst,nullptr); g_lvAlerts=CreateWindowExW(WS_EX_CLIENTEDGE,WC_LISTVIEWW,nullptr,WS_CHILD|WS_VISIBLE|LVS_REPORT,0,0,0,0,hwnd,(HMENU)1002,hInst,nullptr); g_splitter=CreateWindowExW(0,L"STATIC",nullptr,WS_CHILD|WS_VISIBLE,0,0,0,0,hwnd,(HMENU)IDC_SPLITTER,hInst,nullptr); ListView_SetExtendedListViewStyle(g_lvEvents,LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER|LVS_EX_HEADERDRAGDROP); ListView_SetExtendedListViewStyle(g_lvAlerts,LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER|LVS_EX_HEADERDRAGDROP); AddColumns(g_lvEvents); AddColumns(g_lvAlerts); if(g_fontMono.h){ SendMessageW(g_lvEvents,WM_SETFONT,(WPARAM)g_fontMono.h,TRUE); SendMessageW(g_lvAlerts,WM_SETFONT,(WPARAM)g_fontMono.h,TRUE);} g_status=CreateWindowExW(0,STATUSCLASSNAMEW,nullptr,WS_CHILD|WS_VISIBLE,0,0,0,0,hwnd,(HMENU)2001,hInst,nullptr); UpdateThemeOnLists(); Layout(hwnd); ScreenshotCapture::CaptureSettings cs; cs.quality=70; cs.captureAllMonitors=true; cs.compressImages=true; cs.enablePeriodicCapture=false; if(g_screenshotMonitor.Initialize(cs)) g_screenshotMonitor.Start(hwnd); g_procMon.Start(hwnd); g_netMon.Start(hwnd); g_driverMgr.Start(hwnd); SetTimer(hwnd,1,1000,nullptr); Behavioral::SetSettings(g_behaviorSettings); Behavioral::StartBackground(hwnd); RegisterHotKey(hwnd,1,MOD_CONTROL,'F'); UpdateBehaviorMenuChecks(hwnd); XDR::Utils::PostLine(hwnd,WM_XDR_EVENT,L"["+XDR::Utils::TimeNow()+L"] FalconXDR started"); return 0; }
    case WM_TIMER: if(wParam==1) UpdateStatus(); return 0;
    case WM_SIZE: Layout(hwnd); return 0;
    case WM_COMMAND:{ switch(LOWORD(wParam)){ case IDC_SEARCH_BTN:{ wchar_t buf[256]{}; GetWindowTextW(g_searchEdit,buf,255); g_evtFilter=buf; g_alertFilter=buf; ApplySearch(); } break; case IDC_CLEAR_FILTER: g_evtFilter.clear(); g_alertFilter.clear(); SetWindowTextW(g_searchEdit,L""); ApplySearch(); break; case ID_TB_THEME: case IDC_THEME_TOGGLE: ToggleTheme(); break; case ID_TB_COLLECTION: case IDM_TOGGLE_COLLECTION: XDR::g_collect=!XDR::g_collect.load(); XDR::Utils::PostLine(hwnd,WM_XDR_EVENT,L"["+XDR::Utils::TimeNow()+L"] Collection "+(XDR::g_collect.load()?L"ON":L"OFF")); UpdateStatus(); break; case IDM_RELOAD_RULES: XDR::Yara::Unload(); XDR::Yara::Initialize(); break; case ID_TB_CLEAR: case IDM_CLEAR_LISTS: g_events.clear(); g_alerts.clear(); ListView_DeleteAllItems(g_lvEvents); ListView_DeleteAllItems(g_lvAlerts); g_evtCount=0; g_alertCount=0; UpdateStatus(); break; case ID_TB_SCREENSHOT:{ DWORD pid=GetCurrentProcessId(); bool ok=g_screenshotMonitor.CaptureScreenshot(ScreenshotCapture::TriggerCondition::ManualTrigger,pid,L"Manual"); XDR::Utils::PostLine(hwnd,WM_XDR_EVENT,L"["+XDR::Utils::TimeNow()+L"] Screenshot trigger "+(ok?L"OK":L"FAILED")); } break; case ID_TB_YARA: case IDM_YARA_SCAN: XDR::Yara::ScanSelectedProcess(hwnd); break; case ID_TB_EXPORT: ExportAll(hwnd); break; case ID_TB_PAUSE: g_pause=!g_pause; UpdateStatus(); break; case ID_TB_AUTOSCROLL: g_autoScroll=!g_autoScroll; UpdateStatus(); break; case IDM_QUERY_RECENT: DialogBox(hInst,MAKEINTRESOURCE(IDD_QUERYDLG),hwnd,QueryDlgProc); break;
		case IDM_BEHAVIOR_UNSIGNED: g_behaviorSettings.enableUnsignedModuleAlert=!g_behaviorSettings.enableUnsignedModuleAlert; goto _updBeh;
		case IDM_BEHAVIOR_APIHOOKS: g_behaviorSettings.enableApiHookScan=!g_behaviorSettings.enableApiHookScan; goto _updBeh;
		case IDM_BEHAVIOR_EXECREG: g_behaviorSettings.enableExecRegionClassifier=!g_behaviorSettings.enableExecRegionClassifier; goto _updBeh;
		case IDM_BEHAVIOR_INJECTHEUR: g_behaviorSettings.enableInjectionHeuristic=!g_behaviorSettings.enableInjectionHeuristic; goto _updBeh;
		case IDM_BEHAVIOR_THREADSCAN: g_behaviorSettings.enableThreadScan=!g_behaviorSettings.enableThreadScan; goto _updBeh;
		case IDM_BEHAVIOR_PROTTRANS: g_behaviorSettings.enableProtTransitions=!g_behaviorSettings.enableProtTransitions; goto _updBeh;
		case IDM_BEHAVIOR_YARAREG: g_behaviorSettings.enableYaraRegionScan=!g_behaviorSettings.enableYaraRegionScan; goto _updBeh;
		_updBeh: Behavioral::SetSettings(g_behaviorSettings); UpdateBehaviorMenuChecks(hwnd); SaveUI(); break;
        case IDM_PROCESS_REGIONS:{ int sel=ListView_GetNextItem(g_lvEvents,-1,LVNI_SELECTED); if(sel==-1) sel=ListView_GetNextItem(g_lvAlerts,-1,LVNI_SELECTED); if(sel!=-1){ wchar_t line[4096]{}; HWND src=(ListView_GetNextItem(g_lvEvents,-1,LVNI_SELECTED)!=-1)?g_lvEvents:g_lvAlerts; ListView_GetItemText(src,sel,1,line,4095); std::wstring wl=line; size_t p=wl.find(L"pid="); if(p!=std::wstring::npos){ p+=4; size_t e=p; while(e<wl.size()&&iswdigit(wl[e])) ++e; try{ ShowRegionWindow((DWORD)std::stoul(wl.substr(p,e-p))); }catch(...){ } } } } break;
        case IDC_LIST_CTX_COPY:{ HWND f=GetFocus(); if(f==g_lvEvents||f==g_lvAlerts) CopySelected(f);} break;
        case IDC_LIST_CTX_EXPORT:{ HWND f=GetFocus(); if(f==g_lvEvents||f==g_lvAlerts) ExportSelected(f,hwnd);} break;
        case IDC_LIST_CTX_REGIONS: SendMessage(hwnd,WM_COMMAND,IDM_PROCESS_REGIONS,0); break;
        case IDC_LIST_CTX_DUMPREGION: SendMessage(hwnd,WM_COMMAND,IDM_PROCESS_REGIONS,0); break;
        case IDM_EXIT: DestroyWindow(hwnd); break;
        default: break; }
        // Live filtering on edit change (no refactor) 
        if(HIWORD(wParam)==EN_CHANGE && LOWORD(wParam)==IDC_SEARCH_EDIT){ wchar_t buf[256]{}; GetWindowTextW(g_searchEdit,buf,255); g_evtFilter=buf; g_alertFilter=buf; ApplySearch(); }
        return 0; }
    case WM_CONTEXTMENU:{ HWND src=(HWND)wParam; if(src==g_lvEvents||src==g_lvAlerts){ POINT pt{ GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam)}; if(pt.x==-1&&pt.y==-1){ RECT rc; GetClientRect(src,&rc); pt={rc.left+10,rc.top+10}; ClientToScreen(src,&pt);} HMENU m=CreatePopupMenu(); AppendMenuW(m,MF_STRING,IDC_LIST_CTX_COPY,L"Copy"); AppendMenuW(m,MF_STRING,IDC_LIST_CTX_EXPORT,L"Export..."); AppendMenuW(m,MF_SEPARATOR,0,nullptr); AppendMenuW(m,MF_STRING,IDC_LIST_CTX_REGIONS,L"Browse Memory Regions"); AppendMenuW(m,MF_STRING,IDC_LIST_CTX_DUMPREGION,L"Dump Memory..."); TrackPopupMenu(m,TPM_RIGHTBUTTON,pt.x,pt.y,0,hwnd,nullptr); DestroyMenu(m); return 0;} } break;
    case WM_HOTKEY: if(wParam==1){ SetFocus(g_searchEdit); return 0;} break;
    case WM_LBUTTONDOWN:{ POINT pt{GET_X_LPARAM(lParam),GET_Y_LPARAM(lParam)}; RECT rc; GetClientRect(hwnd,&rc); RECT rs{g_uiSettings.splitPos,kBarH+kSearchH+2,g_uiSettings.splitPos+kSplitterW,rc.bottom-kStatusH}; if(PtInRect(&rs,pt)){ g_dragSplit=true; SetCapture(hwnd);} return 0; }
    case WM_MOUSEMOVE: if(g_dragSplit){ int x=GET_X_LPARAM(lParam); RECT rc; GetClientRect(hwnd,&rc); if(x<150) x=150; if(x>rc.right-150-kSplitterW) x=rc.right-150-kSplitterW; g_uiSettings.splitPos=x; Layout(hwnd);} return 0;
    case WM_LBUTTONUP: if(g_dragSplit){ g_dragSplit=false; ReleaseCapture(); } return 0;
    case WM_NOTIFY:{ auto* hdr=reinterpret_cast<NMHDR*>(lParam); 
        // Toolbar custom draw for dark mode text/hover/pressed color
        if(hdr->hwndFrom==g_toolbar && hdr->code==NM_CUSTOMDRAW){
            auto* tcd=reinterpret_cast<NMTBCUSTOMDRAW*>(lParam);
            switch(tcd->nmcd.dwDrawStage){
            case CDDS_PREPAINT: return CDRF_NOTIFYITEMDRAW; 
            case CDDS_ITEMPREPAINT: {
                if(g_dark){
                    tcd->clrText = RGB(255,255,255);
                    // emphasize hot/pressed with lighter text (already white) but request cd colors
                    if(tcd->nmcd.uItemState & CDIS_HOT) tcd->clrText = RGB(255,255,210);
                    if(tcd->nmcd.uItemState & CDIS_SELECTED) tcd->clrText = RGB(255,230,180);
                }
                return CDRF_DODEFAULT; }
            }
        }
        if(hdr->hwndFrom==g_lvEvents||hdr->hwndFrom==g_lvAlerts){ if(hdr->code==LVN_COLUMNCLICK){ auto* cc=reinterpret_cast<NMLISTVIEW*>(lParam); if(cc->iSubItem==1){ if(hdr->hwndFrom==g_lvEvents) ResortListView(g_lvEvents,g_sortEventsAsc); else ResortListView(g_lvAlerts,g_sortAlertsAsc); } return 0;} if(hdr->code==NM_DBLCLK){ SendMessage(hwnd,WM_COMMAND,IDM_PROCESS_REGIONS,0); return 0; } if(hdr->code==NM_CUSTOMDRAW){ auto* cd=reinterpret_cast<NMLVCUSTOMDRAW*>(lParam); switch(cd->nmcd.dwDrawStage){ case CDDS_PREPAINT: return CDRF_NOTIFYITEMDRAW; case CDDS_ITEMPREPAINT:{ int idx=(int)cd->nmcd.dwItemSpec; bool isAlert=(hdr->hwndFrom==g_lvAlerts); COLORREF base=isAlert?g_theme.alertBg:g_theme.surface; if(idx%2==1) base=Lighten(base,g_dark?10:25); cd->clrTextBk=base; if(isAlert){ wchar_t buf[512]{}; ListView_GetItemText(g_lvAlerts,idx,1,buf,511); cd->clrText=GetSeverityColor(buf); } else cd->clrText=g_theme.text; return CDRF_NEWFONT; } } } } break; }
    case WM_DRAWITEM:{ auto dis=reinterpret_cast<LPDRAWITEMSTRUCT>(lParam); if(dis && (dis->hwndItem==g_searchBtn || dis->hwndItem==g_clearBtn)){
            bool pressed = (dis->itemState & ODS_SELECTED)!=0; bool hot = (dis->itemState & ODS_HOTLIGHT)!=0; 
            COLORREF base = Lighten(g_theme.surface,g_dark?35:10);
            if(pressed) base = Lighten(base,g_dark?-25:-15); else if(hot) base = Lighten(base,g_dark?55:25);
            HBRUSH br=CreateSolidBrush(base); FillRect(dis->hDC,&dis->rcItem,br); DeleteObject(br);
            // border
            HPEN pen=CreatePen(PS_SOLID,1,Lighten(base,g_dark?20:-40)); HPEN old=(HPEN)SelectObject(dis->hDC,pen); HBRUSH oldb=(HBRUSH)SelectObject(dis->hDC,GetStockObject(HOLLOW_BRUSH)); Rectangle(dis->hDC,dis->rcItem.left,dis->rcItem.top,dis->rcItem.right,dis->rcItem.bottom); SelectObject(dis->hDC,old); SelectObject(dis->hDC,oldb); DeleteObject(pen);
            // text
            wchar_t txt[64]; GetWindowTextW(dis->hwndItem,txt,63); SetBkMode(dis->hDC,TRANSPARENT); SetTextColor(dis->hDC,g_dark?RGB(255,255,255):g_theme.text); DrawTextW(dis->hDC,txt,-1,(LPRECT)&dis->rcItem,DT_CENTER|DT_VCENTER|DT_SINGLELINE);
            if(dis->itemState & ODS_FOCUS){ RECT fr=dis->rcItem; InflateRect(&fr,-3,-3); DrawFocusRect(dis->hDC,&fr);} return TRUE; }
        return FALSE; }
    case WM_XDR_EVENT: case WM_XDR_ALERT:{ std::wstring* p=reinterpret_cast<std::wstring*>(wParam); if(p){ if(msg==WM_XDR_EVENT){ AddListViewLine(g_lvEvents,g_events,*p,g_evtFilter); ++g_evtCount;} else { AddListViewLine(g_lvAlerts,g_alerts,*p,g_alertFilter); ++g_alertCount;} UpdateStatus(); delete p;} return 0; }
    case WM_SCREENSHOT_EVENT:{ auto* e=reinterpret_cast<ScreenshotCapture::ScreenshotEvent*>(wParam); if(e){ auto line=std::format(L"[{}] SCREENSHOT {}",XDR::Utils::TimeNow(),ScreenshotCapture::FormatScreenshotEvent(*e)); AddListViewLine(g_lvEvents,g_events,line,g_evtFilter); ++g_evtCount; XDR::Event ev; ev.category=XDR::EventCategory::Screenshot; ev.type=XDR::EventType::ScreenshotCaptured; ev.pid=e->triggeringPid; ev.image=e->screenshotPath; ev.details=std::format(L"trigger={} size={}",e->triggerReason,e->screenshotSize); XDR::Storage::Insert(ev); delete e; UpdateStatus(); } return 0; }
    case WM_KEYDOWN: if(wParam==VK_SPACE){ g_pause=!g_pause; UpdateStatus(); return 0;} else if(wParam==VK_ESCAPE){ if(GetFocus()==g_searchEdit){ SetWindowTextW(g_searchEdit,L""); g_evtFilter.clear(); g_alertFilter.clear(); ApplySearch(); return 0; }} else if(wParam=='L' && (GetKeyState(VK_CONTROL)&0x8000)){ SendMessage(hwnd,WM_COMMAND,ID_TB_CLEAR,0); return 0;} else if(wParam==VK_F5){ ApplySearch(); return 0;} else if(wParam=='A' && (GetKeyState(VK_CONTROL)&0x8000)){ g_autoScroll=!g_autoScroll; UpdateStatus(); return 0;} break;
    case WM_CTLCOLORSTATIC: case WM_CTLCOLOREDIT:{ HDC hdc=(HDC)wParam; SetBkMode(hdc,TRANSPARENT); SetTextColor(hdc,g_theme.text); return (LRESULT)(HBRUSH)g_brushBg; }
    case WM_CTLCOLORBTN:{ HDC hdc=(HDC)wParam; SetBkMode(hdc,OPAQUE); SetBkColor(hdc,Lighten(g_theme.surface,g_dark?35:10)); SetTextColor(hdc,g_dark?RGB(255,255,255):g_theme.text); return (LRESULT)(HBRUSH)g_brushBtn; }
    case WM_ERASEBKGND:{ RECT rc; GetClientRect(hwnd,&rc); FillRect((HDC)wParam,&rc,(HBRUSH)g_brushBg); return 1; }
    case WM_DESTROY:{ RECT r; if(GetWindowRect(hwnd,&r)){ g_uiSettings.winX=r.left; g_uiSettings.winY=r.top; g_uiSettings.winW=r.right-r.left; g_uiSettings.winH=r.bottom-r.top; } SaveUI(); KillTimer(hwnd,1); Behavioral::StopBackground(); g_procMon.Stop(); g_netMon.Stop(); g_screenshotMonitor.Stop(); g_driverMgr.Stop(); XDR::Yara::Unload(); PostQuitMessage(0); ExitProcess(0); return 0; }
    }
    return DefWindowProc(hwnd,msg,wParam,lParam);
}
static ATOM MyRegisterClass(HINSTANCE hInstance){ WNDCLASSEXW w{sizeof(w)}; w.style=CS_HREDRAW|CS_VREDRAW; w.lpfnWndProc=WndProc; w.hInstance=hInstance; w.hIcon=LoadIcon(hInstance,MAKEINTRESOURCE(IDI_XDR)); w.hCursor=LoadCursor(nullptr,IDC_ARROW); w.hbrBackground=nullptr; w.lpszMenuName=MAKEINTRESOURCEW(IDC_XDR); w.lpszClassName=szWindowClass; w.hIconSm=LoadIcon(hInstance,MAKEINTRESOURCE(IDI_SMALL)); return RegisterClassExW(&w);} 
static BOOL InitInstance(HINSTANCE hInstance,int nCmdShow){ hInst=hInstance; HWND hWnd=CreateWindowExW(WS_EX_APPWINDOW,szWindowClass,szTitle,WS_OVERLAPPEDWINDOW|WS_CLIPCHILDREN,g_uiSettings.winX,g_uiSettings.winY,g_uiSettings.winW,g_uiSettings.winH,nullptr,nullptr,hInstance,nullptr); if(!hWnd) return FALSE; ShowWindow(hWnd,nCmdShow); UpdateWindow(hWnd); return TRUE; }
int APIENTRY wWinMain(HINSTANCE hInstance,HINSTANCE,LPWSTR,int nCmdShow){ WSADATA wsa; WSAStartup(MAKEWORD(2,2),&wsa); LoadStringW(hInstance,IDS_APP_TITLE,szTitle,MAX_LOADSTRING); LoadStringW(hInstance,IDC_XDR,szWindowClass,MAX_LOADSTRING); MyRegisterClass(hInstance); if(!InitInstance(hInstance,nCmdShow)){ WSACleanup(); return 0; } Logger::Init(); XDR::Storage::Init(); HACCEL hAccel=LoadAccelerators(hInstance,MAKEINTRESOURCE(IDC_XDR)); MSG msg; while(GetMessage(&msg,nullptr,0,0)){ if(!TranslateAccelerator(msg.hwnd,hAccel,&msg)){ TranslateMessage(&msg); DispatchMessage(&msg);} } XDR::Storage::Shutdown(); WSACleanup(); return (int)msg.wParam; }