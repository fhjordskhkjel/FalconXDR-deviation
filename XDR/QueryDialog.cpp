#include "QueryDialog.h"
#include <cwctype>
#include <chrono>
#include <format>

#ifndef IDC_FILTER_TEXT
#define IDC_FILTER_TEXT 203
#define IDC_FILTER_CATEGORY 204
#define IDC_FILTER_APPLY 205
#define IDC_FILTER_LIVE 206
#define IDC_FILTER_PID 207
#define IDC_FILTER_SEVERITY 208
#endif
#ifndef IDC_QUERY_LIST
#define IDC_QUERY_LIST 201
#endif

extern HINSTANCE hInst;

static std::wstring SevToString(XDR::EventType t){
    using XDR::EventType; switch(t){
        case EventType::AlertProcessHollowing: return L"Critical";
        case EventType::AlertProcessInjection: case EventType::AlertDllInjection: case EventType::AlertReflectiveModule: case EventType::AlertReflectiveMemory: case EventType::AlertPrivilegedExec: case EventType::AlertApiHook: return L"High";
        case EventType::AlertSuspiciousExecRegion: case EventType::AlertUnsignedModule: case EventType::AlertYaraMatch: return L"Medium";
        case EventType::AlertSuspiciousProcess: case EventType::AlertSuspiciousRemotePort: return L"Low";
        default: return L"Info";
    } }

static COLORREF SevColor(const std::wstring& sev){ if(sev==L"Critical") return RGB(255,0,0); if(sev==L"High") return RGB(255,128,0); if(sev==L"Medium") return RGB(200,160,0); if(sev==L"Low") return RGB(0,120,215); return RGB(180,180,180); }

std::wstring ToString(XDR::EventCategory cat){
    switch(cat){case XDR::EventCategory::Process: return L"Process"; case XDR::EventCategory::Network: return L"Network"; case XDR::EventCategory::Alert: return L"Alert"; case XDR::EventCategory::Screenshot: return L"Screenshot";} return L"?"; }
std::wstring ToString(XDR::EventType t){
    using XDR::EventType; switch(t){
    case EventType::ProcStart: return L"ProcStart"; case EventType::ProcStop: return L"ProcStop";
    case EventType::NetConnNew: return L"NetConnNew"; case EventType::AlertSuspiciousProcess: return L"AlertSuspiciousProcess";
    case EventType::AlertSuspiciousRemotePort: return L"AlertSuspiciousRemotePort"; case EventType::ScreenshotCaptured: return L"ScreenshotCaptured"; case EventType::AlertScreenshotCaptured: return L"AlertScreenshotCaptured"; case EventType::AlertProcessInjection: return L"AlertProcessInjection"; case EventType::AlertReflectiveModule: return L"AlertReflectiveModule"; case EventType::AlertPrivilegedExec: return L"AlertPrivilegedExec"; case EventType::AlertProcessHollowing: return L"AlertProcessHollowing"; case EventType::AlertDllInjection: return L"AlertDllInjection"; case EventType::AlertReflectiveMemory: return L"AlertReflectiveMemory"; }
    return L"?"; }

struct QueryState { uint64_t lastId{0}; std::optional<XDR::EventCategory> category; std::wstring filter; std::optional<uint32_t> pid; bool live{true}; HWND list{nullptr}; int sevSel{0}; };
static std::wstring Lower(std::wstring s){ for(auto &c:s) c=(wchar_t)towlower(c); return s; }

static void FormatAndAdd(QueryState* qs, const XDR::Event &ev){
    auto ts = std::chrono::duration_cast<std::chrono::seconds>(ev.ts.time_since_epoch()).count();
    std::wstring sev = SevToString(ev.type);
    if(qs->sevSel>0){ static const wchar_t* names[]={L"Info",L"Low",L"Medium",L"High",L"Critical"}; if(sev!=names[qs->sevSel]) return; }
    std::wstring line = std::format(L"#{:06} [{:>8}] {:>5} {} {:>5} {} {}", ev.id, sev, ev.pid, ToString(ev.category), (int)ev.type, ToString(ev.type), ev.details);
    SendMessageW(qs->list, LB_ADDSTRING, 0, (LPARAM)line.c_str());
}

static void QueryPopulate(QueryState* qs, const std::vector<XDR::Event>& evs){
    for(auto &ev: evs){ if(ev.id>qs->lastId) qs->lastId=ev.id; FormatAndAdd(qs, ev);} int count=(int)SendMessageW(qs->list,LB_GETCOUNT,0,0); if(count>0) SendMessageW(qs->list,LB_SETTOPINDEX,count-1,0); }

static void ApplyFilters(QueryState* qs){ SendMessageW(qs->list, LB_RESETCONTENT, 0,0); auto rows = XDR::Storage::QueryRecentAdvanced(qs->category, qs->filter, qs->pid, 500); qs->lastId=0; QueryPopulate(qs, rows); }

INT_PTR CALLBACK QueryDlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam){ QueryState* qs=reinterpret_cast<QueryState*>(GetWindowLongPtrW(hDlg,GWLP_USERDATA)); switch(message){ case WM_INITDIALOG:{ qs=new QueryState(); SetWindowLongPtrW(hDlg,GWLP_USERDATA,(LONG_PTR)qs); HWND list=GetDlgItem(hDlg,IDC_QUERY_LIST); if(!list) list=CreateWindowExW(WS_EX_CLIENTEDGE,L"LISTBOX",nullptr,WS_CHILD|WS_VISIBLE|WS_VSCROLL|LBS_NOINTEGRALHEIGHT|LBS_EXTENDEDSEL,4,40,700,320,hDlg,(HMENU)IDC_QUERY_LIST,hInst,nullptr); qs->list=list; CreateWindowW(L"STATIC",L"Cat",WS_CHILD|WS_VISIBLE,4,4,30,16,hDlg,nullptr,hInst,nullptr); HWND combo=CreateWindowW(L"COMBOBOX",nullptr,WS_CHILD|WS_VISIBLE|CBS_DROPDOWNLIST,32,2,110,200,hDlg,(HMENU)IDC_FILTER_CATEGORY,hInst,nullptr); SendMessageW(combo,CB_ADDSTRING,0,(LPARAM)L"All"); SendMessageW(combo,CB_ADDSTRING,0,(LPARAM)L"Process"); SendMessageW(combo,CB_ADDSTRING,0,(LPARAM)L"Network"); SendMessageW(combo,CB_ADDSTRING,0,(LPARAM)L"Alert"); SendMessageW(combo,CB_ADDSTRING,0,(LPARAM)L"Screenshot"); SendMessageW(combo,CB_SETCURSEL,0,0); CreateWindowW(L"STATIC",L"PID",WS_CHILD|WS_VISIBLE,150,4,24,16,hDlg,nullptr,hInst,nullptr); CreateWindowExW(WS_EX_CLIENTEDGE,L"EDIT",nullptr,WS_CHILD|WS_VISIBLE|ES_AUTOHSCROLL,176,2,60,20,hDlg,(HMENU)IDC_FILTER_PID,hInst,nullptr); CreateWindowW(L"STATIC",L"Text",WS_CHILD|WS_VISIBLE,242,4,28,16,hDlg,nullptr,hInst,nullptr); CreateWindowExW(WS_EX_CLIENTEDGE,L"EDIT",nullptr,WS_CHILD|WS_VISIBLE|ES_AUTOHSCROLL,272,2,200,20,hDlg,(HMENU)IDC_FILTER_TEXT,hInst,nullptr); CreateWindowW(L"STATIC",L"Severity",WS_CHILD|WS_VISIBLE,476,4,56,16,hDlg,nullptr,hInst,nullptr); HWND sev=CreateWindowW(L"COMBOBOX",nullptr,WS_CHILD|WS_VISIBLE|CBS_DROPDOWNLIST,536,2,100,200,hDlg,(HMENU)IDC_FILTER_SEVERITY,hInst,nullptr); const wchar_t* sevs[]={L"All",L"Info",L"Low",L"Medium",L"High",L"Critical"}; for(auto s: sevs) SendMessageW(sev,CB_ADDSTRING,0,(LPARAM)s); SendMessageW(sev,CB_SETCURSEL,0,0); CreateWindowW(L"BUTTON",L"Apply",WS_CHILD|WS_VISIBLE,642,2,60,20,hDlg,(HMENU)IDC_FILTER_APPLY,hInst,nullptr); CreateWindowW(L"BUTTON",L"Live",WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX,706,2,50,20,hDlg,(HMENU)IDC_FILTER_LIVE,hInst,nullptr); SendMessageW(GetDlgItem(hDlg,IDC_FILTER_LIVE),BM_SETCHECK,BST_CHECKED,0); auto initial=XDR::Storage::QueryRecentAdvanced(std::nullopt,L"",std::nullopt,300); QueryPopulate(qs,initial); SetTimer(hDlg,1,1000,nullptr); return TRUE;} case WM_TIMER: if(wParam==1 && qs && qs->live){ auto more=XDR::Storage::QuerySinceAdvanced(qs->lastId,qs->category,qs->filter,qs->pid,300); if(!more.empty()) QueryPopulate(qs,more);} return TRUE; case WM_COMMAND: switch(LOWORD(wParam)){ case IDC_FILTER_APPLY: if(qs){ HWND combo=GetDlgItem(hDlg,IDC_FILTER_CATEGORY); int sel=(int)SendMessageW(combo,CB_GETCURSEL,0,0); wchar_t pidBuf[32]{}; GetWindowTextW(GetDlgItem(hDlg,IDC_FILTER_PID),pidBuf,31); wchar_t textBuf[256]{}; GetWindowTextW(GetDlgItem(hDlg,IDC_FILTER_TEXT),textBuf,255); HWND sev=GetDlgItem(hDlg,IDC_FILTER_SEVERITY); qs->sevSel=(int)SendMessageW(sev,CB_GETCURSEL,0,0); qs->category.reset(); if(sel==1) qs->category=XDR::EventCategory::Process; else if(sel==2) qs->category=XDR::EventCategory::Network; else if(sel==3) qs->category=XDR::EventCategory::Alert; else if(sel==4) qs->category=XDR::EventCategory::Screenshot;
    qs->filter=Lower(textBuf); if(pidBuf[0]){ try { qs->pid = (uint32_t)std::stoul(pidBuf); } catch(...) { qs->pid.reset(); } } else qs->pid.reset(); ApplyFilters(qs);} return TRUE; case IDC_FILTER_LIVE: if(qs){ LRESULT chk=SendMessageW(GetDlgItem(hDlg,IDC_FILTER_LIVE),BM_GETCHECK,0,0); qs->live=(chk==BST_CHECKED);} return TRUE; case IDOK: case IDCANCEL: if(qs){ KillTimer(hDlg,1); delete qs; SetWindowLongPtrW(hDlg,GWLP_USERDATA,0);} EndDialog(hDlg,LOWORD(wParam)); return TRUE; } break; case WM_DESTROY: if(qs){ KillTimer(hDlg,1); delete qs; SetWindowLongPtrW(hDlg,GWLP_USERDATA,0);} break;} return FALSE; }
